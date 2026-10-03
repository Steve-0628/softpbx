//! `pbx-daemon` — the whole program (docs/02).
//!
//! Startup order: load and validate the config file, bind sockets, start
//! reading SIP and media, start the timer loop. Then it just forwards:
//! parsed messages into [`Switch`], its outputs onto the network.
//!
//! This layer owns all I/O; the crates below it own none (docs/02 §2).

mod config;

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use call::{Output, Switch};
use sip_syntax::{parse_message, serialize_message, Message};
use tokio::net::UdpSocket;

use crate::config::FileConfig;

const SIP_BUFFER: usize = 65_535;
const RTP_BUFFER: usize = 2_048;
const TIMER_TICK_MS: u64 = 50;

/// Everything the running daemon shares between its tasks.
struct Pbx {
    switch: Mutex<Switch>,
    started: Instant,
    sip: UdpSocket,
    /// One socket per media relay port (two per call).
    rtp: HashMap<u16, Arc<UdpSocket>>,
    /// Where responses go: Via branch → where its request came from.
    response_route: Mutex<HashMap<String, SocketAddr>>,
    call_log: Mutex<std::fs::File>,
}

impl Pbx {
    /// Real milliseconds since start; the switch only sees this clock.
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// One SIP datagram arrived: parse, feed the switch, send what it says.
    async fn handle_sip(&self, data: &[u8], source: SocketAddr) {
        // Keepalive pings (RFC 5626) get a bare CRLF back and nothing else.
        if sip_syntax::is_keepalive(data) {
            let _ = self.sip.send_to(b"\r\n", source).await;
            return;
        }
        let Ok(message) = parse_message(data) else {
            log(format!("dropped unparsable message from {source}"));
            return;
        };
        if let Message::Request(request) = &message {
            if let Some(branch) = sip_stack::branch(&request.headers) {
                let mut routes = self.response_route.lock().expect("lock");
                // Bounded: old branches only matter for one transaction.
                if routes.len() > 4_096 {
                    routes.clear();
                }
                routes.insert(branch.to_string(), source);
            }
        }
        let outputs = self
            .switch
            .lock()
            .expect("lock")
            .handle(message, self.now_ms());
        self.dispatch(outputs, Some(source)).await;
    }

    /// RTP arrived on a relay port: forward it down the other leg.
    async fn handle_rtp(&self, local_port: u16, data: &[u8], source: SocketAddr) {
        let outputs =
            self.switch
                .lock()
                .expect("lock")
                .on_rtp(local_port, &source.to_string(), data);
        self.dispatch(outputs, None).await;
    }

    /// Fires whatever transaction timers are due.
    async fn tick(&self) {
        let now = self.now_ms();
        let due: Vec<String> = self
            .switch
            .lock()
            .expect("lock")
            .timers()
            .into_iter()
            .filter(|(_, due_ms)| *due_ms <= now)
            .map(|(name, _)| name)
            .collect();
        if due.is_empty() {
            return;
        }
        let mut outputs = Vec::new();
        {
            let mut switch = self.switch.lock().expect("lock");
            for name in due {
                outputs.extend(switch.on_timer(&name, now));
            }
        }
        self.dispatch(outputs, None).await;
    }

    /// Puts the switch's outputs on the network (or in the log).
    async fn dispatch(&self, outputs: Vec<Output>, reply_to: Option<SocketAddr>) {
        for output in outputs {
            match output {
                Output::Send(message) => {
                    let bytes = serialize_message(&message);
                    let destination = match &message {
                        // Responses go where the request came from (rport).
                        Message::Response(response) => sip_stack::branch(&response.headers)
                            .and_then(|branch| {
                                self.response_route
                                    .lock()
                                    .expect("lock")
                                    .get(branch)
                                    .copied()
                            })
                            .or(reply_to),
                        // Requests go to their request-URI (a contact address).
                        Message::Request(request) => resolve_uri(&request.uri),
                    };
                    match destination {
                        Some(destination) => {
                            if let Err(error) = self.sip.send_to(&bytes, destination).await {
                                log(format!("sip send to {destination} failed: {error}"));
                            }
                        }
                        None => log(format!(
                            "no address to send {} to; dropped",
                            start_line(&message)
                        )),
                    }
                }
                Output::SendRtp {
                    from_port,
                    to,
                    data,
                } => {
                    let Ok(destination) = to.parse::<SocketAddr>() else {
                        log(format!("media destination {to} is not an address; dropped"));
                        continue;
                    };
                    match self.rtp.get(&from_port) {
                        Some(socket) => {
                            if let Err(error) = socket.send_to(&data, destination).await {
                                log(format!("media send to {destination} failed: {error}"));
                            }
                        }
                        None => log(format!("no media socket on port {from_port}; dropped")),
                    }
                }
                Output::CallLog(line) => {
                    log(format!("call {line}"));
                    let mut file = self.call_log.lock().expect("lock");
                    if let Err(error) = writeln!(file, "{line}") {
                        log(format!("call log write failed: {error}"));
                    }
                }
            }
        }
    }
}

fn log(message: impl std::fmt::Display) {
    println!("softpbx: {message}");
}

fn start_line(message: &Message) -> String {
    match message {
        Message::Request(request) => format!("{} {}", request.method.as_str(), request.uri),
        Message::Response(response) => format!("SIP/2.0 {}", response.status),
    }
}

/// Resolves a request-URI to an address. No DNS (docs/07): peers are IPs.
fn resolve_uri(uri: &str) -> Option<SocketAddr> {
    let address = sip_stack::uri_of(uri);
    let hostport = address.rsplit('@').next().unwrap_or(address).trim();
    if hostport.contains(':') {
        hostport.parse().ok()
    } else {
        format!("{hostport}:5060").parse().ok()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/softpbx/config.toml".to_string());
    let config = FileConfig::load(&config_path)?;

    // The call log: append only (docs/02 §5).
    if let Some(parent) = std::path::Path::new(&config.general.call_log).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let call_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.general.call_log)
        .with_context(|| format!("cannot open {}", config.general.call_log))?;

    let sip = UdpSocket::bind(&config.general.sip_bind)
        .await
        .with_context(|| format!("cannot bind SIP socket {}", config.general.sip_bind))?;
    let mut rtp = HashMap::new();
    for port in
        config.general.rtp_port_base..config.general.rtp_port_base + config.general.rtp_ports
    {
        let socket = UdpSocket::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("cannot bind media port {port}"))?;
        rtp.insert(port, Arc::new(socket));
    }

    let device_count = config.device.len();
    let pbx = Arc::new(Pbx {
        switch: Mutex::new(Switch::new(config.switch_config())),
        started: Instant::now(),
        sip,
        rtp,
        response_route: Mutex::new(HashMap::new()),
        call_log: Mutex::new(call_log),
    });

    log(format!(
        "started: sip={} media={}-{} devices={}",
        config.general.sip_bind,
        config.general.rtp_port_base,
        config.general.rtp_port_base + config.general.rtp_ports - 1,
        device_count
    ));

    // SIP in and out.
    {
        let pbx = Arc::clone(&pbx);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; SIP_BUFFER];
            loop {
                match pbx.sip.recv_from(&mut buffer).await {
                    Ok((size, source)) => pbx.handle_sip(&buffer[..size], source).await,
                    Err(error) => log(format!("sip receive failed: {error}")),
                }
            }
        });
    }

    // Media in and out, one task per relay port.
    for (port, socket) in &pbx.rtp {
        let pbx = Arc::clone(&pbx);
        let socket = Arc::clone(socket);
        let port = *port;
        tokio::spawn(async move {
            let mut buffer = vec![0u8; RTP_BUFFER];
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((size, source)) => pbx.handle_rtp(port, &buffer[..size], source).await,
                    Err(error) => log(format!("media receive failed: {error}")),
                }
            }
        });
    }

    // Transaction timers (retransmissions, give-up).
    {
        let pbx = Arc::clone(&pbx);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(TIMER_TICK_MS)).await;
                pbx.tick().await;
            }
        });
    }

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    log("shutting down (established calls are dropped; devices will re-register)");
    Ok(())
}
