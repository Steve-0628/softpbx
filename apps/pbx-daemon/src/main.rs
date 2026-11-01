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
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use call::{interface_for, Interface, Output, Switch};
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
    /// The local interfaces (docs/02 §4): which address serves which peers.
    interfaces: Vec<Interface>,
    /// One SIP socket per interface, keyed by the interface's address.
    sip: HashMap<SocketAddr, UdpSocket>,
    /// Media sockets: one per (interface, relay port) pair.
    rtp: HashMap<(IpAddr, u16), Arc<UdpSocket>>,
    /// Where responses go: Via branch → where its request came from.
    response_route: Mutex<ResponseRoutes>,
    call_log: Mutex<std::fs::File>,
}

/// Response routing: branch → (source address, insertion order). Bounded:
/// the oldest entries are evicted when it grows too large.
struct ResponseRoutes {
    next_seq: u64,
    map: HashMap<String, (SocketAddr, u64)>,
}

impl ResponseRoutes {
    fn new() -> Self {
        ResponseRoutes {
            next_seq: 0,
            map: HashMap::new(),
        }
    }

    fn remember(&mut self, branch: String, source: SocketAddr) {
        self.next_seq += 1;
        self.map.insert(branch, (source, self.next_seq));
        if self.map.len() > 4_096 {
            let mut by_age: Vec<(u64, String)> = self
                .map
                .iter()
                .map(|(branch, (_, seq))| (*seq, branch.clone()))
                .collect();
            by_age.sort();
            for (_, branch) in by_age.into_iter().take(1_024) {
                self.map.remove(&branch);
            }
        }
    }

    fn lookup(&self, branch: &str) -> Option<SocketAddr> {
        self.map.get(branch).map(|(source, _)| *source)
    }
}

impl Pbx {
    /// Real milliseconds since start; the switch only sees this clock.
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// The local interface that serves a peer's address (docs/02 §4): the
    /// most specific network containing it — the first interface when the
    /// address is unknown or in no network at all.
    fn local(&self, peer: IpAddr) -> &Interface {
        interface_for(&self.interfaces, peer).unwrap_or(&self.interfaces[0])
    }

    /// One SIP datagram arrived at the interface `local`: parse, feed the
    /// switch, send what it says.
    async fn handle_sip(&self, local: SocketAddr, data: &[u8], source: SocketAddr) {
        // Keepalive pings (RFC 5626) get a bare CRLF back and nothing else.
        if sip_syntax::is_keepalive(data) {
            if let Some(socket) = self.sip.get(&local) {
                let _ = socket.send_to(b"\r\n", source).await;
            }
            return;
        }
        let Ok(message) = parse_message(data) else {
            log(format!("dropped unparsable message from {source}"));
            return;
        };
        if let Message::Request(request) = &message {
            if let Some(branch) = sip_stack::branch(&request.headers) {
                self.response_route
                    .lock()
                    .expect("lock")
                    .remember(branch.to_string(), source);
            }
        }
        let outputs =
            self.switch
                .lock()
                .expect("lock")
                .handle(message, self.now_ms(), Some(source));
        self.dispatch(outputs, Some(source)).await;
    }

    /// RTP arrived on a relay port: forward it down the other leg.
    async fn handle_rtp(&self, local_port: u16, data: &[u8], source: SocketAddr) {
        let outputs = self.switch.lock().expect("lock").on_rtp(
            local_port,
            &source.to_string(),
            data,
            self.now_ms(),
        );
        self.dispatch(outputs, None).await;
    }

    /// Fires whatever transaction timers are due, and sweeps expired
    /// registrations now and then.
    async fn tick(&self) {
        let now = self.now_ms();
        let mut outputs = Vec::new();
        {
            let mut switch = self.switch.lock().expect("lock");
            // sweep() hands back the teardown of calls that died on media
            // silence (BYEs, call log) — it must be dispatched like every
            // other switch output, not dropped.
            outputs.extend(switch.sweep(now));
            switch.expire(now);
            let due: Vec<String> = switch
                .timers()
                .into_iter()
                .filter(|(_, due_ms)| *due_ms <= now)
                .map(|(name, _)| name)
                .collect();
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
                        // Responses go back where their request came from.
                        Message::Response(response) => sip_stack::branch(&response.headers)
                            .and_then(|branch| {
                                self.response_route.lock().expect("lock").lookup(branch)
                            })
                            .or(reply_to),
                        // Requests go to their request-URI (a contact address).
                        Message::Request(request) => resolve_uri(&request.uri),
                    };
                    match destination {
                        Some(destination) => {
                            // Sent from the interface that serves the peer,
                            // so the source address matches the one the
                            // message advertises (docs/02 §4).
                            let local = self.local(destination.ip());
                            match self.sip.get(&local.sip) {
                                Some(socket) => {
                                    if let Err(error) = socket.send_to(&bytes, destination).await {
                                        log(format!("sip send to {destination} failed: {error}"));
                                    }
                                }
                                None => log(format!("no SIP socket on {}; dropped", local.sip)),
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
                    let local = self.local(destination.ip());
                    match self.rtp.get(&(local.rtp, from_port)) {
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

/// Resolves a request-URI to an address. No DNS (docs/07): peers are IP
/// literals. Handles display names, URI parameters and missing user parts:
/// `<sip:1001@192.0.2.1:5060;transport=udp>` → `192.0.2.1:5060`,
/// `sip:192.0.2.1` → `192.0.2.1:5060`.
fn resolve_uri(uri: &str) -> Option<SocketAddr> {
    let address = sip_stack::uri_of(uri);
    let address = address
        .strip_prefix("sips:")
        .or_else(|| address.strip_prefix("sip:"))
        .unwrap_or(address);
    let hostport = address.rsplit('@').next().unwrap_or(address).trim();
    if hostport.is_empty() {
        return None;
    }
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

    // One SIP socket per interface: we listen on, and send from, the address
    // each peer is served from (docs/02 §4).
    let interfaces = config.interfaces();
    let mut sip = HashMap::new();
    for interface in &interfaces {
        let socket = UdpSocket::bind(interface.sip)
            .await
            .with_context(|| format!("cannot bind SIP socket {}", interface.sip))?;
        sip.insert(interface.sip, socket);
    }
    // Media sockets: one per (interface, relay port) pair.
    let mut rtp = HashMap::new();
    let first_port = u32::from(config.general.rtp_port_base);
    let last_port = first_port + u32::from(config.general.rtp_ports);
    for interface in &interfaces {
        for port in first_port..last_port {
            let port = port as u16;
            let socket = UdpSocket::bind((interface.rtp, port))
                .await
                .with_context(|| format!("cannot bind media port {port} on {}", interface.rtp))?;
            rtp.insert((interface.rtp, port), Arc::new(socket));
        }
    }

    let device_count = config.device.len();
    let pbx = Arc::new(Pbx {
        switch: Mutex::new(Switch::new(config.switch_config())),
        started: Instant::now(),
        interfaces,
        sip,
        rtp,
        response_route: Mutex::new(ResponseRoutes::new()),
        call_log: Mutex::new(call_log),
    });

    log(format!(
        "started: sip={} media={}-{} devices={}",
        pbx.interfaces
            .iter()
            .map(|interface| interface.sip.to_string())
            .collect::<Vec<_>>()
            .join(","),
        config.general.rtp_port_base,
        config.general.rtp_port_base + config.general.rtp_ports - 1,
        device_count
    ));

    // SIP in and out, one task per interface.
    for local in pbx.sip.keys().copied().collect::<Vec<_>>() {
        let pbx = Arc::clone(&pbx);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; SIP_BUFFER];
            loop {
                match pbx.sip[&local].recv_from(&mut buffer).await {
                    Ok((size, source)) => pbx.handle_sip(local, &buffer[..size], source).await,
                    Err(error) => log(format!("sip receive failed: {error}")),
                }
            }
        });
    }

    // Media in and out, one task per relay socket.
    for (key, socket) in &pbx.rtp {
        let pbx = Arc::clone(&pbx);
        let socket = Arc::clone(socket);
        let port = key.1;
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

    // Ctrl-C and SIGTERM (`systemctl stop`, `pkill`) both shut down cleanly.
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("installing the SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    log("shutting down (established calls are dropped; devices will re-register)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_uri;
    use std::net::SocketAddr;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    #[test]
    fn resolves_real_world_contact_shapes() {
        // Plain, with user, with port.
        assert_eq!(
            resolve_uri("sip:bob@192.0.2.2:5060"),
            Some(addr("192.0.2.2:5060"))
        );
        // URI parameters (Grandstream `;transport=`, Aastra `;line=`, ...).
        assert_eq!(
            resolve_uri("sip:1001@192.0.2.1:5060;transport=UDP"),
            Some(addr("192.0.2.1:5060"))
        );
        // Bracketed, with display name and parameters.
        assert_eq!(
            resolve_uri("\"Alice\" <sip:1001@192.0.2.1:5060;line=1>"),
            Some(addr("192.0.2.1:5060"))
        );
        // No user part at all.
        assert_eq!(
            resolve_uri("sip:192.0.2.1:5060"),
            Some(addr("192.0.2.1:5060"))
        );
        // No port: SIP's default.
        assert_eq!(
            resolve_uri("sip:alice@192.0.2.1"),
            Some(addr("192.0.2.1:5060"))
        );
    }

    #[test]
    fn refuses_what_it_cannot_use() {
        // No DNS (docs/07): hostnames are not resolved.
        assert_eq!(resolve_uri("sip:bob@example.com:5060"), None);
        assert_eq!(resolve_uri("sip:bob@example.com"), None);
        assert_eq!(resolve_uri(""), None);
        assert_eq!(resolve_uri("<sip:>"), None);
    }
}
