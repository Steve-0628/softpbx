//! Deterministic simulation test bed (docs/04 §2).
//!
//! No real clock, no real sockets: time moves only when the test moves it,
//! all randomness comes from a seeded generator, and everything that happens
//! lands in an ordered trace. Running the same scenario with the same seed
//! must produce the **identical trace** — that is what makes failures
//! reproducible and what the determinism tests assert.
//!
//! Deliberately *not* simulated (docs/04): fax machines, modems, gateways,
//! or an elaborate network model. Just a virtual clock, an ordered event
//! queue, a lossy/delayable datagram network and a trace.

/// A simulated endpoint ("alice", "pbx", ...).
pub type Node = &'static str;

/// Virtual clock. Real time is never consulted.
#[derive(Debug, Clone, Copy)]
pub struct VirtualClock {
    /// Current time in ms.
    pub now_ms: u64,
}

impl VirtualClock {
    /// Moves time forward.
    pub fn advance(&mut self, ms: u64) {
        self.now_ms += ms;
    }
}

/// Deterministic pseudo-random generator (xorshift64*).
///
/// Same seed ⇒ same sequence, on every platform and every run.
#[derive(Debug, Clone)]
pub struct SimRng(u64);

impl SimRng {
    /// Creates a generator from a seed (zero is remapped; it breaks xorshift).
    pub fn new(seed: u64) -> Self {
        SimRng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// Next raw value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `p` (0.0..=1.0).
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        unit < p
    }
}

/// Datagram network characteristics.
#[derive(Debug, Clone, Copy)]
pub struct NetworkConfig {
    /// Probability that a datagram is dropped (0.0..=1.0).
    pub loss: f64,
    /// One-way delay applied to every datagram, ms.
    pub delay_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            loss: 0.0,
            delay_ms: 0,
        }
    }
}

/// Something scheduled in the world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A named timer the test armed.
    Timer {
        /// Timer name ("A", "call:...:B", ...).
        name: String,
    },
    /// A datagram delivered between two nodes.
    Datagram {
        /// Sender.
        from: Node,
        /// Receiver.
        to: Node,
        /// Payload.
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct Scheduled {
    at_ms: u64,
    seq: u64,
    event: Event,
}

/// The simulated world: clock, network, event queue, trace.
#[derive(Debug)]
pub struct World {
    clock: VirtualClock,
    /// Datagram behavior (changeable mid-test).
    pub net: NetworkConfig,
    rng: SimRng,
    queue: Vec<Scheduled>,
    next_seq: u64,
    trace: Vec<String>,
}

impl World {
    /// Creates a world with a fixed seed. Deterministic from here on.
    pub fn with_seed(seed: u64) -> Self {
        let mut world = World {
            clock: VirtualClock { now_ms: 0 },
            net: NetworkConfig::default(),
            rng: SimRng::new(seed),
            queue: Vec::new(),
            next_seq: 0,
            trace: Vec::new(),
        };
        world.log(format!("world seed={seed:#x}"));
        world
    }

    /// Current simulated time.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms
    }

    /// Moves time forward without any event firing (for step-by-step tests).
    pub fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
    }

    /// Seeded randomness (for tests that need it).
    pub fn rng(&mut self) -> &mut SimRng {
        &mut self.rng
    }

    /// Arms a named timer for an absolute time. Arming a name replaces any
    /// outstanding timer with that name.
    pub fn arm(&mut self, name: impl Into<String>, at_ms: u64) {
        let name = name.into();
        self.disarm(&name);
        self.log(format!("arm {name} at {at_ms}"));
        let seq = self.take_seq();
        self.queue.push(Scheduled {
            at_ms,
            seq,
            event: Event::Timer { name },
        });
    }

    /// Arms a named timer relative to now.
    pub fn arm_in(&mut self, name: impl Into<String>, ms: u64) {
        self.arm(name, self.now_ms() + ms);
    }

    /// Disarms a named timer (no-op if not armed).
    pub fn disarm(&mut self, name: &str) {
        self.queue.retain(
            |scheduled| !matches!(&scheduled.event, Event::Timer { name: armed } if armed == name),
        );
    }

    /// Sends a datagram: subject to loss and delay, then delivered as an event.
    pub fn send(&mut self, from: Node, to: Node, data: Vec<u8>) {
        let summary = summary(&data);
        self.log(format!("send {from}->{to} {summary}"));
        if self.rng.chance(self.net.loss) {
            self.log(format!("drop {from}->{to} {summary}"));
            return;
        }
        let at_ms = self.now_ms() + self.net.delay_ms;
        let seq = self.take_seq();
        self.queue.push(Scheduled {
            at_ms,
            seq,
            event: Event::Datagram { from, to, data },
        });
    }

    /// Pops the earliest event (ties broken by scheduling order) and moves the
    /// clock to its time. `None` when the world is quiescent.
    pub fn next_event(&mut self) -> Option<Event> {
        let index = self
            .queue
            .iter()
            .enumerate()
            .min_by_key(|(_, scheduled)| (scheduled.at_ms, scheduled.seq))
            .map(|(index, _)| index)?;
        let scheduled = self.queue.remove(index);
        self.clock.now_ms = scheduled.at_ms;
        match &scheduled.event {
            Event::Timer { name } => self.log(format!("fire timer {name}")),
            Event::Datagram { from, to, data } => {
                self.log(format!("recv {from}->{to} {}", summary(data)))
            }
        }
        Some(scheduled.event)
    }

    /// Runs the world until quiescent, handing every event to `step`.
    pub fn run(&mut self, mut step: impl FnMut(&mut World, Event)) {
        while let Some(event) = self.next_event() {
            step(self, event);
        }
    }

    /// Records a line in the trace (timestamped, like every other entry).
    pub fn log(&mut self, message: impl Into<String>) {
        let line = format!("{:>6} {}", self.clock.now_ms, message.into());
        self.trace.push(line);
    }

    /// The trace so far: time-ordered lines of everything that happened.
    pub fn trace(&self) -> &[String] {
        &self.trace
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}

fn summary(data: &[u8]) -> String {
    let line = data
        .iter()
        .position(|&b| b == b'\n')
        .map(|at| &data[..at])
        .unwrap_or(data);
    let line = String::from_utf8_lossy(line).trim_end().to_string();
    format!("({}B {line:?})", data.len())
}
