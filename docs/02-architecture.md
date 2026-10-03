# 02. Architecture

## 1. The shape of the program

One process (`pbx-daemon`), one async runtime (tokio), one config file read at
startup. No databases, no background management services, no shared-nothing
clusters.

```
        UDP :5060                    UDP (RTP port range)
 phones ────────► ┌─────────────────────────────────────┐ ────► phones
                  │  pbx-daemon                         │
                  │                                     │
                  │  sip-stack   transactions, dialogs  │
                  │  call        call logic, routing    │
                  │  rtp         audio forwarding       │
                  │                                     │
                  │  state in memory:                   │
                  │   registrations, ongoing calls      │
                  └─────────────────────────────────────┘
                              │
                              ▼
                  logs (stdout) + call log (file, append-only)
```

## 2. Crates

| Crate | Responsibility |
| --- | --- |
| `sip-syntax` | Parse and serialize SIP messages and SDP. Pure functions, no I/O, no dependencies. Malformed input must produce an error, never a panic. |
| `sip-stack` | UDP transport, SIP transactions (request/response matching, retransmission), dialogs (a call's signaling session). |
| `call` | The actual PBX logic: who is registered, what a dialed number means, what happens when someone answers or hangs up. Each call is a small state machine. |
| `rtp` | RTP packet parsing and forwarding between the two sides of a call. Small jitter buffer for audio smoothness. |
| `media` | G.711 handling; later, audio mixing if any feature needs it. |
| `engine-sim` | The deterministic simulation test bed (docs/04). |

Dependency rule: `sip-syntax` depends on nothing. `call` may use `sip-stack`
and `rtp`. Nothing depends on `engine-sim`.

## 3. Concurrency and state

- tokio tasks: one for the SIP socket, one per call (both signaling and audio
  forwarding for that call), one for logging.
- Shared state is small and coarse: a table of registered devices and a table
  of active calls, behind ordinary locks. At a few hundred devices this is
  not a performance question.
- Call audio is forwarded by the call's own task reading and writing UDP
  sockets. There is no special "media plane" — no core pinning, no real-time
  scheduling, no lock-free ring buffers. If we ever need them, the design has a
  clear seam to add them; we don't build that now.
- **State is memory-only.** Registrations expire and re-register; calls are
  rebuilt from nothing after a restart. Nothing is persisted except logs.

## 4. Configuration

A single TOML file, written by a human, validated at startup. If it is invalid,
the daemon refuses to start and says why. There is no runtime configuration
API and no reload mechanism in v1 (restart the process to apply changes).

```toml
# /etc/softpbx/config.toml

[general]
sip_bind = "0.0.0.0:5060"
rtp_port_range = "10000-10800"
log_level = "info"
call_log = "/var/log/softpbx/calls.ndjson"

[[device]]
number = "1001"
name = "Alice"
secret = "change-me"        # what the phone uses to register

[[device]]
number = "1002"
name = "Bob"
secret = "change-me-too"

# Call routing: first matching rule wins.
[[routing]]
match = "1XXX"              # what the caller dialed (glob-style)
target = "device"           # ring the device with that number

[[routing]]
match = "0"                 # example: operator
target = "1001"
```

Later additions to this file: ring groups, trunk definitions, per-device quirk
profiles. No separate quirk files, no per-entity directories.

## 5. Logging

- Human-readable structured logs to stdout (journald in production).
- One append-only NDJSON call log: one line per call with start time, end time,
  caller, callee, and outcome. This is what answers "why did that call fail?"
  and "did that fax ever go out?" later on. Lines are appended and never
  rewritten; a torn last line after a crash is ignored on startup.

## 6. Security posture

The system runs on a trusted office network or VPN. What we still do:

- Digest authentication for phone registrations; a phone without the right
  password cannot register or make calls.
- Clear refusal of malformed or oversized SIP messages (no panics, no unbounded
  memory growth).
- No remote management surface at all, which is the simplest possible attack
  surface reduction.

We explicitly do not implement TLS, SRTP, intrusion detection, or rate limiting
beyond basic sanity limits.

## 7. Deliberate omissions (and why)

| Omission | Why |
| --- | --- |
| Database | A config file and a log file are enough at this scale |
| Management API / UI | Config is a file; state is inspected in logs |
| Desired-state config management | "Write the file, restart" is a complete workflow |
| High availability | A crashed daemon restarts in seconds; calls re-establish |
| Real-time media engineering | Tens of G.711 calls do not justify it |
| Conference, recording, billing | Out of scope (docs/01) |

## 8. Room left for later features

Fax and dial-up modem support are explicitly *not* built now (docs/06), but the
first phase keeps the seams open so they arrive as additions, not as rewrites:

- **The audio path is a transparent byte pipe.** Forwarded audio is never
  processed (no VAD, no packet-loss concealment, no AGC, no transcoding). Fax
  and modem signals survive this path; they do not survive a DSP pipeline.
  This is a day-one constraint, not a later change.
- **Call states extend downward.** The call state machine reserves states after
  `Answered` (a "data mode" for fax/modem, a "held" state for hold). v1 simply
  has no transitions into them.
- **The config file can grow.** Future `[[trunk]]`, `[[group]]` and gateway
  entries fit the existing shape; no schema migration needed since nothing
  reads it but the daemon.
- **Call routing can grow a new target** ("send this call to the trunk", "this
  number is a fax machine on a gateway port") without restructuring the rules.
- **re-INVITE handling stays in the stack**, because fax/modem switching and
  trunks will need mid-call media renegotiation. v1 just answers "keep things
  as they are".
