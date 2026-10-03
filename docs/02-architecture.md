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
                  │  call        call logic             │
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
| `sip-stack` | SIP transactions (request/response matching, retransmission, timers) and dialogs (a call's signaling session). The sockets live in the daemon; this crate is pure. |
| `call` | The actual PBX logic: who is registered, where a dialed number goes, what happens when someone answers or hangs up. Each call is a small state machine. |
| `rtp` | RTP packet parsing and forwarding between the two sides of a call — byte for byte, unprocessed. |
| `media` | G.711 handling; later, audio mixing if any feature needs it. |
| `engine-sim` | The deterministic simulation test bed (docs/04). |

Dependency rule: `sip-syntax` depends on nothing. `call` may use `sip-stack`
and `rtp`. Nothing depends on `engine-sim`.

## 3. Concurrency and state

- tokio tasks, one per piece of I/O: one for the SIP socket, one per media
  relay port, one timer tick loop. A call is just data inside the switch —
  there are no per-call tasks and no separate media plane.
- Shared state is small and coarse: the switch (calls) and the registrar
  (devices, bindings) behind ordinary locks. At a few hundred devices this is
  not a performance question.
- Call audio is relayed by the media-port tasks reading and writing UDP
  sockets. No core pinning, no real-time scheduling, no lock-free rings. If we
  ever need them, the design has a clear seam to add them; we don't build that
  now.
- **State is memory-only.** Registrations expire and re-register; calls are
  rebuilt from nothing after a restart. Nothing is persisted except logs.

## 4. Configuration

A single TOML file, written by a human, validated at startup. If it is invalid,
the daemon refuses to start and says why. Unknown keys are refused too: a typo
or a leftover section is an error, not silence. There is no runtime
configuration API and no reload mechanism in v1 (restart the process to apply
changes).

```toml
# /etc/softpbx/config.toml

[general]
realm = "softpbx"                 # digest-authentication realm
sip_bind = "0.0.0.0:5060"         # where we listen for SIP
pbx_host = "192.0.2.10:5060"      # our address as devices see it (Via/Contact)
rtp_host = "192.0.2.10"           # our IP as devices see it (SDP media)
rtp_port_base = 10000             # first media relay port
rtp_ports = 100                   # ports to bind (two per concurrent call)
call_log = "/var/log/softpbx/calls.ndjson"

[[device]]
number = "1001"
name = "Alice"
secret = "change-me"              # what the phone uses to register

[[device]]
number = "1002"
name = "Bob"
secret = "change-me-too"

# Call routing (docs/03 §4): first match wins. Optional — without any
# [[routing]] sections, a dialed number rings the device that has it.
[[routing]]
match = "0"                     # what the caller dialed (* and ? wildcard)
to = "1001"                     # "dialed", "reject", or a number

[[routing]]
match = "9*"
to = "dialed"
strip = "9"                     # drop the leading 9 before the lookup

[[routing]]
match = "3*"                    # 3xxx lives on the other PBX
to = "trunk:mikopbx"

[[trunk]]
name = "mikopbx"                # the peer routes the number itself
peer = "192.168.77.108:5060"
```

Ring groups and trunk targets get their own sections here later.

## 5. Logging

- Human-readable structured logs to stdout (journald in production).
- One append-only NDJSON call log: one line per call with the caller, the
  callee, start/end offsets in milliseconds since the daemon started, and the
  outcome. `callee` is the *routed* number once routing ran, and what was
  dialed for refusals that happen before it (unauthorized, restricted). This
  is what answers "why did that call fail?" later on. Lines are
  appended and never rewritten, and nothing ever reads the file back — it is
  for humans (and `jq`).

## 6. Security posture

The system runs on a trusted office network or VPN. What we still do:

- Digest authentication for phone registrations: without the right password a
  device cannot register. Call admission then requires a live registration.
- Clear refusal of malformed or oversized SIP messages (no panics, no unbounded
  memory growth).
- No remote management surface at all, which is the simplest possible attack
  surface reduction.

What we deliberately do **not** do: verify that an INVITE's `From` really is
who it claims (any registered device can present any caller ID — phones do
this anyway for legitimate reasons), challenge INVITEs themselves, or track
devices by network address. On a hostile network none of this is enough; that
is what the "trusted network" premise means.

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
- **Call states extend downward.** The call state machine is one enum and one
  transition function; adding a "data mode" for fax/modem later means adding
  variants and transitions, not restructuring. v1 simply has no such states.
- **The config file can grow.** Future `[[trunk]]`, `[[group]]` and gateway
  entries fit the existing shape; no schema migration needed since nothing
  reads it but the daemon.
- **Call routing can grow a new target** ("send this call to the trunk", "this
  number is a fax machine on a gateway port") without restructuring the rules.
- **re-INVITE handling stays in the stack**, because fax/modem switching and
  trunks will need mid-call media renegotiation. v1 just answers "keep things
  as they are".
