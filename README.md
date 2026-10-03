# softpbx — a small SIP call server

softpbx is a software phone system (a PBX) for a small office, written in Rust.
SIP phones register to it and call each other through it. That is the core, and
everything else is deliberately left out.

Design stance: **small, understandable, and honest about what it is not.**

- One binary, one config file written by a human, read at startup.
- All state (registrations, ongoing calls) lives in memory. If the process
  crashes, calls drop and phones re-register. That is acceptable for this use.
- No web UI, no REST/gRPC API, no database, no TLS/SRTP, no high availability.
- Protocols are implemented in this repository (a minimal SIP stack in Rust),
  because the quirks of real phones are where the work actually is.

## What it does (v1)

| Feature | Notes |
| --- | --- |
| Devices | Phones register with a number and a password |
| Calls | Calls between devices with G.711 audio |
| Call routing | Rules for where a call goes: what a dialed number means (which device to ring) |

## What it does not do

Recording, billing, public phone network (PSTN) access, voicemail, IVR/call
center features, conferencing, fax *(later, if ever)*, web UI, remote
management APIs, provisioning of phones or gateways, TLS/SRTP, clustering or
hot failover.

Later (not in the first phase): hold/transfer, ring groups (ring several phones
at once, first to answer wins), a SIP trunk to a remote MikoPBX-compatible PBX,
and fax / dial-up modem traffic. The design keeps room for all of these — see
[docs/06-later.md](docs/06-later.md) — but the first phase is just calls.

Analog phones, fax machines and modems can be reached through an external
analog gateway (e.g. a Yamaha NVR500/510-class box), configured by hand from
[docs/06-later.md](docs/06-later.md). softpbx sees such devices as ordinary SIP
endpoints.

## Repository layout

```
softpbx/
├── docs/            design docs (01-06, read in order)
├── crates/
│   ├── sip-syntax/  SIP message and SDP parsing (pure, no I/O)
│   ├── sip-stack/   transport, transactions, dialogs
│   ├── call/        call logic (B2BUA), call routing
│   ├── rtp/         RTP packet handling and forwarding
│   ├── media/       jitter buffer, G.711, later mixing
│   └── engine-sim/  deterministic simulation test bed
└── apps/
    └── pbx-daemon/  the whole program
```

Crates for fax (`t38`, `vbd`, `faxserver`), gateway management (`line-gw`) and
the old management plane (`api`, `store`) are removed from the tree until such
features come back.

## Getting started

```bash
cargo check --workspace     # type check
cargo test  --workspace     # unit tests + simulation tests
cargo run -p pbx-daemon -- --config config.toml
```

A minimal config file is described in [docs/02-architecture.md](docs/02-architecture.md).

## Documentation

| File | Contents |
| --- | --- |
| [docs/01-scope.md](docs/01-scope.md) | What we build, what we don't, and why |
| [docs/02-architecture.md](docs/02-architecture.md) | How the program is put together |
| [docs/03-calls.md](docs/03-calls.md) | How a call works, in plain terms |
| [docs/04-testing.md](docs/04-testing.md) | Test strategy and the simulation test bed |
| [docs/05-roadmap.md](docs/05-roadmap.md) | Order of work and exit criteria |
| [docs/06-later.md](docs/06-later.md) | Future work: trunk, analog gateways, fax, modems |
| [docs/07-sip-subset.md](docs/07-sip-subset.md) | Exactly which parts of SIP we implement (and which we don't) |
| [docs/08-build-phases.md](docs/08-build-phases.md) | How the code gets built, phase by phase |
| [docs/09-softphone-testing.md](docs/09-softphone-testing.md) | Real-phone testing notes and interop findings |

## Principles

1. **Calls first.** A change that does not make calling more reliable or more
   understandable needs a good reason to exist.
2. **Boring and explicit.** State machines are written out as enums and
   transition tables. No clever abstractions before they are needed.
3. **Real phones are the spec.** The written standard is a hint; what matters is
   that actual phones work. Device quirks live in data tables, not in `if`
   statements scattered through the code.
4. **Reproducible tests.** Failures must be reproducible from a fixed seed, so
   bugs can be found and fixed without a phone on the desk.
