# 08. Build phases

How step 1 of the [roadmap](05-roadmap.md) is constructed: five pieces, each
finished and verified before the next depends on it. The rule that shapes the
order: **every phase ends with something verified, not something that merely
compiles.** Phases 1–5 run entirely in the simulation test bed, so there is no
"works on my machine" stage — by the time real sockets and real phones enter
the picture (phases 6–7), the behavior underneath is already covered by tests.

## Phase 0 — Workspace cleanup

Prune `api`, `store`, `t38`, `vbd`, `faxserver`, `line-gw` and `pbx-cli` from
the tree; the six surviving crates are the ones in the README layout.

**Done when:** `cargo check --workspace` passes on the trimmed tree.

## Phase 1 — SIP parsing (`sip-syntax`)

Message parse/serialize: start line, headers (compact forms included), body,
limits. Pure functions, no dependencies.

**Done when:** unit tests cover well-formed and malformed messages, and the
parser fuzzer runs without a panic.

## Phase 2 — Transactions over the virtual transport (`sip-stack`, `engine-sim`)

INVITE and non-INVITE client/server transactions, retransmission timers on the
virtual clock, `100 Trying`. This phase also builds the DST skeleton itself
(virtual clock, event queue, determinism assertion) — the test bed has to exist
before there is anything interesting to run on it (docs/04 §2).

**Done when:** timer-driven retransmission and response matching are proven in
simulation (e.g. packet lost → retransmit at T1, 2·T1, …), and the same seed
produces an identical event trace.

## Phase 3 — Registration (registrar + digest auth)

REGISTER handling, contact bindings with expiry, MD5 challenge/response,
unknown number → `403`.

**Done when:** DST test 1 (registration, rejected bad password) is green.

## Phase 4 — Dialogs + the call FSM (`call`)

INVITE/ACK/BYE/CANCEL as a B2BUA: two dialogs per call, the call state machine
(Idle → Offering → Ringing → Answered → Terminated), cancelling a ringing call.

**Done when:** DST tests 2 and 4 (call setup; teardown with clean release and a
call-log line) are green.

## Phase 5 — Audio (`rtp`)

RTP forwarding between the two legs, small jitter buffer, G.711 handling — the
transparent byte pipe (docs/02 §8).

**Done when:** DST tests 3 and 5 (60 s lossless call; 10 concurrent calls) are
green — i.e. **all 7 exit criteria in [docs/04](04-testing.md) §3 pass**.
Step 1 of the roadmap is complete here.

## Phase 6 — The real daemon (`pbx-daemon`)

Wire it to reality: real UDP sockets, config file loading with useful
validation errors, stdout logging, the call log file. Thin phase — the logic is
already proven.

**Done when:** the daemon starts from a config file and the phase 1–5 suite
still passes.

## Phase 7+ — Roadmap steps 2–5

Real phones and device quirks (step 2) → call routing (step 3) → trunk
(step 4) → analog devices, fax, modems (step 5). Each of those is planned and
reviewed when it starts, not before.
