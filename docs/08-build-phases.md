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
(Offering → Ringing → Answered → Terminating → Terminated), cancelling a ringing call.

**Done when:** DST tests 2 and 4 (call setup; teardown with clean release and a
call-log line) are green.

## Phase 5 — Audio (`rtp`)

RTP forwarding between the two legs, byte for byte (no jitter buffer in the
relay — the phones buffer), G.711 handling — the transparent pipe (docs/02 §8).

**Done when:** DST tests 3 and 5 (60 s lossless call; 10 concurrent calls) are
green — i.e. **all 7 exit criteria in [docs/04](04-testing.md) §3 pass**.
Step 1 of the roadmap is complete here.

## Phase 6 — The real daemon (`pbx-daemon`)

Wire it to reality: real UDP sockets, config file loading with useful
validation errors, stdout logging, the call log file. Thin phase — the logic is
already proven.

**Done when:** the daemon starts from a config file and the phase 1–5 suite
still passes.

## Phase 7 — Softphone hardening (finishes roadmap step 2)

Step 2 is *mostly* done: round 1 (linphone ↔ baresip through the PBX) and two
independent review rounds are behind us. What remains is making it boring:

- Regression round 2 over real phones: both hang-up directions, keepalives,
  mid-call re-INVITEs (session refresh), CANCEL-as-the-callee-answers, a
  restart mid-call
- A third phone type (twinkle) and at least one hardphone when available
- Stress: SIPp scenario with 50+ concurrent calls; a multi-hour soak with
  periodic calls; zero stuck calls, zero leaked media ports
- Device quirk data tables as devices demand them (none needed yet)

**Done when:** two different phone types run calls for hours (both directions,
all hang-up ways) without a stuck call or a leaked resource; the stress and
soak runs pass; findings are in docs/09.

## Phase 8 — Call routing (roadmap step 3)

- `[[routing]]` config sections: match (what was dialed) → target, with number
  rewriting and rejection; normalization rules (`+81…`, leading digits)
- Refuse calls to nowhere with a clear code (`404` today becomes "no rule
  matched")

**Done when:** routing works on real phones and every rule has a simulation
test; the config validator rejects nonsense rules at startup.

## Phase 9 — Trunk core (roadmap step 4, part one)

Before touching the real peer, the trunk exists in the simulation — but now
shaped by **what MikoPBX actually does** (docs/09 §6, captured 2026-10):

- `[[trunk]]` config: peer address, authentication (digest and/or IP), its
  number range and ours
- Outbound: routing rules that send a number range down a trunk (the phase 8
  engine already does number ranges — the target just gains "trunk X"); the
  callee leg becomes a trunk leg (its own Call-IDs, its own quirks)
- Inbound: INVITEs from the trunk map to local devices. **Trunk legs are not
  challenged** (IP identify / inbound registration) — and the simplest shape
  has *MikoPBX register to us*, which already works against today's registrar
- Answer its 60 s OPTIONS probes (today's behavior — keep), keep re-REGISTER
  working (today's behavior), and preserve caller identity on the leg (its
  `username` trunk mode hides the real caller — configure it accordingly)
- What the capture says we do **not** need: session timers, UPDATE, PRACK, an
  outbound REGISTER client. The SIP subset stays as it is (docs/07)

**Done when:** site-to-site call scenarios (both directions, busy, no-answer,
hang-up both sides, lost packets) pass in the DST against a fake remote PBX
that speaks the captured MikoPBX wire forms.

## Phase 10 — MikoPBX interop (roadmap step 4, part two)

The real thing. **Environment is ready**: MikoPBX 2026.3.40 runs at
`192.168.77.108` (QEMU, tap bridge `192.168.77.1/24`, tmux `miko`; restart
instructions in [reference/mikopbx-2026.3.md](reference/mikopbx-2026.3.md)),
admin/admin, extensions and trunks already configured from the capture work.

- Bring-up: trunk both directions, calls site to site (already half-done:
  MikoPBX registers to softpbx and sends INVITEs today)
- Interop matrix in docs/09 per behavior, with quirk-table entries for each
  divergence
- Soak: 72 hours of periodic site-to-site calls

**Done when:** site-to-site calls and hang-ups work reliably against the real
MikoPBX; every divergence is either fixed or recorded as a quirk; the soak is
clean.

## Phase 11 — Analog devices, fax, modems (roadmap step 5, when wanted)

- Gateway setup documented and verified (docs/06 §2); analog phones as devices
- G.711 fax pass-through first, tested against real machines; dial-up modem
  expectations documented honestly (LAN only)
- T.38 relay and a fax server only if pass-through proves insufficient

**Done when:** whatever subset is actually wanted works against real
hardware, and what does not work is documented rather than guessed.

## Notes on the phasing

- Phases 7 and 8 are independent of the trunk; 9 must precede 10 (never point
  a real peer at unproven signaling); 11 is optional.
- Phases are cut so each ends in something *verified*: a soak, a matrix, a
  green scenario set — not a code-complete milestone.
- Reviews stay part of the process: a fresh-eyes review at each phase
  boundary, before the next phase starts.
