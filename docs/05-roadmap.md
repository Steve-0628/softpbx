# 05. Roadmap

Order of work. "Calls first" is the rule: we do not start a later step because
it is more interesting than the current one.

## Step 1 — A call between two fake phones

The skeleton that proves the shape of the system, entirely in the simulation
bed. Built phase by phase: see [docs/08](08-build-phases.md).

- SIP parser (`sip-syntax`): requests, responses, headers, SDP; no panics on
  garbage input
- SIP transactions and dialogs over the virtual transport
- Registration with digest authentication
- INVITE / ACK / BYE between two fake phones; G.711 audio flowing in
  simulation
- In-memory registration and call tables; call log line per call

**Done when:** the first-milestone test list in [docs/04](04-testing.md) §3
passes, and the same seed reproduces the identical event trace.

## Step 2 — Real phones *(phase 7 — mostly done)*

Run it on the LAN against actual softphones (linphone, baresip, twinkle, a
desk phone if one is around). This is where real-world SIP messiness appears.

- Fix what real phones break; capture quirks in device data tables
- Comfortable config file with good startup error messages
- Process behavior: starts, restarts, survives a phone doing odd things

**Done when:** two real phones can call each other through softpbx and hang up
cleanly, repeatedly, for hours. (Round 1 + two review rounds done; the phase 7
hardening list is in [docs/08](08-build-phases.md).)

## Step 3 — Call routing *(phase 8)*

- Routing rules: matching, number rewriting, rejection

**Done when:** rules work on real phones, each backed by simulation tests.

Hold/transfer and ring groups are not planned now (docs/01). If they are wanted
later, they fit after this step as small additions (docs/03 §5–6).

## Step 4 — Trunk to a remote PBX *(priority after softphones — phases 9–10)*

Interoperability with **MikoPBX** is the goal here — this comes right after
local softphones are verified, before any fax work.

- Phase 9 (trunk core, in the simulation): `[[trunk]]` config, number-range
  routing both directions, trunk authentication, whatever SIP additions the
  peer forces
- Phase 10 (real interop): bring-up against a real MikoPBX, interop matrix in
  docs/09, quirk entries per divergence, 72-hour soak

**Done when:** site-to-site calls and hang-ups work against a real remote PBX.

## Step 5 — Analog devices, fax, modems *(phase 11, only if wanted)*

- Document gateway setup (docs/06); analog phones appear as SIP devices
- Fax and dial-up modem traffic over G.711 pass-through (the transparent audio
  path from docs/02 §8 makes this possible without rework); T.38 relay only if
  testing shows pass-through is not enough
- Fix problems empirically against real machines; no pre-built fax architecture

Fax work starts **after** the MikoPBX trunk (step 4) is solid.

## Not on the roadmap

Web UI, management APIs, config management tooling, provisioning, recording,
billing, conferencing, TLS/SRTP, high availability. See
[docs/01](01-scope.md).
