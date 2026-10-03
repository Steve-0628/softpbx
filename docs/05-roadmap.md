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

## Step 2 — Real phones

Run it on the LAN against actual softphones (Linphone, Zoiper, a desk phone if
one is around). This is where real-world SIP messiness appears.

- Fix what real phones break; capture quirks in device data tables
- Comfortable config file with good startup error messages
- Process behavior: starts, restarts, survives a phone doing odd things

**Done when:** two real phones can call each other through softpbx and hang up
cleanly, repeatedly, for hours.

## Step 3 — Call routing

- Routing rules: matching, number rewriting, rejection

**Done when:** rules work on real phones, each backed by simulation tests.

Hold/transfer and ring groups are not planned now (docs/01). If they are wanted
later, they fit after this step as small additions (docs/03 §5–6).

## Step 4 — Trunk to a remote PBX

- SIP trunk to a MikoPBX-compatible PBX: calls between sites
- Number range routing (site A = 2xx, site B = 3xx)
- Trunk quirks (re-INVITE timing, caller ID handling) in data tables

**Done when:** site-to-site calls and transfers work against a real remote PBX.

## Step 5 — Analog devices, fax, modems (only if wanted)

- Document gateway setup (docs/06); analog phones appear as SIP endpoints
- Fax and dial-up modem traffic over G.711 pass-through (the transparent audio
  path from docs/02 §8 makes this possible without rework); T.38 relay only if
  testing shows pass-through is not enough
- Fix problems empirically against real machines; no pre-built fax architecture

## Not on the roadmap

Web UI, management APIs, config management tooling, provisioning, recording,
billing, conferencing, TLS/SRTP, high availability. See
[docs/01](01-scope.md).
