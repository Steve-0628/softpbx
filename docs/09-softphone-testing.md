# 09. Softphone testing notes

Real-device verification (roadmap step 2) against the tools installed in the
test VM: linphonec 5.3.105, baresip 1.1.0, twinkle 1.10.3, SIPp 3.7.3.
Setup recipes and headless notes live in the environment report kept with the
test VM; what belongs here is what the **devices taught us about our code**.

## 1. Verified (round 1: linphonec ↔ baresip through softpbx)

| Check | Result |
| --- | --- |
| Registration with digest auth, both phones | ✅ `401` challenge → `200` |
| Call A → B through the B2BUA | ✅ `INVITE → 100 → 180/200 → ACK` |
| Call B → A (reverse direction) | ✅ |
| RTP relayed both ways, correct relay ports | ✅ phones send to the port we advertised; we forward from the port the other side expects |
| ptime negotiation | ✅ baresip adopted our `a=ptime:10` |
| BYE teardown (caller side) | ✅ — the callee side was *not* tested here and turned out to be broken; see §2 |
| Call log line per call | ✅ `{"caller","callee","started_ms","ended_ms","result"}` |
| Keepalives (`\r\n\r\n`) | ✅ answered with a bare CRLF (RFC 5626) |
| Restart model | ✅ after a daemon restart phones re-register; calls to unregistered numbers get `404` + a `not-found` log line |

## 2. Bugs the softphones found (all fixed)

1. **RFC 5626 keepalives looked like garbage.** linphone sends exactly four
   bytes (`\r\n\r\n`) every few seconds. We logged them as "unparsable
   message". Now recognized (`sip_syntax::is_keepalive`) and acknowledged with
   a single CRLF. Lesson: phones ping constantly; silence is the right answer
   to silence.
2. **Display names broke caller identity.** baresip sends
   `From: "1002" <sip:1002@...>`; our URI extraction took the whole value and
   produced `caller: "\"1002\" <sip:1002"`. Now `uri_of` skips display names.
   The simulation never sent one — real phones do.

An independent review round after this test (three reviewers over code,
docs and tests) then found the callee-side BYE bug, the swallowed re-INVITE,
the leaking media ports and the fire-and-forget message lifecycle — all fixed
with regression tests in `crates/engine-sim/tests/m0.rs`. The lesson from
round 1 stands: **test both directions of everything with real phones.**

## 3. Operational notes

- A restarted daemon loses registrations (by design, docs/01 §3). Phones
  re-register on their own interval (30–3600 s); until then calls to them are
  `not-found`. For tests, force re-registration after a restart
  (linphonec: `linphonecsh register`, baresip: restart it).
- linphonec's daemon keeps stale state across PBX restarts:
  `linphonecsh exit && linphonecsh init` when registration commands go quiet.
- baresip: `;answermode=auto` makes a scriptable callee; use `/`-prefixed
  commands (`-e '/dial sip:...'`), bare commands are eaten by hotkey aliases.
- All of it runs headless; no audio hardware is needed for signaling, and RTP
  flows regardless.

## 4. Round 2 (phase 7 hardening)

Scripted regression over real phones (`/tmp/opencode/softpbx/round2.sh`) plus a
real-socket stress tool (`stress.py`: fake phones that digest-register and run
full INVITE/200/ACK/RTP/BYE flows):

| Check | Result |
| --- | --- |
| Caller-side hang-up (linphone BYE) | ✅ `completed`, logged |
| **Callee-side hang-up** (baresip quits with BYE) | ✅ `completed`, logged — this was the review-critical bug; verified on real phones now |
| Daemon restart mid-call | calls drop (by design); phones re-register on their own interval; SIGTERM now exits as cleanly as Ctrl-C (fixed) |
| Keepalives over the whole run | ✅ zero "unparsable" noise |
| 50 concurrent real-socket calls | ✅ 50/50 completed, exactly 50 call-log lines, zero parser noise |
| Soak (300 × 10 calls, background) | running; assertions are per-loop completion counts |

Adversarial probes (the "evil peer" set), all locked as golden tests in
`crates/engine-sim/tests/m0.rs`:

| Probe | Behavior |
| --- | --- |
| `Require: 100rel, timer` | `400`? no — `420 Bad Extension` + `Unsupported` (docs/07 rule: never half an extension) |
| `UPDATE` / `PRACK` / `REFER` | `405` + `Allow` |
| `Session-Expires: 1800;refresher=uas` | answered `200` with `Session-Expires: 1800;refresher=uac` — the peer times and refreshes; our re-INVITE handling absorbs it |
| INVITE without Contact | `400` (RFC 3261 §8.1.1.8 — no Contact means an unhangupable call) |
| Simultaneous re-INVITE ("glare") | each leg answered independently with the session unchanged — by design, and covered per leg |

Harness lessons (why two of these took debugging): test tools must send a
request *line*, BYEs must carry the *right dialog leg's* tag, and probe
sockets must be drained between checks — each of these produced a convincing
"the PBX is broken" symptom that was the harness's own bug. The PBX's own
failures so far have all been found by tests and reviewers instead.

## 5. Next rounds

- twinkle as a third phone; a hardphone when one is available
- The same recipe against a **MikoPBX trunk** (roadmap step 4) — interop
  findings get recorded here per device

## 6. MikoPBX (the trunk peer) — what it actually is

Captured 2026-10 against MikoPBX 2026.3.40 (Asterisk 22.8.2 / chan_pjsip).
Full evidence and verbatim messages: [reference/mikopbx-2026.3.md](reference/mikopbx-2026.3.md).
The facts that shape the trunk work:

| Fact | Consequence for us |
| --- | --- |
| **No session timers, ever** (`timers=no`; 78 s call with zero mid-dialog traffic) | the scariest interop risk is gone; our `refresher=uac` answer stays but will likely never fire |
| No UPDATE, no PRACK, no re-INVITE refresh from it | our SIP subset is closer than feared |
| It sends **OPTIONS qualify probes every 60 s** | our OPTIONS handling is load-bearing — never break it |
| **It challenges INVITEs** from authenticated endpoints (401 before call setup) | trunk legs are exempt (IP identify / inbound registration) — the trunk shape avoids this; a future direct-extension dial would need INVITE digest |
| Trunk modes: **outbound registration / inbound registration / static IP** | MikoPBX *registers to us* works today (verified live); no outbound REGISTER client needed for the first interop shape |
| Digest MD5, `qop=auth` + `opaque` when it challenges; it answers challenges with or without qop | our qop-less challenge is fine (verified); its challenges need qop=auth computation when we are the client |
| With trunk `username` set, `From`/`Contact` become the trunk login — **the real caller disappears** | use no-username/IP trunk mode (or `fromuser`/`manualattributes`) so caller identity survives; it never sends PAI on trunk legs |
| Codecs offered: opus, PCMA, PCMU, G729, G722, GSM + two telephone-events (fmtp `0-16`) | our answer intersects to PCMA/PCMU/101 — fine; note the odd fmtp |
| `183` with SDP appears on internal legs (`inband_progress=yes`) | early media is still deferred; we forward the status code only |
| Provider AORs take exactly **one** contact (`max_contacts=1`) | when *we* register to it later, reuse one source port |

First interop already happened: MikoPBX registered to a test `pbx-daemon`,
re-registers every ~60 s, and its INVITEs are answered correctly (`404` for an
unmapped number, ACKed and torn down cleanly).
