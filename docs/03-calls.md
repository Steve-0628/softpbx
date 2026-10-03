# 03. How a call works

This is the mental model for the code in `call/` and `sip-stack/`. No protocol
expertise required to follow it.

## 1. Registration

A phone needs to tell the PBX "my number is 1001, and I am here". It sends a
REGISTER message with its number and password. The PBX answers "OK" and
remembers the phone's network address in memory. Registration expires after a
while and the phone repeats it; that is also how a restarted PBX learns about
its phones again.

A wrong password gets rejected. An unknown number gets rejected.

## 2. Making a call

Alice (1001) picks up her phone and dials 1002.

1. Her phone sends an **INVITE** to the PBX saying "connect me to 1002".
2. The PBX looks at its **call routing rules** and decides 1002 is a number on
   this system — Bob's phone, which is registered and can be rung.
3. The PBX sends an INVITE to Bob's phone. Bob's phone starts **ringing**.
4. Bob picks up. His phone says "OK".
5. The PBX tells Alice's phone "OK" too, and from now on it forwards audio
   packets between the two phones. Neither phone talks to the other directly —
   the PBX sits in the middle of both the signaling and the audio (this is
   called a B2BUA, and it is what lets us do hold, transfer, and later trunk
   and fax tricks).
6. Either side hangs up (**BYE**), audio stops, both sides are told, and one
   line is written to the call log.

While the call is being set up, the two sides also agree on the audio format.
In v1 that is always **G.711** (the standard phone-quality codec, uncompressed,
very widely supported). The PBX forwards audio roughly every 10–20 ms.

## 3. Call states

Every call is a small state machine (the real ones live in `call/src/call.rs`):

```
Offering → Ringing → Answered → Terminating → Terminated
```

- `Offering`: the INVITE arrived; the callee has not been reached yet
- `Ringing`: the callee is being alerted (a 180/183 came back)
- `Answered`: the call is up
- `Terminating` → `Terminated`: teardown messages go out, then the call log
  line is written

A BYE ends the call from *any* of the first three states; a CANCEL ends it
while it is still being set up. Hold and transfer would add states on top of
`Answered` — they are not wanted yet (docs/01), and adding them means adding
enum variants and transitions, nothing more. The rules are written out
explicitly (an enum plus a transition function), because "what happens if Bob
hangs up while the call is being set up" is exactly the kind of question we
want to answer with a test rather than with a phone on a desk.

## 4. Call routing (not built yet)

The plan: a list of rules — *"when someone dials something matching this
pattern, do that"*, first match wins — with number rewriting and rejection
along the way. Today there are no rules at all: a dialed number simply rings
the device with that number, and anything else gets `404`.

This is roadmap step 3 (docs/05). When it lands, the actions will be:

| Action | Meaning |
| --- | --- |
| `device` | Ring the device whose number was dialed |
| `device` with a fixed number | Ring that specific device |
| `reject` | Don't allow this number (e.g. dial 0 for outside line → no) |

Later: ring groups, rules that send a call to a trunk (remote PBX), rules for a
fax machine on a gateway port.

## 5. Hold and transfer (later, not in the first phase)

Wanted eventually, easy to add on this model — the PBX sits in the middle of
every call, so these are just state machine transitions plus re-pointing audio
forwarding:

- **Hold**: stop forwarding audio to one side (or play music) while both stay
  connected to the PBX.
- **Blind transfer**: "send this call to Bob" — the PBX rings Bob, drops Alice.
- **Attended transfer**: Alice checks with Bob first (a second call), then the
  PBX joins the two calls and Alice leaves.

When this happens, the SIP subset grows `REFER`/`NOTIFY` support
([docs/07](07-sip-subset.md)).

## 6. Ring groups (later)

A routing rule pointing at a group of endpoints instead of one: all of them
ring at the same time, the first to answer gets the call, the rest stop
ringing. Cheap to add on this model, but not wanted yet — so it is not in v1.

## 7. Real-world quirks

Actual phones and PBXs bend the rules. We handle that in one place:

- The standard-following code path stays clean.
- Per-device behavior differences (odd header ordering, unusual re-INVITE
  timing, how a device signals DTMF keys) go into **data tables** — one entry
  per device type, added when we first meet the device. (None yet: the
  softphones we have tested against behave. The tables appear with the first
  quirk, not before.)
- Each quirk entry gets a test in the simulation bed so we know when it breaks.

This is the difference between "works with my softphone" and "works with the
phones the office actually owns".
