# 07. What "minimal SIP stack" means, exactly

"Minimal" is defined as: **the smallest subset of SIP in which every v1 feature
is expressible (docs/01), and with which real phones can register and call each
other.** Everything outside this list is rejected cleanly or ignored — it is
never half-implemented.

The spec we follow is RFC 3261 (SIP) plus RFC 3264 (offer/answer) and RFC 4566
(SDP). Where real phones deviate from these, docs/03 §7 applies (quirks in data
tables).

## 1. Implement

### Transport
- UDP, port 5060. One datagram = one message; hard size cap (64 KB).
- Retransmission is the transaction layer's job (§3). Nothing else.

### Methods
| Method | Why it is in |
| --- | --- |
| INVITE / ACK / BYE | making and ending calls — the product |
| CANCEL | cancelling a call that is still ringing |
| REGISTER | phones announcing where they are |
| OPTIONS | capability probes and NAT keepalive; phones send these constantly |

Any other method: `405 Method Not Allowed` with an `Allow` header. This is the
standard, complete answer — not a gap. (This includes `REFER`/`NOTIFY`/`INFO`
for now: hold and transfer are not in the first phase, docs/01.)

### Parsing (`sip-syntax`)
- Request line / status line; headers as name-value pairs preserving order.
- **Compact header forms** (`v`, `l`, `f`, `t`, `i`, `m`, `c`, `k`, …) — real
  phones use them; not handling them is a classic interop bug.
- Multiple headers of the same name (Via, Contact, Route).
- Quoted display names and escaped characters in URIs. URI validation stays
  loose: we copy and compare, we don't audit.
- Body delimited by `Content-Length`, trimmed to the datagram.
- Resource limits: max message size, line length, header count, body size.
  Over the limit → the parser refuses the message; the daemon drops such
  datagrams (no response — nothing to answer).
- Malformed input → an error value. **Never a panic, never unbounded memory.**

### Transactions (RFC 3261 §17)
- Stateful INVITE and non-INVITE transactions, client and server side.
- Standard timers: T1 = 500 ms, T2 = 4 s, give-up at 64 × T1.
- `100 Trying` to stop the far side retransmitting while we think.

### Dialogs (RFC 3261 §12)
- Early and confirmed dialogs; CSeq ordering; the remote target is the peer's
  Contact.
- **No** `Record-Route` / `Route` handling. We are a B2BUA: each leg is our own
  dialog and we never proxy for someone else's route set.

### Registrar
- Contact bindings with expiry; `Expires: 0` removes a binding; stale bindings
  are swept.
- Digest authentication (MD5, with and without `qop`): `REGISTER` is
  challenged, wrong password → `401`, unknown number → `403`. Only nonces we
  issued verify within a five-minute window, so a sniffed response cannot be replayed.
- **Only registered devices may place calls** — and trunk peers, which are
  identified by their address and do not register: an `INVITE` whose caller
  has no live binding gets `403`, unless it comes from a configured trunk
  (whose callers may be anyone except *our own* numbers in our domain —
  impersonation gets `403` too).

### NAT hygiene
- `rport` / `received` (RFC 3581) processing is not implemented — instead,
  responses go back to the network address their request came from, which is
  what makes phones behind a router work at all.

### Offer/answer and SDP
- The RFC 3264 exchange, once per call leg (we re-originate both sides).
- SDP subset: we *parse* the media and connection lines (`m=`, `c=`) and
  match codecs by payload type; we *emit* `a=rtpmap` for **G.711 (PCMU/PCMA)**
  and **telephone-event**, `a=ptime`, `a=silenceSupp:off`.
- Unknown SDP lines and attributes — including direction attributes — are
  ignored. Unknown codecs are not offered and are declined in answers.
- re-INVITE that phones occasionally send mid-call (codec refresh, session
  refresh, quirks): accepted and answered. A media move in the offer moves our
  relay target; a declined stream (`c=0.0.0.0` / `m=audio 0`) pauses the relay
  in both directions until an active offer resumes it.

### Response codes we use

Originated by us: `100` (auto), `180`/`183` (callee progress, forwarded with
its real code), `200`, `400`, `401`, `403`, `404`, `405`, `408`, `420`, `481`,
`487`, `488`, `491`, `503`. Most final responses from the callee reach the
caller with the same code (a `486` from a busy phone arrives as `486`); the
exceptions are `401`/`407`, which become `503` (their challenge died with the
callee leg), and reason phrases are regenerated. Nothing else needs to exist
in the code.

## 2. Not implemented (on purpose)

Rejected with a standard error response or ignored:

- Methods: `REFER`, `NOTIFY`, `INFO`, `PRACK`, `UPDATE`, `SUBSCRIBE`,
  `PUBLISH`, `MESSAGE`
- SIP extensions: 100-rel, session timers (RFC 4028 — not at all, see §3),
  Path, Outbound (RFC 5626 — except its double-CRLF keepalive, which is
  recognized and acknowledged), GRUU, replaces, event packages (BLF, message
  waiting)
- **`Require` is checked** (RFC 3261 §8.2.2.3): a request whose `Require`
  names anything we do not implement gets `420 Bad Extension` with an
  `Unsupported` header. We never half-implement an extension. Per the same
  section, `Require` is **ignored** in ACK and CANCEL — and we extend that to
  BYE on purpose: a teardown must never be blocked by an extension we do not
  implement.
- Media negotiation: ICE, RTCP, SRTP (`a=crypto`), RTCP-mux, multiple codecs
  beyond G.711
- Transport: TCP, TLS, SCTP, WebSocket; DNS/SRV resolution (peers are IP
  addresses in the config file)
- Misc: IPv6 edge cases, proxy behavior (we are a B2BUA), third-party call
  control

## 3. Deferred, with a trigger

| Item | Trigger |
| --- | --- |
| `REFER` / `NOTIFY` | Hold / transfer being wanted (docs/03 §5) |
| Parallel forking (several early dialogs per call) | Ring groups being wanted (docs/03 §6) |
| `INFO` + RFC 4733 telephone-event handling (DTMF) | Any feature that consumes DTMF; analog gateways |
| `UPDATE` as a refresh mechanism | A peer that refreshes with UPDATE (the MikoPBX capture shows none ever does; re-INVITE refreshes already work) |
| Session timers (RFC 4028) | A peer that turns out to need them. Policy: **we never claim the extension** — an INVITE carrying `Session-Expires` is answered *without* it (the peer then runs no timer or self-refreshes), and `Require: timer` gets `420` like anything unsupported. This is coherent with "never half an extension": claiming `refresher=uac` over a UAC's `refresher=uas` would violate §9 Table 2, and implementing the UAS side obliges us to refresh. (MikoPBX, our actual peer, sends none — one peer's capture, not a law of nature.) |
| TCP transport | A real device that cannot do UDP (none expected at this size) |
| `183` early media handling | Trunk or gateway interop shows it matters |
| Direction attributes (`sendonly` etc.) | Hold / music-on-hold |

## 4. Ground rules for growing the list

1. A feature is added to this document **before** it is coded.
2. Adding a SIP extension means adding its rejection behavior to the golden tests
   first — we must be able to show we say no cleanly.
3. "Device X needs it" is a valid reason. "The RFC lists it" is not.
