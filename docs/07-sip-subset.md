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
- Resource limits: max line length, max header count, max body size. Over the
  limit → `400`/`413`.
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
  issued verify, so a sniffed response cannot be replayed.
- **Only registered devices may place calls**: an `INVITE` whose caller has no
  live binding gets `403`. (No digest challenge on `INVITE` itself — being
  registered is the admission ticket.)

### NAT hygiene
- `rport` / `received` (RFC 3581) on responses. Cheap, and it is why phones
  behind a router work at all.

### Offer/answer and SDP
- The RFC 3264 exchange, once per call leg (we re-originate both sides).
- SDP subset: media line, connection line, `a=rtpmap` for **G.711 (PCMU/PCMA)**
  and `a=rtpmap`/`a=fmtp` for **telephone-event**, and `a=ptime`.
- Unknown SDP lines and attributes — including direction attributes — are
  ignored. Unknown codecs are not offered and are declined in answers.
- re-INVITE that phones occasionally send mid-call (codec refresh, device
  quirks): accepted and answered with the current session unchanged.

### Response codes we use

Originated by us: `100` (auto), `180`/`183` (callee progress, forwarded with
its real code), `200`, `400`, `401`, `403`, `404`, `405`, `408`, `481`, `487`,
`503`. Final responses from the callee are forwarded as-is (a `486` from a busy
phone arrives as `486`). `488`, `491` and `500` are defined for later use.
Nothing else needs to exist in the code.

## 2. Not implemented (on purpose)

Rejected with a standard error response or ignored:

- Methods: `REFER`, `NOTIFY`, `INFO`, `PRACK`, `UPDATE`, `SUBSCRIBE`,
  `PUBLISH`, `MESSAGE`
- SIP extensions: 100-rel, session timers (RFC 4028), Path, Outbound (RFC 5626
  — except its double-CRLF keepalive, which is recognized and acknowledged),
  GRUU, replaces, event packages (BLF, message waiting)
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
| `UPDATE` + session timers | Trunk work (step 4): MikoPBX/Asterisk peers use them for refresh |
| TCP transport | A real device that cannot do UDP (none expected at this size) |
| `183` early media handling | Trunk or gateway interop shows it matters |
| Direction attributes (`sendonly` etc.) | Hold / music-on-hold |

## 4. Ground rules for growing the list

1. A feature is added to this document **before** it is coded.
2. Adding a SIP extension means adding its rejection behavior to the golden tests
   first — we must be able to show we say no cleanly.
3. "Device X needs it" is a valid reason. "The RFC lists it" is not.
