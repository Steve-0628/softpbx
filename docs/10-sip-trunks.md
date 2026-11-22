# SIP trunks and MikoPBX

SoftPBX supports static digest trunks, incoming registration (the other PBX
registers to SoftPBX), and outgoing registration (SoftPBX registers to the other
PBX). Registration accounts are independent of phone extensions. Credentials
used for REGISTER also authenticate trunk INVITEs; registration does not grant
an IP address permission to call without authentication.

The setup below follows the two-account procedure in
[いまさら VoIP 網](https://zenn.dev/kusaremkn/articles/abd760f9f2f450):
create an incoming provider on each PBX and an outgoing provider pointing to
that account on the other PBX. The mechanisms are REGISTER and digest
challenge/response as specified in [RFC 3261 §10 and §22](https://www.rfc-editor.org/rfc/rfc3261.html#section-10).
No device account masquerading as a trunk or custom Asterisk configuration is
needed for this setup.

## Example

Assume SoftPBX is `192.0.2.10:5060`, MikoPBX is `192.0.2.20:5060`, and SoftPBX
has registered phones `1001`/`1002`. Use reachable LAN or VPN addresses in both
PBXs' SIP and RTP settings. SoftPBX currently uses UDP and IP literals; enter
MikoPBX's IP address rather than its DNS name. SIP and RTP must be reachable in
both directions; registering does not create a media tunnel.

Add these sections to SoftPBX's existing configuration. Replace the example
passwords and the remote account name with your own values.

```toml
# MikoPBX's Outgoing Registration provider logs into this account.
[[trunk]]
name = "from-mikopbx"
registration = "incoming"
# No peer needed: its REGISTER supplies its contact address.
[trunk.inbound]
username = "SIP-TRUNK-SOFTPBX"
secret = "replace-local-secret"

# SoftPBX logs into MikoPBX's Incoming Registration provider.
[[trunk]]
name = "to-mikopbx"
registration = "outgoing"
peer = "192.0.2.20:5060"
expires = 3600
[trunk.outbound]
username = "SIP-TRUNK-REMOTE" # copy from MikoPBX
secret = "replace-remote-secret"

# Dial 7 + remote extension; remove 7 before sending the call.
# Put this before any catch-all routing rule.
[[routing]]
match = "7*"
strip = "7"
to = "trunk:to-mikopbx"

# Incoming DIDs ring their matching local extensions.
[[routing]]
match = "*"
to = "dialed"
```

Restart SoftPBX after changing its configuration.

On MikoPBX, under **Call Routing → Telephony providers → Connect SIP**:

1. Create `from-softpbx`, account type **Incoming Registration**. Copy its
   generated username and password into SoftPBX's `to-mikopbx` outbound
   credentials. The article's optional `[aor] max_contacts` setting can be used
   on MikoPBX when several PBXs share this account; one SoftPBX process uses
   one stable contact.
2. Create `to-softpbx`, account type **Outgoing Registration**. Set the provider
   host to `192.0.2.10`, port 5060, transport UDP, username
   `SIP-TRUNK-SOFTPBX`, and the matching local secret above.
3. Add an **Incoming routing** rule for `from-softpbx`, forwarding to
   **Direct to employee (match by DID)**.
4. Add an **Outbound routing** rule through `to-softpbx`. For example, numbers
   beginning with `8`, unrestricted remaining length, cut off one digit. This
   sends `81001` to SoftPBX extension `1001`.

Both MikoPBX providers should show registered. From SoftPBX, dial `7` followed
by a MikoPBX extension; from MikoPBX dial `8` followed by a SoftPBX extension.
Caller identity is carried by the call's From header independently of digest
username; MikoPBX's own caller-ID/provider settings still control the identity
it sends.

## Configuration and lifecycle

| Setting | Behavior |
| --- | --- |
| `registration = "none"` (default) | Existing static trunk behavior; `peer` required, no REGISTER sent or accepted for the trunk |
| `registration = "outgoing"` | `peer` and `[trunk.outbound]` required; register at startup and refresh automatically |
| `registration = "incoming"` | `[trunk.inbound]` required; `peer` optional and unused for registered-contact routing |
| `expires` | Outgoing requested lifetime, default 3600 seconds, valid range 60–86400 |
| `[trunk.outbound]` | Credentials used to answer REGISTER/INVITE challenges from the peer |
| `[trunk.inbound]` | Credentials the peer uses for incoming REGISTER (when enabled) and INVITE |

Inbound usernames must be unique across trunks. Incoming registration
usernames must not collide with local extension numbers. A SoftPBX incoming account holds one contact, updated
by subsequent registrations; provision a separate incoming trunk account for
each remote PBX. Multiple Contact values in a single REGISTER are outside the
supported subset. Static trunks and existing configuration files remain valid.

You may route calls through an incoming trunk as well: SoftPBX sends the dialed
DID to its live registered host/port. If that PBX challenges these calls,
configure `[trunk.outbound]` on the same trunk too. Without a live binding,
SoftPBX returns `480 Temporarily Unavailable`; it does not fall back to an old
contact or a configured peer address. Normal routing loop protection applies.

Outgoing registrations keep the same Call-ID and contact throughout a process
lifetime, increment CSeq and change the Via branch for new requests, and
refresh at 80% of the granted lifetime. SoftPBX handles 401/407 MD5 challenges,
`qop=auth`, `opaque`, 423/Min-Expires, and Retry-After. UDP retransmissions and
timeouts use the existing non-INVITE transaction implementation. Authentication
retries are bounded; failures retry after 30 seconds unless Retry-After says
otherwise. A refresh failure leaves the previous binding valid until its
original expiry. A restart uses a new registration Call-ID. On shutdown the
remote binding expires naturally.

Incoming registrations support authenticated queries without Contact, Contact
expiry overriding Expires, refresh, specific-contact removal with expiry zero,
and `Contact: *` with `Expires: 0`. Trunks requesting less than 60 seconds get
423 with Min-Expires; maximum lifetime is 86400 seconds. The device registrar is unchanged; these rules apply only to trunks. Duplicate successful REGISTER
requests receive their cached response without extending the binding. Older
CSeq values cannot overwrite a newer registration with the same Call-ID.
Registrations expire in memory and are rebuilt after restart.

`Switch::trunk_registered(name, now_ms)` exposes live registration state to
embedders and tests. The daemon drives registration through its normal timer
loop. When diagnosing a connection, inspect the UDP SIP exchange:
REGISTER → 401 → REGISTER with Authorization → 200; a later INVITE may have its
own 401 challenge. Missing responses indicate reachability/port configuration;
repeated challenges indicate account, secret, realm, or supported digest
algorithm mismatch. OPTIONS continues to return 200 independently of registration.

## Validation

`cargo test --workspace --locked` covers incoming/outgoing trunk registration,
digest and proxy authentication, negotiated refresh, retransmission, timeout
recovery, rejected credentials, deregistration, contact routing, expiry,
interface selection, and a two-switch REGISTER plus authenticated call setup.
Existing static-trunk call, media, dialog, routing, and phone-registration tests
also run. These are deterministic protocol tests; this change has not been
verified against a running MikoPBX appliance. Earlier live captures are recorded
in [the historical interop report](reference/mikopbx-2026.3.md).
