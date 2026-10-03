# 01. Scope

## 1. What this is

A software phone system (PBX) for a small office. SIP phones (desk phones,
softphones) register to it, and it connects calls between them. Later it can
reach phones at another office's PBX over an IP link (a SIP trunk), and reach
analog devices through an external analog gateway.

It is **not** a product platform. It is a small, well-tested call server that
one team can hold entirely in their heads.

## 2. Features

### v1 (calls)

- Registration: a device (today: a phone) registers with a number (e.g. `1001`)
  and a password (SIP digest authentication).
- Calls between devices: ringing, answering, G.711 audio both ways, hanging up.
- Call routing: rules mapping a dialed number to a destination, with number
  rewriting and rejection. *(Not built yet — roadmap step 3. Today a dialed
  number simply rings the device with that number.)*

### Later

- Hold and transfer (blind / attended). Not wanted yet; the call state machine
  and the B2BUA model leave room for them.
- Ring groups: ring several devices at once, first to answer takes the call,
  the others stop ringing.
- SIP trunk to a remote MikoPBX-compatible PBX: calls between sites, number
  range routing (site A owns 2xx, site B owns 3xx).
- Analog devices via an external analog gateway (Yamaha NVR500/510-class):
  analog phones, fax machines and modems appear as SIP devices. The gateway
  is configured by hand; we only document the settings.
- Fax and dial-up modem traffic: not implemented in the first phase. The design
  reserves room for them (docs/06); they arrive when there is a real need, and
  get fixed empirically.

### Never (unless requirements change)

- Call recording, monitoring, billing
- Public phone network (PSTN) connections
- Voicemail, IVR, ACD / call center features, conferencing
- Web UI, REST/gRPC APIs, remote management
- Provisioning (automatic configuration) of phones and gateways
- TLS / SRTP — the system is expected to run on a LAN or a VPN
- Clustering, hot failover, five-nines availability
- Database engines; multi-tenant / SaaS

## 3. Scale and reality check

Target: a few hundred devices, tens of concurrent calls. This is small. A
single process with a simple async runtime handles it without any special
real-time engineering. If the process crashes, active calls are lost and phones
re-register within a minute — that is the accepted failure model.

## 4. Requirements that actually matter

| Area | Requirement |
| --- | --- |
| Audio quality | No dropped audio under normal LAN conditions; low added latency |
| Audio transparency | The audio path must stay usable for future fax/modem traffic: no DSP on the forwarded stream (no VAD, no packet-loss concealment, no AGC). This is a design constraint from day one, even though those features come later |
| Reliability | Restart after a crash in seconds; no manual cleanup needed |
| Operability | Logs good enough to answer "why did that call fail?" |
| Compatibility | Works with common SIP phones; interop quirks handled per device via data tables |
| Security | Password authentication for registrations; runs on a trusted network |

## 5. Known risks

- **Real phones are messy.** Vendors interpret SIP loosely. Mitigation: keep
  quirk handling in per-device data tables and test against real phones early
  (roadmap step 2), not just against our own test bed.
- **Fax is unpredictable.** It depends on analog gateway hardware and far-end
  machines. That is why it is deferred; when we do it, we fix problems
  empirically instead of designing for every case up front.
- **Trunk interop** with another vendor's PBX has the same "messy reality"
  problem as phones, plus timing quirks. Deferred until calls are solid.
