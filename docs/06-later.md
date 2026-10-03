# 06. Later work: trunk, analog gateways, fax

Notes for when these come up. Nothing here needs deciding now.

## 1. SIP trunk between sites

Two offices, two PBXs, one number plan: site A owns number range `2xx`,
site B owns `3xx`. Each PBX has a "trunk" entry pointing at the other, and
routing rules sending the other site's number range down that trunk.

The awkward part is not the concept, it is that the other PBX (likely
MikoPBX / Asterisk-based) will not follow the SIP standard perfectly:
different re-INVITE timing, different caller-ID handling, quirks around session
timers. Those go in per-device data tables (docs/03 §7), each with a test.

## 2. Analog devices via an external gateway

Analog phones, fax machines, and similar devices connect to an **external
analog gateway** (e.g. Yamaha NVR500/510-class), which converts them to SIP.
softpbx just sees more SIP endpoints.

We do not provision or manage the gateway. A human configures it once through
its own web interface, using a checklist we document here:

- Register each gateway port as a device (number, password) — same as a
  phone
- Codec: G.711 only; packet period 10 ms; disable VAD/DTX ("silence
  suppression")
- Disable the gateway's own echo canceller and jitter-buffer adaptation when
  the port carries fax or modem traffic (these destroy fax signals)
- DTMF signaling: RFC 4733 (RTP events) preferred
- Caller-ID: FSK (Japanese style) for analog phones that display it
- Fax ports: prefer T.38 if the gateway offers it reliably; otherwise G.711
  pass-through with the settings above

These settings are the difference between "fax works" and "fax sometimes
works". When fax gets serious, verify each item against the actual gateway.

## 3. Fax

Fax arrives last, and gets fixed empirically rather than designed up front.

| Path | When |
| --- | --- |
| G.711 pass-through | First. A fax machine on a gateway port calls another fax; audio just flows like a call. Most of the work is the gateway settings above. |
| Fax server (receive to PDF/TIFF, send from files) | Only if the office actually wants it. Terminal equipment + image codecs (T.4/T.6) from an existing library. |
| T.38 relay | Only if pass-through proves unreliable on real links. |

Known hard truths: fax is timing-sensitive, sensitive to packet loss, and
dependent on the far-end machine and gateway hardware. V.34 ("super G3") fax is
out of scope entirely. When problems appear, we debug with packet captures and
real machines — not with more architecture.

## 4. Dial-up modems (3.1 kHz data)

A modem call is "a phone call where the audio is data": two modems negotiate
over the line, then exchange data as audio. The PBX does not understand the
data — it must simply carry the audio **unchanged and on time**.

What this needs from us when the day comes:

- The transparent audio path promised in [docs/02 §8](02-architecture.md): no
  VAD, no packet-loss concealment, no AGC, no jitter-buffer adaptation, no
  transcoding. G.711 at 10 ms packet period, forwarded as it arrives.
- Gateway settings per [§2](#2-analog-devices-via-an-external-gateway):
  echo canceller and jitter adaptation off on that port.
- Nothing else in softpbx changes: a modem call looks like a call between two
  SIP endpoints.

Honest expectation: this works well on a quiet LAN and degrades badly on a
lossy link — modems are far less forgiving than voice or fax. If a use case
appears, we test with the real modems and document what holds up.
