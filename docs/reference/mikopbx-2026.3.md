# MikoPBX in this VM — deployment & SIP wire report

**Date:** 2026-10-04 · **Host:** Debian 13 VM (`debian-opencode`), KVM available, 8 vCPU / 15 GB RAM
**Status: ✅ MikoPBX is RUNNING and speaking SIP.** Nothing is blocked.

> **VERDICT — "MikoPBX is running at `192.168.77.108` (web `https://192.168.77.108`, SIP `192.168.77.108:5060` UDP/TCP)
> and speaks: Asterisk 22.8.2 / PJSIP behind a generated config, digest auth (MD5, qop=auth) with
> per-system realm `db2d59c4412c`, `User-Agent: PBX`, `Server: PBX`, `P-Asserted-Identity` on internal legs,
> **no session timers at all** (no Session-Expires / UPDATE / re-INVITE / PRACK ever observed, verified on a 78 s call),
> three trunk auth modes (outbound registration / inbound registration / static IP)."**

All statements below are backed by captures in this directory (`sip-all.pcap`, `stub*.msg`, `inbound-*.msg`)
and by the generated `pjsip.conf.generated`.

---

## 1. Where MikoPBX comes from (exact URLs, version, checksums)

| Item | Value |
|---|---|
| Product page | https://www.mikopbx.com/download/ |
| Source / releases | https://github.com/mikopbx/Core (GitHub releases are the canonical artifact host) |
| Version booted | **MikoPBX 2026.3.40** (released 2026-08-03), x86_64 |
| Download URL used | `https://lic.mikopbx.com/releases/v1/mikopbx/downloadFirmware?version=latest&arch=x86_64&ext=iso` (redirects to `github.com/mikopbx/Core/releases/download/2026.3.40/mikopbx-2026.3.40-x86_64.iso`) |
| File | `mikopbx.iso`, 451,936,256 bytes, "Miko PBX Live" bootable ISO 9660 |
| **Checksum verified** | MD5 `a83d81ae251631c0b28807e874d51b25` — **matches** the published `checksum.md5` from the same release (https://github.com/mikopbx/Core/releases/download/2026.3.40/checksum.md5) |
| sha256 (computed here) | `5b3a53fd9b505146986b677d3e3ce216c17eb62c8ebe615c1981c357bb18c394` |

Other artifacts of the same release (all listed with MD5s in `checksum.md5`):
`x86_64.img` (160 MB gzip'd disk image), `x86_64.raw` / `.vhd` (630 MB raw disk), `x86_64.ova`, `x86_64-lxc.tar.gz`,
`x86_64-docker.tar`, `x86_64-legacy.img`, plus arm64 variants.

### 1.1 Important gotcha: the ISO is a LiveCD **without** Asterisk/nginx

The ISO boots fine, but its rootfs contains only the PHP web app + admin tools — **no `asterisk` and no `nginx`
binaries** (only `rasterisk`). The full appliance is inside the ISO as `firmware.img.gz` (160 MB gz → 630 MB raw),
which is byte-identical to the `x86_64.raw` release artifact. In live mode the console menu runs but the PBX
services never start ("Starting Asterisk/Nginx" steps never appear).

**What actually works:** extract/gunzip `firmware.img.gz` (or download `x86_64.raw`) and boot that disk image
directly — it is the complete installed system (GPT: 100 MB EFI + 483 MB root + 15 MB + BIOS boot). Attach a
second blank disk for data ("offload" storage). This is exactly what the appliance writes to disk when installed.

## 2. How it runs here (and how to restart it)

QEMU 10.0.13, KVM acceleration, running inside tmux session `miko`:

```bash
qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 \
  -drive file=/tmp/opencode/mikopbx/firmware.qcow2,if=virtio,format=qcow2 \
  -drive file=/tmp/opencode/mikopbx/disk.qcow2,if=virtio,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::8080-:80,hostfwd=tcp::8443-:443,hostfwd=tcp::2222-:22,hostfwd=udp::5070-:5060 \
  -device virtio-net-pci,netdev=net0 \
  -netdev tap,id=net1,ifname=tap-miko,script=no,downscript=no \
  -device virtio-net-pci,netdev=net1 \
  -serial mon:stdio -display none
```

* `firmware.qcow2` = qcow2 overlay backed by `firmware.img` (the gunzipped release image — pristine).
* `disk.qcow2` = 8 GB data disk; MikoPBX auto-partitioned it and mounts it at `/storage/usbdisk1` (configs, CDR, logs, sounds).
* **eth0** = QEMU user-net (10.0.2.15, internet via host) with host-forwards:
  `127.0.0.1:8080→80`, `127.0.0.1:8443→443`, `127.0.0.1:2222→22`, `127.0.0.1:5070(udp)→5060`.
* **eth1** = tap `tap-miko` bridged to `br-miko` (host `192.168.77.1`, VM gets `192.168.77.108` via dnsmasq DHCP).
  This is the interface used for all SIP/RTP testing because user-net can't forward RTP.
  Host NAT (MASQUERADE) is set up so the VM has internet via both NICs.

Access from the host:

| Service | Address | Notes |
|---|---|---|
| Web UI | **https://192.168.77.108** (also http://127.0.0.1:8080 → redirects to https) | self-signed cert |
| REST API | https://192.168.77.108/pbxcore/api/v3/… | JWT bearer (15 min) |
| SIP | **192.168.77.108:5060 UDP + TCP**, TLS on 5061, WSS on 8089 | Asterisk 22.8.2 |
| SSH | 127.0.0.1:2222 → guest 22 | dropbear, **password auth disabled** (see §3) |
| Console | `tmux attach -t miko` | serial console, root auto-login |

**To restart after a host reboot** (⚠️ `/tmp` is tmpfs — images vanish on reboot; re-fetch takes ~2 min):

```bash
mkdir -p /tmp/opencode/mikopbx && cd /tmp/opencode/mikopbx
curl -L -o mikopbx.iso 'https://lic.mikopbx.com/releases/v1/mikopbx/downloadFirmware?version=latest&arch=x86_64&ext=iso'
echo 'a83d81ae251631c0b28807e874d51b25  mikopbx.iso' | md5sum -c -
7z e -y mikopbx.iso firmware.img.gz && gunzip -kf firmware.img.gz          # == x86_64.raw
qemu-img create -f qcow2 -b firmware.img -F raw firmware.qcow2
qemu-img create -f qcow2 disk.qcow2 8G
# recreate network: br-miko 192.168.77.1/24 + tap-miko (user=user), dnsmasq DHCP on br-miko,
# iptables MASQUERADE 192.168.77.0/24 -> enp1s0, sysctl net.ipv4.ip_forward=1
# then the qemu command above in tmux
```

**What is running right now (left running on purpose):**

| Process | tmux/where | Purpose |
|---|---|---|
| MikoPBX QEMU VM | tmux `miko` | the PBX (state: extensions 3001/3002, trunks, routes configured) |
| `sipstub.py` on 192.168.77.1:5099 | background (log `stubB.log`) | fake SIP provider; MikoPBX trunk registers to it |
| softpbx `pbx-daemon` on 192.168.77.1:5080 | tmux `sp` (log `softpbx.log`) | our SIP stack interop target |
| baresip as ext 3002 (auto-answer) | tmux `bs2` | registered to MikoPBX |
| baresip as 9001 (inbound trunk) | tmux `bs3` | registered to MikoPBX's inbound trunk |
| linphonec as ext 3001 | `linphonecsh` daemon | registered to MikoPBX |
| tcpdump on `br-miko` → `sip-all.pcap` | background | still capturing (stop with `sudo pkill tcpdump`) |

## 3. First boot & credentials story

* **Web UI: `admin` / `admin`** (official default, confirmed working; docs: "Getting to know MikoPBX",
  "Resetting WEB Interface Credentials"). First login prompts for a password change (I kept the default).
* **REST API v3** (this is what the web UI itself uses):

  ```bash
  curl -sk -X POST 'https://192.168.77.108/pbxcore/api/v3/auth:login' \
    -H 'Content-Type: application/json' --data '{"login":"admin","password":"admin"}'
  # -> {"data":{"accessToken":"<JWT>","tokenType":"Bearer","expiresIn":900,...}}
  ```

  Resource CRUD: `GET/POST/PUT/PATCH/DELETE /pbxcore/api/v3/{resource}[/{id}]`, custom methods as
  `/{resource}:method` (e.g. `system:executeBashCommand` — yes, the PBX has a remote-root-shell API for admins,
  which is how most of the evidence below was gathered).
* **SSH: disabled by default.** dropbear runs with `-s` (password auth off), root password is *locked*, and every
  SSH session is forced into `/etc/rc/hello`. To enable: System → General settings ("SSH password" /
  "SSH Authorized Keys"). Docs confirm: keys by default, password must be explicitly enabled.
* **Console: root auto-login with no password** on ttyS0 (serial) and a curses menu on tty1
  (options incl. reboot/shutdown; menu disables itself after 4 idle iterations). Reset web credentials from the menu.
* **Fresh install seeds demo data**: SIP extensions 201/202/203 ("Smith James"…), queues 2001 ("Sales office") /
  2002, IVR 2003, conference 1111, external numbers, time frames incl. a weekend "out of work times" rule that
  answers+plays a prompt+hangups outside business hours. **This is why 2001/2002 were not usable as extensions** —
  I created **3001/3002** instead (secrets `Sec3001miko` / `Sec3002miko`).
* Boot banner (`/etc/rc/welcome_banner`) prints version, web URL, SSH line and service status
  (Asterisk ● Nginx ● PHP ● Redis ● Nats ● Fail2ban ● Monit).

## 4. Registration & authentication for internal users (extensions)

* Model: one "employee" = SIP peer + user record. REST: `/pbxcore/api/v3/employees` (full CRUD;
  `employees:getDefault` returns a template with a random `sip_secret`).
* Regenerated on every config change into `/etc/asterisk/pjsip.conf`. Each extension gets **three endpoints**:
  `<num>` (UDP/TCP auto), `<num>-WS` (WebRTC/WSS), `<num>-TLS` (TLS + SDES SRTP), all sharing auth `<num>-AUTH`:

  ```ini
  [3001-AUTH]
  type = auth
  username = 3001            # auth username == extension number
  password = Sec3001miko     # == sip_secret
  realm = db2d59c4412c       # per-system realm (see below)

  [3001](aor-common)         # qualify_frequency=60, max_contacts=5, remove_existing=yes
  [3001](endpoint-auto)
  callerid = Test User 3001 <3001>
  aors = 3001
  auth = 3001-AUTH
  outbound_auth = 3001-AUTH
  dtmf_mode = auto
  ```

* **Digest realm** = 12 hex chars, **not** "asterisk": generated as `substr(md5(primary-iface-MAC),0,12)`
  (source: `Core/Asterisk/Configs/SIPConf.php::getSipRealm()`) and overridable via the `SIP_REALM` PBX setting.
  Challenge: `WWW-Authenticate: Digest realm="db2d59c4412c",nonce="…",opaque="…",algorithm=MD5,qop="auth"`.
* **Calls are authenticated too** — an INVITE from a registered peer still gets `401` + digest challenge
  (see capture in §6.2). Registrations and INVITEs both matter.
* Challenge realm for *trunk inbound-registration* auth is different: **`asterisk`** (the generated trunk auth
  object has no `realm=` line). Implementers must not hard-code one realm.
* Transport per peer: `sip_transport = "udp,tcp"` (plus TLS/WebSocket variants). `dtmf_mode = auto`
  (RFC2833 preferred, inband negotiated).

## 5. SIP trunk ("provider" / провайдер) configuration

REST: `/pbxcore/api/v3/sip-providers` (CRUD). Record schema (`sip-providers:getDefault`):

```
id = SIP-TRUNK-<8hex>            type = SIP | IAX
note / description / disabled
username, secret                 # digest credentials (secret masked as XXXXXXXX on read)
host, port = 5060, transport = udp | tcp | tls
registration_type = outbound | inbound | none     # "Account type"
qualify, qualifyfreq = 60
networkfilterid                  # IP allow-list ("Connections from any addresses are allowed")
dtmfmode = auto
fromuser, fromdomain, disablefromuser
cid_source = default | <custom header | regex parser>   + cid_custom_header/cid_parser_*
did_source = default | <custom header | regex parser>   + did_custom_header/did_parser_*
additionalHosts = []             # extra IPs for the identify match
manualattributes                 # raw pjsip config lines (!)
```

### 5.1 The three account types (official tooltips, from `Messages/en/Providers.php`)

| Mode | Tooltip | Generated pjsip |
|---|---|---|
| `outbound` — "Outgoing registration" | "Your PBX registers on provider server" | `[X-REG](registration-base)` with `server_uri`/`client_uri`/`outbound_auth`, endpoint gets `outbound_auth` |
| `inbound` — "Incoming registration" | "Provider registers on your PBX. Used when external server connects to you" | endpoint **named after `username`** (e.g. `[9001]`), `auth = X-AUTH`, AOR `[9001](provider-aor-base)`, `identify_by = username,auth_username` |
| `none` — "No registration" | "Static connection by IP address without registration" | AOR `contact = sip:host:port`, `type = identify match = <host IP(s)>` |

Registration timing (all modes): `expiration = 120`, `retry_interval = 45`, `max_retries = 200`,
`forbidden_retry_interval = 300`, `fatal_retry_interval = 300`. Provider AORs: `max_contacts = 1`
(no `remove_existing` — a second REGISTER from a new contact is rejected 403
`registrar_attempt_exceeds_maximum_configured_contacts`).

### 5.2 Verified generated config excerpts (from this VM)

IP-based trunk (`registration_type=none`, host=192.168.77.1:5099):

```ini
; ============================================================
; OUTBOUND TRUNK: IP trunk to test stub (UDP)
; ============================================================
[SIP-TRUNK-5D251358](provider-aor-base)
contact = sip:192.168.77.1:5099
qualify_frequency = 60
qualify_timeout = 3.0

[SIP-TRUNK-5D251358]
type = identify
endpoint = SIP-TRUNK-5D251358
match = 192.168.77.1

[SIP-TRUNK-5D251358](provider-endpoint-udp)
set_var = providerID=SIP-TRUNK-5D251358
context = SIP-TRUNK-5D251358-incoming
dtmf_mode = auto
from_user =
from_domain = 192.168.77.1
contact_user =
aors = SIP-TRUNK-5D251358
```

Registration-based trunk (`registration_type=outbound`, username=testtrunk):

```ini
[SIP-TRUNK-5D251358-REG-AUTH]
type = auth
username = testtrunk
password = trunkpass123

[SIP-TRUNK-5D251358-REG](registration-base)
outbound_auth = SIP-TRUNK-5D251358-REG-AUTH
contact_user = testtrunk
server_uri = sip:192.168.77.1:5099
client_uri = sip:testtrunk@192.168.77.1:5099
transport = transport-udp
# endpoint additionally gets:
#   from_user = testtrunk
#   from_domain = 192.168.77.1        <-- from_domain == trunk host, always
#   contact_user = testtrunk
#   outbound_auth = SIP-TRUNK-5D251358-AUTH
```

Inbound-registration trunk (`registration_type=inbound`, username=9001, secret=inbpass9001):

```ini
[SIP-TRUNK-4F4B1684-AUTH]
type = auth
username = 9001
password = inbpass9001                       # NOTE: no realm= line -> challenge realm "asterisk"

[9001](provider-aor-base)
[9001](provider-endpoint-udp)
set_var = providerID=SIP-TRUNK-4F4B1684
context = 9001-incoming
from_user = 9001
from_domain = 192.168.77.1
contact_user = 9001
aors = 9001
auth = SIP-TRUNK-4F4B1684-AUTH
identify_by = username,auth_username
```

Provider endpoint template (all trunks) — the wire-relevant options:

```ini
[provider-endpoint-base](!)
disallow=all; allow=opus,g722,alaw,ulaw,g729,gsm,h265,h264,vp9,vp8
100rel = no
rtp_symmetric = yes ; force_rport = yes ; rewrite_contact = yes
ice_support = no ; direct_media = no
sdp_session = PBX
timers = no                      # <<< session timers OFF
rtp_keepalive = 0 ; rtp_timeout = 60 ; rtp_timeout_hold = 300
inband_progress = yes ; tone_zone = us
```

Internal endpoint template differs: `send_pai = yes`, **no `100rel=no`** (but see §7 — PRACK is never actually used),
`timers = no` as well, `rtp_keepalive = 30`, `rtp_timeout = 120`, `message_context = messages`.

### 5.3 Routing to trunks

* Outgoing: `/pbxcore/api/v3/outbound-routes` — `{rulename, providerid, priority, numberbeginswith (prefix/regex),
  restnumbers (-1=any length), trimfrombegin, prepend}`. Generated per-trunk outgoing context, e.g.
  `Dial(PJSIP/123456789@SIP-TRUNK-5D251358,600,TKU(dial_answer)b(dial_create_chan,s,1))`.
* Incoming: `/pbxcore/api/v3/incoming-routes` — `{rulename, number (DID, masks X/N/Z/.), providerid (or "none"),
  priority, timeout, extension, audio_message_id}`. Generates per-trunk context `…-incoming` with CID/DID parsing
  hooks (`add-trim-prefix-clid`, `check-out-work-time`, then `Dial(Local/<ext>@internal-incoming,…)` and a
  fallback default action).
* CID/DID sources per trunk: `cid_source`/`did_source` can take a **custom SIP header + regex parser**
  (start/end/regex fields) — useful for gateways that put the called number in e.g. `Diversion`/`X-Number`.

## 6. Captured SIP messages (verbatim)

All from `/tmp/opencode/mikopbx/sip-all.pcap` (host-side tcpdump on the QEMU bridge) and the stub message files.

### 6.1 Registration of an internal user (baresip 3002 → MikoPBX)

```
REGISTER sip:192.168.77.108 SIP/2.0
Via: SIP/2.0/UDP 192.168.77.1:5071;branch=z9hG4bK9f528f3ed5284446;rport
Contact: <sip:3002-0x563dc2f1bbe0@192.168.77.1:5071>;expires=300;+sip.instance="<urn:uuid:9541effa-…>"
Max-Forwards: 70
To: <sip:3002@192.168.77.108>
From: <sip:3002@192.168.77.108>;tag=dec9efa8195d3424
Call-ID: 5a0f44882f7fab20
CSeq: 57689 REGISTER
User-Agent: baresip v1.1.0 (x86_64/linux)
Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,NOTIFY,SUBSCRIBE,INFO,MESSAGE,REFER
Content-Length: 0

SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.77.1:5071;rport=5071;received=192.168.77.1;branch=z9hG4bK9f528f3ed5284446
Call-ID: 5a0f44882f7fab20
From: <sip:3002@192.168.77.108>;tag=dec9efa8195d3424
To: <sip:3002@192.168.77.108>;tag=z9hG4bK9f528f3ed5284446
CSeq: 57689 REGISTER
WWW-Authenticate: Digest realm="db2d59c4412c",nonce="1791062031/fe3cb5cf6cb7d77863eaf2fdba9c291d",opaque="6c9783300393211d",algorithm=MD5,qop="auth"
Server: PBX
Content-Length:  0
```

(followed by REGISTER with `Authorization: Digest username="3002", realm="db2d59c4412c", … qop=auth, nc=00000001`
and `200 OK`.) Note the **To-tag == the Via branch** in 401s (Asterisk quirk).

### 6.2 Call 3001 → 3002 — MikoPBX answers AND authenticates the caller

The caller's INVITE gets challenged before the call proceeds:

```
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.77.1:5060;rport=5060;received=192.168.77.1;branch=z9hG4bK.M6YkOP1Lp
Call-ID: oJCSMy35P3
From: <sip:3001@192.168.77.108>;tag=SKqFBfJsV
To: <sip:3002@192.168.77.108>;tag=z9hG4bK.M6YkOP1Lp
CSeq: 20 INVITE
WWW-Authenticate: Digest realm="db2d59c4412c",nonce="1791062047/aa17b9565f662c648cfe3a562cbc98e6",opaque="23ea01fb6bb23bfd",algorithm=MD5,qop="auth"
Server: PBX
Content-Length:  0
```

### 6.3 MikoPBX as UAC — INVITE to an internal peer (what your softphone will receive)

```
INVITE sip:3002-0x563dc2f1bbe0@192.168.77.1:5071 SIP/2.0
Via: SIP/2.0/UDP 192.168.77.108:5060;rport;branch=z9hG4bKPj659da951-65a4-4978-8793-bd9f69f61b88
From: "Test User 3001" <sip:3001@10.0.2.15>;tag=5808b679-8e4f-495c-9b5b-599a1a4e4283
To: <sip:3002-0x563dc2f1bbe0@192.168.77.1>
Contact: <sip:asterisk@192.168.77.108:5060>
Call-ID: 73977611-6ff2-44f1-9f02-69d42a5d2382
CSeq: 23096 INVITE
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER
Supported: 100rel, replaces, norefersub, histinfo
P-Asserted-Identity: "Test User 3001" <sip:3001@10.0.2.15>
Max-Forwards: 70
User-Agent: PBX
Content-Type: application/sdp
Content-Length:   418

v=0
o=- 429836734 429836734 IN IP4 192.168.77.108
s=PBX
c=IN IP4 192.168.77.108
t=0 0
m=audio 10680 RTP/AVP 107 8 0 18 9 3 101 102
a=rtpmap:107 opus/48000/2
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:9 G722/8000
a=rtpmap:3 GSM/8000
a=rtpmap:101 telephone-event/48000
a=fmtp:101 0-16
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
```

Observations: Request-URI is the **registered contact** (rewrite_contact=yes, so `user@client-addr`).
`Contact: <sip:asterisk@192.168.77.108:5060>` — user part is literally **`asterisk`**, not the extension.
`From`/`P-Asserted-Identity` carry caller name+number, but the **URI host is the PBX's first-interface IP
(10.0.2.15), not the signaling source (192.168.77.108)** — a multi-homed trap worth knowing.
`Supported: 100rel` is advertised on internal legs but 100rel is not used (no PRACK ever).

### 6.4 MikoPBX as UAC — INVITE to an IP-based trunk (external call)

Dialed `8123456789` with outbound route `8*` → provider, `trimfrombegin=1` (recorded as `stubA-001.msg`):

```
INVITE sip:123456789@192.168.77.1:5099 SIP/2.0
Via: SIP/2.0/UDP 192.168.77.108:5060;rport;branch=z9hG4bKPj5d8bb0de-a436-4122-8c78-96ad945dea48
From: "Test User 3001" <sip:3001@192.168.77.1>;tag=92930802-6cfe-4c50-951f-52cc3679f0d1
To: <sip:123456789@192.168.77.1>
Contact: <sip:asterisk@192.168.77.108:5060>
Call-ID: 74fdfe6b-d516-4177-b421-042d5a651611
CSeq: 3847 INVITE
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, MESSAGE, REFER
Supported: replaces, norefersub, histinfo
Max-Forwards: 70
User-Agent: PBX
Content-Type: application/sdp
Content-Length:   418

v=0
o=- 585284397 585284397 IN IP4 192.168.77.108
s=PBX
c=IN IP4 192.168.77.108
t=0 0
m=audio 10788 RTP/AVP 107 8 0 18 9 3 101 102
…(same codec set as above)…
```

Differences vs internal: **`From` URI host = the trunk host** (`from_domain` is always set to the provider host),
`To` URI host = trunk host, **no P-Asserted-Identity**, **no PRACK in Allow**, `Supported` without `100rel`.
With a username configured (registration-mode trunk) `From`/`Contact` become the **trunk login**, hiding the caller:

```
INVITE sip:123456789@192.168.77.1:5099 SIP/2.0
From: <sip:testtrunk@192.168.77.1>;tag=49b072be-94d0-48da-a235-cdc3bedf4446
To: <sip:123456789@192.168.77.1>
Contact: <sip:testtrunk@192.168.77.108:5060>
…(headers otherwise identical)…
```

When is each shape used? Generated config: `from_user`/`contact_user` are set from the trunk `username`
(`disablefromuser=false` default); with no username (IP trunk) the caller's extension is used.

### 6.5 MikoPBX as a SIP registrar client — REGISTER to the provider

From `stubB-001/002.msg` (trunk: username=testtrunk, host=192.168.77.1:5099):

```
REGISTER sip:192.168.77.1:5099 SIP/2.0
Via: SIP/2.0/UDP 192.168.77.108:5060;rport;branch=z9hG4bKPje78b48dc-74df-44b1-8d28-b78aa0ddb08b
From: <sip:testtrunk@192.168.77.1>;tag=81cb5308-d519-424c-9d7e-7190f0dfed34
To: <sip:testtrunk@192.168.77.1>
Call-ID: 68e1e357-0443-45c9-881f-8731cff6debd
CSeq: 51991 REGISTER
Contact: <sip:testtrunk@192.168.77.108:5060>
Expires: 120
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER
Max-Forwards: 70
User-Agent: PBX
Content-Length:  0

# after 401 challenge:
REGISTER sip:192.168.77.1:5099 SIP/2.0
…
CSeq: 51992 REGISTER
Contact: <sip:testtrunk@192.168.77.108:5060>
Expires: 120
Authorization: Digest username="testtrunk", realm="trunk-realm", nonce="33ce0249cd9747eeae8fe8687328a815", uri="sip:192.168.77.1:5099", response="7b9b2cdb8040333d522b1e6cbff98357", algorithm=MD5, cnonce="64f40e4c58904207a15616c1367b4e65", opaque="7606db30a7494b6d96c4ee50c31397a4", qop=auth, nc=00000001
Content-Length:  0
```

Key facts: **Expires: 120** always (32-bit max 3600 configurable only via pjsip), From/To = `sip:login@trunk-host`
(host part is the *provider host*, not the registrar realm/domain), Contact = `sip:login@pbx-ip:5060`, CSeq
increments between the challenge/retry pair, and after registering MikoPBX sends periodic
`OPTIONS sip:login@host` qualify probes (every `qualifyfreq` 60 s) — your far end must answer OPTIONS politely.

### 6.6 BYE

```
BYE sip:stub@192.168.77.1:5099 SIP/2.0
Via: SIP/2.0/UDP 192.168.77.108:5060;rport;branch=z9hG4bKPj31a93fb0-0e62-4a3b-bc26-2a5894617daa
From: "Test User 3001" <sip:3001@192.168.77.1>;tag=92930802-6cfe-4c50-951f-52cc3679f0d1
To: <sip:123456789@192.168.77.1>;tag=2f871ed37059
Call-ID: 74fdfe6b-d516-4177-b421-042d5a651611
CSeq: 3848 BYE
Reason: Q.850;cause=16
Max-Forwards: 70
User-Agent: PBX
Content-Length:  0
```

**`Reason: Q.850;cause=16` is included on BYE.** BYE R-URI uses the remote Contact (not the original To).

### 6.7 Inbound call from a trunk (far end → MikoPBX)

Sent INVITE as the provider (from IP 192.168.77.1, To: `777@192.168.77.108`):

* **No auth challenge**: the trunk endpoint has no inbound `auth` in IP mode; identification is
  `type=identify match=192.168.77.1` (IP match) / `identify_by=username,auth_username` (inbound-reg mode).
* 100 Trying → routed via the Incoming route (DID from To user by default) → 200 OK with `Contact:
  <sip:testtrunk@192.168.77.108:5060>` (trunk's contact_user) and an SDP *answer* limited to the offered codecs.
* Today being Sunday, the seeded weekend Time Frame answered with the "out of work times" prompt and hung up
  (200 OK → ~8 s of audio → BYE `Reason: Q.850;cause=16`). Call-ID/From/To pass through unchanged.

## 7. Session behavior (the part SIP implementers care about)

* **`timers = no`** is set on *both* internal and provider endpoint templates → **session timers are disabled**.
* Verified empirically: over every captured call — including a **77.7-second call** (`Call-ID: a709d845-…`,
  INVITE t=969.88 s → BYE t=1047.58 s) — the only mid-dialog messages were ACK and BYE.
  `Session-Expires` header occurrences in the whole capture: **0**. `UPDATE`: **0**. `PRACK`: **0**. re-INVITE: **0**.
* Consequence for a trunk builder: do **not** expect session refreshes from MikoPBX, and do not rely on
  `Session-Expires`/`Min-SE` negotiation. If your softswitch requires session timers, you must drive them
  yourself (re-INVITE/UPDATE), and MikoPBX will accept UPDATE (it lists UPDATE in Allow) but never initiates it.
* `Supported: 100rel` appears on internal legs only; provider legs drop it (`100rel = no`). No PRACK flows exist.
* Early media: `inband_progress = yes` — 183 with SDP can appear (observed 183 on an internal call).
* RTP: symmetric RTP + forced rport + `rewrite_contact`, no ICE, no direct media (always relays through the PBX's
  own SDP address — `c=IN IP4 192.168.77.108`, media port near 10xxx, `rtp_keepalive` 0/30 s per template,
  `rtp_timeout` 60/120 s). SDP session name is `s=PBX`, `o=- <ts> <ts> IN IP4 <pbx-ip>`.
* Codec offer order from MikoPBX: `opus(107), PCMA(8), PCMU(0), G729(18), G722(9), GSM(3)` + two
  telephone-event dyn payloads 101/102 (fmtp `0-16` — note: **0-16**, not the usual 0-15), `ptime:20`, `maxptime:60`
  (140 on answers seen). Video codecs h265/h264/vp9/vp8 are also allowed per config but not offered in audio-only calls.

## 8. softpbx interop results (this repo's daemon)

`pbx-daemon` (from `/home/user/proj/softpbx/target/debug/pbx-daemon`, config in `/tmp/opencode/mikopbx/softpbx-config.toml`,
**repo untouched**) ran on `192.168.77.1:5080` with devices 1001/1002. MikoPBX was pointed at it as a
registration-mode trunk (username 1001 / secret `sp1001pass`):

Final live state: MikoPBX trunk `SIP-TRUNK-50F7B001` ("softpbx interop trunk", host 192.168.77.1:5080,
outbound registration as 1001) is **Registered** and re-registers continuously; outbound route id 23
(`7*` → strip 1 digit → that trunk) maps dial-7xxx to it. Trunk `SIP-TRUNK-5D251358` registers to the
test stub on :5099, and inbound-mode trunk `SIP-TRUNK-4F4B1684` (username 9001) accepts registrations.

* **MikoPBX REGISTER → softpbx: SUCCESS.** softpbx challenged with
  `WWW-Authenticate: Digest realm="softpbx", nonce="81d3-1", algorithm=MD5` (**no qop, no opaque**) and MikoPBX
  answered correctly with `Authorization: Digest username="1001", realm="softpbx", … algorithm=MD5`
  (qop-less digest — MikoPBX handles both qop and non-qop challenges). MikoPBX then showed the registration as
  `Registered (exp. 54s)` in `pjsip show registrations` and keeps re-registering every ~60 s (Expires: 120).
* **MikoPBX INVITE → softpbx: delivered and parsed.** softpbx logged
  `call {"caller":"1001","callee":"12345","result":"not-found"}` and replied `100 Trying` + `404 Not Found`,
  which MikoPBX treated as a normal failure (ACK, call torn down).
* Wire forms on this leg are exactly §6.4/§6.5 with `testtrunk`→`1001`:
  `From: <sip:1001@192.168.77.1>`, `To: <sip:12345@192.168.77.1>`, `Contact: <sip:1001@192.168.77.108:5060>`.
  Note the far end sees **caller=1001 (the trunk login)**, not the real caller 3001 — if softpbx needs the real
  caller, MikoPBX must be told to send it (trunk `fromuser` field, or `manualattributes`, or the CID settings).

## 9. What a SIP-stack implementer must know before building a trunk to MikoPBX

1. **It is Asterisk 22.8.2 / chan_pjsip** with a generated config (`/etc/asterisk/pjsip.conf`, regenerated on every
   web/API change and `res_pjsip` reloaded). Protocol conformance is Asterisk's; quirks are Asterisk's.
   `User-Agent: PBX`, `Server: PBX` (custom), SDP `s=PBX`.
2. **Auth:** HTTP Digest MD5, **qop="auth" + opaque** when MikoPBX challenges; it *answers* challenges with or
   without qop. Extension realm is `substr(md5(mac),0,12)` (ours: `db2d59c4412c`); **trunk inbound-auth realm is
   `asterisk`**. Auth username = extension number (peers) or trunk `username` (trunks).
3. **MikoPBX challenges INVITEs as well as REGISTERs** from authenticated endpoints (401 before the call setup).
   Trunks in IP mode and inbound-reg mode are identified by IP / auth-username and are not challenged.
4. **No session timers.** No Session-Expires/Min-SE, no UPDATE, no re-INVITE refresh, no PRACK — ever.
   Keep-alives on the SIP level: only re-REGISTER and 60 s OPTIONS qualify probes (answer them!).
5. **From/Contact shapes depend on the trunk's `username`:**
   * no username (IP trunk): `From: "Caller Name" <caller@trunk-host>`, `Contact: <sip:asterisk@pbx:5060>`
   * with username: `From: <sip:login@trunk-host>`, `Contact: <sip:login@pbx:5060>` — the real caller disappears.
   `from_domain` is always forced to the **provider host**; `fromuser`/`disablefromuser`/`manualattributes` let you
   override. `P-Asserted-Identity` is sent **only to internal peers** (`send_pai=yes`), never on trunk legs.
6. **REGISTER expectations:** Expires is 120 s; From/To = `sip:login@host`; Contact is a bare `sip:login@ip:5060`
   (no +sip.instance); re-registration cadence driven by the registrar's 200/Expires (min 60, max 3600).
   Provider AORs accept exactly **one** contact (`max_contacts=1`, no `remove_existing`) — a second, differently
   located contact gets **403** (`registrar_attempt_exceeds_maximum_configured_contacts`). Reuse the same source
   port or deregister first.
7. **Media:** PBX always relays RTP itself (no direct media). Symmetric RTP + rport + rewritten Contact. No ICE.
   Telephone-event fmtp is `0-16`. Two telephone-event payloads (48k + 8k) offered. rtp_timeout kills dead calls
   (60 s trunk / 120 s peer).
8. **Routing knobs you'll likely need:** outbound routes (`numberbeginswith` regex, `restnumbers`, `trimfrombegin`,
   `prepend`), incoming routes (DID masks `X/N/Z/.`, per-trunk or "any provider", with **custom-header + regex
   CID/DID parsers** per trunk — good for gateways that pass the called number in arbitrary headers).
9. **TLS/WSS** are preconfigured (TLS 5061 with SDES SRTP option; WSS 8089 WebRTC endpoints per extension).
10. **Admin API** (`/pbxcore/api/v3/…`, JWT) can do everything the UI does, incl. `system:executeBashCommand` and
    `system:executeSqlRequest` — useful for automation and for reading generated configs.
11. Watch the multi-homed From-host quirk (§6.3): `From`/`PAI` host = the PBX's *primary* interface IP, which may
    differ from the signaling source address.
12. Config editing pitfall (API): creating a `sip-providers` record whose JSON contains the template `id`
    (from `getDefault`) **overwrites** an existing trunk with that id — always clear/replace `id` on create.

## 10. Quirks / bugs noticed along the way

* ISO live mode boots to a console with no PBX services (no Asterisk/nginx binaries in the live rootfs).
* `Fail2ban` failed to start on the live-CD boot (works on the firmware boot).
* Trunk create via API reuses the `getDefault` id if not reset (silent overwrite — see §9.12).
* PATCH on `/sip-providers/{id}` requires a full record (no merge semantics) despite being "patch".
* Trunk inbound-auth challenges use realm `asterisk` while everything else uses the system realm.
* Duplicate REGISTER from a new contact port → 403 (max_contacts=1) even though auth succeeds — some clients
  (baresip here) treat that as a registration failure and back off.
* Seeded demo Time Frames make inbound test calls "answer + play out-of-hours prompt + BYE" on weekends —
  don't confuse this with trunk behavior.

## 11. Artifact inventory (all in `/tmp/opencode/mikopbx/`)

| File | What |
|---|---|
| `mikopbx.iso`, `checksum.md5`, `mikopbx.iso.sha256` | downloaded distribution + verification |
| `firmware.img(.gz)`, `firmware.qcow2`, `disk.qcow2` | the booted system + data disk |
| `report.md` | this file |
| `sip-all.pcap` | **all SIP traffic** (registration, internal call, trunk calls, softpbx interop) |
| `sip-trace.pcap` | earlier capture (first call) |
| `stubA-*.msg`, `stubB-*.msg`, `stubB.log` | verbatim messages seen by the fake provider (IP trunk & reg trunk) |
| `inbound-*.msg` | verbatim inbound-trunk call messages |
| `baresip*.log` | softphone-side SIP traces (incl. `baresip-inb.log` inbound-reg attempt) |
| `pjsip.conf.generated` | full generated Asterisk PJSIP config (411 lines) |
| `sipstub.py`, `sendinvite.py` | test harnesses (far-end provider simulator, inbound caller) |
| `miko.sh` | helper to run admin commands on the PBX over its REST API |
| `softpbx-config.toml`, `softpbx.log`, `softpbx-calls.ndjson` | softpbx daemon interop evidence |
| `serial.log`, `serial2.log` | boot consoles (live-CD boot vs firmware boot) |
