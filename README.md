# pi-nat64

**[Live UI Demo →](https://alqu-it.github.io/pi-nat64/)**

NAT64/DNS64 gateway + network-wide ad blocking + Wi-Fi access point, with a browser-based management UI. Built for Raspberry Pi 5.

Lets **IPv6-only devices** reach IPv4-only services transparently, while blocking ads and trackers for every device on the network.

---

## How it works

```
Internet  (IPv6-only ISP)
       │
    eth0   ──  Raspberry Pi 5
       │
   ┌───┴────────────────────────────────┐
   │  Jool       NAT64                  │  translates IPv6 ↔ IPv4 packets
   │  Pi-hole    DNS sinkhole           │  blocks ads & trackers network-wide
   │  Unbound    DNS64                  │  synthesises AAAA records for IPv4 hosts
   │  hostapd    Wi-Fi AP               │  wlan0 access point
   │  Flask      web UI                 │  manage everything via browser
   └───┬────────────────────────────────┘
       │
    wlan0   (fd00::/64)
       │
   Your devices  (phone, laptop, …)
```

**DNS query path:**

```
Device  →  Pi-hole :53  ──── blocked? ──→  NXDOMAIN  (ad/tracker dropped)
                │
                └── not blocked  →  Unbound :5335  →  Internet
                                        (DNS64 synthesis if needed)
```

---

## Requirements

- Raspberry Pi 5 running Raspbian OS (bookworm)
- `eth0` connected to an IPv6-only ISP
- `wlan0` available for the access point
- Root access (`sudo`)

---

## Install

```bash
git clone https://github.com/ALQU-IT/pi-nat64.git
cd pi-nat64
sudo bash install.sh
```

The installer handles everything:

1. Installs packages — `jool-tools`, `unbound`, `hostapd`, `dnsmasq`, `radvd`, `flask`, `curl`
2. Loads the Jool NAT64 kernel module and configures prefix `64:ff9b::/96`
3. Configures Unbound DNS64 on `127.0.0.1:5335` (loopback only)
4. Installs Pi-hole unattended (no separate web UI — stats are in the pi-nat64 UI)
5. Configures the Wi-Fi AP (`pi-nat64` SSID, `ChangeMe123` passphrase)
6. Sets up DHCP and IPv6 router advertisements on `wlan0`
7. Applies and persists firewall rules via `netfilter-persistent`
8. Deploys the Flask web UI as a systemd service on port 80
9. Enables `avahi-daemon` so `gateway.local` resolves on the AP

> **Change the AP passphrase and admin password immediately after the first login.**

---

## USB Wi-Fi adapter drivers

If your Raspberry Pi needs an external USB Wi-Fi adapter for `wlan0`, run the driver installer after the main setup:

```bash
sudo bash install-drivers.sh --auto   # detect plugged-in adapter and install
sudo bash install-drivers.sh          # interactive menu to pick manually
sudo bash install-drivers.sh --all    # install every supported driver
```

Supported chipsets:

| Chipset | Type | Example adapters |
|---------|------|-----------------|
| RTL8812AU / RTL8821AU | AC1200 / AC600 | Alfa AWUS036ACH, TP-Link Archer T4U / T2U |
| RTL8814AU | AC1900 | Alfa AWUS1900, ASUS USB-AC68 |
| RTL8188EUS | N150 | TP-Link TL-WN725N v3 |
| MT7610U / MT7612U | AC600 / AC1200 | Alfa AWUS036ACHM / AWUS036ACM |
| AR9271 | N150 | Alfa AWUS036NHA, TP-Link TL-WN722N v1 |
| MT7921U | AX1800 | Alfa AWUS036AXML, Panda PAU0F, BrosTrend AX9L |
| RTL8832BU | AX1800 | BrosTrend AX1L / AX4L (Model AX4) |

Out-of-tree drivers are installed via DKMS and survive kernel updates. In-kernel chipsets (MT7610U, MT7612U, AR9271, MT7921U) only require a firmware package — no compilation needed.

---

## Web UI

Connect any device to the `pi-nat64` Wi-Fi, then open:

```
http://gateway.local
```

or `http://192.168.50.1`. Default login password: `admin`.

| Tab | What you can do |
|-----|----------------|
| **Status** | Live NAT64 session count, AP client count, per-service health indicators |
| **Blocking** | Queries today, blocked today, block %, gravity size, top-10 blocked domains, toggle blocking, manage adlists, whitelist |
| **Clients** | View connected devices, signal strength, data usage, block/unblock individual clients |
| **Port Forwarding** | Add, enable/disable, and delete TCP/UDP DNAT rules |
| **Settings** | SSID, Wi-Fi channel, WPA2 passphrase, admin password |

---

## Services

| Service | Role | Listens on |
|---------|------|------------|
| `jool` | NAT64 packet translation | kernel netfilter |
| `pihole-FTL` | DNS sinkhole + ad blocking | `:53` on all interfaces |
| `unbound` | DNS64 recursive resolver | `127.0.0.1:5335` |
| `hostapd` | Wi-Fi access point | `wlan0` |
| `dnsmasq` | DHCP (DNS disabled) | `wlan0` |
| `radvd` | IPv6 router advertisements | `wlan0` |
| `pi-nat64-ui` | Flask management UI | `0.0.0.0:80` |
| `avahi-daemon` | mDNS (`gateway.local`) | all interfaces |

---

## File layout

```
pi-nat64/
├── install.sh                  ← one-shot installer, run as root
├── install-drivers.sh          ← optional USB Wi-Fi adapter driver installer
├── docs/
│   └── index.html              ← interactive UI demo (GitHub Pages)
├── configs/
│   ├── dns64.conf              ← Unbound DNS64 (127.0.0.1:5335)
│   ├── pihole-setupVars.conf   ← Pi-hole unattended install config
│   ├── hostapd.conf            ← Wi-Fi AP defaults
│   ├── dnsmasq.conf            ← DHCP for wlan0
│   ├── radvd.conf              ← IPv6 router advertisements
│   └── 99-pi-nat64.conf        ← sysctl IP forwarding settings
├── web/
│   ├── app.py                  ← Flask application
│   ├── requirements.txt
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/app.js
└── systemd/
    └── pi-nat64-ui.service
```

---

## Port forwarding

Rules are stored in `/etc/pi-nat64/port-rules.json` and applied as `ip6tables` DNAT rules. They survive reboots via `netfilter-persistent`.

---

## Useful commands

```bash
# NAT64 — show active translation sessions
jool session display --numeric

# Pi-hole — update blocklists (gravity)
pihole -g

# Pi-hole — live query log
pihole -t

# Pi-hole — today's stats summary
pihole -c

# DNS64 — test Unbound directly
dig @127.0.0.1 -p 5335 example.com AAAA

# DNS64 — end-to-end test via Pi-hole (from AP client)
dig @fd00::1 example.com AAAA
```

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Wi-Fi AP visible | `systemctl status hostapd` — verify `country_code` in `/etc/hostapd/hostapd.conf` |
| USB adapter not detected | `lsusb` — check adapter is listed; run `sudo bash install-drivers.sh --auto` |
| IPv4 sites unreachable | `jool session display` — sessions should appear; check `ip6tables -t nat -L` |
| Ads still showing | `pihole status` — should say `active`; run `pihole -g` to refresh blocklists |
| DNS not resolving | `dig @127.0.0.1 -p 5335 google.com AAAA` (Unbound); `dig @fd00::1 google.com AAAA` (Pi-hole) |
| Blocking tab shows `—` | `systemctl status pihole-FTL` — FTL socket `/run/pihole/FTL.sock` must exist |
| Web UI not loading | `journalctl -u pi-nat64-ui -f`; confirm nothing else occupies port 80 |
| `gateway.local` not resolving | `systemctl status avahi-daemon` |
| Pi-hole not starting after reboot | `journalctl -u pihole-FTL -f`; check `/etc/pihole/setupVars.conf` |

---

## Security

The installer applies the following hardening out of the box:

- **Firewall rules inserted at chain top** (`-I INPUT 1`) so they cannot be bypassed by pre-existing ACCEPT rules.
- **Web UI and DNS blocked on `eth0`** — TCP 80 and UDP 53 are dropped from the upstream interface.
- **CSRF tokens** on all state-changing API endpoints (`X-CSRF-Token` header, per-session).
- **Login rate limiting** — IP locked out for 60 s after 10 failed attempts.
- **Session cookies** are `HttpOnly` and `SameSite=Lax`.
- **Flask `SECRET_KEY`** stored in `/etc/pi-nat64/secret.env` (mode 600), loaded via systemd `EnvironmentFile=` — not visible in `systemctl cat`.
- **Admin password** stored as SHA-256 hash in `/etc/pi-nat64/admin.passwd` (mode 600).
- **WPA2 passphrase** validated to reject `#` (hostapd comment character) which would silently truncate the key.
- **Port-forwarding rules** are only saved to disk after the `ip6tables` command succeeds — no phantom rules on module-load failure.

> The web UI has no TLS. Keep it on the local AP segment and do not expose port 80 on `eth0` (the installer drops those packets automatically).
