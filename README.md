# pi-nat64

**[Live UI Demo →](https://alqu-it.github.io/pi-nat64/)**

NAT64/DNS64 gateway + network-wide ad blocking + Wi-Fi access point, with a browser-based management UI. Built for Raspberry Pi 5.

Lets **IPv6-only devices** reach IPv4-only services transparently, while blocking ads and trackers for every device on the network.

---

## How it works

```
Internet  (dual-stack uplink: IPv4 + IPv6)
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
    wlan0   (fd00::/64, 192.168.50.0/24)
       │
   Your devices  (phone, laptop, …)
```

**DNS query path:**

```
Device  →  Pi-hole :53  ──── blocked? ──→  NXDOMAIN  (ad/tracker dropped)
                │
                └── not blocked  →  Unbound :5335  →  Internet
                                        (DNSSEC validation + DNS64 synthesis)
```

---

## Requirements

- Raspberry Pi 5 running Raspberry Pi OS (bookworm or trixie)
- `eth0` connected to a **dual-stack** uplink. NAT64 turns the Wi-Fi clients' IPv6 traffic into **IPv4**, so the uplink must have IPv4. IPv6 on the uplink is optional: the AP network uses its own IPv6 prefix, which is NATed.
- `wlan0` available for the access point (onboard Wi-Fi or a USB adapter)
- Root access (`sudo`)

No Wi-Fi hardware (e.g. testing in a VM)? The installer detects that and skips the access point. NAT64, DNS64, Pi-hole and the web UI are still installed.

---

## Install

```bash
git clone https://github.com/ALQU-IT/pi-nat64.git
cd pi-nat64
sudo bash install.sh          # add -y to skip the confirmation prompt
```

The installer handles everything:

1. Installs packages: `jool-tools`/`jool-dkms`, `unbound`, `hostapd`, `dnsmasq`, `radvd`, `python3-flask`, `avahi`
2. Builds and loads the Jool NAT64 module and configures prefix `64:ff9b::/96`. On kernel 6.15+/6.18+ it automatically applies the upstream compatibility patches (see `fix-jool.sh`).
3. Configures Unbound DNS64 on `127.0.0.1:5335` (loopback only, DNSSEC-validating)
4. Installs Pi-hole unattended and points it at Unbound. Pi-hole's own web UI is kept off ports 80/443; its stats are shown in the pi-nat64 UI.
5. Configures the Wi-Fi AP (`pi-nat64` SSID, `ChangeMe123` passphrase) and keeps NetworkManager from interfering with `wlan0`
6. Sets up DHCPv4 (dnsmasq) and IPv6 router advertisements with DNS (radvd) on `wlan0`
7. Applies and persists firewall rules via `netfilter-persistent`
8. Deploys the web UI as a systemd service over HTTPS (port 443, self-signed cert; port 80 redirects to HTTPS)
9. Publishes `gateway.local` via mDNS and Pi-hole

> **Change the Wi-Fi passphrase and the admin password right after the first login.**

Re-running `install.sh` is safe. It keeps your admin password, session secret, Wi-Fi settings, port-forwards and blocked clients.

---

## Updating

When a newer version is available on GitHub, an **Update available** button appears in the web UI's sidebar. Clicking it pulls the latest code and re-applies it (`update.sh` → `install.sh --upgrade`), then the page reloads. The update keeps all your settings. Progress and errors are logged to `/var/log/pi-nat64-update.log`.

The same from a shell:

```bash
sudo bash ~/pi-nat64/update.sh
```

The Update button needs the git checkout you installed from to stay in place. If you delete it, re-clone and run `install.sh` once.

---

## USB Wi-Fi adapter drivers

If your Raspberry Pi needs an external USB Wi-Fi adapter for `wlan0`, run the driver installer, then re-run `install.sh` so the access point is set up on it:

```bash
sudo bash install-drivers.sh --auto   # detect plugged-in adapter and install
sudo bash install-drivers.sh          # interactive menu to pick manually
sudo bash install-drivers.sh --all    # install every supported driver
```

Supported chipsets:

| Chipset | Type | Example adapters | Driver on current kernels |
|---------|------|------------------|---------------------------|
| RTL8812AU | AC1200 | Alfa AWUS036ACH, TP-Link Archer T4U | in-kernel `rtw88_8812au` (6.13+) |
| RTL8821AU | AC600 | TP-Link Archer T2U / T2U Nano | in-kernel `rtw88_8821au` (6.13+) |
| RTL8814AU | AC1900 | Alfa AWUS1900, ASUS USB-AC68 | in-kernel `rtw88_8814au` (6.16+) |
| RTL8188EU(S) | N150 | TP-Link TL-WN725N v2/v3 | in-kernel `rtl8xxxu` |
| RTL8832BU / RTL8852BU | AX1800 | BrosTrend AX1L / AX4L (Model AX4) | in-kernel `rtw89_8852bu` (6.17+) |
| MT7610U / MT7612U | AC600 / AC1200 | Alfa AWUS036ACHM / AWUS036ACM | in-kernel `mt76` |
| MT7921U | AX1800 | Alfa AWUS036AXML, Panda PAU0F, BrosTrend AX9L | in-kernel `mt7921u` |
| AR9271 | N150 | Alfa AWUS036NHA, TP-Link TL-WN722N v1 | in-kernel `ath9k_htc` |

On a current Raspberry Pi OS kernel every chipset has an in-kernel driver, so the script only installs **firmware**. For Realtek chips on an older kernel that lacks the in-kernel driver, it builds the out-of-tree DKMS driver instead.

---

## Web UI

Connect any device to the `pi-nat64` Wi-Fi, then open:

```
https://gateway.local
```

or `https://192.168.50.1`. The UI is served over HTTPS with a self-signed certificate, so your browser shows a one-time warning. That's expected on a local device. Plain `http://` is redirected to `https://`.

The installer generates a **random admin password and prints it once** at the end of the first install. Save it. You can change it anytime in Settings (enter the current password; other sessions are signed out).

Forgot it? On the gateway:

```bash
sudo python3 /opt/pi-nat64/web/app.py --set-password
```

| Tab | What you can do |
|-----|----------------|
| **Status** | Live NAT64 session count, DNS queries today, AP client count, per-service health |
| **Blocking** | Queries today, blocked today, block %, gravity size, top-10 blocked domains, toggle blocking, manage adlists, allowlist |
| **Clients** | Connected devices, signal strength, data usage, block/unblock individual clients |
| **Port Forwarding** | Add, enable/disable, and delete TCP/UDP forwards from the uplink to an IPv6 host on the AP |
| **Settings** | SSID, Wi-Fi channel, WPA2 passphrase, admin password |

---

## Services

| Service | Role | Listens on |
|---------|------|------------|
| `pi-nat64-jool` | Creates the Jool NAT64 instance at boot | kernel netfilter |
| `pihole-FTL` | DNS sinkhole + ad blocking | `:53` (local networks); its web server on `127.0.0.1:8053` |
| `unbound` | DNS64 recursive resolver | `127.0.0.1:5335` |
| `hostapd` | Wi-Fi access point | `wlan0` |
| `dnsmasq` | DHCPv4 only (DNS disabled) | `wlan0` |
| `radvd` | IPv6 router advertisements + DNS (RDNSS) | `wlan0` |
| `pi-nat64-ap-addr` | Assigns `192.168.50.1` / `fd00::1` to `wlan0` at boot | — |
| `pi-nat64-ui` | Flask management UI | `0.0.0.0:443` (HTTPS; `:80` redirects) |
| `pi-nat64-mdns` | Publishes `gateway.local` via avahi | mDNS |

---

## File layout

```
pi-nat64/
├── install.sh                  ← installer / upgrader, run as root
├── update.sh                   ← pull the latest version and re-apply it
├── install-drivers.sh          ← optional USB Wi-Fi adapter driver/firmware installer
├── fix-jool.sh                 ← patch + rebuild Jool NAT64 for kernel 6.15+/6.18+
├── docs/
│   └── index.html              ← interactive UI demo (GitHub Pages)
├── configs/                    ← reference copies of what install.sh writes
│   ├── dns64.conf              ← Unbound DNS64 (127.0.0.1:5335)
│   ├── pihole-setupVars.conf   ← Pi-hole unattended install config (used by install.sh)
│   ├── hostapd.conf            ← Wi-Fi AP defaults
│   ├── dnsmasq.conf            ← DHCPv4 for wlan0
│   ├── radvd.conf              ← IPv6 router advertisements
│   └── 99-pi-nat64.conf        ← sysctl forwarding settings
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
    └── pi-nat64-ui.service     ← reference copy
```

---

## Port forwarding

Rules are stored in `/etc/pi-nat64/port-rules.json` and applied as `ip6tables` DNAT rules for traffic **arriving on `eth0`** (outbound connections of your own devices are never redirected). Ports the gateway itself uses (22, 53, 80, 443, 5335, 8053) can't be forwarded. Rules survive reboots via `netfilter-persistent` and are re-checked when the UI starts.

---

## Useful commands

```bash
# NAT64 — show active translation sessions
jool session display --numeric --tcp     # also --udp / --icmp

# Pi-hole — update blocklists (gravity)
pihole -g

# Pi-hole — live query log
pihole -t

# Pi-hole — current configuration (v6)
pihole-FTL --config dns.upstreams

# DNS64 — test Unbound directly (IPv4-only name → synthesised 64:ff9b:: address)
dig @127.0.0.1 -p 5335 ipv4only.arpa AAAA +short

# DNS64 — end-to-end test via Pi-hole (from an AP client)
dig @fd00::1 ipv4only.arpa AAAA +short
```

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Wi-Fi AP visible | `systemctl status hostapd`, `rfkill list`, and `country_code` in `/etc/hostapd/hostapd.conf` |
| AP clients get no IP address | `systemctl status pi-nat64-ap-addr dnsmasq`; `ip addr show wlan0` should list `192.168.50.1` and `fd00::1` |
| USB adapter not detected | `lsusb` should list the adapter; run `sudo bash install-drivers.sh --auto`, then re-run `install.sh` |
| IPv4 sites unreachable from IPv6-only clients | `jool instance display` and `jool session display --tcp`; `systemctl status pi-nat64-jool` |
| Jool fails to build on kernel 6.15+/6.18+ | `sudo bash fix-jool.sh` applies the upstream kernel-compat patches ([PR #441](https://github.com/NICMx/Jool/pull/441) and the `timer_delete_sync` fix) and rebuilds the DKMS module |
| Ads still showing | `pihole status` should say blocking is enabled; run `pihole -g` to refresh blocklists |
| DNS not resolving | `dig @127.0.0.1 -p 5335 google.com AAAA` (Unbound); `dig @fd00::1 google.com AAAA` (Pi-hole) |
| Blocking tab shows `—` or `0` | Stats are read from `/etc/pihole/pihole-FTL.db` and `/etc/pihole/gravity.db`; confirm `systemctl status pihole-FTL` is active |
| Web UI not loading | `journalctl -u pi-nat64-ui -f`; confirm nothing else occupies ports 443/80 (`ss -ltnp`) |
| `gateway.local` not resolving | `systemctl status pi-nat64-mdns avahi-daemon`, or use `https://192.168.50.1` |
| Pi-hole not starting after reboot | `journalctl -u pihole-FTL -f`; v6 settings live in `/etc/pihole/pihole.toml` |
| Update button fails | `/var/log/pi-nat64-update.log`; local changes in the checkout block the fast-forward |

---

## Security

The installer applies the following hardening out of the box:

- **Uplink firewall.** DNS (TCP and UDP 53) and NTP (UDP 123) are dropped on `eth0`. When an AP exists, the web UI (TCP 80/443) is dropped on `eth0` too, and hosts on the uplink segment can't route into the AP network (only replies and your port-forwards pass). Rules are added idempotently at the top of their chains.
- **Client blocking** drops a device's packets before NAT64 translation (raw/PREROUTING), so NAT64 traffic is blocked too. Blocked devices are also refused by hostapd's deny list.
- **CSRF tokens** on all state-changing API endpoints (`X-CSRF-Token` header, per-session).
- **Login rate limiting.** 10 failed attempts lock a source (an IPv6 /64 or an IPv4 address) out for 60 s. There's also a global cap across all sources.
- **Session cookies** are `HttpOnly`, `SameSite=Lax` and `Secure`. Changing the admin password (which requires the current one) signs out all other sessions.
- **Flask `SECRET_KEY`** is stored in `/etc/pi-nat64/secret.env` (mode 600) and loaded via systemd `EnvironmentFile=`, so it's not visible in `systemctl cat`.
- **Admin password** is stored as a salted **scrypt** hash in `/etc/pi-nat64/admin.passwd` (mode 600). It's randomly generated per install; there's no shipped default. Legacy SHA-256 hashes are upgraded automatically on the next login.
- **Wi-Fi settings** are validated before anything is applied. hostapd is only restarted when an AP setting changed, and the previous config is restored if hostapd rejects the new one. `hostapd.conf` is mode 600.
- **HTTPS with a self-signed certificate.** The admin password and session cookie are never sent in cleartext. HSTS is enabled; port 80 only issues a redirect to HTTPS. The TLS handshake runs per connection with a timeout, so a stalled client can't block the UI.
