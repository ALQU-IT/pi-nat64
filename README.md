# Pi Gateway

NAT64/DNS64 gateway + Wi-Fi access point + web management UI for Raspberry Pi 5.

Lets devices on an IPv6-only connection reach IPv4-only services transparently.

---

## What it does

```
Internet (IPv6 only)
       │
    eth0 (Pi 5)
       │
   ┌───┴────────────────────┐
   │  Jool  — NAT64         │  translates IPv6 ↔ IPv4 packets
   │  Unbound — DNS64       │  synthesises AAAA records for IPv4 hosts
   │  hostapd — AP          │  wlan0 Wi-Fi access point
   │  Flask — web UI        │  manage everything via browser
   └───┬────────────────────┘
       │
    wlan0 (fd00::/64)
       │
   Your devices (phone, laptop, …)
```

---

## Requirements

- Raspberry Pi 5 running Raspbian OS (bookworm recommended)
- `eth0` connected to your IPv6-only ISP
- `wlan0` available for the access point
- Root access

---

## Quick install

```bash
git clone https://github.com/ALQU-IT/Pi-Gateway.git
cd pi-gateway
sudo chmod +x install.sh
sudo bash install.sh
```

The script will:

1. Install all dependencies (`jool-tools`, `unbound`, `hostapd`, `dnsmasq`, `radvd`, `flask`, …)
2. Configure Jool NAT64 with prefix `64:ff9b::/96`
3. Configure Unbound DNS64
4. Set up the Wi-Fi access point (`Pi-Gateway` / `ChangeMe123`)
5. Enable DHCP + IPv6 RAs for connected clients
6. Apply forwarding rules and persist them via `netfilter-persistent`
7. Deploy and start the Flask web UI as a systemd service
8. Enable `avahi-daemon` so `gateway.local` resolves on the AP

---

## Web UI

After installation, connect any device to the `Pi-Gateway` Wi-Fi and open:

```
http://gateway.local
```

or

```
http://192.168.50.1
```

Default password: `admin` — **change it immediately in Settings**.

### Features

| Tab | What you can do |
|-----|----------------|
| Status | Live NAT64 session count, DNS query count, AP clients, service health |
| Port Forwarding | Add / toggle / delete TCP or UDP port-forward rules |
| Settings | Change SSID, channel, WPA2 passphrase, admin password |

---

## File layout

```
pi-gateway/
├── install.sh              ← run this first
├── configs/
│   ├── hostapd.conf        ← AP config (copied to /etc/hostapd/)
│   ├── dns64.conf          ← Unbound DNS64 (copied to /etc/unbound/…)
│   ├── dnsmasq.conf        ← DHCP for wlan0 (copied to /etc/dnsmasq.d/)
│   ├── radvd.conf          ← IPv6 router advertisements
│   └── 99-pi-gateway.conf  ← sysctl forwarding settings
├── web/
│   ├── app.py              ← Flask application
│   ├── requirements.txt
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/app.js
└── systemd/
    └── pi-gateway-ui.service
```

---

## Port forwarding

Rules are written to `/etc/pi-gateway/port-rules.json` and applied as `ip6tables` DNAT rules:

```
ip6tables -t nat -A PREROUTING -p tcp --dport <ext> -j DNAT --to-destination [<dest_ip>]:<dest_port>
```

Rules survive reboots via `netfilter-persistent`.

---

## Manual Jool commands

```bash
# Show active sessions
jool session display --numeric

# Show current config
jool global display

# Reload prefix
jool instance flush
jool instance add default --netfilter --pool6 64:ff9b::/96
```

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Wi-Fi AP visible | `systemctl status hostapd` — check country code in hostapd.conf |
| IPv4 sites unreachable | `jool session display` — sessions should appear; check `ip6tables -t nat -L` |
| DNS not working | `systemctl status unbound`; test with `dig @fd00::1 google.com AAAA` |
| Web UI not loading | `journalctl -u pi-gateway-ui -f`; check port 80 is free |
| gateway.local not resolving | `systemctl status avahi-daemon` |

---

## Security notes

- The web UI runs on port 80 with no TLS. Use it only on your local AP network.
- The admin password is stored in plaintext at `/etc/pi-gateway/admin.passwd`. Change it promptly.
- Port-forwarding rules expose internal services — only add rules you need.
- Consider adding a firewall rule to block web UI access from `eth0`:
  ```bash
  ip6tables -A INPUT -i eth0 -p tcp --dport 80 -j DROP
  iptables  -A INPUT -i eth0 -p tcp --dport 80 -j DROP
  ```
