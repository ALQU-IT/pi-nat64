#!/usr/bin/env bash
# =============================================================================
#  pi-nat64 — one-shot install script
#  Raspberry Pi 5 · Raspbian OS (bookworm/bullseye)
#  Run as root: sudo bash install.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run this script as root: sudo bash install.sh"

# ── Config — edit before running ─────────────────────────────────────────────
AP_SSID="pi-nat64"
AP_PASS="ChangeMe123"         # min 8 chars
AP_CHANNEL="6"
AP_IFACE="wlan0"
ETH_IFACE="eth0"
AP_IPV4="192.168.50.1"
AP_PREFIX="fd00::/64"
AP_GW_IPV6="fd00::1"
JOOL_PREFIX="64:ff9b::/96"
# Web UI admin password — randomly generated per install and shown once at the end.
# Override by exporting ADMIN_PASS first, e.g. ADMIN_PASS=secret sudo -E bash install.sh
ADMIN_PASS="${ADMIN_PASS:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14 || true)}"
INSTALL_DIR="/opt/pi-nat64"
SECRET_KEY=$(tr -dc 'A-Za-z0-9!@^&*' </dev/urandom | head -c 32 || true)

# Validate passphrase doesn't contain '#' (hostapd treats it as a comment character)
[[ "$AP_PASS" == *"#"* ]] && error "AP_PASS must not contain '#'"

echo ""
echo "  pi-nat64 installer"
echo "  ─────────────────────────────────────────────"
echo "  AP SSID   : $AP_SSID"
echo "  AP iface  : $AP_IFACE"
echo "  ETH iface : $ETH_IFACE"
echo "  NAT64 pfx : $JOOL_PREFIX"
echo "  Install to: $INSTALL_DIR"
echo ""
read -rp "  Continue? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ── 1. System update ──────────────────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

# ── 2. Install packages ───────────────────────────────────────────────────────
# Kernel headers first: Raspberry Pi OS ships none by default, and without them
# the jool-dkms module build fails silently and NAT64 never works.
info "Installing kernel headers for the Jool DKMS module..."
if ! apt-get install -y --no-install-recommends "linux-headers-$(uname -r)"; then
  warn "linux-headers-$(uname -r) unavailable — falling back to raspberrypi-kernel-headers"
  apt-get install -y --no-install-recommends raspberrypi-kernel-headers \
    || error "Could not install kernel headers — the Jool NAT64 module cannot be built."
fi

# NOTE: no '| grep ... || true' wrapper — that would mask apt failures under
# 'set -o pipefail' and report a broken install as success. Let set -e abort.
info "Installing packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  jool-tools \
  jool-dkms \
  unbound \
  hostapd \
  dnsmasq \
  radvd \
  iptables \
  netfilter-persistent \
  iptables-persistent \
  python3 \
  python3-pip \
  python3-flask \
  avahi-daemon \
  openssl \
  curl
ok "Packages installed."

# ── 3. Load Jool kernel module ────────────────────────────────────────────────
info "Loading Jool kernel module..."
modprobe jool || error "Failed to load the Jool kernel module — the jool-dkms build may have failed. Check: dkms status"
# Use /sys/module (no pipe) — 'lsmod | grep -q' can return SIGPIPE under pipefail
[[ -d /sys/module/jool ]] || error "Jool module is not loaded — NAT64 will not work."
grep -qxF 'jool' /etc/modules || echo 'jool' >> /etc/modules
ok "Jool module loaded."

# ── 4. Configure Jool (NAT64) ─────────────────────────────────────────────────
info "Configuring Jool NAT64..."
jool instance add "default" --netfilter --pool6 "$JOOL_PREFIX" 2>/dev/null || true

# Persist via rc.local
cat > /etc/rc.local <<EOF
#!/bin/bash
modprobe jool
jool instance add "default" --netfilter --pool6 $JOOL_PREFIX 2>/dev/null || true
exit 0
EOF
chmod +x /etc/rc.local
ok "Jool configured with prefix $JOOL_PREFIX"

# ── 5. Configure Unbound (DNS64) ──────────────────────────────────────────────
info "Configuring Unbound DNS64 (127.0.0.1:5335 — Pi-hole is the public resolver)..."

# Disable systemd-resolved BEFORE starting Unbound (frees port 53 / resolv.conf)
if systemctl is-active --quiet systemd-resolved; then
  warn "Disabling systemd-resolved (conflicts with Unbound/Pi-hole on port 53)..."
  systemctl disable --now systemd-resolved
  rm -f /etc/resolv.conf
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

mkdir -p /etc/unbound/unbound.conf.d

# Overwrite main config so Unbound ONLY loads our drop-in (no hidden :53 listener)
cat > /etc/unbound/unbound.conf <<'UBMAIN'
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
UBMAIN

cat > /etc/unbound/unbound.conf.d/dns64.conf <<EOF
server:
  interface: 127.0.0.1
  port: 5335
  access-control: 0.0.0.0/0 refuse
  access-control: ::/0 refuse
  access-control: 127.0.0.1/32 allow
  do-ip4: yes
  do-ip6: yes
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  # DNS64: the prefix is a server-clause option (there is no "dns64:" section)
  module-config: "dns64 iterator"
  dns64-prefix: $JOOL_PREFIX

forward-zone:
  name: "."
  forward-addr: 2606:4700:4700::1111
  forward-addr: 2606:4700:4700::1001
EOF

# Initialise DNSSEC root trust-anchor (required before first start on a fresh system)
mkdir -p /var/lib/unbound
unbound-anchor -a /var/lib/unbound/root.key || true
chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

systemctl enable unbound
systemctl restart unbound || { journalctl -u unbound -n 30 --no-pager; error "Unbound failed to start — see logs above."; }
ok "Unbound DNS64 configured on 127.0.0.1:5335."

# ── 5.5 Install Pi-hole (no web UI — stats shown in pi-nat64 UI) ──────────────
info "Installing Pi-hole..."

mkdir -p /etc/pihole
SCRIPT_DIR_TMP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sed "s/^PIHOLE_INTERFACE=.*/PIHOLE_INTERFACE=$AP_IFACE/" \
    "$SCRIPT_DIR_TMP/configs/pihole-setupVars.conf" > /etc/pihole/setupVars.conf

curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

# Pi-hole installer may restart dnsmasq; ensure dnsmasq stays DHCP-only
systemctl is-active --quiet dnsmasq && systemctl restart dnsmasq || true

# Pi-hole v6's FTL embeds its own web server on :80/:443 by default, which would
# collide with the pi-nat64 UI. We read stats straight from FTL's SQLite DBs, so
# move FTL's web server to a loopback-only high port to free 80/443 for the UI.
if command -v pihole-FTL >/dev/null 2>&1; then
  pihole-FTL --config webserver.port '127.0.0.1:8053' 2>/dev/null \
    || warn "Could not move FTL's web server port — watch for a port-80 clash with the UI."
  systemctl restart pihole-FTL 2>/dev/null || true
fi

ok "Pi-hole installed."

# ── 6. Configure hostapd ──────────────────────────────────────────────────────
info "Configuring hostapd access point..."
cat > /etc/hostapd/hostapd.conf <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
ieee80211n=1
wmm_enabled=1
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
country_code=DE
EOF

# Uncomment DAEMON_CONF in /etc/default/hostapd
sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# Give wlan0 a static IPv4 + IPv6 address
ip addr add "$AP_IPV4/24" dev "$AP_IFACE" 2>/dev/null || true
ip addr add "$AP_GW_IPV6/64" dev "$AP_IFACE" 2>/dev/null || true

# Persist via /etc/network/interfaces.d/
cat > /etc/network/interfaces.d/wlan0 <<EOF
auto $AP_IFACE
iface $AP_IFACE inet static
  address $AP_IPV4
  netmask 255.255.255.0

iface $AP_IFACE inet6 static
  address $AP_GW_IPV6
  netmask 64
EOF

systemctl unmask hostapd
systemctl enable --now hostapd
ok "hostapd access point configured (SSID: $AP_SSID)."

# ── 7. Configure dnsmasq (DHCP) ───────────────────────────────────────────────
info "Configuring dnsmasq DHCP..."

# Disable dnsmasq's own DNS (Unbound handles it)
cat > /etc/dnsmasq.d/pi-nat64.conf <<EOF
interface=$AP_IFACE
bind-interfaces
port=0
dhcp-range=192.168.50.10,192.168.50.200,255.255.255.0,24h
dhcp-range=::10,::ff,constructor:$AP_IFACE,ra-stateless,64,24h
dhcp-option=option:dns-server,$AP_IPV4
dhcp-option=option6:dns-server,[$AP_GW_IPV6]
address=/gateway.local/$AP_IPV4
address=/gateway.local/$AP_GW_IPV6
EOF

systemctl enable --now dnsmasq
ok "dnsmasq DHCP configured."

# ── 8. Configure radvd ────────────────────────────────────────────────────────
info "Configuring radvd (IPv6 RA)..."
cat > /etc/radvd.conf <<EOF
interface $AP_IFACE {
    AdvSendAdvert on;
    AdvManagedFlag off;
    AdvOtherConfigFlag on;

    prefix fd00::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };

    RDNSS $AP_GW_IPV6 {
        AdvRDNSSLifetime 3600;
    };
};
EOF

systemctl enable --now radvd
ok "radvd configured."

# ── 9. Kernel forwarding + iptables ──────────────────────────────────────────
info "Enabling IP forwarding and NAT rules..."

cat > /etc/sysctl.d/99-pi-nat64.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.$ETH_IFACE.accept_ra = 2
net.ipv6.conf.$AP_IFACE.accept_ra = 0
EOF
sysctl --system -q

# IPv6 forwarding rules
ip6tables -t nat -F POSTROUTING 2>/dev/null || true
ip6tables -t nat -A POSTROUTING -o "$ETH_IFACE" -j MASQUERADE

# IPv4 fallback masquerade (for devices that fall back)
iptables -t nat -A POSTROUTING -o "$ETH_IFACE" -j MASQUERADE

# Block web UI (ports 80 + 443) from the internet-facing eth0
# Use -I to insert at the top so pre-existing ACCEPT rules don't bypass the block
for _port in 80 443; do
  iptables  -I INPUT 1 -i "$ETH_IFACE" -p tcp --dport "$_port" -j DROP
  ip6tables -I INPUT 1 -i "$ETH_IFACE" -p tcp --dport "$_port" -j DROP
done

# Block external access to DNS (Unbound) from eth0
iptables  -I INPUT 1 -i "$ETH_IFACE" -p udp --dport 53 -j DROP
ip6tables -I INPUT 1 -i "$ETH_IFACE" -p udp --dport 53 -j DROP

# Save rules
netfilter-persistent save
ok "Forwarding and NAT rules applied."

# ── 10. Deploy web UI ────────────────────────────────────────────────────────
info "Deploying web UI to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR/web" "$INSTALL_DIR/"
mkdir -p /etc/pi-nat64

# Generate a self-signed TLS certificate so the UI can serve HTTPS (the admin
# password and session cookie must not cross the Wi-Fi in cleartext).
info "Generating self-signed TLS certificate..."
mkdir -p /etc/pi-nat64/tls
if [[ ! -f /etc/pi-nat64/tls/cert.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/pi-nat64/tls/key.pem \
    -out    /etc/pi-nat64/tls/cert.pem \
    -days 3650 \
    -subj "/CN=gateway.local" \
    -addext "subjectAltName=DNS:gateway.local,IP:${AP_IPV4},IP:${AP_GW_IPV6}" \
    || error "Failed to generate TLS certificate (is openssl installed?)"
fi
chmod 600 /etc/pi-nat64/tls/key.pem
chmod 644 /etc/pi-nat64/tls/cert.pem

# Store SECRET_KEY + TLS paths in a root-only file; the unit's EnvironmentFile reads it
cat > /etc/pi-nat64/secret.env <<EOF
SECRET_KEY=$SECRET_KEY
TLS_CERT=/etc/pi-nat64/tls/cert.pem
TLS_KEY=/etc/pi-nat64/tls/key.pem
EOF
chmod 600 /etc/pi-nat64/secret.env

# Store admin password as a salted scrypt hash (matches web/app.py format; never plaintext)
ADMIN_PASS_HASH=$(python3 - "$ADMIN_PASS" <<'PY'
import hashlib, os, sys
salt = os.urandom(16)
key = hashlib.scrypt(sys.argv[1].encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
print(f"scrypt${salt.hex()}${key.hex()}")
PY
)
echo "$ADMIN_PASS_HASH" > /etc/pi-nat64/admin.passwd
chmod 600 /etc/pi-nat64/admin.passwd

# Install Python deps
pip3 install flask --break-system-packages -q

# Install systemd service
cat > /etc/systemd/system/pi-nat64-ui.service <<EOF
[Unit]
Description=pi-nat64 Web UI
After=network.target hostapd.service unbound.service pihole-FTL.service
Wants=pihole-FTL.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/web
EnvironmentFile=/etc/pi-nat64/secret.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/web/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Lock down install dir — no world read
chmod 750 "$INSTALL_DIR/web"
chmod 640 "$INSTALL_DIR/web/app.py"

systemctl daemon-reload
systemctl enable --now pi-nat64-ui
ok "Web UI deployed and started."

# ── 11. Avahi (mDNS for gateway.local) ───────────────────────────────────────
info "Enabling mDNS (gateway.local)..."
systemctl enable --now avahi-daemon
ok "gateway.local will be resolvable on the AP network."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "  ════════════════════════════════════════════"
echo -e "  ${GREEN}Installation complete!${NC}"
echo "  ════════════════════════════════════════════"
echo ""
echo "  Wi-Fi AP  : $AP_SSID  (pass: $AP_PASS)"
echo "  Web UI    : https://gateway.local  or  https://$AP_IPV4"
echo "              (self-signed cert — your browser will warn once; that's expected)"
echo -e "  ${YELLOW}Admin password (randomly generated — save it now): ${ADMIN_PASS}${NC}"
echo "  This password is shown ONLY here. Change it anytime in Settings."
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "  1. Connect a device to the '$AP_SSID' Wi-Fi"
echo "  2. Open https://gateway.local in a browser"
echo "  3. Change the admin password in Settings"
echo "  4. Change the AP passphrase in Settings"
echo "  5. Add port-forwarding rules as needed"
echo ""
echo -e "  ${YELLOW}Using a USB Wi-Fi adapter? Install drivers:${NC}"
echo "    sudo bash install-drivers.sh --auto"
echo "    (RTL8812AU, RTL8814AU, RTL8188EUS, MT7610U/7612U,"
echo "     AR9271, MT7921U, RTL8832BU — includes BrosTrend AX4)"
echo ""
echo "  Logs:"
echo "    journalctl -u pi-nat64-ui -f"
echo "    journalctl -u hostapd -f"
echo "    journalctl -u unbound -f"
echo "    journalctl -u pihole-FTL -f"
echo ""
