#!/usr/bin/env bash
# =============================================================================
#  pi-gateway — one-shot install script
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
AP_SSID="Pi-Gateway"
AP_PASS="ChangeMe123"         # min 8 chars
AP_CHANNEL="6"
AP_IFACE="wlan0"
ETH_IFACE="eth0"
AP_IPV4="192.168.50.1"
AP_PREFIX="fd00::/64"
AP_GW_IPV6="fd00::1"
JOOL_PREFIX="64:ff9b::/96"
ADMIN_PASS="admin"            # web UI password — change after first login
INSTALL_DIR="/opt/pi-gateway"
SECRET_KEY=$(tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c 32 || true)

echo ""
echo "  Pi Gateway installer"
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
info "Installing packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  jool-tools \
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
  curl \
  2>&1 | grep -E "^(Get|Unpacking|Setting up|E:)" || true
ok "Packages installed."

# ── 3. Load Jool kernel module ────────────────────────────────────────────────
info "Loading Jool kernel module..."
modprobe jool || warn "jool modprobe failed — module may not be available. Check: sudo apt install linux-headers-$(uname -r)"
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
info "Configuring Unbound DNS64..."
mkdir -p /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/dns64.conf <<EOF
server:
  interface: 0.0.0.0
  interface: ::0
  port: 53
  access-control: 127.0.0.0/8 allow
  access-control: ::1/128 allow
  access-control: 10.0.0.0/8 allow
  access-control: 192.168.0.0/16 allow
  access-control: 172.16.0.0/12 allow
  access-control: fd00::/8 allow
  do-ip6: yes
  do-ip4: yes
  module-config: "dns64 iterator"

dns64:
  prefix: $JOOL_PREFIX

forward-zone:
  name: "."
  forward-addr: 2606:4700:4700::1111
  forward-addr: 2606:4700:4700::1001
EOF

# Disable systemd-resolved conflict if active
if systemctl is-active --quiet systemd-resolved; then
  warn "Disabling systemd-resolved (conflicts with Unbound on port 53)..."
  systemctl disable --now systemd-resolved
  rm -f /etc/resolv.conf
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

systemctl enable --now unbound
ok "Unbound DNS64 configured."

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
cat > /etc/dnsmasq.d/pi-gateway.conf <<EOF
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

cat > /etc/sysctl.d/99-pi-gateway.conf <<EOF
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

# Block web UI (port 80) from the internet-facing eth0
iptables  -A INPUT -i "$ETH_IFACE" -p tcp --dport 80 -j DROP
ip6tables -A INPUT -i "$ETH_IFACE" -p tcp --dport 80 -j DROP

# Block external access to DNS (Unbound) from eth0
iptables  -A INPUT -i "$ETH_IFACE" -p udp --dport 53 -j DROP
ip6tables -A INPUT -i "$ETH_IFACE" -p udp --dport 53 -j DROP

# Save rules
netfilter-persistent save
ok "Forwarding and NAT rules applied."

# ── 10. Deploy web UI ────────────────────────────────────────────────────────
info "Deploying web UI to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR/web" "$INSTALL_DIR/"
mkdir -p /etc/pi-gateway

# Store admin password as SHA-256 hash (never store plaintext)
ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')
echo "$ADMIN_PASS_HASH" > /etc/pi-gateway/admin.passwd
chmod 600 /etc/pi-gateway/admin.passwd

# Install Python deps
pip3 install flask --break-system-packages -q

# Install systemd service
cat > /etc/systemd/system/pi-gateway-ui.service <<EOF
[Unit]
Description=Pi Gateway Web UI
After=network.target hostapd.service unbound.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/web
Environment=SECRET_KEY=$SECRET_KEY
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
systemctl enable --now pi-gateway-ui
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
echo "  Web UI    : http://gateway.local  or  http://$AP_IPV4"
echo "  Login     : password = $ADMIN_PASS"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "  1. Connect a device to the '$AP_SSID' Wi-Fi"
echo "  2. Open http://gateway.local in a browser"
echo "  3. Change the admin password in Settings"
echo "  4. Change the AP passphrase in Settings"
echo "  5. Add port-forwarding rules as needed"
echo ""
echo "  Logs:"
echo "    journalctl -u pi-gateway-ui -f"
echo "    journalctl -u hostapd -f"
echo "    journalctl -u unbound -f"
echo ""
