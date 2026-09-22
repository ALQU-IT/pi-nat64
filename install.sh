#!/usr/bin/env bash
# =============================================================================
#  pi-nat64 — one-shot install script
#  Raspberry Pi 5 · Raspberry Pi OS (bookworm / trixie)
#  Run as root: sudo bash install.sh [-y] [--upgrade]
#
#    -y, --yes    don't ask for confirmation
#    --upgrade    re-apply this version to an existing install, non-interactively.
#                 Keeps the admin password, session secret, Wi-Fi settings,
#                 port-forwards and blocked clients (used by update.sh / the
#                 web UI's Update button). Safe to run repeatedly.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run this script as root: sudo bash install.sh"

ASSUME_YES=false
UPGRADE=false
for arg in "$@"; do
  case "$arg" in
    -y|--yes)  ASSUME_YES=true ;;
    --upgrade) UPGRADE=true; ASSUME_YES=true ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *)         error "Unknown option: $arg (see --help)" ;;
  esac
done

# ── Config — edit before running ─────────────────────────────────────────────
AP_SSID="pi-nat64"
AP_PASS="ChangeMe123"         # min 8 chars — change it in the web UI afterwards
AP_CHANNEL="6"
AP_COUNTRY="DE"
AP_IFACE="wlan0"
ETH_IFACE="eth0"
AP_IPV4="192.168.50.1"
AP_DHCP_START="192.168.50.10"
AP_DHCP_END="192.168.50.200"
AP_PREFIX="fd00::/64"
AP_GW_IPV6="fd00::1"
JOOL_PREFIX="64:ff9b::/96"
INSTALL_DIR="/opt/pi-nat64"
CONF_DIR="/etc/pi-nat64"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Web UI admin password — randomly generated on first install and shown once.
# Override by exporting ADMIN_PASS first, e.g. ADMIN_PASS=secret sudo -E bash install.sh
ADMIN_PASS_ENV="${ADMIN_PASS:-}"

# Wait for the dpkg lock (unattended-upgrades often holds it right after boot)
APT=(apt-get -o DPkg::Lock::Timeout=300)
export DEBIAN_FRONTEND=noninteractive

# Validate passphrase doesn't contain '#' (hostapd treats it as a comment character)
[[ "$AP_PASS" == *"#"* ]] && error "AP_PASS must not contain '#'"

echo ""
echo "  pi-nat64 installer$($UPGRADE && echo ' (upgrade)')"
echo "  ─────────────────────────────────────────────"
echo "  AP SSID   : $AP_SSID"
echo "  AP iface  : $AP_IFACE"
echo "  ETH iface : $ETH_IFACE"
echo "  NAT64 pfx : $JOOL_PREFIX"
echo "  Install to: $INSTALL_DIR"
echo ""
if ! $ASSUME_YES; then
  [[ -t 0 ]] || error "No terminal to ask for confirmation — re-run with -y"
  read -rp "  Continue? [y/N] " confirm || confirm=""
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# Detect whether the Wi-Fi AP interface exists. In a VM (or on a board with no
# Wi-Fi radio / no USB adapter plugged in) it won't — so the access-point steps
# (hostapd, DHCP, router advertisements) are skipped and only the NAT64 / DNS64 /
# Pi-hole / web-UI stack is configured.
if ip link show "$AP_IFACE" >/dev/null 2>&1; then
  HAS_AP_IFACE=true
else
  HAS_AP_IFACE=false
  warn "Wi-Fi interface '$AP_IFACE' not found — the access point (hostapd, DHCP,"
  warn "router advertisements) will be SKIPPED. NAT64, DNS64, Pi-hole and the web"
  warn "UI are still installed. Add Wi-Fi hardware (or pass a USB adapter into the"
  warn "VM) and re-run to enable the AP."
fi

# Is jool-dkms installed but left half-configured (failed module build)?
jool_dkms_broken() {
  local st
  st=$(dpkg-query -W -f='${db:Status-Abbrev}' jool-dkms 2>/dev/null || true)
  [[ -n "$st" && "$st" != "ii "* && "$st" != "un "* && "$st" != "rc "* ]]
}

# Try the bundled Jool patch/rebuild helper (kernel 6.15+/6.18+ support)
run_jool_fix() {
  if [[ -f "$SCRIPT_DIR/fix-jool.sh" ]] && ls -d /usr/src/jool-* >/dev/null 2>&1; then
    warn "Attempting automatic Jool fix (upstream kernel-compat patches + rebuild)..."
    bash "$SCRIPT_DIR/fix-jool.sh" --no-config || warn "Automatic Jool fix failed."
  fi
}

# ── 0. Heal a dpkg state broken by a previous failed run ──────────────────────
# A failed jool-dkms build leaves dpkg half-configured; every apt call (ours AND
# Pi-hole's installer) then re-attempts the failing configure and aborts.
if ! dpkg --configure -a >/dev/null 2>&1; then
  warn "dpkg is in a broken state (likely a failed jool-dkms build from a previous run)."
  run_jool_fix
  if ! dpkg --configure -a >/dev/null 2>&1; then
    warn "Still broken — removing jool-dkms to unblock apt (retry NAT64 later with fix-jool.sh)."
    dpkg --remove --force-remove-reinstreq jool-dkms 2>/dev/null || true
    dpkg --configure -a || true
  fi
fi

# ── 1. System update ──────────────────────────────────────────────────────────
info "Updating package lists..."
"${APT[@]}" update -qq

# ── 2. Install packages ───────────────────────────────────────────────────────
# Kernel headers: needed to build the Jool module. Not fatal — without them only
# NAT64 is unavailable (e.g. rpi-update kernels have no headers package).
info "Installing kernel headers for the Jool DKMS module..."
HEADERS_OK=true
if ! "${APT[@]}" install -y --no-install-recommends "linux-headers-$(uname -r)"; then
  warn "linux-headers-$(uname -r) unavailable — trying the Raspberry Pi meta package"
  case "$(uname -r)" in
    *2712*) HDR_PKG=linux-headers-rpi-2712 ;;
    *v8*)   HDR_PKG=linux-headers-rpi-v8 ;;
    *)      HDR_PKG=raspberrypi-kernel-headers ;;
  esac
  "${APT[@]}" install -y --no-install-recommends "$HDR_PKG" || HEADERS_OK=false
fi
[[ -d "/lib/modules/$(uname -r)/build" ]] || HEADERS_OK=false
$HEADERS_OK || warn "No kernel headers for $(uname -r) — the Jool NAT64 module can't be built."

# Core packages — fatal on failure (no '| grep ... || true' wrapper, which would
# mask apt errors under pipefail and report a broken install as success).
info "Installing packages..."
"${APT[@]}" install -y \
  unbound \
  hostapd \
  dnsmasq \
  radvd \
  iptables \
  netfilter-persistent \
  iptables-persistent \
  python3 \
  python3-flask \
  avahi-daemon \
  avahi-utils \
  rfkill \
  iw \
  git \
  openssl \
  curl
ok "Packages installed."

# The dnsmasq package starts immediately with its stock config — a DNS server on
# :53 — which would stop Pi-hole's FTL from binding :53. We only use dnsmasq for
# DHCP, so disable its DNS (port=0) and stop it until the AP is configured.
info "Restricting dnsmasq to DHCP only (Pi-hole owns port 53)..."
cat > /etc/dnsmasq.d/pi-nat64.conf <<EOF
# pi-nat64: DHCPv4 for the access point only. DNS is Pi-hole (FTL) on :53,
# IPv6 addressing/RDNSS comes from radvd.
interface=$AP_IFACE
bind-interfaces
port=0
dhcp-range=$AP_DHCP_START,$AP_DHCP_END,255.255.255.0,24h
dhcp-option=option:router,$AP_IPV4
dhcp-option=option:dns-server,$AP_IPV4
EOF
systemctl stop dnsmasq 2>/dev/null || true

# ── 3. Jool (NAT64) ───────────────────────────────────────────────────────────
# Installed separately and failure TOLERATED: jool-dkms builds for every
# installed kernel, and a very new kernel can fail the build and make apt return
# an error even when the RUNNING kernel is fine. Verify on the running kernel.
info "Installing Jool (NAT64)..."
"${APT[@]}" install -y jool-tools jool-dkms \
  || warn "jool-dkms reported build errors — verifying the module next."

info "Loading Jool kernel module..."
modprobe jool 2>/dev/null || true

# Module missing, OR loaded but dpkg left half-configured (build failed for
# another installed kernel — Pi-hole's installer would then abort on apt): try
# the patch/rebuild helper, which also re-runs dpkg --configure.
if [[ ! -d /sys/module/jool ]] || jool_dkms_broken; then
  run_jool_fix
  modprobe jool 2>/dev/null || true
fi

if jool_dkms_broken; then
  # Still half-configured: apt is unusable until this is resolved. Removing
  # jool-dkms unblocks apt; a module that's already loaded keeps working until
  # the next reboot, and NAT64 can be restored later with fix-jool.sh.
  warn "jool-dkms is still half-configured — removing it so apt keeps working..."
  dpkg --remove --force-remove-reinstreq jool-dkms 2>/dev/null || true
  dpkg --configure -a 2>/dev/null || true
fi

if [[ -d /sys/module/jool ]] \
   && [[ "$(dpkg-query -W -f='${db:Status-Abbrev}' jool-dkms 2>/dev/null || true)" == "ii "* ]]; then
  JOOL_OK=true
  ok "Jool module loaded — NAT64 available."
else
  JOOL_OK=false
  warn "════════════════════════════════════════════════════════════════"
  warn "The Jool NAT64 module could NOT be built/loaded on kernel $(uname -r)"
  warn "(see /var/lib/dkms/jool/*/build/make.log). NAT64 is disabled;"
  warn "DNS64, Pi-hole and the web UI will still be installed. To retry:"
  warn "    sudo apt-get install -y jool-dkms || true   # build may fail — expected"
  warn "    sudo bash fix-jool.sh                       # patches + rebuilds + repairs"
  warn "════════════════════════════════════════════════════════════════"
fi

# ── 4. Configure Jool (NAT64) — persistent systemd unit ───────────────────────
# (replaces the old rc.local approach, which overwrote the user's rc.local)
if [[ -f /etc/rc.local ]] && grep -q 'jool instance add "default"' /etc/rc.local; then
  sed -i -e '/^modprobe jool$/d' -e '/jool instance add "default"/d' /etc/rc.local
fi
if $JOOL_OK; then
  info "Configuring Jool NAT64..."
  cat > /etc/systemd/system/pi-nat64-jool.service <<EOF
[Unit]
Description=pi-nat64 Jool NAT64 instance
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/modprobe jool
ExecStart=/bin/sh -c 'jool -i default global display >/dev/null 2>&1 || jool instance add default --netfilter --pool6 $JOOL_PREFIX'
ExecStop=-/usr/bin/jool instance remove default

[Install]
WantedBy=multi-user.target
EOF
  grep -qxF 'jool' /etc/modules || echo 'jool' >> /etc/modules
  systemctl daemon-reload
  systemctl enable pi-nat64-jool
  systemctl restart pi-nat64-jool || warn "pi-nat64-jool failed to start — see: journalctl -u pi-nat64-jool"
  ok "Jool configured with prefix $JOOL_PREFIX"
else
  warn "Skipping Jool NAT64 configuration (module not loaded)."
fi

# ── 5. Configure Unbound (DNS64) ──────────────────────────────────────────────
info "Configuring Unbound DNS64 (127.0.0.1:5335 — Pi-hole is the public resolver)..."

# Disable systemd-resolved BEFORE starting Unbound (it would hold port 53)
if systemctl is-active --quiet systemd-resolved; then
  warn "Disabling systemd-resolved (conflicts with Unbound/Pi-hole on port 53)..."
  systemctl disable --now systemd-resolved
fi

# The gateway itself resolves through public resolvers, not its own Pi-hole:
# Pi-hole isn't installed yet, and afterwards its DNS64 answers would point the
# host at 64:ff9b:: addresses it can't reach (Jool only translates FORWARDED
# traffic, not the Pi's own). Written unconditionally so re-runs heal a broken
# resolv.conf. (NetworkManager may later replace it with DHCP-provided DNS —
# that works too.)
if [[ -L /etc/resolv.conf ]] || ! grep -q '^nameserver' /etc/resolv.conf 2>/dev/null \
   || grep -q '^nameserver 127\.' /etc/resolv.conf; then
  rm -f /etc/resolv.conf
  cat > /etc/resolv.conf <<'RESOLV'
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 2606:4700:4700::1111
RESOLV
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
  # DNS64 must run before the validator and iterator. The prefix is a
  # server-clause option (there is no "dns64:" section).
  module-config: "dns64 validator iterator"
  dns64-prefix: $JOOL_PREFIX

# IPv6 and IPv4 upstreams, so resolution works whichever family the uplink has
forward-zone:
  name: "."
  forward-addr: 2606:4700:4700::1111
  forward-addr: 2606:4700:4700::1001
  forward-addr: 1.1.1.1
  forward-addr: 1.0.0.1
EOF

# Initialise DNSSEC root trust-anchor (required before first start on a fresh system)
mkdir -p /var/lib/unbound
unbound-anchor -a /var/lib/unbound/root.key || true
chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

systemctl enable unbound
systemctl restart unbound || { journalctl -u unbound -n 30 --no-pager; error "Unbound failed to start — see logs above."; }
ok "Unbound DNS64 configured on 127.0.0.1:5335."

# ── 5.5 Install Pi-hole (no web UI — stats shown in pi-nat64 UI) ──────────────
if command -v pihole >/dev/null 2>&1 && command -v pihole-FTL >/dev/null 2>&1; then
  info "Pi-hole already installed — re-applying its configuration."
else
  info "Installing Pi-hole..."
  mkdir -p /etc/pihole
  # A fresh v6 install imports these legacy keys into pihole.toml.
  sed "s/^PIHOLE_INTERFACE=.*/PIHOLE_INTERFACE=$AP_IFACE/" \
      "$SCRIPT_DIR/configs/pihole-setupVars.conf" > /etc/pihole/setupVars.conf
  curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
fi

# Apply the settings through FTL itself — setupVars.conf is only read on a fresh
# v6 install, so this is the only way that also works when Pi-hole was already
# present (otherwise DNS64 would be silently bypassed).
info "Configuring Pi-hole (upstream = Unbound DNS64, web server off 80/443)..."
ftl_set() {
  pihole-FTL --config "$1" "$2" >/dev/null 2>&1 || warn "Could not set Pi-hole option $1"
}
ftl_set dns.upstreams       '["127.0.0.1#5335"]'
ftl_set dns.listeningMode   'LOCAL'
ftl_set dns.dnssec          'false'          # Unbound validates
ftl_set dhcp.active         'false'          # dnsmasq does DHCP
ftl_set dns.hosts           "[\"$AP_IPV4 gateway.local\", \"$AP_GW_IPV6 gateway.local\"]"
ftl_set ntp.ipv4.active     'false'          # don't run an NTP server on the uplink
ftl_set ntp.ipv6.active     'false'
# FTL's own web server/API: loopback only, off 80/443 (the pi-nat64 UI lives there)
ftl_set webserver.port      '127.0.0.1:8053'
systemctl restart pihole-FTL || warn "pihole-FTL failed to restart — see: journalctl -u pihole-FTL"
ok "Pi-hole configured."

# ── 6. Access point: interface, hostapd ───────────────────────────────────────
if $HAS_AP_IFACE; then
  info "Configuring the Wi-Fi access point..."

  # NetworkManager (default on bookworm/trixie) manages wlan0 and runs
  # wpa_supplicant scans on it, fighting hostapd. Tell it to leave wlan0 alone.
  if systemctl is-active --quiet NetworkManager; then
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-pi-nat64.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:$AP_IFACE
EOF
    systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager || true
  fi

  # Old installs wrote an ifupdown stanza; NetworkManager ignores it — remove it.
  rm -f /etc/network/interfaces.d/wlan0

  # Wi-Fi is soft-blocked on Raspberry Pi OS until a country is set
  rfkill unblock wlan 2>/dev/null || true
  command -v raspi-config >/dev/null 2>&1 \
    && raspi-config nonint do_wifi_country "$AP_COUNTRY" >/dev/null 2>&1 || true

  # Static AP addresses, applied at every boot before hostapd/dnsmasq/radvd.
  # keep_addr_on_down: hostapd restarts bounce the link, which would otherwise
  # drop the IPv6 gateway address that radvd advertises.
  cat > /etc/systemd/system/pi-nat64-ap-addr.service <<EOF
[Unit]
Description=pi-nat64 access point addresses on $AP_IFACE
BindsTo=sys-subsystem-net-devices-$AP_IFACE.device
After=sys-subsystem-net-devices-$AP_IFACE.device
Before=hostapd.service dnsmasq.service radvd.service pihole-FTL.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/usr/sbin/rfkill unblock wlan
ExecStart=/usr/sbin/sysctl -q -w net.ipv6.conf.$AP_IFACE.keep_addr_on_down=1
ExecStart=/usr/sbin/ip addr replace $AP_IPV4/24 dev $AP_IFACE
ExecStart=/usr/sbin/ip -6 addr replace $AP_GW_IPV6/64 dev $AP_IFACE nodad

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable pi-nat64-ap-addr
  systemctl restart pi-nat64-ap-addr || warn "Could not assign the AP addresses to $AP_IFACE"

  # hostapd.conf: written on first install only — afterwards it holds the SSID /
  # passphrase the user set in the web UI, which a re-run must not reset.
  if [[ ! -f /etc/hostapd/hostapd.conf ]] || ! grep -q '^wpa_passphrase=' /etc/hostapd/hostapd.conf; then
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
country_code=$AP_COUNTRY
EOF
    AP_PASS_SHOWN="$AP_PASS"
  else
    AP_PASS_SHOWN="(unchanged)"
  fi
  # Keys the web UI relies on: control socket (hostapd_cli) and the deny list
  # used to block clients. Added to older configs too.
  for kv in "ctrl_interface=/var/run/hostapd" "macaddr_acl=0" \
            "deny_mac_file=/etc/hostapd/hostapd.deny"; do
    grep -q "^${kv%%=*}=" /etc/hostapd/hostapd.conf || echo "$kv" >> /etc/hostapd/hostapd.conf
  done
  touch /etc/hostapd/hostapd.deny
  chmod 600 /etc/hostapd/hostapd.conf

  # The unit sets DAEMON_CONF itself on current Debian; keep old setups working
  [[ -f /etc/default/hostapd ]] && \
    sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

  systemctl unmask hostapd
  systemctl enable hostapd
  if systemctl restart hostapd; then
    ok "hostapd access point running (SSID: $(sed -n 's/^ssid=//p' /etc/hostapd/hostapd.conf))."
  else
    warn "hostapd failed to start — check: journalctl -u hostapd  (driver/AP-mode support, rfkill, country)"
  fi
else
  systemctl disable --now hostapd 2>/dev/null || true
  AP_PASS_SHOWN=""
  warn "Skipped hostapd (no $AP_IFACE)."
fi

# ── 7. dnsmasq (DHCPv4) ───────────────────────────────────────────────────────
if $HAS_AP_IFACE; then
  info "Starting dnsmasq DHCP..."
  systemctl enable dnsmasq
  systemctl restart dnsmasq || warn "dnsmasq failed to start — see: journalctl -u dnsmasq"
  ok "dnsmasq DHCP configured."
else
  systemctl disable --now dnsmasq 2>/dev/null || true
  warn "Skipped dnsmasq DHCP (no $AP_IFACE)."
fi

# ── 8. radvd (IPv6 router advertisements + RDNSS) ────────────────────────────
# radvd is the only RA source (dnsmasq no longer sends RAs — two daemons
# advertising on one link confused clients).
cat > /etc/radvd.conf <<EOF
interface $AP_IFACE {
    AdvSendAdvert on;
    AdvManagedFlag off;
    AdvOtherConfigFlag off;

    prefix $AP_PREFIX {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };

    RDNSS $AP_GW_IPV6 {
        AdvRDNSSLifetime 3600;
    };
};
EOF

if $HAS_AP_IFACE; then
  info "Starting radvd (IPv6 RA)..."
  systemctl enable radvd
  systemctl restart radvd || warn "radvd failed to start — see: journalctl -u radvd"
  ok "radvd configured."
else
  systemctl disable --now radvd 2>/dev/null || true
  warn "Skipped radvd (no $AP_IFACE)."
fi

# ── 9. Kernel forwarding + firewall ──────────────────────────────────────────
info "Enabling IP forwarding and firewall rules..."

cat > /etc/sysctl.d/99-pi-nat64.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.$ETH_IFACE.accept_ra = 2
EOF
# Only pin the AP interface's keys when it exists (absent in a VM, and
# sysctl --system would otherwise error on the missing key).
if $HAS_AP_IFACE; then
  echo "net.ipv6.conf.$AP_IFACE.accept_ra = 0" >> /etc/sysctl.d/99-pi-nat64.conf
  echo "net.ipv6.conf.$AP_IFACE.keep_addr_on_down = 1" >> /etc/sysctl.d/99-pi-nat64.conf
fi
sysctl --system -q >/dev/null 2>&1 || true

# Add a rule only if it isn't there yet, so re-runs don't stack duplicates.
#   fw <iptables|ip6tables> <table> <-A|-I> <chain> <rule...>
fw() {
  local cmd=$1 table=$2 op=$3 chain=$4; shift 4
  "$cmd" -t "$table" -C "$chain" "$@" 2>/dev/null && return 0
  if [[ $op == -I ]]; then "$cmd" -t "$table" -I "$chain" 1 "$@"
  else "$cmd" -t "$table" -A "$chain" "$@"; fi
}

for ipt in iptables ip6tables; do
  # Outbound NAT: IPv4 for NAT64-translated and dual-stack traffic; IPv6 because
  # the AP uses a ULA prefix (fd00::/64), which isn't routable upstream.
  fw "$ipt" nat -A POSTROUTING -o "$ETH_IFACE" -j MASQUERADE

  # Nothing on the uplink may query DNS (TCP or UDP) or NTP on the gateway
  for proto in udp tcp; do
    fw "$ipt" filter -I INPUT -i "$ETH_IFACE" -p "$proto" --dport 53 -j DROP
  done
  fw "$ipt" filter -I INPUT -i "$ETH_IFACE" -p udp --dport 123 -j DROP

  if $HAS_AP_IFACE; then
    # Web UI only from the AP side
    for port in 80 443; do
      fw "$ipt" filter -I INPUT -i "$ETH_IFACE" -p tcp --dport "$port" -j DROP
    done
    # Hosts on the uplink segment must not be able to route into the AP network
    # (only replies, and port-forwards set up in the UI, which are DNAT'ed)
    fw "$ipt" filter -A FORWARD -i "$ETH_IFACE" -o "$AP_IFACE" \
      -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP
  fi
done
$HAS_AP_IFACE || warn "No AP interface — leaving the web UI reachable on $ETH_IFACE (do not use this on an internet-facing host)."

netfilter-persistent save
ok "Forwarding and firewall rules applied."

# ── 10. Deploy web UI ────────────────────────────────────────────────────────
info "Deploying web UI to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR" "$CONF_DIR"
# Replace atomically so a running UI never sees a half-copied tree
rm -rf "$INSTALL_DIR/web.new"
cp -r "$SCRIPT_DIR/web" "$INSTALL_DIR/web.new"
rm -rf "$INSTALL_DIR/web.old"
[[ -d "$INSTALL_DIR/web" ]] && mv "$INSTALL_DIR/web" "$INSTALL_DIR/web.old"
mv "$INSTALL_DIR/web.new" "$INSTALL_DIR/web"
rm -rf "$INSTALL_DIR/web.old"
chmod 750 "$INSTALL_DIR/web"
chmod 640 "$INSTALL_DIR/web/app.py"

# Generate a self-signed TLS certificate so the UI can serve HTTPS (the admin
# password and session cookie must not cross the Wi-Fi in cleartext).
mkdir -p "$CONF_DIR/tls"
if [[ ! -f "$CONF_DIR/tls/cert.pem" ]]; then
  info "Generating self-signed TLS certificate..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CONF_DIR/tls/key.pem" \
    -out    "$CONF_DIR/tls/cert.pem" \
    -days 3650 \
    -subj "/CN=gateway.local" \
    -addext "subjectAltName=DNS:gateway.local,IP:${AP_IPV4},IP:${AP_GW_IPV6}" \
    || error "Failed to generate TLS certificate (is openssl installed?)"
fi
chmod 600 "$CONF_DIR/tls/key.pem"
chmod 644 "$CONF_DIR/tls/cert.pem"

# SECRET_KEY signs sessions — keep the existing one so re-runs don't log everyone out
SECRET_KEY=""
[[ -f "$CONF_DIR/secret.env" ]] && SECRET_KEY=$(sed -n 's/^SECRET_KEY=//p' "$CONF_DIR/secret.env")
[[ -n "$SECRET_KEY" ]] || SECRET_KEY=$(openssl rand -hex 32)
cat > "$CONF_DIR/secret.env" <<EOF
SECRET_KEY=$SECRET_KEY
TLS_CERT=$CONF_DIR/tls/cert.pem
TLS_KEY=$CONF_DIR/tls/key.pem
AP_IFACE=$AP_IFACE
WAN_IFACE=$ETH_IFACE
EOF
chmod 600 "$CONF_DIR/secret.env"

# Admin password: generated only on first install (or when ADMIN_PASS is given)
# — a re-run must not undo a password changed in the UI.
ADMIN_PASS_NEW=""
if [[ -n "$ADMIN_PASS_ENV" ]] || [[ ! -s "$CONF_DIR/admin.passwd" ]]; then
  ADMIN_PASS_NEW="${ADMIN_PASS_ENV:-$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-14)}"
  # Salted scrypt hash (matches web/app.py format; never plaintext)
  python3 - "$ADMIN_PASS_NEW" > "$CONF_DIR/admin.passwd.tmp" <<'PY'
import hashlib, os, sys
salt = os.urandom(16)
key = hashlib.scrypt(sys.argv[1].encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
print(f"scrypt${salt.hex()}${key.hex()}")
PY
  chmod 600 "$CONF_DIR/admin.passwd.tmp"
  mv "$CONF_DIR/admin.passwd.tmp" "$CONF_DIR/admin.passwd"
fi

# Record the deployed version + the checkout it came from (Update button)
GIT=(git -c "safe.directory=$SCRIPT_DIR" -C "$SCRIPT_DIR")
if "${GIT[@]}" rev-parse HEAD >/dev/null 2>&1; then
  python3 - "$CONF_DIR/version.json" "$SCRIPT_DIR" \
    "$("${GIT[@]}" rev-parse HEAD)" \
    "$("${GIT[@]}" rev-parse --abbrev-ref HEAD)" \
    "$("${GIT[@]}" log -1 --format=%cI)" <<'PY'
import json, sys
path, repo, commit, branch, date = sys.argv[1:6]
if branch == "HEAD":          # detached checkout — follow main
    branch = "main"
with open(path, "w") as f:
    json.dump({"commit": commit, "branch": branch, "date": date, "repo_dir": repo}, f, indent=2)
PY
else
  warn "Not installed from a git checkout — the web UI's Update button will be unavailable."
  rm -f "$CONF_DIR/version.json"
fi

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
EnvironmentFile=$CONF_DIR/secret.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/web/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pi-nat64-ui
systemctl restart pi-nat64-ui
ok "Web UI deployed and started."

# ── 11. mDNS: publish gateway.local ──────────────────────────────────────────
# avahi only announces <hostname>.local on its own; publish the gateway.local
# alias explicitly (Pi-hole's dns.hosts answers it for plain DNS lookups too).
info "Publishing gateway.local via mDNS..."
systemctl enable --now avahi-daemon
if $HAS_AP_IFACE; then
  cat > /etc/systemd/system/pi-nat64-mdns.service <<EOF
[Unit]
Description=pi-nat64 mDNS alias gateway.local
After=avahi-daemon.service pi-nat64-ap-addr.service
Requires=avahi-daemon.service

[Service]
ExecStart=/usr/bin/avahi-publish -a -R gateway.local $AP_IPV4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable pi-nat64-mdns
  systemctl restart pi-nat64-mdns || warn "Could not publish gateway.local via mDNS"
fi
ok "gateway.local will be resolvable on the AP network."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "  ════════════════════════════════════════════"
echo -e "  ${GREEN}$($UPGRADE && echo 'Upgrade' || echo 'Installation') complete!${NC}"
echo "  ════════════════════════════════════════════"
echo ""
if $JOOL_OK; then
  echo -e "  NAT64     : ${GREEN}active${NC}  (Jool, prefix $JOOL_PREFIX)"
else
  echo -e "  NAT64     : ${RED}NOT active${NC} — Jool module failed to build on kernel $(uname -r)"
  echo "              DNS64/Pi-hole/UI work; see the warning above to enable NAT64."
fi
if $HAS_AP_IFACE; then
  echo "  Wi-Fi AP  : $(sed -n 's/^ssid=//p' /etc/hostapd/hostapd.conf)  (pass: $AP_PASS_SHOWN)"
  echo "  Web UI    : https://gateway.local  or  https://$AP_IPV4"
else
  echo -e "  ${YELLOW}Wi-Fi AP  : SKIPPED — no '$AP_IFACE' interface (VM / no Wi-Fi hardware)${NC}"
  echo "  Web UI    : https://<this-host-IP>   (reachable on $ETH_IFACE for testing)"
fi
echo "              (self-signed cert — your browser will warn once; that's expected)"
if [[ -n "$ADMIN_PASS_NEW" ]]; then
  echo -e "  ${YELLOW}Admin password (save it now — shown only here): ${ADMIN_PASS_NEW}${NC}"
else
  echo "  Admin password: unchanged. Forgot it?  sudo python3 $INSTALL_DIR/web/app.py --set-password"
fi
echo ""
if ! $UPGRADE; then
  echo -e "  ${YELLOW}Next steps:${NC}"
  if $HAS_AP_IFACE; then
    echo "  1. Connect a device to the Wi-Fi above"
    echo "  2. Open https://gateway.local in a browser"
    echo "  3. Change the admin password and the Wi-Fi passphrase in Settings"
    echo "  4. Add port-forwarding rules as needed"
  else
    echo "  1. Open https://<this-host-IP> in a browser (accept the cert warning)"
    echo "  2. Log in with the admin password above"
    echo "  3. NAT64/DNS64/Pi-hole are running; the Wi-Fi AP needs real hardware"
    echo "  4. Test DNS64:  dig @127.0.0.1 -p 5335 ipv4only.arpa AAAA +short"
  fi
  echo ""
  echo -e "  ${YELLOW}Using a USB Wi-Fi adapter? Install drivers/firmware:${NC}"
  echo "    sudo bash install-drivers.sh --auto"
  echo ""
  echo "  Logs:"
  echo "    journalctl -u pi-nat64-ui -f"
  echo "    journalctl -u hostapd -f"
  echo "    journalctl -u unbound -f"
  echo "    journalctl -u pihole-FTL -f"
  echo ""
fi
