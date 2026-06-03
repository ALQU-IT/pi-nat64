#!/usr/bin/env bash
# USB Wi-Fi adapter driver installer — Raspberry Pi 5 (Raspbian bookworm)
#
# Supported chipsets:
#   RTL8812AU / RTL8821AU   out-of-tree DKMS  (aircrack-ng/rtl8812au)
#   RTL8814AU               out-of-tree DKMS  (morrownr/8814au)
#   RTL8188EUS              out-of-tree DKMS  (aircrack-ng/rtl8188eus)
#   MT7610U / MT7612U       in-kernel mt76    (firmware-misc-nonfree)
#   AR9271                  in-kernel ath9k   (firmware-ath9k-htc)
#   MT7921U                 in-kernel mt7921u (firmware-misc-nonfree, kernel ≥5.18)
#   RTL8852BU / RTL8832BU   out-of-tree DKMS  (morrownr/rtl8852bu-20240418)
#     └─ includes: BrosTrend AX1L / AX4L AX1800
#
# Usage:
#   sudo bash install-drivers.sh            # interactive menu
#   sudo bash install-drivers.sh --auto     # auto-detect connected adapters
#   sudo bash install-drivers.sh --all      # install every driver

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
die()   { error "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root:  sudo bash install-drivers.sh"

ARCH=$(uname -m)
BUILD_DIR=/tmp/pi-nat64-drivers
mkdir -p "$BUILD_DIR"

# ── USB ID → driver-group table ───────────────────────────────────────────────
declare -A USB_ID_TO_GROUP=()

_add() {
  local grp=$1; shift
  for id in "$@"; do USB_ID_TO_GROUP[$id]=$grp; done
}

# RTL8812AU — Alfa AWUS036ACH, TP-Link Archer T4U / T2U (AC1200)
_add rtl8812au \
  0bda:8812 0bda:881a 0bda:881b 0bda:881c \
  2357:0101 2357:0103 2357:010d 2357:010e 2357:010f 2357:0122 \
  0409:0408 0b05:17d2 0846:9051 07b8:8812 7392:a822 \
  13b1:003f 2001:330e 2001:3313 2001:3315 2001:3316

# RTL8821AU — TP-Link Archer T2U Mini / Nano (AC600)
_add rtl8821au \
  0bda:0811 0bda:0821 0bda:8822 0bda:a811 \
  2357:011e 2357:011f 2357:0120 \
  0846:9052 7392:a811 7392:a812 7392:a813 7392:b611 \
  2001:3314 2001:3318 2019:ab32

# RTL8814AU — Alfa AWUS1900, ASUS USB-AC68, Edimax EW-7833UAC (AC1900)
_add rtl8814au \
  0bda:8813 0b05:1817 13d3:3487 2001:331a

# RTL8188EUS — TP-Link TL-WN725N v3, various N150 dongles
_add rtl8188eus \
  0bda:8179 0bda:8178 0bda:0179 2001:330f

# MT7610U — Alfa AWUS036ACHM, Panda PAU0A/PAU0B (AC600 dual-band)
_add mt76 \
  148f:7610 0e8d:7610 0e8d:7650

# MT7612U — Alfa AWUS036ACM, Panda PAU0D (AC1200 dual-band)
_add mt76 \
  0e8d:7612 0e8d:7662 148f:7612 0846:9053

# AR9271 — Alfa AWUS036NHA, TP-Link TL-WN722N v1 (N150)
_add ath9k \
  0cf3:9271 0cf3:7010 0846:9030 0cf3:b004 07d1:3a09

# MT7921U — Alfa AWUS036AXML, Panda PAU0F, Netgear A8000, BrosTrend AX9L (AX1800/AXE3000)
_add mt7921u \
  0e8d:7961 0846:9060 0846:9065 35bc:0107

# RTL8852BU / RTL8832BU — BrosTrend AX1L / AX4L AX1800, D-Link DWA-183
_add rtl8852bu \
  0bda:b832 0bda:b852 0bda:885a 0bda:c832 2001:3323

# ── Detect connected adapters ─────────────────────────────────────────────────
declare -a DETECTED_GROUPS=()

detect_connected() {
  declare -A _seen=()
  local found=0
  while IFS= read -r line; do
    local id
    id=$(printf '%s' "$line" | grep -oP 'ID \K[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}' | tr '[:upper:]' '[:lower:]' || true)
    [[ -z $id ]] && continue
    local grp=${USB_ID_TO_GROUP[$id]:-}
    [[ -z $grp || -n ${_seen[$grp]:-} ]] && continue
    _seen[$grp]=1
    DETECTED_GROUPS+=("$grp")
    found=1
  done < <(lsusb 2>/dev/null)
  return $(( 1 - found ))
}

# ── Prerequisites ─────────────────────────────────────────────────────────────
install_prereqs() {
  info "Installing build prerequisites…"
  apt-get update -qq
  # Try distro kernel headers first, fall back to RPi-specific package
  apt-get install -y --no-install-recommends build-essential dkms git \
    "linux-headers-$(uname -r)" 2>/dev/null \
    || apt-get install -y --no-install-recommends \
         build-essential dkms git raspberrypi-kernel-headers
}

# Ensure the non-free section is enabled (needed for firmware packages)
enable_nonfree() {
  if apt-cache show firmware-misc-nonfree &>/dev/null; then
    return 0  # already reachable
  fi
  info "Enabling non-free firmware repository…"
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i \
      '/^deb .*bookworm.*main/s/main$/main contrib non-free non-free-firmware/' \
      /etc/apt/sources.list
  fi
  apt-get update -qq
}

# ── Out-of-tree driver installers ─────────────────────────────────────────────

_clone_and_enter() {
  local url=$1 dir=$2
  rm -rf "$dir"
  git clone --depth=1 "$url" "$dir"
  cd "$dir"
}

_arm64_patch_makefile() {
  sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/' Makefile 2>/dev/null || true
  if grep -q 'CONFIG_PLATFORM_ARM64_RPI' Makefile 2>/dev/null; then
    sed -i 's/CONFIG_PLATFORM_ARM64_RPI = n/CONFIG_PLATFORM_ARM64_RPI = y/' Makefile
  elif grep -q 'CONFIG_PLATFORM_ARM_RPI' Makefile 2>/dev/null; then
    sed -i 's/CONFIG_PLATFORM_ARM_RPI = n/CONFIG_PLATFORM_ARM_RPI = y/' Makefile
  fi
}

install_rtl8812au() {
  info "Installing RTL8812AU / RTL8821AU driver…"
  _clone_and_enter https://github.com/aircrack-ng/rtl8812au.git "$BUILD_DIR/rtl8812au"
  [[ $ARCH == aarch64 ]] && _arm64_patch_makefile
  make dkms_install
  info "RTL8812AU / RTL8821AU installed."
}

install_rtl8821au() { install_rtl8812au; }

install_rtl8814au() {
  info "Installing RTL8814AU driver…"
  _clone_and_enter https://github.com/morrownr/8814au.git "$BUILD_DIR/8814au"
  bash install-driver.sh NoPrompt
  info "RTL8814AU installed."
}

install_rtl8188eus() {
  info "Installing RTL8188EUS driver…"
  _clone_and_enter https://github.com/aircrack-ng/rtl8188eus.git "$BUILD_DIR/rtl8188eus"
  [[ $ARCH == aarch64 ]] && _arm64_patch_makefile
  make dkms_install
  info "RTL8188EUS installed."
}

install_rtl8852bu() {
  info "Installing RTL8832BU / RTL8852BU driver (BrosTrend AX1L / AX4L Model AX4)…"
  _clone_and_enter \
    https://github.com/morrownr/rtl8852bu-20250826.git \
    "$BUILD_DIR/rtl8852bu"
  if [[ -f install-driver.sh ]]; then
    bash install-driver.sh NoPrompt
  else
    [[ $ARCH == aarch64 ]] && _arm64_patch_makefile
    make dkms_install
  fi
  info "RTL8852BU / RTL8832BU installed."
}

# ── Firmware-only installers (in-kernel drivers) ──────────────────────────────

install_mt76() {
  info "Installing MediaTek MT7610U / MT7612U firmware (in-kernel mt76 driver)…"
  enable_nonfree
  apt-get install -y firmware-misc-nonfree
  info "MT7610U / MT7612U firmware installed."
}

install_ath9k() {
  info "Installing Atheros AR9271 firmware (in-kernel ath9k_htc driver)…"
  enable_nonfree
  apt-get install -y firmware-ath9k-htc 2>/dev/null \
    || apt-get install -y firmware-atheros
  info "AR9271 firmware installed."
}

install_mt7921u() {
  info "Installing MediaTek MT7921U firmware (in-kernel mt7921u driver, kernel ≥5.18)…"
  enable_nonfree
  apt-get install -y firmware-misc-nonfree
  info "MT7921U firmware installed."
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

do_install() {
  case $1 in
    rtl8812au)  install_rtl8812au  ;;
    rtl8821au)  install_rtl8821au  ;;
    rtl8814au)  install_rtl8814au  ;;
    rtl8188eus) install_rtl8188eus ;;
    mt76)       install_mt76       ;;
    ath9k)      install_ath9k      ;;
    mt7921u)    install_mt7921u    ;;
    rtl8852bu)  install_rtl8852bu  ;;
    *)          warn "Unknown driver group: $1" ;;
  esac
}

# ── Driver menu entries ───────────────────────────────────────────────────────
# Format: "group|display label"
MENU_ENTRIES=(
  "rtl8812au|RTL8812AU / RTL8821AU   AC1200/AC600  Alfa AWUS036ACH, TP-Link Archer T4U/T2U"
  "rtl8814au|RTL8814AU               AC1900        Alfa AWUS1900, ASUS USB-AC68"
  "rtl8188eus|RTL8188EUS             N150          TP-Link TL-WN725N v3"
  "mt76|MT7610U / MT7612U            AC600/AC1200  Alfa AWUS036ACHM / AWUS036ACM"
  "ath9k|AR9271                      N150          Alfa AWUS036NHA, TP-Link TL-WN722N v1"
  "mt7921u|MT7921U                   AX1800        Alfa AWUS036AXML, Panda PAU0F, BrosTrend AX9L"
  "rtl8852bu|RTL8832BU (RTL8852BU)    AX1800        BrosTrend AX1L / AX4L (Model AX4)"
)

# ── Main ──────────────────────────────────────────────────────────────────────

AUTO_DETECT=false
INSTALL_ALL=false

for arg in "${@:-}"; do
  case $arg in
    --auto)    AUTO_DETECT=true ;;
    --all)     INSTALL_ALL=true ;;
    --help|-h)
      echo "Usage: sudo bash install-drivers.sh [--auto | --all]"
      echo
      echo "  (no args)  interactive menu"
      echo "  --auto     detect plugged-in adapters and install only those drivers"
      echo "  --all      install all supported drivers"
      exit 0
      ;;
  esac
done

declare -a SELECTED_GROUPS=()

if $INSTALL_ALL; then
  for entry in "${MENU_ENTRIES[@]}"; do
    SELECTED_GROUPS+=( "${entry%%|*}" )
  done

elif $AUTO_DETECT; then
  detect_connected || true
  if [[ ${#DETECTED_GROUPS[@]} -eq 0 ]]; then
    warn "No recognised USB Wi-Fi adapters detected."
    warn "Plug in your adapter and retry, or run without --auto to use the menu."
    exit 0
  fi
  info "Detected adapters — will install the following drivers:"
  for g in "${DETECTED_GROUPS[@]}"; do printf "    • %s\n" "$g"; done
  SELECTED_GROUPS=("${DETECTED_GROUPS[@]}")

else
  # Interactive menu
  detect_connected 2>/dev/null || true

  echo
  printf "${BOLD}Available Wi-Fi adapter drivers:${NC}\n\n"

  declare -a MENU_GROUPS=()
  local_idx=1
  for entry in "${MENU_ENTRIES[@]}"; do
    local_grp="${entry%%|*}"
    local_label="${entry#*|}"
    detected_marker=""
    for d in "${DETECTED_GROUPS[@]}"; do
      [[ $d == "$local_grp" ]] && detected_marker="  ${GREEN}← detected${NC}" && break
    done
    printf "  %d) %s%b\n" "$local_idx" "$local_label" "$detected_marker"
    MENU_GROUPS+=("$local_grp")
    (( local_idx++ ))
  done

  echo
  echo "  a) All of the above"
  echo "  q) Quit"
  echo

  while true; do
    read -rp "Select driver(s) to install (e.g.  1 3 5,  or  a): " choices
    [[ $choices == q ]] && { info "Aborted."; exit 0; }
    if [[ $choices == a ]]; then
      SELECTED_GROUPS=("${MENU_GROUPS[@]}")
      break
    fi
    ok=true
    for c in $choices; do
      if [[ $c =~ ^[0-9]+$ ]] && (( c >= 1 && c <= ${#MENU_GROUPS[@]} )); then
        SELECTED_GROUPS+=("${MENU_GROUPS[$((c-1))]}")
      else
        warn "Invalid choice: '$c'"; ok=false; break
      fi
    done
    $ok && [[ ${#SELECTED_GROUPS[@]} -gt 0 ]] && break
  done
fi

[[ ${#SELECTED_GROUPS[@]} -eq 0 ]] && { warn "Nothing selected — exiting."; exit 0; }

install_prereqs

declare -A _done=()
for grp in "${SELECTED_GROUPS[@]}"; do
  [[ -n ${_done[$grp]:-} ]] && continue
  _done[$grp]=1
  do_install "$grp"
done

echo
info "Done. A reboot is recommended to activate any new kernel modules."
