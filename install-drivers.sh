#!/usr/bin/env bash
# USB Wi-Fi adapter driver/firmware installer — Raspberry Pi 5 (Raspberry Pi OS
# bookworm / trixie).
#
# Recent kernels ship drivers for all supported chipsets, so on a current
# kernel this usually only installs FIRMWARE. An out-of-tree DKMS driver is
# built only when the running kernel lacks the in-kernel one.
#
#   Chipset                 In-kernel driver (since)      Fallback (older kernels)
#   RTL8812AU               rtw88_8812au   (6.13)         DKMS aircrack-ng/rtl8812au
#   RTL8821AU               rtw88_8821au   (6.13)         DKMS aircrack-ng/rtl8812au
#   RTL8814AU               rtw88_8814au   (6.16)         DKMS morrownr/8814au
#   RTL8188EU(S)            rtl8xxxu                      DKMS aircrack-ng/rtl8188eus
#   RTL8852BU / RTL8832BU   rtw89_8852bu   (6.17)         DKMS morrownr/rtl8852bu-20250826
#     └─ includes: BrosTrend AX1L / AX4L AX1800
#   MT7610U / MT7612U       mt76x0u / mt76x2u             —   (firmware-misc-nonfree)
#   MT7921U                 mt7921u        (5.18)         —   (firmware-misc-nonfree)
#   AR9271                  ath9k_htc                     —   (firmware-ath9k-htc)
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
KVER=$(uname -r)
APT=(apt-get -o DPkg::Lock::Timeout=300)
export DEBIAN_FRONTEND=noninteractive

# Private, unpredictable build dir (a fixed /tmp path could be pre-created by
# another local user and swapped for their code before we build it as root).
BUILD_DIR=$(mktemp -d /tmp/pi-nat64-drivers.XXXXXX)
trap 'rm -rf "$BUILD_DIR"' EXIT

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

# RTL8814AU — Alfa AWUS1900, ASUS USB-AC68 (AC1900)
_add rtl8814au \
  0bda:8813 0b05:1817 13d3:3487 2001:331a

# RTL8188EU(S) — TP-Link TL-WN725N v2/v3, various N150 dongles
_add rtl8188eus \
  0bda:8179 0bda:0179 2001:330f

# MT7610U — Alfa AWUS036ACHM, Panda PAU0A/PAU0B (AC600 dual-band)
_add mt76 \
  148f:7610 0e8d:7610 0e8d:7650

# MT7612U — Alfa AWUS036ACM, Panda PAU0D (AC1200 dual-band)
_add mt76 \
  0e8d:7612 0e8d:7662 148f:7612 0846:9053

# AR9271 — Alfa AWUS036NHA, TP-Link TL-WN722N v1 (N150)
_add ath9k \
  0cf3:9271 0cf3:7010 0846:9030

# MT7921U — Alfa AWUS036AXML, Panda PAU0F, Netgear A8000, BrosTrend AX9L (AX1800/AXE3000)
_add mt7921u \
  0e8d:7961 0846:9060 0846:9065 35bc:0107

# RTL8852BU / RTL8832BU — BrosTrend AX1L / AX4L AX1800, D-Link DWA-183
_add rtl8852bu \
  0bda:b832 0bda:b83a 0bda:b852 0bda:b85a 0bda:a85b 0bda:885a \
  2001:3323 2001:3327

# ── Detect connected adapters ─────────────────────────────────────────────────
declare -a DETECTED_GROUPS=()

detect_connected() {
  declare -A _seen=()
  local found=0
  command -v lsusb >/dev/null 2>&1 || { "${APT[@]}" install -y usbutils >/dev/null 2>&1 || true; }
  while IFS= read -r line; do
    local id
    id=$(printf '%s' "$line" | grep -oP 'ID \K[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}' | tr '[:upper:]' '[:lower:]' || true)
    [[ -z $id ]] && continue
    local grp=${USB_ID_TO_GROUP[$id]:-}
    [[ -z $grp || -n ${_seen[$grp]:-} ]] && continue
    _seen[$grp]=1
    DETECTED_GROUPS+=("$grp")
    found=1
  done < <(lsusb 2>/dev/null || true)
  return $(( 1 - found ))
}

# Does the running kernel have this (in-tree) module?
have_module() { modinfo "$1" >/dev/null 2>&1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
heal_dpkg() {
  # A failed DKMS build (e.g. jool-dkms on a new kernel) leaves dpkg
  # half-configured and makes every apt-get call fail.
  dpkg --configure -a >/dev/null 2>&1 \
    || warn "dpkg reports unconfigured packages — if apt fails below, run: sudo bash fix-jool.sh"
}

PREREQS_DONE=false
install_build_prereqs() {
  $PREREQS_DONE && return 0
  info "Installing build prerequisites and kernel headers for $KVER…"
  "${APT[@]}" install -y --no-install-recommends build-essential dkms git bc
  if ! "${APT[@]}" install -y --no-install-recommends "linux-headers-$KVER"; then
    local hdr
    case "$KVER" in
      *2712*) hdr=linux-headers-rpi-2712 ;;
      *v8*)   hdr=linux-headers-rpi-v8 ;;
      *)      hdr=raspberrypi-kernel-headers ;;
    esac
    warn "linux-headers-$KVER not found — trying $hdr"
    "${APT[@]}" install -y --no-install-recommends "$hdr" || true
  fi
  [[ -d "/lib/modules/$KVER/build" ]] \
    || die "No kernel headers for $KVER (/lib/modules/$KVER/build missing) — can't build DKMS drivers."
  PREREQS_DONE=true
}

# Ensure the non-free firmware components are enabled (firmware packages)
enable_nonfree() {
  if apt-cache show firmware-misc-nonfree &>/dev/null && apt-cache show firmware-realtek &>/dev/null; then
    return 0  # already reachable
  fi
  info "Enabling non-free firmware repository…"
  # bookworm: one-line sources.list
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i -E '/^deb .*debian.* (bookworm|trixie)[^ ]* main$/s/main$/main contrib non-free non-free-firmware/' \
      /etc/apt/sources.list
  fi
  # trixie+: deb822 .sources files
  local f
  for f in /etc/apt/sources.list.d/*.sources; do
    [[ -f $f ]] || continue
    grep -q 'debian' "$f" || continue
    sed -i -E '/^Components:/{/non-free-firmware/!s/$/ non-free-firmware/}' "$f"
  done
  "${APT[@]}" update -qq
}

install_firmware() {
  enable_nonfree
  "${APT[@]}" install -y "$@"
}

# ── Out-of-tree DKMS fallback (only for kernels without the in-tree driver) ────

_clone_and_enter() {
  local url=$1 dir=$2
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

# Remove an already-registered copy of the module described by ./dkms.conf so
# `dkms add` doesn't fail with "already contains" on a re-run.
_dkms_forget_existing() {
  [[ -f dkms.conf ]] || return 0
  local name ver
  name=$(sed -n 's/^PACKAGE_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' dkms.conf | head -1)
  ver=$(sed -n 's/^PACKAGE_VERSION="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' dkms.conf | head -1)
  [[ -n $name && -n $ver ]] || return 0
  if dkms status -m "$name" -v "$ver" 2>/dev/null | grep -q .; then
    dkms remove -m "$name" -v "$ver" --all >/dev/null 2>&1 || true
  fi
  rm -rf "/usr/src/$name-$ver"
}

_dkms_from_git() {   # url dir
  install_build_prereqs
  warn "The running kernel has no in-tree driver — building an out-of-tree DKMS module."
  warn "These track upstream HEAD and may not build on newer kernels."
  _clone_and_enter "$1" "$BUILD_DIR/$2"
  _dkms_forget_existing
  if [[ -f install-driver.sh ]]; then
    bash install-driver.sh NoPrompt
  else
    [[ $ARCH == aarch64 ]] && _arm64_patch_makefile
    make dkms_install
  fi
  cd - >/dev/null
}

# ── Per-chipset installers ────────────────────────────────────────────────────

install_rtl8812au() {
  if have_module rtw88_8812au; then
    info "RTL8812AU: using the in-kernel rtw88_8812au driver — installing firmware…"
    install_firmware firmware-realtek
  else
    _dkms_from_git https://github.com/aircrack-ng/rtl8812au.git rtl8812au
  fi
  info "RTL8812AU ready."
}

install_rtl8821au() {
  if have_module rtw88_8821au; then
    info "RTL8821AU: using the in-kernel rtw88_8821au driver — installing firmware…"
    install_firmware firmware-realtek
  else
    _dkms_from_git https://github.com/aircrack-ng/rtl8812au.git rtl8812au
  fi
  info "RTL8821AU ready."
}

install_rtl8814au() {
  if have_module rtw88_8814au; then
    info "RTL8814AU: using the in-kernel rtw88_8814au driver — installing firmware…"
    install_firmware firmware-realtek
  else
    _dkms_from_git https://github.com/morrownr/8814au.git 8814au
  fi
  info "RTL8814AU ready."
}

install_rtl8188eus() {
  if have_module rtl8xxxu; then
    info "RTL8188EU(S): using the in-kernel rtl8xxxu driver — installing firmware…"
    install_firmware firmware-realtek
  else
    _dkms_from_git https://github.com/aircrack-ng/rtl8188eus.git rtl8188eus
  fi
  info "RTL8188EU(S) ready."
}

install_rtl8852bu() {
  if have_module rtw89_8852bu; then
    info "RTL8832BU / RTL8852BU: using the in-kernel rtw89_8852bu driver — installing firmware…"
    install_firmware firmware-realtek
  else
    _dkms_from_git https://github.com/morrownr/rtl8852bu-20250826.git rtl8852bu
  fi
  info "RTL8852BU / RTL8832BU ready (BrosTrend AX1L / AX4L)."
}

install_mt76() {
  info "Installing MediaTek MT7610U / MT7612U firmware (in-kernel mt76 driver)…"
  install_firmware firmware-misc-nonfree
  info "MT7610U / MT7612U firmware installed."
}

install_ath9k() {
  info "Installing Atheros AR9271 firmware (in-kernel ath9k_htc driver)…"
  enable_nonfree
  "${APT[@]}" install -y firmware-ath9k-htc || "${APT[@]}" install -y firmware-atheros
  info "AR9271 firmware installed."
}

install_mt7921u() {
  info "Installing MediaTek MT7921U firmware (in-kernel mt7921u driver, kernel ≥5.18)…"
  install_firmware firmware-misc-nonfree
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
  "rtl8812au|RTL8812AU               AC1200        Alfa AWUS036ACH, TP-Link Archer T4U"
  "rtl8821au|RTL8821AU               AC600         TP-Link Archer T2U / T2U Nano"
  "rtl8814au|RTL8814AU               AC1900        Alfa AWUS1900, ASUS USB-AC68"
  "rtl8188eus|RTL8188EU(S)           N150          TP-Link TL-WN725N v2/v3"
  "mt76|MT7610U / MT7612U            AC600/AC1200  Alfa AWUS036ACHM / AWUS036ACM"
  "ath9k|AR9271                      N150          Alfa AWUS036NHA, TP-Link TL-WN722N v1"
  "mt7921u|MT7921U                   AX1800        Alfa AWUS036AXML, Panda PAU0F, BrosTrend AX9L"
  "rtl8852bu|RTL8832BU (RTL8852BU)    AX1800        BrosTrend AX1L / AX4L (Model AX4)"
)

# ── Main ──────────────────────────────────────────────────────────────────────

AUTO_DETECT=false
INSTALL_ALL=false

for arg in "$@"; do
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
    *) die "Unknown option: $arg (see --help)" ;;
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
  [[ -t 0 ]] || die "No terminal for the menu — use --auto or --all"
  detect_connected 2>/dev/null || true

  echo
  printf "${BOLD}Available Wi-Fi adapter drivers:${NC}\n\n"

  declare -a MENU_GROUPS=()
  menu_idx=1
  for entry in "${MENU_ENTRIES[@]}"; do
    menu_grp="${entry%%|*}"
    menu_label="${entry#*|}"
    detected_marker=""
    for d in "${DETECTED_GROUPS[@]}"; do
      [[ $d == "$menu_grp" ]] && detected_marker="  ${GREEN}← detected${NC}" && break
    done
    printf "  %d) %s%b\n" "$menu_idx" "$menu_label" "$detected_marker"
    MENU_GROUPS+=("$menu_grp")
    menu_idx=$(( menu_idx + 1 ))
  done

  echo
  echo "  a) All of the above"
  echo "  q) Quit"
  echo

  while true; do
    read -rp "Select driver(s) to install (e.g.  1 3 5,  or  a): " choices || die "No input."
    [[ $choices == q ]] && { info "Aborted."; exit 0; }
    if [[ $choices == a ]]; then
      SELECTED_GROUPS=("${MENU_GROUPS[@]}")
      break
    fi
    SELECTED_GROUPS=()          # a rejected line must not leave earlier picks behind
    valid=true
    for c in $choices; do
      if [[ $c =~ ^[0-9]+$ ]] && (( c >= 1 && c <= ${#MENU_GROUPS[@]} )); then
        SELECTED_GROUPS+=("${MENU_GROUPS[$((c-1))]}")
      else
        warn "Invalid choice: '$c'"; valid=false; break
      fi
    done
    $valid && [[ ${#SELECTED_GROUPS[@]} -gt 0 ]] && break
    SELECTED_GROUPS=()
  done
fi

[[ ${#SELECTED_GROUPS[@]} -eq 0 ]] && { warn "Nothing selected — exiting."; exit 0; }

heal_dpkg
"${APT[@]}" update -qq

declare -A _done=()
for grp in "${SELECTED_GROUPS[@]}"; do
  # rtl8812au and rtl8821au share one out-of-tree package — build it once
  key=$grp
  [[ $grp == rtl8821au ]] && ! have_module rtw88_8821au && key=rtl8812au-dkms
  [[ $grp == rtl8812au ]] && ! have_module rtw88_8812au && key=rtl8812au-dkms
  [[ -n ${_done[$key]:-} ]] && continue
  _done[$key]=1
  do_install "$grp"
done

echo
info "Done. Replug the adapter (or reboot) to load the driver, then re-run"
info "install.sh if the access point interface (wlan0) was missing before."
