#!/usr/bin/env bash
# update.sh — update pi-nat64 to the latest version of its branch and re-apply it.
#
# Pulls the git checkout this install came from (fast-forward only) and runs
# `install.sh --upgrade`, which keeps the admin password, session secret, Wi-Fi
# settings, port-forwards and blocked clients.
#
# Started by the web UI's Update button (in a transient systemd unit, so it
# survives the UI restarting mid-update), or by hand:  sudo bash update.sh
# Output goes to /var/log/pi-nat64-update.log; the last line is a marker the UI
# reads (PI_NAT64_UPDATE_OK / PI_NAT64_UPDATE_FAILED).

set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash update.sh"; exit 1; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG=/var/log/pi-nat64-update.log

# Log this run only (the UI reads the tail for the result marker); also echo to
# the terminal when run by hand.
if [[ -t 1 ]]; then
  exec > >(tee "$LOG") 2>&1
else
  exec >"$LOG" 2>&1
fi

fail() { echo "PI_NAT64_UPDATE_FAILED: $*"; exit 1; }
git_() { git -c "safe.directory=$REPO" -C "$REPO" "$@"; }

echo "=== pi-nat64 update started $(date -Is) ==="

git_ rev-parse --git-dir >/dev/null 2>&1 || fail "$REPO is not a git checkout"

BRANCH=$(git_ rev-parse --abbrev-ref HEAD)
[[ "$BRANCH" == "HEAD" ]] && fail "checkout is detached — run: git -C $REPO checkout main"

BEFORE=$(git_ rev-parse --short HEAD)
git_ fetch origin "$BRANCH" || fail "git fetch failed (network?)"
git_ merge --ff-only "origin/$BRANCH" \
  || fail "local changes in $REPO prevent a fast-forward — commit/stash them or re-clone"
AFTER=$(git_ rev-parse --short HEAD)
echo "Updated $BRANCH: $BEFORE -> $AFTER"

# Run the NEW install.sh (just pulled) in upgrade mode
bash "$REPO/install.sh" --upgrade || fail "install.sh --upgrade failed — see the log above"

echo "PI_NAT64_UPDATE_OK $AFTER $(date -Is)"
