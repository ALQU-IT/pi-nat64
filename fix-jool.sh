#!/usr/bin/env bash
# fix-jool.sh — make Jool (NAT64) build on Linux kernel 6.18+
#
# Jool 4.1.x fails to compile against kernel 6.18 because the kernel renamed
# the flowi4_tos field to flowi4_dscp. Upstream fix: NICMx/Jool PR #441
# (not yet in a release). This script applies that patch to the installed
# jool-dkms source, rebuilds the module for the running kernel, repairs the
# dpkg/apt state, and finishes the NAT64 configuration that install.sh
# skipped when the module was unavailable.
#
# Usage:  sudo bash fix-jool.sh
# Safe to re-run: the patch is skipped if already applied.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }

[[ $EUID -eq 0 ]] || error "Run as root:  sudo bash fix-jool.sh"

JOOL_PREFIX="64:ff9b::/96"
KVER=$(uname -r)

# ── Locate the jool-dkms source ───────────────────────────────────────────────
JOOL_SRC=$(ls -d /usr/src/jool-* 2>/dev/null | sort -V | tail -1 || true)
[[ -n "$JOOL_SRC" && -d "$JOOL_SRC" ]] \
  || error "No jool source found in /usr/src — install jool-dkms first (apt-get install jool-dkms)."
JOOL_VER=${JOOL_SRC##*/jool-}
TARGET="$JOOL_SRC/src/mod/common/rfc7915/6to4.c"
[[ -f "$TARGET" ]] || error "Expected source file not found: $TARGET"

info "Found Jool $JOOL_VER source at $JOOL_SRC (running kernel: $KVER)"

# ── Apply the PR #441 patch (flowi4_tos -> flowi4_dscp on kernel >= 6.18) ─────
if grep -q 'flowi4_dscp' "$TARGET"; then
  ok "Patch already applied — skipping."
else
  info "Applying NICMx/Jool PR #441 patch..."
  PATCH_FILE=$(mktemp)
  cat > "$PATCH_FILE" <<'EOF'
--- a/src/mod/common/rfc7915/6to4.c
+++ b/src/mod/common/rfc7915/6to4.c
@@ -203,7 +203,11 @@ static verdict compute_flowix64(struct xlation *state)
 	hdr6 = pkt_ip6_hdr(&state->in);
 
 	flow4->flowi4_mark = state->in.skb->mark;
+#if LINUX_VERSION_AT_LEAST(6, 18, 0, 0, 0)
+	flow4->flowi4_dscp = xlat_tos(&state->jool.globals, hdr6);
+#else
 	flow4->flowi4_tos = xlat_tos(&state->jool.globals, hdr6);
+#endif
 	flow4->flowi4_scope = RT_SCOPE_UNIVERSE;
 	flow4->flowi4_proto = xlat_proto(hdr6);
 	/*
@@ -645,7 +649,11 @@ static verdict ttp64_ipv4_external(struct xlation *state)
 
 	hdr4->version = 4;
 	hdr4->ihl = 5;
+#if LINUX_VERSION_AT_LEAST(6, 18, 0, 0, 0)
+	hdr4->tos = flow4->flowi4_dscp;
+#else
 	hdr4->tos = flow4->flowi4_tos;
+#endif
 	hdr4->tot_len = cpu_to_be16(state->out.skb->len);
 	generate_ipv4_id(state, hdr4, hdr_frag);
 	hdr4->frag_off = xlat_frag_off(hdr_frag, state);
EOF
  if patch -p1 -d "$JOOL_SRC" --dry-run < "$PATCH_FILE" >/dev/null 2>&1; then
    patch -p1 -d "$JOOL_SRC" < "$PATCH_FILE"
    ok "Patch applied."
  else
    rm -f "$PATCH_FILE"
    error "Patch did not apply cleanly to Jool $JOOL_VER — the source may differ. See https://github.com/NICMx/Jool/pull/441"
  fi
  rm -f "$PATCH_FILE"
fi

# ── Rebuild the module for the running kernel ─────────────────────────────────
info "Rebuilding Jool $JOOL_VER for kernel $KVER (this takes a few minutes)..."
dkms remove  "jool/$JOOL_VER" -k "$KVER" 2>/dev/null || true
dkms build   "jool/$JOOL_VER" -k "$KVER"
dkms install "jool/$JOOL_VER" -k "$KVER"
ok "Module built and installed."

# ── Repair dpkg state (jool-dkms postinst failed during apt install) ──────────
info "Repairing dpkg/apt state..."
dpkg --configure -a || warn "dpkg --configure -a reported issues — check 'dkms status' for other kernels."

# ── Load and verify ───────────────────────────────────────────────────────────
info "Loading Jool module..."
modprobe jool
[[ -d /sys/module/jool ]] || error "Module built but failed to load — check: journalctl -k | tail -20"
ok "Jool module loaded."

# ── Finish the NAT64 config install.sh skipped ────────────────────────────────
info "Configuring NAT64 instance (prefix $JOOL_PREFIX)..."
grep -qxF 'jool' /etc/modules || echo 'jool' >> /etc/modules
jool instance add "default" --netfilter --pool6 "$JOOL_PREFIX" 2>/dev/null \
  || warn "Jool instance already exists — leaving it as-is."

cat > /etc/rc.local <<EOF
#!/bin/bash
modprobe jool
jool instance add "default" --netfilter --pool6 $JOOL_PREFIX 2>/dev/null || true
exit 0
EOF
chmod +x /etc/rc.local

echo ""
ok "NAT64 is active. Verify with:  jool instance display"
warn "Note: a future kernel upgrade may hit the same problem until Jool ships"
warn "a release containing PR #441 — re-run this script if NAT64 stops loading."
