#!/usr/bin/env python3
"""pi-nat64 - NAT64/DNS64 management web UI."""

import collections
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    print("WARNING: SECRET_KEY is not set — generating an ephemeral key. "
          "All sessions will be invalidated on restart. "
          "Set SECRET_KEY in /etc/pi-nat64/secret.env for a stable key.",
          file=sys.stderr)
    _secret = secrets.token_hex(32)
app.secret_key = _secret

# TLS is enabled when the systemd unit provides a cert+key (see install.sh).
# The Secure cookie flag is tied to it so HTTP-only fallback still allows login.
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY  = os.environ.get("TLS_KEY", "")
_TLS_ENABLED = bool(TLS_CERT and TLS_KEY and os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY))

# Enforce secure session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_TLS_ENABLED,   # only send cookie over HTTPS when TLS is on
    PERMANENT_SESSION_LIFETIME=3600,       # 1-hour session timeout
    MAX_CONTENT_LENGTH=64 * 1024,          # every API body is tiny
)

# ---------------------------------------------------------------------------
# Config paths
# ---------------------------------------------------------------------------
_IFACE_RE           = re.compile(r'^[a-zA-Z0-9_.-]{1,15}$')
AP_IFACE            = os.environ.get("AP_IFACE", "wlan0")
WAN_IFACE           = os.environ.get("WAN_IFACE", "eth0")
if not (_IFACE_RE.match(AP_IFACE) and _IFACE_RE.match(WAN_IFACE)):
    sys.exit("AP_IFACE / WAN_IFACE contain invalid characters")

HOSTAPD_CONF        = "/etc/hostapd/hostapd.conf"
HOSTAPD_DENY_FILE   = "/etc/hostapd/hostapd.deny"
JOOL_PREFIX         = "64:ff9b::/96"
PORT_RULES_FILE     = "/etc/pi-nat64/port-rules.json"
ADMIN_PASSWORD_FILE = "/etc/pi-nat64/admin.passwd"
VERSION_FILE        = "/etc/pi-nat64/version.json"
UPDATE_LOG          = "/var/log/pi-nat64-update.log"
PIHOLE_GRAVITY_DB    = "/etc/pihole/gravity.db"
PIHOLE_FTL_DB        = "/etc/pihole/pihole-FTL.db"   # long-term query DB (v6)
BLOCKED_CLIENTS_FILE = "/etc/pi-nat64/blocked-clients.json"
DNSMASQ_LEASES       = "/var/lib/misc/dnsmasq.leases"

# FTL query "status" values that count as blocked (Pi-hole v6):
# https://docs.pi-hole.net/database/query-database/ — 17 is "stale cache"
# (allowed), 18 is "blocked upstream (EDE 15)".
_FTL_BLOCKED_STATUS = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)

# External ports the gateway itself serves — never allow a port-forward to
# shadow them (SSH, DNS, the web UI, Unbound, FTL's web server).
_RESERVED_PORTS = {22, 53, 80, 443, 5335, 8053}

# Allowlists / validators
_VALID_PROTO = {"TCP", "UDP"}
_MAC_RE      = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
_SIGNAL_RE   = re.compile(r'signal:\s+(-?\d+)')
_URL_RE      = re.compile(r'^https?://[^\s<>"\'`\\{}|\[\]^]{1,2000}$')
# Detect a valid SHA-256 hex digest (exactly 64 lowercase hex chars)
_HASH_RE     = re.compile(r'^[0-9a-f]{64}$')
# Valid hostname / domain label (no wildcards, no shell chars)
_DOMAIN_RE   = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

# Serialises every load → modify → save of the JSON state files and the
# matching iptables changes (the server is threaded).
_state_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Subprocess helpers — list args only, never shell=True, always a timeout
# ---------------------------------------------------------------------------

def _run(args: list, timeout: int = 20) -> int:
    """Run a command, return its exit code (non-zero on timeout/missing)."""
    try:
        return subprocess.run(args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _run_safe(args: list, default: str = "", timeout: int = 10) -> str:
    """Run a command and return its stdout, or `default` on any failure."""
    try:
        return subprocess.run(args, capture_output=True, text=True, check=True,
                              timeout=timeout).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return default


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

class BadRequest(Exception):
    pass


@app.errorhandler(BadRequest)
def _bad_request(exc):
    return jsonify({"error": str(exc)}), 400


@app.errorhandler(413)
def _too_large(_exc):
    return jsonify({"error": "Request too large"}), 413


def _json_body() -> dict:
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        raise BadRequest("Expected a JSON object")
    return data


def _str_field(data: dict, key: str, default: str = "") -> str:
    val = data.get(key, default)
    if val is None:
        return default
    if not isinstance(val, str):
        raise BadRequest(f"'{key}' must be a string")
    return val


def _int_field(data: dict, key: str) -> int:
    val = data.get(key)
    if isinstance(val, bool):
        raise BadRequest(f"Invalid {key}")
    try:
        return int(val)
    except (TypeError, ValueError):
        raise BadRequest(f"Invalid {key}")


# ---------------------------------------------------------------------------
# Login rate limiting (in-memory)
# ---------------------------------------------------------------------------
_login_attempts: dict = {}
_MAX_ATTEMPTS    = 10
_LOCKOUT_SECS    = 60
_MAX_TRACKED_IPS = 4096   # bound the table so failed logins can't exhaust memory
# Global cap: a LAN attacker can rotate through a whole IPv6 /64 (SLAAC), so
# also limit total failures across all sources.
_GLOBAL_MAX_FAILS = 30
_global_fails: collections.deque = collections.deque()


def _rate_key(ip: str) -> str:
    """Rate-limit IPv6 clients per /64, IPv4 per address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    while _global_fails and _global_fails[0] < now - _LOCKOUT_SECS:
        _global_fails.popleft()
    if len(_global_fails) >= _GLOBAL_MAX_FAILS:
        return False
    key = _rate_key(ip)
    entry = _login_attempts.get(key)
    if entry and entry["count"] >= _MAX_ATTEMPTS:
        if now < entry["reset_at"]:
            return False
        del _login_attempts[key]
    return True


def _record_failed_login(ip: str):
    now = time.monotonic()
    _global_fails.append(now)
    key = _rate_key(ip)
    # Bound the table: if full and this is a new key, evict the entry nearest expiry
    if key not in _login_attempts and len(_login_attempts) >= _MAX_TRACKED_IPS:
        oldest = min(_login_attempts, key=lambda k: _login_attempts[k]["reset_at"])
        del _login_attempts[oldest]
    entry = _login_attempts.setdefault(key, {"count": 0, "reset_at": 0.0})
    entry["count"] += 1
    entry["reset_at"] = now + _LOCKOUT_SECS


def _clear_login_attempts(ip: str):
    _login_attempts.pop(_rate_key(ip), None)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

# Salted scrypt (stdlib, memory-hard) — format: "scrypt$<salt_hex>$<key_hex>".
# Legacy formats (bare 64-hex SHA-256 or plain text) are still accepted and
# transparently upgraded to scrypt on the next successful login.
_SCRYPT_N     = 16384   # CPU/memory cost (2^14) — light enough for a Pi
_SCRYPT_R     = 8
_SCRYPT_P     = 1
_SCRYPT_DKLEN = 32


def _scrypt_hash(password: str, salt: bytes) -> str:
    key = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N,
                         r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"scrypt${salt.hex()}${key.hex()}"


def _hash_password(password: str) -> str:
    """Return a fresh salted scrypt hash for a new/changed password."""
    return _scrypt_hash(password, os.urandom(16))


def load_password_hash():
    """Stored hash, or None when no password file exists (login disabled —
    there is deliberately no built-in default password)."""
    try:
        with open(ADMIN_PASSWORD_FILE) as f:
            return f.read().strip() or None
    except OSError:
        return None


def _write_password_hash(h: str):
    os.makedirs(os.path.dirname(ADMIN_PASSWORD_FILE), exist_ok=True)
    tmp = ADMIN_PASSWORD_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            f.write(h)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ADMIN_PASSWORD_FILE)  # atomic
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _verify_password(candidate: str, stored: str) -> bool:
    """Constant-time verify against scrypt, legacy SHA-256, or legacy plaintext."""
    if stored.startswith("scrypt$"):
        try:
            _, salt_hex, _key_hex = stored.split("$", 2)
            calc = _scrypt_hash(candidate, bytes.fromhex(salt_hex))
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(calc, stored)
    if _HASH_RE.match(stored):   # legacy bare SHA-256 (64 hex chars)
        legacy = hashlib.sha256(candidate.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    return hmac.compare_digest(candidate, stored)   # legacy plaintext


def _check_password(candidate: str) -> bool:
    stored = load_password_hash()
    if stored is None or not _verify_password(candidate, stored):
        return False
    # Upgrade any legacy (non-scrypt) hash to salted scrypt on successful login
    if not stored.startswith("scrypt$"):
        try:
            _write_password_hash(_hash_password(candidate))
        except Exception:
            pass
    return True


def _pw_fingerprint() -> str:
    """Changes whenever the admin password changes — stored in the session so
    changing the password logs out every other session."""
    stored = load_password_hash() or ""
    return hashlib.sha256(stored.encode()).hexdigest()[:16]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in") or session.get("pw_fp") != _pw_fingerprint():
            session.clear()
            if request.path.startswith("/api/"):
                # JSON 401 instead of a redirect: fetch() would silently follow a
                # 302 to the login page and treat its HTML as a successful reply.
                return jsonify({"error": "Session expired — please log in again"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def _get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token  = request.headers.get("X-CSRF-Token", "")
        stored = session.get("csrf_token", "")
        if not stored or not hmac.compare_digest(token, stored):
            return jsonify({"error": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def _inject_csrf():
    if session.get("logged_in"):
        return {"csrf_token": _get_csrf_token()}
    return {"csrf_token": ""}


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or ""
        if not _check_rate_limit(ip):
            error = "Too many failed attempts. Try again later."
        elif load_password_hash() is None:
            error = ("No admin password is set. On the gateway run: "
                     "sudo python3 /opt/pi-nat64/web/app.py --set-password")
        elif _check_password(request.form.get("password", "")):
            _clear_login_attempts(ip)
            session.clear()                    # session fixation protection
            session["logged_in"] = True
            session["pw_fp"] = _pw_fingerprint()
            session["csrf_token"] = secrets.token_hex(32)
            session.permanent = True
            return redirect(url_for("index"))
        else:
            _record_failed_login(ip)
            error = "Wrong password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template("index.html", version=_local_version())


# ---------------------------------------------------------------------------
# API — status
# ---------------------------------------------------------------------------

@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "nat64_sessions":   _nat64_session_count(),
        "dns_queries":      _pihole_stats()["queries_today"],
        "ap_clients":       _ap_clients(),
        "jool_running":     _jool_active(),
        "unbound_running":  _service_active("unbound"),
        "hostapd_running":  _service_active("hostapd"),
        "pihole_running":   _service_active("pihole-FTL"),
    })


def _jool_active() -> bool:
    # Jool is a kernel module configured from rc.local/jool.service — there may
    # be no running service to ask. It is "up" when the module is loaded and the
    # default instance exists.
    return (os.path.isdir("/sys/module/jool")
            and _run(["jool", "-i", "default", "global", "display"], timeout=5) == 0)


def _nat64_session_count() -> int:
    # `jool session display` shows only the TCP table unless told otherwise.
    total = 0
    for proto in ("--tcp", "--udp", "--icmp"):
        out = _run_safe(["jool", "-i", "default", "session", "display", proto,
                         "--numeric", "--csv", "--no-headers"], "", timeout=5)
        total += sum(1 for line in out.splitlines() if line.strip())
    return total


def _ap_clients() -> int:
    out = _run_safe(["iw", "dev", AP_IFACE, "station", "dump"], "", timeout=5)
    return out.count("Station")


def _service_active(name: str) -> bool:
    # Allowlist service names to prevent injection through stored data
    if name not in ("unbound", "hostapd", "dnsmasq", "radvd", "pihole-FTL"):
        return False
    return _run(["systemctl", "is-active", "--quiet", name], timeout=5) == 0


# ---------------------------------------------------------------------------
# Pi-hole helpers (Pi-hole v6: the legacy FTL telnet/socket API was removed, so
# stats are read directly from the SQLite databases and the FTL config).
# ---------------------------------------------------------------------------

def _sqlite_ro(path: str):
    """Open a SQLite DB read-only (never locks/creates the file)."""
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)


def _today_start() -> int:
    """Unix timestamp for local midnight today."""
    t = time.localtime()
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)))


def _gravity_domain_count() -> int:
    """Number of domains on the active blocklists (gravity)."""
    try:
        with _sqlite_ro(PIHOLE_GRAVITY_DB) as db:
            # gravity writes its count into `info` — COUNT(*) scans millions of rows
            row = db.execute("SELECT value FROM info WHERE property='gravity_count'").fetchone()
            if row and str(row[0]).lstrip("-").isdigit():
                return max(int(row[0]), 0)
            return int(db.execute("SELECT COUNT(*) FROM gravity").fetchone()[0])
    except Exception:
        return 0


def _blocking_active() -> str:
    """Blocking state: 'enabled' | 'disabled' | 'unknown'.

    `pihole status` reflects the live state (including a timed `pihole disable`);
    the FTL config key is only a fallback."""
    out = _run_safe(["pihole", "status"], "", timeout=10).lower()
    if "blocking is enabled" in out:
        return "enabled"
    if "blocking is disabled" in out:
        return "disabled"
    cfg = _run_safe(["pihole-FTL", "--config", "dns.blocking.active"], "", timeout=5).lower()
    return {"true": "enabled", "false": "disabled"}.get(cfg, "unknown")


def _pihole_stats() -> dict:
    """Today's query/blocked totals from FTL's long-term query database."""
    stats = {"queries_today": 0, "blocked_today": 0, "block_pct": 0.0}
    since = _today_start()
    marks = ",".join("?" * len(_FTL_BLOCKED_STATUS))
    try:
        with _sqlite_ro(PIHOLE_FTL_DB) as db:
            total = int(db.execute(
                "SELECT COUNT(*) FROM queries WHERE timestamp >= ?", (since,)
            ).fetchone()[0])
            blocked = int(db.execute(
                f"SELECT COUNT(*) FROM queries WHERE timestamp >= ? AND status IN ({marks})",
                (since, *_FTL_BLOCKED_STATUS),
            ).fetchone()[0])
    except Exception:
        return stats
    stats["queries_today"] = total
    stats["blocked_today"] = blocked
    stats["block_pct"]     = round(100.0 * blocked / total, 1) if total else 0.0
    return stats


def _pihole_top_blocked(n: int = 10) -> list:
    """Top blocked domains today, from FTL's long-term query database."""
    since = _today_start()
    marks = ",".join("?" * len(_FTL_BLOCKED_STATUS))
    try:
        with _sqlite_ro(PIHOLE_FTL_DB) as db:
            rows = db.execute(
                f"SELECT domain, COUNT(*) AS c FROM queries "
                f"WHERE timestamp >= ? AND status IN ({marks}) "
                f"GROUP BY domain ORDER BY c DESC LIMIT ?",
                (since, *_FTL_BLOCKED_STATUS, n),
            ).fetchall()
        return [{"rank": i + 1, "count": int(r[1]), "domain": r[0]} for i, r in enumerate(rows)]
    except Exception:
        return []


def _pihole_reload_lists():
    """Make FTL pick up allow/deny list changes written to gravity.db."""
    _run(["pihole", "reloadlists"], timeout=60)


# ---------------------------------------------------------------------------
# API — port forwarding
# ---------------------------------------------------------------------------

def _load_rules() -> list:
    try:
        with open(PORT_RULES_FILE) as f:
            rules = json.load(f)
        return rules if isinstance(rules, list) else []
    except (OSError, ValueError):
        return []


def _save_rules(rules: list):
    os.makedirs(os.path.dirname(PORT_RULES_FILE), exist_ok=True)
    tmp = PORT_RULES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rules, f, indent=2)
    os.replace(tmp, PORT_RULES_FILE)   # atomic write


def _normalize_ipv6(addr: str):
    """Return the compressed form of a routable unicast IPv6 address, else None."""
    try:
        ip = ipaddress.IPv6Address(addr.strip())
    except ValueError:
        return None
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return None
    return ip.compressed


def _rule_spec(rule: dict, legacy: bool = False) -> list:
    """ip6tables DNAT match/target for a rule. Only traffic arriving on the WAN
    interface is forwarded — without `-i` the DNAT also hijacked the AP clients'
    own outbound connections to that port (and traffic to the gateway itself).
    `legacy` builds the pre-fix spec so old rules can still be removed."""
    spec = ["PREROUTING"]
    if not legacy:
        spec += ["-i", WAN_IFACE]
    spec += ["-p", rule["proto"].lower(), "--dport", str(int(rule["ext_port"])),
             "-j", "DNAT", "--to-destination",
             f"[{rule['dest_ip']}]:{int(rule['dest_port'])}"]
    return spec


def _rule_present(rule: dict, legacy: bool = False) -> bool:
    return _run(["ip6tables", "-t", "nat", "-C", *_rule_spec(rule, legacy)]) == 0


def _rule_enable(rule: dict) -> bool:
    if not _rule_present(rule):
        if _run(["ip6tables", "-t", "nat", "-A", *_rule_spec(rule)]) != 0:
            return False
    return True


def _rule_disable(rule: dict) -> bool:
    """Remove every copy of the rule (current and legacy form). A rule that is
    already missing counts as removed, so the UI can never get stuck."""
    for legacy in (False, True):
        for _ in range(16):
            if not _rule_present(rule, legacy):
                break
            if _run(["ip6tables", "-t", "nat", "-D", *_rule_spec(rule, legacy)]) != 0:
                return False
    return True


def _persist_firewall():
    _run(["netfilter-persistent", "save"], timeout=30)


@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules_get():
    return jsonify(_load_rules())


@app.route("/api/rules", methods=["POST"])
@login_required
@csrf_required
def api_rules_add():
    data = _json_body()
    name  = _str_field(data, "name").strip()[:64]
    proto = _str_field(data, "proto").upper()
    if not name:
        raise BadRequest("Name is required")
    if proto not in _VALID_PROTO:
        raise BadRequest("proto must be TCP or UDP")

    ports = {}
    for field in ("ext_port", "dest_port"):
        p = _int_field(data, field)
        if not 1 <= p <= 65535:
            raise BadRequest(f"Invalid port: {field}")
        ports[field] = p
    if ports["ext_port"] in _RESERVED_PORTS:
        raise BadRequest(f"External port {ports['ext_port']} is used by the gateway itself")

    dest_ip = _normalize_ipv6(_str_field(data, "dest_ip"))
    if not dest_ip:
        raise BadRequest("Invalid IPv6 destination address")

    with _state_lock:
        rules = _load_rules()
        if any(r["proto"] == proto and r["ext_port"] == ports["ext_port"] for r in rules):
            return jsonify({"error": f"{proto} port {ports['ext_port']} is already forwarded"}), 409
        rule = {
            "id":        max((r["id"] for r in rules), default=0) + 1,
            "name":      name,
            "proto":     proto,
            "ext_port":  ports["ext_port"],
            "dest_ip":   dest_ip,
            "dest_port": ports["dest_port"],
            "enabled":   True,
        }
        if not _rule_enable(rule):
            return jsonify({"error": "Failed to apply ip6tables rule — is ip6table_nat loaded?"}), 500
        rules.append(rule)
        _save_rules(rules)
        _persist_firewall()
    return jsonify(rule), 201


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_rules_delete(rule_id):
    with _state_lock:
        rules = _load_rules()
        target = next((r for r in rules if r["id"] == rule_id), None)
        if not target:
            return jsonify({"error": "Not found"}), 404
        if not _rule_disable(target):
            return jsonify({"error": "Failed to remove ip6tables rule"}), 500
        _save_rules([r for r in rules if r["id"] != rule_id])
        _persist_firewall()
    return jsonify({"deleted": rule_id})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
@csrf_required
def api_rules_toggle(rule_id):
    with _state_lock:
        rules = _load_rules()
        target = next((r for r in rules if r["id"] == rule_id), None)
        if not target:
            return jsonify({"error": "Not found"}), 404
        if target["enabled"]:
            if not _rule_disable(target):
                return jsonify({"error": "Failed to remove ip6tables rule"}), 500
            target["enabled"] = False
        else:
            if not _rule_enable(target):
                return jsonify({"error": "Failed to apply ip6tables rule"}), 500
            target["enabled"] = True
        _save_rules(rules)
        _persist_firewall()
    return jsonify(target)


# ---------------------------------------------------------------------------
# API — settings
# ---------------------------------------------------------------------------

# Strict allowlist for hostapd keys the UI is allowed to write.
# "wpa" is intentionally excluded — toggling encryption mode requires
# deliberate manual config, not a single API field.
_HOSTAPD_ALLOWED_KEYS = {
    "interface", "driver", "ssid", "hw_mode", "channel",
    "ieee80211n", "wmm_enabled", "wpa_passphrase",
    "wpa_key_mgmt", "rsn_pairwise", "country_code",
}

# Channels valid per band (EU/DE regulatory domain, non-DFS for 5 GHz).
_CHANNELS = {
    "g": set(range(1, 14)),
    "b": set(range(1, 14)),
    "a": {36, 40, 44, 48},
}


def _read_hostapd() -> dict:
    cfg = {}
    try:
        with open(HOSTAPD_CONF) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    k = k.strip()
                    if k in _HOSTAPD_ALLOWED_KEYS:
                        cfg[k] = v.strip()
    except OSError:
        pass
    return cfg


def _write_hostapd(updates: dict) -> bool:
    """Apply allowlisted key changes to hostapd.conf and restart hostapd.
    Rolls back to the previous file if hostapd refuses to start. Returns success."""
    # The UI may only change allowlisted keys, but the rest of the file
    # (wpa=2, ieee80211w, wps_state, comments, …) MUST be preserved — rewriting
    # from the allowlist alone would silently drop wpa=2 and open the network.
    updates = {k: v for k, v in updates.items() if k in _HOSTAPD_ALLOWED_KEYS}

    try:
        with open(HOSTAPD_CONF) as f:
            original = f.read()
    except OSError:
        original = ""

    seen, out = set(), []
    for line in original.splitlines():
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        out.append(line)
    # Append any allowlisted keys that weren't already present in the file
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")

    def _install(content: str):
        tmp = HOSTAPD_CONF + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o600)     # contains the WPA passphrase
        os.replace(tmp, HOSTAPD_CONF)

    _install("\n".join(out) + "\n")
    if _run(["systemctl", "restart", "hostapd"], timeout=30) == 0:
        return True
    if original:
        _install(original)
        _run(["systemctl", "restart", "hostapd"], timeout=30)
    return False


@app.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    ap = _read_hostapd()
    return jsonify({
        "ssid":            ap.get("ssid", "pi-nat64"),
        "channel":         ap.get("channel", "6"),
        "hw_mode":         ap.get("hw_mode", "g"),
        "wpa_passphrase":  "••••••••",   # never expose
        "jool_prefix":     JOOL_PREFIX,
        "upstream_dns":    "2606:4700:4700::1111",
    })


def _sanitize_ssid(s: str) -> str:
    """Allow printable ASCII excluding shell-special characters."""
    return re.sub(r'[^\x20-\x7E]', '', s)[:32]


@app.route("/api/settings", methods=["POST"])
@login_required
@csrf_required
def api_settings_save():
    data = _json_body()
    current = _read_hostapd()
    changes = {}

    # ── Validate EVERYTHING before touching anything, so a rejected field can't
    #    leave the settings half-applied.
    if "ssid" in data:
        ssid = _sanitize_ssid(_str_field(data, "ssid"))
        if not ssid:
            raise BadRequest("SSID cannot be empty")
        if ssid != current.get("ssid"):
            changes["ssid"] = ssid

    if "channel" in data and str(data["channel"]).strip() != "":
        ch = _int_field(data, "channel")
        band = current.get("hw_mode", "g")
        allowed = _CHANNELS.get(band, _CHANNELS["g"])
        if ch not in allowed:
            raise BadRequest(f"Channel {ch} is not valid for hw_mode={band} "
                             f"(allowed: {', '.join(map(str, sorted(allowed)))})")
        if str(ch) != current.get("channel"):
            changes["channel"] = str(ch)

    pw = _str_field(data, "wpa_passphrase")
    if pw not in ("", "••••••••"):
        if len(pw) < 8 or len(pw) > 63:
            raise BadRequest("Passphrase must be 8–63 characters")
        # WPA2 passphrase: printable ASCII excluding '#' (hostapd treats it as comment)
        if not re.match(r'^[\x20-\x22\x24-\x7E]+$', pw):
            raise BadRequest("Passphrase contains invalid characters (# not allowed)")
        if pw != current.get("wpa_passphrase"):
            changes["wpa_passphrase"] = pw

    new_admin = _str_field(data, "new_password")
    if new_admin:
        if len(new_admin) < 8:
            raise BadRequest("Admin password must be at least 8 characters")
        stored = load_password_hash()
        if stored is None or not _verify_password(_str_field(data, "current_password"), stored):
            return jsonify({"error": "Current admin password is incorrect"}), 403

    # ── Apply
    if new_admin:
        _write_password_hash(_hash_password(new_admin))
        session["pw_fp"] = _pw_fingerprint()   # keep THIS session; others are logged out

    ap_restarted = False
    if changes:
        # Only restart hostapd (which drops every Wi-Fi client) when an AP
        # setting actually changed.
        if not _write_hostapd(changes):
            return jsonify({"error": "hostapd rejected the new settings — previous "
                                     "configuration restored"}), 500
        ap_restarted = True

    return jsonify({"ok": True, "ap_restarted": ap_restarted})


# ---------------------------------------------------------------------------
# API — Pi-hole
# ---------------------------------------------------------------------------

@app.route("/api/pihole/stats")
@login_required
def api_pihole_stats():
    s = _pihole_stats()
    return jsonify({
        "domains_blocked": _gravity_domain_count(),
        "queries_today":   s["queries_today"],
        "blocked_today":   s["blocked_today"],
        "block_pct":       s["block_pct"],
        "status":          _blocking_active(),
    })


@app.route("/api/pihole/top-blocked")
@login_required
def api_pihole_top_blocked():
    return jsonify(_pihole_top_blocked())


@app.route("/api/reboot", methods=["POST"])
@login_required
@csrf_required
def api_reboot():
    # Popen instead of call so the HTTP response is sent before the system goes down
    subprocess.Popen(["systemctl", "reboot"])
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# API — connected clients
# ---------------------------------------------------------------------------

def _load_blocked_clients() -> set:
    try:
        with open(BLOCKED_CLIENTS_FILE) as f:
            macs = json.load(f)
        return {m for m in macs if isinstance(m, str) and _MAC_RE.match(m)}
    except (OSError, ValueError, TypeError):
        return set()


def _save_blocked_clients(macs: set):
    os.makedirs(os.path.dirname(BLOCKED_CLIENTS_FILE), exist_ok=True)
    tmp = BLOCKED_CLIENTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(macs), f, indent=2)
    os.replace(tmp, BLOCKED_CLIENTS_FILE)
    # hostapd's deny list (deny_mac_file in hostapd.conf) — survives restarts
    try:
        tmp = HOSTAPD_DENY_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write("".join(m + "\n" for m in sorted(macs)))
        os.replace(tmp, HOSTAPD_DENY_FILE)
    except OSError:
        pass


def _get_stations() -> list:
    """Parse `iw dev <ap> station dump` into a list of dicts."""
    out = _run_safe(["iw", "dev", AP_IFACE, "station", "dump"], "", timeout=5)
    stations, cur = [], {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Station "):
            if cur:
                stations.append(cur)
            cur = {"mac": line.split()[1].lower()}
        elif line.startswith("signal:"):
            m = _SIGNAL_RE.search(line)
            if m:
                cur["signal"] = int(m.group(1))
        elif line.startswith("tx bytes:"):
            try:
                cur["tx_bytes"] = int(line.split()[-1])
            except ValueError:
                pass
        elif line.startswith("rx bytes:"):
            try:
                cur["rx_bytes"] = int(line.split()[-1])
            except ValueError:
                pass
        elif line.startswith("connected time:"):
            try:
                cur["connected_sec"] = int(line.split()[-2])
            except (ValueError, IndexError):
                pass
    if cur:
        stations.append(cur)
    return stations


def _get_leases() -> dict:
    """Return {mac: {ip, hostname}} from dnsmasq leases file."""
    leases = {}
    try:
        with open(DNSMASQ_LEASES) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and _MAC_RE.match(parts[1].lower()):
                    leases[parts[1].lower()] = {
                        "ip":       parts[2],
                        "hostname": parts[3] if parts[3] != "*" else "",
                    }
    except OSError:
        pass
    return leases


@app.route("/api/clients")
@login_required
def api_clients():
    stations = _get_stations()
    leases   = _get_leases()
    blocked  = _load_blocked_clients()
    clients  = []

    for s in stations:
        mac    = s["mac"]
        lease  = leases.get(mac, {})
        clients.append({
            "mac":           mac,
            "ip":            lease.get("ip", ""),
            "hostname":      lease.get("hostname", ""),
            "signal":        s.get("signal"),
            "tx_bytes":      s.get("tx_bytes"),
            "rx_bytes":      s.get("rx_bytes"),
            "connected_sec": s.get("connected_sec"),
            "online":        True,
            "blocked":       mac in blocked,
        })

    # Include blocked-but-offline clients so they can be unblocked from the UI
    seen = {c["mac"] for c in clients}
    for mac in sorted(blocked - seen):
        lease = leases.get(mac, {})
        clients.append({
            "mac":           mac,
            "ip":            lease.get("ip", ""),
            "hostname":      lease.get("hostname", ""),
            "signal":        None,
            "tx_bytes":      None,
            "rx_bytes":      None,
            "connected_sec": None,
            "online":        False,
            "blocked":       True,
        })

    return jsonify(clients)


def _mac_valid(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _apply_client_block(mac: str, block: bool):
    """Drop everything from `mac` in the raw table's PREROUTING.

    Jool (netfilter mode) translates packets at PREROUTING, so NAT64 traffic
    never traverses FORWARD — a FORWARD rule missed exactly the traffic this
    gateway exists for. raw/PREROUTING runs before Jool and before INPUT, so it
    also stops the client's DNS and web-UI access to the gateway itself.
    Idempotent: existing rules (and legacy FORWARD ones) are cleared first."""
    for ipt in ("iptables", "ip6tables"):
        for table, chain in (("filter", "FORWARD"), ("raw", "PREROUTING")):
            for _ in range(16):
                if _run([ipt, "-t", table, "-D", chain, "-m", "mac",
                         "--mac-source", mac, "-j", "DROP"]) != 0:
                    break   # no more matching rules
        if block:
            _run([ipt, "-t", "raw", "-I", "PREROUTING", "-m", "mac",
                  "--mac-source", mac, "-j", "DROP"])
    # hostapd: refuse (re)association, and kick the client off right now
    _run(["hostapd_cli", "-i", AP_IFACE, "deny_acl",
          "ADD_MAC" if block else "DEL_MAC", mac], timeout=5)
    if block:
        _run(["hostapd_cli", "-i", AP_IFACE, "deauthenticate", mac], timeout=5)


@app.route("/api/clients/block", methods=["POST"])
@login_required
@csrf_required
def api_client_block():
    mac = _str_field(_json_body(), "mac").strip().lower()
    if not _mac_valid(mac):
        raise BadRequest("Invalid MAC address")

    with _state_lock:
        _apply_client_block(mac, block=True)
        _persist_firewall()
        blocked = _load_blocked_clients()
        blocked.add(mac)
        _save_blocked_clients(blocked)
    return jsonify({"mac": mac, "blocked": True})


@app.route("/api/clients/unblock", methods=["POST"])
@login_required
@csrf_required
def api_client_unblock():
    mac = _str_field(_json_body(), "mac").strip().lower()
    if not _mac_valid(mac):
        raise BadRequest("Invalid MAC address")

    with _state_lock:
        _apply_client_block(mac, block=False)
        _persist_firewall()
        blocked = _load_blocked_clients()
        blocked.discard(mac)
        _save_blocked_clients(blocked)
    return jsonify({"mac": mac, "blocked": False})


@app.route("/api/pihole/toggle", methods=["POST"])
@login_required
@csrf_required
def api_pihole_toggle():
    current = _blocking_active()
    cmd = ["pihole", "disable"] if current == "enabled" else ["pihole", "enable"]
    if _run(cmd, timeout=30) != 0:
        return jsonify({"error": "Failed to toggle Pi-hole blocking"}), 500
    return jsonify({"status": _blocking_active()})


# ---------------------------------------------------------------------------
# Pi-hole gravity / adlists / allowlist
# ---------------------------------------------------------------------------

_gravity_proc = None


def _gravity_running() -> bool:
    return _gravity_proc is not None and _gravity_proc.poll() is None


def _gravity_busy_response():
    # gravity rebuilds gravity.db in a temp copy and swaps it in — writes made
    # meanwhile would be lost.
    return jsonify({"error": "A gravity update is running — try again when it finishes"}), 409


def _validate_domain(domain: str) -> bool:
    return bool(domain) and len(domain) <= 253 and bool(_DOMAIN_RE.match(domain))


def _pihole_whitelist_read() -> list:
    """Exact-match allowlist from Pi-hole's gravity DB (domainlist type=0)."""
    try:
        with _sqlite_ro(PIHOLE_GRAVITY_DB) as db:
            rows = db.execute(
                "SELECT domain FROM domainlist WHERE type=0 ORDER BY domain"
            ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


def _adlist_read() -> list:
    try:
        with _sqlite_ro(PIHOLE_GRAVITY_DB) as db:
            rows = db.execute(
                "SELECT id, address, enabled, comment, COALESCE(number, 0) "
                "FROM adlist ORDER BY address"
            ).fetchall()
        return [
            {"id": r[0], "url": r[1], "enabled": bool(r[2]),
             "comment": r[3] or "", "domains": r[4]}
            for r in rows
        ]
    except Exception:
        return []


@app.route("/api/pihole/adlists", methods=["GET"])
@login_required
def api_adlists_get():
    return jsonify(_adlist_read())


@app.route("/api/pihole/adlists", methods=["POST"])
@login_required
@csrf_required
def api_adlists_add():
    data    = _json_body()
    url     = _str_field(data, "url").strip()
    comment = _str_field(data, "comment").strip()[:255]

    if not _URL_RE.match(url):
        raise BadRequest("Invalid URL — must start with http:// or https://")
    if _gravity_running():
        return _gravity_busy_response()

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB, timeout=5) as db:
            db.execute(
                "INSERT INTO adlist (address, enabled, date_added, comment) VALUES (?, 1, ?, ?)",
                (url, int(time.time()), comment),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "This URL is already in your adlists"}), 409
    except Exception:
        return jsonify({"error": "Database error — is Pi-hole installed?"}), 500

    return jsonify({"ok": True, "url": url}), 201


@app.route("/api/pihole/adlists", methods=["DELETE"])
@login_required
@csrf_required
def api_adlists_delete():
    adlist_id = _int_field(_json_body(), "id")
    if _gravity_running():
        return _gravity_busy_response()

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB, timeout=5) as db:
            db.execute("DELETE FROM adlist WHERE id = ?", (adlist_id,))
    except Exception:
        return jsonify({"error": "Database error"}), 500

    return jsonify({"ok": True, "deleted": adlist_id})


@app.route("/api/pihole/adlists/toggle", methods=["POST"])
@login_required
@csrf_required
def api_adlists_toggle():
    adlist_id = _int_field(_json_body(), "id")
    if _gravity_running():
        return _gravity_busy_response()

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB, timeout=5) as db:
            row = db.execute(
                "SELECT enabled FROM adlist WHERE id = ?", (adlist_id,)
            ).fetchone()
            if not row:
                return jsonify({"error": "Adlist not found"}), 404
            new_state = 0 if row[0] else 1
            db.execute(
                "UPDATE adlist SET enabled = ?, date_modified = ? WHERE id = ?",
                (new_state, int(time.time()), adlist_id),
            )
    except Exception:
        return jsonify({"error": "Database error"}), 500

    return jsonify({"ok": True, "id": adlist_id, "enabled": bool(new_state)})


@app.route("/api/pihole/gravity", methods=["POST"])
@login_required
@csrf_required
def api_pihole_gravity():
    """Trigger `pihole -g` in the background; response returns before it finishes."""
    global _gravity_proc
    with _state_lock:
        if _gravity_running():
            return _gravity_busy_response()
        _gravity_proc = subprocess.Popen(
            ["pihole", "-g"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    return jsonify({"ok": True})


@app.route("/api/pihole/whitelist", methods=["GET"])
@login_required
def api_pihole_whitelist_get():
    return jsonify(_pihole_whitelist_read())


# The allowlist is written straight to gravity.db (like the adlists) and FTL is
# told to reload. This avoids the CLI, whose syntax changed in Pi-hole v6
# (`pihole -w` → `pihole allow`); the DB schema's insert trigger assigns new
# domains to the default group.
@app.route("/api/pihole/whitelist", methods=["POST"])
@login_required
@csrf_required
def api_pihole_whitelist_add():
    domain = _str_field(_json_body(), "domain").strip().lower()
    if not _validate_domain(domain):
        raise BadRequest("Invalid domain name")
    if _gravity_running():
        return _gravity_busy_response()
    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB, timeout=5) as db:
            db.execute(
                "INSERT INTO domainlist (type, domain, enabled, date_added, comment) "
                "VALUES (0, ?, 1, ?, 'added by pi-nat64')",
                (domain, int(time.time())),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Domain already whitelisted"}), 409
    except Exception:
        return jsonify({"error": "Database error — is Pi-hole installed?"}), 500
    _pihole_reload_lists()
    return jsonify({"domain": domain}), 201


@app.route("/api/pihole/whitelist", methods=["DELETE"])
@login_required
@csrf_required
def api_pihole_whitelist_remove():
    domain = _str_field(_json_body(), "domain").strip().lower()
    if not _validate_domain(domain):
        raise BadRequest("Invalid domain name")
    if _gravity_running():
        return _gravity_busy_response()
    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB, timeout=5) as db:
            cur = db.execute("DELETE FROM domainlist WHERE type=0 AND domain=?", (domain,))
    except Exception:
        return jsonify({"error": "Database error"}), 500
    if cur.rowcount == 0:
        return jsonify({"error": "Domain is not whitelisted"}), 404
    _pihole_reload_lists()
    return jsonify({"deleted": domain})


# ---------------------------------------------------------------------------
# API — software update
# ---------------------------------------------------------------------------
# install.sh records the deployed commit and the git checkout it came from in
# VERSION_FILE. "Update available" means origin/<branch> has commits the
# deployed version doesn't; applying runs update.sh (git pull + install.sh
# --upgrade) in a transient systemd unit so it survives this service being
# restarted halfway through.

_UPDATE_UNIT = "pi-nat64-update"
_update_cache = {"at": 0.0, "result": None}
_UPDATE_CACHE_SECS = 3600
_SHA_RE = re.compile(r'^[0-9a-f]{7,40}$')


def _version_info() -> dict:
    try:
        with open(VERSION_FILE) as f:
            info = json.load(f)
        return info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        return {}


def _local_version() -> dict:
    info = _version_info()
    commit = str(info.get("commit", ""))
    return {
        "commit":   commit[:7] if _SHA_RE.match(commit) else "",
        "date":     str(info.get("date", ""))[:25],
        "branch":   str(info.get("branch", "main"))[:64],
    }


def _git(repo: str, *args, timeout: int = 30) -> str:
    return _run_safe(["git", "-c", f"safe.directory={repo}", "-C", repo, *args],
                     "", timeout=timeout)


def _check_for_update(force: bool = False) -> dict:
    now = time.time()
    if not force and _update_cache["result"] and now - _update_cache["at"] < _UPDATE_CACHE_SECS:
        return _update_cache["result"]

    info   = _version_info()
    repo   = str(info.get("repo_dir", ""))
    branch = str(info.get("branch", "main"))
    local  = str(info.get("commit", ""))
    result = {"supported": False, "available": False, "current": _local_version()}

    if (repo and os.path.isdir(os.path.join(repo, ".git")) and _SHA_RE.match(local)
            and re.match(r'^[A-Za-z0-9._/-]{1,64}$', branch)):
        result["supported"] = True
        _git(repo, "fetch", "--quiet", "origin", branch, timeout=60)
        remote = _git(repo, "rev-parse", f"origin/{branch}")
        if _SHA_RE.match(remote) and remote != local:
            behind = _git(repo, "rev-list", "--count", f"{local}..{remote}")
            if behind.isdigit() and int(behind) > 0:
                result.update({
                    "available": True,
                    "behind":    int(behind),
                    "latest":    remote[:7],
                    "summary":   _git(repo, "log", "-1", "--format=%s", remote)[:200],
                    "date":      _git(repo, "log", "-1", "--format=%cs", remote)[:10],
                })

    _update_cache.update(at=now, result=result)
    return result


def _update_state() -> str:
    """'running' | 'success' | 'failed' | 'idle' — from the unit + log marker."""
    if _run(["systemctl", "is-active", "--quiet", _UPDATE_UNIT], timeout=5) == 0:
        return "running"
    try:
        with open(UPDATE_LOG, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(f.tell() - 4096, 0))
            tail = f.read().decode(errors="replace")
    except OSError:
        return "idle"
    if "PI_NAT64_UPDATE_OK" in tail:
        return "success"
    if "PI_NAT64_UPDATE_FAILED" in tail:
        return "failed"
    return "idle"


@app.route("/api/update/check")
@login_required
def api_update_check():
    return jsonify(_check_for_update(force=request.args.get("force") == "1"))


@app.route("/api/update/apply", methods=["POST"])
@login_required
@csrf_required
def api_update_apply():
    info = _version_info()
    repo = str(info.get("repo_dir", ""))
    script = os.path.join(repo, "update.sh")
    if not (repo and os.path.isfile(script)):
        return jsonify({"error": "Updates are not supported on this install "
                                 "(no git checkout recorded — re-run install.sh)"}), 400
    with _state_lock:
        if _update_state() == "running":
            return jsonify({"error": "An update is already running"}), 409
        rc = _run(["systemd-run", f"--unit={_UPDATE_UNIT}", "--collect",
                   "--property=TimeoutStartSec=1800", "--quiet",
                   "/bin/bash", script], timeout=30)
    if rc != 0:
        return jsonify({"error": "Could not start the updater"}), 500
    _update_cache["result"] = None
    return jsonify({"ok": True}), 202


@app.route("/api/update/status")
@login_required
def api_update_status():
    return jsonify({"state": _update_state(), "version": _local_version()})


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["Referrer-Policy"]           = "strict-origin"
    response.headers["Content-Security-Policy"]  = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if _TLS_ENABLED:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


# ---------------------------------------------------------------------------
# Startup reconciliation
# ---------------------------------------------------------------------------

def _reconcile_firewall():
    """Re-apply saved port-forwards and client blocks (idempotent), in case the
    saved netfilter rules were lost or predate the current rule format."""
    with _state_lock:
        rules = _load_rules()
        for r in rules:
            try:
                if r.get("enabled"):
                    _rule_disable(r)       # also clears legacy (no -i) copies
                    _rule_enable(r)
            except (KeyError, TypeError, ValueError):
                continue
        blocked = _load_blocked_clients()
        for mac in blocked:
            _apply_client_block(mac, block=True)
        _save_blocked_clients(blocked)     # (re)writes hostapd's deny file
        if rules or blocked:
            _persist_firewall()


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _make_servers():
    from werkzeug.serving import ThreadedWSGIServer, load_ssl_context

    class _TLSServer(ThreadedWSGIServer):
        """HTTPS server that does the TLS handshake in the per-connection
        thread, with a timeout. Werkzeug's own ssl_context wraps the LISTENING
        socket, so the handshake runs inside accept() on the main thread — one
        client that connects and never finishes the handshake froze the UI for
        everyone."""

        def __init__(self, host, port, wsgi_app, certfile, keyfile):
            super().__init__(host, port, wsgi_app)                # plain listener
            self.ssl_context = load_ssl_context(certfile, keyfile)  # → https environ

        def finish_request(self, request, client_address):
            request.settimeout(15)   # bounds the handshake and idle keep-alives
            try:
                tls = self.ssl_context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            try:
                super().finish_request(tls, client_address)
            finally:
                try:
                    tls.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                tls.close()

    def _redirect_app(environ, start_response):
        host = environ.get("HTTP_HOST", "")
        if host.startswith("["):                       # [v6addr]:port
            host = host[: host.find("]") + 1] if "]" in host else ""
        else:
            host = host.split(":")[0]
        if not (host and re.fullmatch(r'[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\]', host)):
            host = "gateway.local"
        path = environ.get("PATH_INFO", "") or "/"
        qs   = environ.get("QUERY_STRING", "")
        target = f"https://{host}{path}" + (f"?{qs}" if qs else "")
        start_response("301 Moved Permanently", [("Location", target)])
        return [b""]

    return _TLSServer, ThreadedWSGIServer, _redirect_app


def _serve(host: str):
    TLSServer, PlainServer, redirect_app = _make_servers()
    if _TLS_ENABLED:
        try:
            redirect_srv = PlainServer(host, 80, redirect_app)
            threading.Thread(target=redirect_srv.serve_forever, daemon=True).start()
        except OSError as exc:
            print(f"WARNING: could not start HTTP->HTTPS redirect on :80: {exc}",
                  file=sys.stderr)
        TLSServer(host, 443, app, TLS_CERT, TLS_KEY).serve_forever()
    else:
        print("WARNING: TLS_CERT/TLS_KEY not configured — serving plain HTTP on :80. "
              "The admin password and session cookie will be sent in cleartext.",
              file=sys.stderr)
        PlainServer(host, 80, app).serve_forever()


def _cli_set_password():
    """`app.py --set-password` — (re)set the admin password from the console."""
    pw = getpass.getpass("New admin password (min 8 chars): ")
    if len(pw) < 8:
        sys.exit("Password too short.")
    if getpass.getpass("Repeat: ") != pw:
        sys.exit("Passwords do not match.")
    _write_password_hash(_hash_password(pw))
    print(f"Admin password written to {ADMIN_PASSWORD_FILE}. "
          "Existing sessions are now logged out.")


if __name__ == "__main__":
    if "--set-password" in sys.argv:
        _cli_set_password()
        sys.exit(0)
    _reconcile_firewall()
    _serve("0.0.0.0")
