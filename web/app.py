#!/usr/bin/env python3
"""pi-nat64 - NAT64/DNS64 management web UI."""

import hashlib
import hmac
import json
import os
import re
import secrets
import socket as _unix_sock
import sqlite3
import subprocess
import time
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Enforce secure session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,   # 1-hour session timeout
)

# ---------------------------------------------------------------------------
# Config paths
# ---------------------------------------------------------------------------
HOSTAPD_CONF        = "/etc/hostapd/hostapd.conf"
JOOL_PREFIX         = "64:ff9b::/96"
PORT_RULES_FILE     = "/etc/pi-nat64/port-rules.json"
ADMIN_PASSWORD_FILE = "/etc/pi-nat64/admin.passwd"
PIHOLE_SOCKET        = "/run/pihole/FTL.sock"
PIHOLE_GRAVITY_DB    = "/etc/pihole/gravity.db"
BLOCKED_CLIENTS_FILE = "/etc/pi-nat64/blocked-clients.json"
DNSMASQ_LEASES       = "/var/lib/misc/dnsmasq.leases"

# Allowlists / validators
_VALID_PROTO = {"TCP", "UDP"}
_IPV6_RE     = re.compile(r'^[0-9a-fA-F:]+$')
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


# ---------------------------------------------------------------------------
# Login rate limiting (in-memory, per remote IP)
# ---------------------------------------------------------------------------
_login_attempts: dict = {}
_MAX_ATTEMPTS  = 10
_LOCKOUT_SECS  = 60


def _check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    entry = _login_attempts.get(ip)
    if entry and entry["count"] >= _MAX_ATTEMPTS:
        if now < entry["reset_at"]:
            return False
        del _login_attempts[ip]
    return True


def _record_failed_login(ip: str):
    now = time.monotonic()
    entry = _login_attempts.setdefault(ip, {"count": 0, "reset_at": 0.0})
    entry["count"] += 1
    entry["reset_at"] = now + _LOCKOUT_SECS


def _clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """SHA-256 hex digest — good enough for a local device; use bcrypt for internet-exposed services."""
    return hashlib.sha256(password.encode()).hexdigest()


def load_password_hash() -> str:
    if os.path.exists(ADMIN_PASSWORD_FILE):
        with open(ADMIN_PASSWORD_FILE) as f:
            stored = f.read().strip()
        # Migrate plain-text passwords: a real hash is exactly 64 lowercase hex chars
        if not _HASH_RE.match(stored):
            h = _hash_password(stored)
            _write_password_hash(h)
            return h
        return stored
    return _hash_password("admin")


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


def _check_password(candidate: str) -> bool:
    stored = load_password_hash()
    return hmac.compare_digest(_hash_password(candidate), stored)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
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
        ip = request.remote_addr
        if not _check_rate_limit(ip):
            error = "Too many failed attempts. Try again later."
        elif _check_password(request.form.get("password", "")):
            _clear_login_attempts(ip)
            session.clear()                    # session fixation protection
            session["logged_in"] = True
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
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API — status
# ---------------------------------------------------------------------------

@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "nat64_sessions":   _nat64_session_count(),
        "dns_queries":      _dns_query_count(),
        "ap_clients":       _ap_clients(),
        "jool_running":     _service_active("jool"),
        "unbound_running":  _service_active("unbound"),
        "hostapd_running":  _service_active("hostapd"),
        "pihole_running":   _service_active("pihole-FTL"),
    })


def _run_safe(args: list, default="0") -> str:
    """Run a command with a list of args — NO shell=True."""
    try:
        return subprocess.check_output(
            args, stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return default


def _nat64_session_count() -> int:
    out = _run_safe(["jool", "session", "display", "--numeric"], "")
    return out.count("Expires")


def _dns_query_count() -> int:
    log = "/var/log/unbound.log"
    if not os.path.exists(log):
        return 0
    try:
        out = subprocess.check_output(
            ["grep", "-c", "query[", log],
            stderr=subprocess.DEVNULL, text=True
        ).strip()
        return int(out)
    except Exception:
        return 0


def _ap_clients() -> int:
    out = _run_safe(["iw", "dev", "wlan0", "station", "dump"], "")
    return out.count("Station")


def _service_active(name: str) -> bool:
    # Allowlist service names to prevent injection through stored data
    if name not in ("jool", "unbound", "hostapd", "dnsmasq", "radvd", "pihole-FTL"):
        return False
    rc = subprocess.call(
        ["systemctl", "is-active", "--quiet", name],
        stderr=subprocess.DEVNULL
    )
    return rc == 0


# ---------------------------------------------------------------------------
# Pi-hole FTL helpers
# ---------------------------------------------------------------------------

def _ftl_command(cmd: str) -> str:
    """Send a command to Pi-hole FTL via its Unix socket and return the response."""
    try:
        with _unix_sock.socket(_unix_sock.AF_UNIX, _unix_sock.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(PIHOLE_SOCKET)
            s.sendall((cmd + "\n").encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"---EOM---" in buf:
                    break
            return buf.replace(b"---EOM---", b"").decode(errors="replace").strip()
    except Exception:
        return ""


def _pihole_stats() -> dict:
    raw = _ftl_command(">stats")
    result: dict = {}
    for line in raw.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            val = parts[1].strip()
            try:
                result[parts[0]] = float(val) if "." in val else int(val)
            except ValueError:
                result[parts[0]] = val
    return result


def _pihole_top_blocked(n: int = 10) -> list:
    raw = _ftl_command(f">top-ads ({n})")
    result = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                result.append({"rank": int(parts[0]), "count": int(parts[1]), "domain": parts[2]})
            except (ValueError, IndexError):
                pass
    return result


# ---------------------------------------------------------------------------
# API — port forwarding
# ---------------------------------------------------------------------------

def _load_rules() -> list:
    if os.path.exists(PORT_RULES_FILE):
        with open(PORT_RULES_FILE) as f:
            return json.load(f)
    return []


def _save_rules(rules: list):
    os.makedirs(os.path.dirname(PORT_RULES_FILE), exist_ok=True)
    tmp = PORT_RULES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rules, f, indent=2)
    os.replace(tmp, PORT_RULES_FILE)   # atomic write


def _validate_ipv6(addr: str) -> bool:
    """Strict IPv6 address validation — rejects anything that could be a shell injection."""
    if not _IPV6_RE.match(addr):
        return False
    # Must contain at least one colon and no shell-special chars
    if ":" not in addr:
        return False
    # Reject anything too long
    if len(addr) > 39:
        return False
    return True


def _apply_rule(rule: dict, delete=False) -> bool:
    """Build ip6tables command from validated fields — NO shell=True. Returns True on success."""
    action  = "-D" if delete else "-A"
    proto   = rule["proto"].lower()          # already validated as tcp/udp
    ext_p   = str(int(rule["ext_port"]))     # already validated int 1-65535
    dst_ip  = rule["dest_ip"]               # already validated by _validate_ipv6
    dst_p   = str(int(rule["dest_port"]))   # already validated int 1-65535

    rc = subprocess.call([
        "ip6tables", "-t", "nat", action, "PREROUTING",
        "-p", proto,
        "--dport", ext_p,
        "-j", "DNAT",
        "--to-destination", f"[{dst_ip}]:{dst_p}",
    ])
    if rc != 0:
        return False
    subprocess.call(["netfilter-persistent", "save"])
    return True


@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules_get():
    return jsonify(_load_rules())


@app.route("/api/rules", methods=["POST"])
@login_required
@csrf_required
def api_rules_add():
    data = request.get_json(force=True) or {}
    required = {"name", "proto", "ext_port", "dest_ip", "dest_port"}
    if not required.issubset(data):
        return jsonify({"error": "Missing fields"}), 400

    if data["proto"].upper() not in _VALID_PROTO:
        return jsonify({"error": "proto must be TCP or UDP"}), 400

    for field in ("ext_port", "dest_port"):
        try:
            p = int(data[field])
            assert 1 <= p <= 65535
        except (ValueError, AssertionError):
            return jsonify({"error": f"Invalid port: {field}"}), 400

    if not _validate_ipv6(data["dest_ip"]):
        return jsonify({"error": "Invalid IPv6 destination address"}), 400

    rules = _load_rules()
    rule = {
        "id":        max((r["id"] for r in rules), default=0) + 1,
        "name":      data["name"][:64],
        "proto":     data["proto"].upper(),
        "ext_port":  int(data["ext_port"]),
        "dest_ip":   data["dest_ip"],
        "dest_port": int(data["dest_port"]),
        "enabled":   True,
    }
    if not _apply_rule(rule):
        return jsonify({"error": "Failed to apply ip6tables rule — is ip6table_nat loaded?"}), 500
    rules.append(rule)
    _save_rules(rules)
    return jsonify(rule), 201


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_rules_delete(rule_id):
    rules = _load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify({"error": "Not found"}), 404
    if not _apply_rule(target, delete=True):
        return jsonify({"error": "Failed to remove ip6tables rule"}), 500
    rules = [r for r in rules if r["id"] != rule_id]
    _save_rules(rules)
    return jsonify({"deleted": rule_id})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
@csrf_required
def api_rules_toggle(rule_id):
    rules = _load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify({"error": "Not found"}), 404
    if target["enabled"]:
        if not _apply_rule(target, delete=True):
            return jsonify({"error": "Failed to remove ip6tables rule"}), 500
        target["enabled"] = False
    else:
        if not _apply_rule(target):
            return jsonify({"error": "Failed to apply ip6tables rule"}), 500
        target["enabled"] = True
    _save_rules(rules)
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


def _read_hostapd() -> dict:
    cfg = {}
    if not os.path.exists(HOSTAPD_CONF):
        return cfg
    with open(HOSTAPD_CONF) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                k = k.strip()
                if k in _HOSTAPD_ALLOWED_KEYS:
                    cfg[k] = v.strip()
    return cfg


def _write_hostapd(cfg: dict):
    # Only write allowed keys
    safe_cfg = {k: v for k, v in cfg.items() if k in _HOSTAPD_ALLOWED_KEYS}
    tmp = HOSTAPD_CONF + ".tmp"
    with open(tmp, "w") as f:
        for k, v in safe_cfg.items():
            f.write(f"{k}={v}\n")
    os.replace(tmp, HOSTAPD_CONF)
    subprocess.call(["systemctl", "restart", "hostapd"])


@app.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    ap = _read_hostapd()
    return jsonify({
        "ssid":            ap.get("ssid", "pi-nat64"),
        "channel":         ap.get("channel", "6"),
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
    data = request.get_json(force=True) or {}
    ap = _read_hostapd()

    if "ssid" in data:
        ap["ssid"] = _sanitize_ssid(data["ssid"])
        if not ap["ssid"]:
            return jsonify({"error": "SSID cannot be empty"}), 400

    if "channel" in data:
        try:
            ch = int(data["channel"])
            assert 1 <= ch <= 14
            ap["channel"] = str(ch)
        except (ValueError, AssertionError):
            return jsonify({"error": "Invalid channel (must be 1–14)"}), 400

    if "wpa_passphrase" in data and data["wpa_passphrase"] not in ("", "••••••••"):
        pw = data["wpa_passphrase"]
        if len(pw) < 8 or len(pw) > 63:
            return jsonify({"error": "Passphrase must be 8–63 characters"}), 400
        # WPA2 passphrase: printable ASCII excluding '#' (hostapd treats it as comment)
        if not re.match(r'^[\x20-\x22\x24-\x7E]+$', pw):
            return jsonify({"error": "Passphrase contains invalid characters (# not allowed)"}), 400
        ap["wpa_passphrase"] = pw

    _write_hostapd(ap)

    if "new_password" in data and data["new_password"]:
        np = data["new_password"]
        if len(np) < 8:
            return jsonify({"error": "Admin password must be at least 8 characters"}), 400
        _write_password_hash(_hash_password(np))

    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# API — Pi-hole
# ---------------------------------------------------------------------------

@app.route("/api/pihole/stats")
@login_required
def api_pihole_stats():
    s = _pihole_stats()
    return jsonify({
        "domains_blocked": int(s.get("domains_being_blocked", 0)),
        "queries_today":   int(s.get("dns_queries_today", 0)),
        "blocked_today":   int(s.get("ads_blocked_today", 0)),
        "block_pct":       round(float(s.get("ads_percentage_today", 0)), 1),
        "status":          s.get("status", "unknown"),
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
    if os.path.exists(BLOCKED_CLIENTS_FILE):
        with open(BLOCKED_CLIENTS_FILE) as f:
            return set(json.load(f))
    return set()


def _save_blocked_clients(macs: set):
    os.makedirs(os.path.dirname(BLOCKED_CLIENTS_FILE), exist_ok=True)
    tmp = BLOCKED_CLIENTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(macs), f, indent=2)
    os.replace(tmp, BLOCKED_CLIENTS_FILE)


def _get_stations() -> list:
    """Parse `iw dev wlan0 station dump` into a list of dicts."""
    out = _run_safe(["iw", "dev", "wlan0", "station", "dump"], "")
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
    if not os.path.exists(DNSMASQ_LEASES):
        return leases
    try:
        with open(DNSMASQ_LEASES) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    mac = parts[1].lower()
                    leases[mac] = {
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
    for mac in blocked:
        if mac not in seen:
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
    action = "-I" if block else "-D"
    for ipt in ("iptables", "ip6tables"):
        subprocess.call(
            [ipt, action, "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
            stderr=subprocess.DEVNULL,
        )


@app.route("/api/clients/block", methods=["POST"])
@login_required
@csrf_required
def api_client_block():
    data = request.get_json(force=True) or {}
    mac  = data.get("mac", "").strip().lower()
    if not _mac_valid(mac):
        return jsonify({"error": "Invalid MAC address"}), 400

    _apply_client_block(mac, block=True)
    # Immediately deauthenticate from the AP
    subprocess.call(
        ["hostapd_cli", "-i", "wlan0", "deauthenticate", mac],
        stderr=subprocess.DEVNULL,
    )
    subprocess.call(["netfilter-persistent", "save"], stderr=subprocess.DEVNULL)

    blocked = _load_blocked_clients()
    blocked.add(mac)
    _save_blocked_clients(blocked)
    return jsonify({"mac": mac, "blocked": True})


@app.route("/api/clients/unblock", methods=["POST"])
@login_required
@csrf_required
def api_client_unblock():
    data = request.get_json(force=True) or {}
    mac  = data.get("mac", "").strip().lower()
    if not _mac_valid(mac):
        return jsonify({"error": "Invalid MAC address"}), 400

    _apply_client_block(mac, block=False)
    subprocess.call(["netfilter-persistent", "save"], stderr=subprocess.DEVNULL)

    blocked = _load_blocked_clients()
    blocked.discard(mac)
    _save_blocked_clients(blocked)
    return jsonify({"mac": mac, "blocked": False})


@app.route("/api/pihole/toggle", methods=["POST"])
@login_required
@csrf_required
def api_pihole_toggle():
    s = _pihole_stats()
    current = s.get("status", "unknown")
    cmd = ["pihole", "enable"] if current != "enabled" else ["pihole", "disable"]
    rc = subprocess.call(cmd, stderr=subprocess.DEVNULL)
    if rc != 0:
        return jsonify({"error": "Failed to toggle Pi-hole blocking"}), 500
    updated = _pihole_stats()
    return jsonify({"status": updated.get("status", "unknown")})


# ---------------------------------------------------------------------------
# Pi-hole whitelist helpers
# ---------------------------------------------------------------------------

def _pihole_whitelist_read() -> list:
    """Read exact-match whitelist from Pi-hole's gravity DB (type=0)."""
    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB) as db:
            rows = db.execute(
                "SELECT domain FROM domainlist WHERE type=0 ORDER BY domain"
            ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


def _validate_domain(domain: str) -> bool:
    return bool(domain) and len(domain) <= 253 and bool(_DOMAIN_RE.match(domain))


# ---------------------------------------------------------------------------
# Pi-hole adlist helpers
# ---------------------------------------------------------------------------

def _adlist_read() -> list:
    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB) as db:
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
    data    = request.get_json(force=True) or {}
    url     = data.get("url", "").strip()
    comment = data.get("comment", "").strip()[:255]

    if not _URL_RE.match(url):
        return jsonify({"error": "Invalid URL — must start with http:// or https://"}), 400

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB) as db:
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
    data = request.get_json(force=True) or {}
    try:
        adlist_id = int(data["id"])
    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "Invalid id"}), 400

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB) as db:
            db.execute("DELETE FROM adlist WHERE id = ?", (adlist_id,))
    except Exception:
        return jsonify({"error": "Database error"}), 500

    return jsonify({"ok": True, "deleted": adlist_id})


@app.route("/api/pihole/adlists/toggle", methods=["POST"])
@login_required
@csrf_required
def api_adlists_toggle():
    data = request.get_json(force=True) or {}
    try:
        adlist_id = int(data["id"])
    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "Invalid id"}), 400

    try:
        with sqlite3.connect(PIHOLE_GRAVITY_DB) as db:
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
    """Trigger pihole -g in the background; response returns before it finishes."""
    subprocess.Popen(
        ["pihole", "-g"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return jsonify({"ok": True})


@app.route("/api/pihole/whitelist", methods=["GET"])
@login_required
def api_pihole_whitelist_get():
    return jsonify(_pihole_whitelist_read())


@app.route("/api/pihole/whitelist", methods=["POST"])
@login_required
@csrf_required
def api_pihole_whitelist_add():
    data   = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip().lower()
    if not _validate_domain(domain):
        return jsonify({"error": "Invalid domain name"}), 400
    if domain in _pihole_whitelist_read():
        return jsonify({"error": "Domain already whitelisted"}), 409
    rc = subprocess.call(["pihole", "-w", domain], stderr=subprocess.DEVNULL)
    if rc != 0:
        return jsonify({"error": "pihole -w failed"}), 500
    return jsonify({"domain": domain}), 201


@app.route("/api/pihole/whitelist", methods=["DELETE"])
@login_required
@csrf_required
def api_pihole_whitelist_remove():
    data   = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip().lower()
    if not _validate_domain(domain):
        return jsonify({"error": "Invalid domain name"}), 400
    rc = subprocess.call(["pihole", "-w", "-d", domain], stderr=subprocess.DEVNULL)
    if rc != 0:
        return jsonify({"error": "pihole -w -d failed"}), 500
    return jsonify({"deleted": domain})


# Security headers middleware
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin"
    response.headers["Content-Security-Policy"]  = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
