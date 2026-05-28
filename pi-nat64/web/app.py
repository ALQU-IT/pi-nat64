#!/usr/bin/env python3
"""pi-nat64 - NAT64/DNS64 management web UI."""

import hashlib
import hmac
import json
import os
import re
import secrets
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

# Allowlists
_VALID_PROTO = {"TCP", "UDP"}
_IPV6_RE     = re.compile(r'^[0-9a-fA-F:]+$')
# Detect a valid SHA-256 hex digest (exactly 64 lowercase hex chars)
_HASH_RE     = re.compile(r'^[0-9a-f]{64}$')


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
        "nat64_sessions":  _nat64_session_count(),
        "dns_queries":     _dns_query_count(),
        "ap_clients":      _ap_clients(),
        "jool_running":    _service_active("jool"),
        "unbound_running": _service_active("unbound"),
        "hostapd_running": _service_active("hostapd"),
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
    if name not in ("jool", "unbound", "hostapd", "dnsmasq", "radvd"):
        return False
    rc = subprocess.call(
        ["systemctl", "is-active", "--quiet", name],
        stderr=subprocess.DEVNULL
    )
    return rc == 0


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
