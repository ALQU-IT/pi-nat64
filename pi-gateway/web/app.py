#!/usr/bin/env python3
"""Pi Gateway - NAT64/DNS64 management web UI."""

import json
import os
import re
import subprocess
from functools import wraps

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# ---------------------------------------------------------------------------
# Config paths
# ---------------------------------------------------------------------------
HOSTAPD_CONF   = "/etc/hostapd/hostapd.conf"
UNBOUND_CONF   = "/etc/unbound/unbound.conf.d/dns64.conf"
JOOL_PREFIX    = "64:ff9b::/96"
PORT_RULES_FILE = "/etc/pi-gateway/port-rules.json"
ADMIN_PASSWORD_FILE = "/etc/pi-gateway/admin.passwd"

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def load_password():
    if os.path.exists(ADMIN_PASSWORD_FILE):
        with open(ADMIN_PASSWORD_FILE) as f:
            return f.read().strip()
    return "admin"          # default; setup script changes this


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == load_password():
            session["logged_in"] = True
            return redirect(url_for("index"))
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
        "nat64_sessions": _nat64_session_count(),
        "dns_queries":    _dns_query_count(),
        "ap_clients":     _ap_clients(),
        "jool_running":   _service_active("jool"),
        "unbound_running":_service_active("unbound"),
        "hostapd_running":_service_active("hostapd"),
    })


def _run(cmd, default="0"):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                       text=True).strip()
    except Exception:
        return default


def _nat64_session_count():
    out = _run("jool session display --numeric 2>/dev/null | grep -c 'Expires'", "0")
    try:
        return int(out)
    except ValueError:
        return 0


def _dns_query_count():
    out = _run("grep -c 'query\\[' /var/log/unbound.log 2>/dev/null || echo 0")
    try:
        return int(out)
    except ValueError:
        return 0


def _ap_clients():
    out = _run("iw dev wlan0 station dump 2>/dev/null | grep -c 'Station'", "0")
    try:
        return int(out)
    except ValueError:
        return 0


def _service_active(name):
    rc = subprocess.call(["systemctl", "is-active", "--quiet", name])
    return rc == 0


# ---------------------------------------------------------------------------
# API — port forwarding
# ---------------------------------------------------------------------------

def _load_rules():
    if os.path.exists(PORT_RULES_FILE):
        with open(PORT_RULES_FILE) as f:
            return json.load(f)
    return []


def _save_rules(rules):
    os.makedirs(os.path.dirname(PORT_RULES_FILE), exist_ok=True)
    with open(PORT_RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def _apply_rule(rule, delete=False):
    """Add or delete an ip6tables DNAT rule."""
    action = "-D" if delete else "-A"
    proto  = rule["proto"].lower()
    ext_p  = rule["ext_port"]
    dst_ip = rule["dest_ip"]
    dst_p  = rule["dest_port"]
    cmd = (
        f"ip6tables -t nat {action} PREROUTING "
        f"-p {proto} --dport {ext_p} "
        f"-j DNAT --to-destination [{dst_ip}]:{dst_p}"
    )
    subprocess.call(cmd, shell=True)
    subprocess.call("netfilter-persistent save", shell=True)


@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules_get():
    return jsonify(_load_rules())


@app.route("/api/rules", methods=["POST"])
@login_required
def api_rules_add():
    data = request.get_json(force=True)
    required = {"name", "proto", "ext_port", "dest_ip", "dest_port"}
    if not required.issubset(data):
        return jsonify({"error": "Missing fields"}), 400

    # Basic validation
    if data["proto"].upper() not in ("TCP", "UDP"):
        return jsonify({"error": "proto must be TCP or UDP"}), 400
    for field in ("ext_port", "dest_port"):
        try:
            p = int(data[field])
            assert 1 <= p <= 65535
        except (ValueError, AssertionError):
            return jsonify({"error": f"Invalid port: {field}"}), 400

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
    rules.append(rule)
    _save_rules(rules)
    _apply_rule(rule)
    return jsonify(rule), 201


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_rules_delete(rule_id):
    rules = _load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify({"error": "Not found"}), 404
    _apply_rule(target, delete=True)
    rules = [r for r in rules if r["id"] != rule_id]
    _save_rules(rules)
    return jsonify({"deleted": rule_id})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_rules_toggle(rule_id):
    rules = _load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify({"error": "Not found"}), 404
    if target["enabled"]:
        _apply_rule(target, delete=True)
        target["enabled"] = False
    else:
        _apply_rule(target)
        target["enabled"] = True
    _save_rules(rules)
    return jsonify(target)


# ---------------------------------------------------------------------------
# API — settings
# ---------------------------------------------------------------------------

def _read_hostapd():
    cfg = {}
    if not os.path.exists(HOSTAPD_CONF):
        return cfg
    with open(HOSTAPD_CONF) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                cfg[k.strip()] = v.strip()
    return cfg


def _write_hostapd(cfg):
    lines = [f"{k}={v}\n" for k, v in cfg.items()]
    with open(HOSTAPD_CONF, "w") as f:
        f.writelines(lines)
    subprocess.call("systemctl restart hostapd", shell=True)


@app.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    ap = _read_hostapd()
    return jsonify({
        "ssid":         ap.get("ssid", "Pi-Gateway"),
        "channel":      ap.get("channel", "6"),
        "wpa_passphrase": "••••••••",   # never expose
        "jool_prefix":  JOOL_PREFIX,
        "upstream_dns": "2606:4700:4700::1111",
    })


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings_save():
    data = request.get_json(force=True)
    ap = _read_hostapd()

    if "ssid" in data:
        ap["ssid"] = data["ssid"][:32]
    if "channel" in data:
        try:
            ch = int(data["channel"])
            assert 1 <= ch <= 14
            ap["channel"] = str(ch)
        except (ValueError, AssertionError):
            return jsonify({"error": "Invalid channel"}), 400
    if "wpa_passphrase" in data and data["wpa_passphrase"] not in ("", "••••••••"):
        if len(data["wpa_passphrase"]) < 8:
            return jsonify({"error": "Passphrase must be at least 8 chars"}), 400
        ap["wpa_passphrase"] = data["wpa_passphrase"]

    _write_hostapd(ap)

    if "new_password" in data and data["new_password"]:
        os.makedirs(os.path.dirname(ADMIN_PASSWORD_FILE), exist_ok=True)
        with open(ADMIN_PASSWORD_FILE, "w") as f:
            f.write(data["new_password"])

    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
