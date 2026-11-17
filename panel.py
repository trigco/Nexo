#!/usr/bin/env python3
"""Nexo - a 3x-ui style management panel for a multi-protocol VPS.

Single file, Python standard library only. Manages:
  - SSH users (real Linux accounts) with quota + expiry, WebSocket proxy and
    stunnel as the SSH front doors
  - DNSTT server (install state, domain, key, service control)
  - V2Ray (Xray) VLESS users with per-user traffic accounting via the Xray API
  - OpenVPN users (easy-rsa certificates) with traffic from the status log
  - Per-user bandwidth accounting and automatic lockout at quota or expiry
  - Server statistics (CPU, RAM, disk, network, uptime, service states)

Modes:
  panel.py serve            run the web panel (default)
  panel.py --enforce        one accounting + lockout pass (systemd timer)
  panel.py --init-net       recreate iptables accounting chains from the DB
  panel.py --set-admin PW   set the admin password

Set PANEL_MOCK=1 to run without touching the system (development and tests).
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import uuid as uuidlib
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MOCK = os.environ.get("PANEL_MOCK") == "1"
BASE = os.environ.get("PANEL_HOME", "/etc/mpanel")
DB_PATH = os.path.join(BASE, "panel.db")
CERT_FILE = os.path.join(BASE, "panel.crt")
KEY_FILE = os.path.join(BASE, "panel.key")
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
XRAY_API = "127.0.0.1:10085"
OVPN_DIR = "/etc/openvpn"
OVPN_STATUS = "/var/log/openvpn/status.log"
DNSTT_DIR = "/etc/dnstt"
GB = 1024 ** 3

DEFAULT_SETTINGS = {
    "panel_port": "8443",
    "server_host": "",            # public IP or hostname shown in client info
    "ssh_port": "22",
    "ws_port": "80",
    "wss_port": "443",
    "xray_port": "8880",
    "xray_vmess_port": "3389",
    "xray_path": "/ray",
    "cf_ws_host": "ws.mominul.tech",
    "sni_host": "m.youtube.com",
    "ovpn_port": "33500",
    "ovpn_proto": "udp",
    "dnstt_domain": "",
    "dnstt_port": "53",
    "brand": "NEXO",
    "telegram": "https://t.me/unique_solution1",
}

_lock = threading.Lock()
LOGIN_WINDOW_SECONDS = 900
LOGIN_MAX_FAILURES = 8
SESSION_TTL_SECONDS = 7 * 86400
MAX_REQUEST_BODY = 1024 * 1024


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def today():
    return date.today()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120000)
    return f"{salt}${digest.hex()}"


def check_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def run(cmd, timeout=30, check=False):
    """Run a shell command list. In mock mode, log and pretend success.

    A missing binary (e.g. xray not installed yet) must never crash the
    caller: it is reported as a failed command instead of raising OSError.
    """
    if MOCK:
        print("[mock] $", " ".join(cmd), flush=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}: {result.stderr.strip()}")
    return result


def run_shell(script, timeout=60):
    if MOCK:
        print("[mock] shell:", script[:120], flush=True)
        return subprocess.CompletedProcess(["bash"], 0, "", "")
    try:
        return subprocess.run(["bash", "-c", script], capture_output=True,
                              text=True, timeout=timeout)
    except OSError as exc:
        return subprocess.CompletedProcess(["bash"], 1, "", str(exc))


def service_active(name):
    if MOCK:
        return True
    return subprocess.run(
        ["systemctl", "is-active", "--quiet", name]
    ).returncode == 0


def service_installed(name):
    """True when a systemd unit exists at all (vs. never installed)."""
    if MOCK:
        return True
    return subprocess.run(
        ["systemctl", "cat", name],
        capture_output=True, text=True,
    ).returncode == 0


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.2f} {unit}"
        n /= 1024


# --------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def init_db():
    os.makedirs(BASE, exist_ok=True)
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            csrf_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS login_attempts (
            source_key TEXT PRIMARY KEY,
            failures INTEGER NOT NULL DEFAULT 0,
            window_started INTEGER NOT NULL,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL DEFAULT 'admin',
            action TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            request_id TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT 'success',
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL DEFAULT '',
            protocols TEXT NOT NULL DEFAULT 'ssh',
            uuid TEXT NOT NULL DEFAULT '',
            quota_bytes INTEGER NOT NULL DEFAULT 0,
            used_bytes INTEGER NOT NULL DEFAULT 0,
            expire_date TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT '',
            ssh_last INTEGER NOT NULL DEFAULT 0,
            xray_up_last INTEGER NOT NULL DEFAULT 0,
            xray_down_last INTEGER NOT NULL DEFAULT 0,
            ovpn_last INTEGER NOT NULL DEFAULT 0,
            ip_limit INTEGER NOT NULL DEFAULT 0,
            hwid_limit INTEGER NOT NULL DEFAULT 0,
            hwids TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remark TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT 'vless',
            port INTEGER NOT NULL DEFAULT 0,
            network TEXT NOT NULL DEFAULT 'ws',
            path TEXT NOT NULL DEFAULT '/ray',
            security TEXT NOT NULL DEFAULT 'none',
            enabled INTEGER NOT NULL DEFAULT 1
        );
        """
    )
    # Migrations for databases created by earlier panel versions.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    for column, ddl in (
        ("ip_limit", "ALTER TABLE users ADD COLUMN ip_limit INTEGER NOT NULL DEFAULT 0"),
        ("hwid_limit", "ALTER TABLE users ADD COLUMN hwid_limit INTEGER NOT NULL DEFAULT 0"),
        ("hwids", "ALTER TABLE users ADD COLUMN hwids TEXT NOT NULL DEFAULT ''"),
    ):
        if column not in columns:
            conn.execute(ddl)
    inbound_columns = {row[1] for row in conn.execute("PRAGMA table_info(inbounds)")}
    if "stream_json" not in inbound_columns:
        conn.execute(
            "ALTER TABLE inbounds ADD COLUMN stream_json TEXT NOT NULL DEFAULT '{}'")
    if "max_clients" not in inbound_columns:
        conn.execute(
            "ALTER TABLE inbounds ADD COLUMN max_clients INTEGER NOT NULL DEFAULT 0")
    if "last_online" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN last_online TEXT NOT NULL DEFAULT ''")
    if "auto_locked" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN auto_locked INTEGER NOT NULL DEFAULT 0")
    if "inbound_ids" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN inbound_ids TEXT NOT NULL DEFAULT ''")
    # No inbounds are seeded: the admin creates exactly the inbounds they
    # want (older versions auto-created two defaults, which looked like
    # fake/pre-opened entries in the panel).
    for key, value in DEFAULT_SETTINGS.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )
    if not conn.execute("SELECT 1 FROM admin WHERE id = 1").fetchone():
        initial = os.environ.get("PANEL_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
        conn.execute(
            "INSERT INTO admin (id, username, password_hash) VALUES (1, 'admin', ?)",
            (hash_password(initial),),
        )
        print(f"Admin created: user 'admin', password '{initial}'", flush=True)
        print("Change it after first login (Settings) or with --set-admin.", flush=True)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at)")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.commit()
    conn.close()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass



def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def audit_event(action, target_type="", target_id="", request_id="",
                outcome="success", details=None):
    conn = db()
    conn.execute(
        "INSERT INTO audit_events (actor, action, target_type, target_id, "
        "request_id, outcome, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("admin", action, target_type, str(target_id or ""), request_id, outcome,
         json.dumps(details or {}, separators=(",", ":")),
         datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def login_lock_state(source_key):
    now = int(time.time())
    conn = db()
    row = conn.execute(
        "SELECT failures, window_started, locked_until FROM login_attempts WHERE source_key=?",
        (source_key,),
    ).fetchone()
    conn.close()
    if not row:
        return False, 0
    return int(row["locked_until"]) > now, max(0, int(row["locked_until"]) - now)


def record_login_failure(source_key):
    now = int(time.time())
    conn = db()
    row = conn.execute(
        "SELECT failures, window_started FROM login_attempts WHERE source_key=?",
        (source_key,),
    ).fetchone()
    if not row or now - int(row["window_started"]) > LOGIN_WINDOW_SECONDS:
        failures, started = 1, now
    else:
        failures, started = int(row["failures"]) + 1, int(row["window_started"])
    locked_until = 0
    if failures >= LOGIN_MAX_FAILURES:
        locked_until = now + min(900, 30 * (2 ** min(max(failures - LOGIN_MAX_FAILURES, 0), 5)))
        "INSERT INTO login_attempts (source_key, failures, window_started, locked_until) "
        "VALUES (?, ?, ?, ?) ON CONFLICT(source_key) DO UPDATE SET "
        "failures=excluded.failures, window_started=excluded.window_started, "
        "locked_until=excluded.locked_until",
        (source_key, failures, started, locked_until),
    )
    conn.commit()
    conn.close()


def clear_login_failures(source_key):
    conn = db()
    conn.execute("DELETE FROM login_attempts WHERE source_key=?", (source_key,))
    conn.commit()
    conn.close()


def get_settings():
    conn = db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    settings = dict(DEFAULT_SETTINGS)
    settings.update({row["key"]: row["value"] for row in rows})
    return settings


def set_setting(key, value):
    conn = db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
    conn.commit()
    conn.close()


def server_host(settings):
    if settings.get("server_host"):
        return settings["server_host"]
    if MOCK:
        return "203.0.113.10"
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


# --------------------------------------------------------------------------
# server statistics
# --------------------------------------------------------------------------

def _cpu_times():
    with open("/proc/stat") as fh:
        parts = fh.readline().split()[1:]
    values = [int(x) for x in parts]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_percent():
    if MOCK:
        return 7.0
    total1, idle1 = _cpu_times()
    time.sleep(0.25)
    total2, idle2 = _cpu_times()
    if total2 == total1:
        return 0.0
    return round(100.0 * (1 - (idle2 - idle1) / (total2 - total1)), 1)


def server_stats(settings):
    if MOCK:
        return {
            "cpu": 7.0, "ram_used": 612 * 1024 ** 2, "ram_total": 2 * GB,
            "disk_used": 9 * GB, "disk_total": 30 * GB,
            "net_rx": 812 * 1024 ** 2, "net_tx": 905 * 1024 ** 2,
            "uptime": "3 days, 4:12", "load": "0.12 0.08 0.03",
            "host": server_host(settings),
        }
    mem = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            mem[key] = int(rest.split()[0]) * 1024
    disk = shutil.disk_usage("/")
    rx = tx = 0
    with open("/proc/net/dev") as fh:
        for line in fh:
            if ":" not in line:
                continue
            name, _, rest = line.partition(":")
            if name.strip() == "lo":
                continue
            fields = rest.split()
            rx += int(fields[0])
            tx += int(fields[8])
    with open("/proc/uptime") as fh:
        seconds = int(float(fh.read().split()[0]))
    days, rem = divmod(seconds, 86400)
    hours, minutes = divmod(rem // 60, 60)
    uptime = f"{days} days, {hours}:{minutes:02d}" if days else f"{hours}:{minutes:02d}"
    return {
        "cpu": cpu_percent(),
        "ram_used": mem["MemTotal"] - mem.get("MemAvailable", 0),
        "ram_total": mem["MemTotal"],
        "disk_used": disk.used,
        "disk_total": disk.total,
        "net_rx": rx,
        "net_tx": tx,
        "uptime": uptime,
        "load": " ".join(open("/proc/loadavg").read().split()[:3]),
        "host": server_host(settings),
    }


# --------------------------------------------------------------------------
# SSH users and iptables accounting
# --------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")


def chain_name(username):
    return f"MP_{username}"[:28]


def ssh_create_user(username, password, expire_date):
    run(["useradd", "-m", "-s", "/bin/bash", username], check=True)
    proc = subprocess.run(
        ["chpasswd"], input=f"{username}:{password}\n",
        capture_output=True, text=True,
    ) if not MOCK else subprocess.CompletedProcess([], 0, "", "")
    if not MOCK and proc.returncode != 0:
        raise RuntimeError(f"chpasswd failed: {proc.stderr.strip()}")
    if expire_date:
        run(["chage", "-E", expire_date, username], check=True)
    ssh_ensure_chain(username)


def ssh_ensure_chain(username):
    chain = chain_name(username)
    run(["iptables", "-N", chain])
    run(["iptables", "-F", chain])
    run(["iptables", "-A", chain, "-m", "owner", "--uid-owner", username, "-j", "RETURN"])
    # Single jump from OUTPUT; remove duplicates first.
    while run(["iptables", "-D", "OUTPUT", "-j", chain]).returncode == 0 and not MOCK:
        pass
    run(["iptables", "-A", "OUTPUT", "-j", chain])


def ssh_chain_bytes(username):
    if MOCK:
        return 0
    result = run(["iptables", "-L", chain_name(username), "-v", "-x", "-n"])
    total = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].isdigit():
            total += int(fields[1])
    return total


def ssh_set_enabled(username, enabled):
    if enabled:
        run(["usermod", "-U", username])
    else:
        run(["usermod", "-L", username])
        run(["pkill", "-u", username])


def ssh_delete_user(username):
    run(["pkill", "-u", username])
    run(["userdel", "-r", username])
    chain = chain_name(username)
    run(["iptables", "-D", "OUTPUT", "-j", chain])
    run(["iptables", "-F", chain])
    run(["iptables", "-X", chain])


def ssh_user_exists(username):
    if MOCK:
        return True
    return subprocess.run(["id", username], capture_output=True).returncode == 0


# --------------------------------------------------------------------------
# Xray (V2Ray) users
# --------------------------------------------------------------------------

API_INBOUND = {
    "tag": "api", "listen": "127.0.0.1", "port": 10085,
    "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
}


def list_inbounds():
    conn = db()
    rows = conn.execute("SELECT * FROM inbounds ORDER BY id").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def xray_load():
    if MOCK:
        return {"inbounds": [API_INBOUND]}
    with open(XRAY_CONFIG) as fh:
        return json.load(fh)


def xray_save(config):
    """Validate, atomically publish and health-check an Xray config.

    A bad candidate must never replace the last-known-good file. If restart
    fails after publication, restore the previous config and restart again.
    """
    if MOCK:
        return
    import tempfile

    config_dir = os.path.dirname(XRAY_CONFIG)
    os.makedirs(config_dir, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".nexo-xray-", suffix=".json",
                                     dir=config_dir)
    backup = XRAY_CONFIG + ".nexo-last-good"
    had_previous = os.path.isfile(XRAY_CONFIG)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(config, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        test = run(["xray", "run", "-test", "-config", candidate], timeout=30)
        if test.returncode != 0:
            detail = (test.stderr or test.stdout or "unknown Xray config error").strip()
            raise RuntimeError("Xray rejected generated config: " + detail[-1600:])
        if had_previous:
            shutil.copy2(XRAY_CONFIG, backup)
        os.replace(candidate, XRAY_CONFIG)
        restart = run(["systemctl", "restart", "xray"], timeout=45)
        if restart.returncode != 0 or not service_active("xray"):
            detail = (restart.stderr or restart.stdout or "Xray service is not active").strip()
            if had_previous and os.path.exists(backup):
                shutil.copy2(backup, candidate)
                os.replace(candidate, XRAY_CONFIG)
                run(["systemctl", "restart", "xray"], timeout=45)
            raise RuntimeError("Xray failed after config publish; previous config restored: "
                               + detail[-1200:])
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


INBOUND_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")
INBOUND_NETWORKS = ("tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp")
INBOUND_SECURITIES = ("none", "tls", "reality")
SS_METHODS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
CERT_DIR = os.path.join(BASE, "certs")


def inbound_stream(inbound):
    """Parse an inbound row's stream_json into a settings dict."""
    try:
        data = json.loads(inbound["stream_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    if "path" not in data and inbound["path"]:
        data["path"] = inbound["path"]
    return data


def _b64url(raw):
    import base64
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def gen_reality_keys():
    """Return (private, public) X25519 keys in Xray base64url format."""
    if MOCK:
        return _b64url(secrets.token_bytes(32)), _b64url(secrets.token_bytes(32))
    result = run(["xray", "x25519"], timeout=15)
    priv = pub = ""
    for line in (result.stdout or "").splitlines():
        low = line.lower()
        if "private" in low and ":" in line:
            priv = line.split(":", 1)[1].strip()
        if "public" in low and ":" in line:
            pub = line.split(":", 1)[1].strip().split(" ")[0]
    if result.returncode == 0 and priv and pub:
        return priv, pub
    # Fallback: OpenSSL X25519; validate each subprocess result.
    proc = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519"],
                          capture_output=True, timeout=20)
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError("Unable to generate Reality private key: " +
                           (proc.stderr or b"").decode(errors="replace")[-500:])
    priv_pem = proc.stdout
    priv_result = subprocess.run(["openssl", "pkey", "-outform", "DER"],
                                 input=priv_pem, capture_output=True, timeout=20)
    pub_result = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"],
                                input=priv_pem, capture_output=True, timeout=20)
    if priv_result.returncode != 0 or pub_result.returncode != 0:
        raise RuntimeError("OpenSSL failed to derive Reality key pair.")
    priv_der, pub_der = priv_result.stdout, pub_result.stdout
    if len(priv_der) < 32 or len(pub_der) < 32:
        raise RuntimeError("OpenSSL returned malformed X25519 key material.")
    return _b64url(priv_der[-32:]), _b64url(pub_der[-32:])


def gen_inbound_cert(inbound_id, server_name):
    """Self-signed TLS cert for an inbound; returns (cert_path, key_path)."""
    os.makedirs(CERT_DIR, exist_ok=True)
    cert = os.path.join(CERT_DIR, f"inb{inbound_id}.crt")
    key = os.path.join(CERT_DIR, f"inb{inbound_id}.key")
    if MOCK:
        return cert, key
    if not (os.path.exists(cert) and os.path.exists(key)):
        result = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                      "-days", "3650", "-keyout", key, "-out", cert,
                      "-subj", f"/CN={server_name or 'localhost'}"], timeout=60)
        if result.returncode != 0 or not (os.path.isfile(cert) and os.path.isfile(key)):
            raise RuntimeError("TLS certificate generation failed: " +
                               (result.stderr or result.stdout or "")[-800:])
        os.chmod(key, 0o600)
    return cert, key


def _ss_key(material, method):
    import base64
    size = SS_METHODS.get(method, 32)
    digest = hashlib.sha256(material.encode()).digest()
    return base64.b64encode(digest[:size]).decode()


def ss_server_key(inbound):
    stream = inbound_stream(inbound)
    return _ss_key(f"mpanel-ss-server:{inbound['id']}",
                   stream.get("ss_method", "2022-blake3-aes-256-gcm"))


def ss_user_key(user, method):
    return _ss_key(f"mpanel-ss:{user['id']}:{user['password']}", method)


def _stream_settings(inbound):
    stream = inbound_stream(inbound)
    network = inbound["network"]
    security = inbound["security"] or "none"
    out = {"network": network, "security": security}
    path = stream.get("path") or inbound["path"] or "/ray"
    if network == "ws":
        ws = {"path": path}
        if stream.get("host_header"):
            ws["headers"] = {"Host": stream["host_header"]}
        out["wsSettings"] = ws
    elif network == "grpc":
        out["grpcSettings"] = {
            "serviceName": stream.get("service_name", ""),
            "multiMode": bool(stream.get("multi_mode")),
        }
    elif network == "httpupgrade":
        hu = {"path": path}
        if stream.get("host_header"):
            hu["host"] = stream["host_header"]
        out["httpupgradeSettings"] = hu
    elif network == "xhttp":
        out["xhttpSettings"] = {"path": path, "mode": stream.get("xhttp_mode", "auto")}
    elif network == "tcp":
        header = {"type": stream.get("header_type", "none")}
        if header["type"] == "http":
            header["request"] = {
                "version": "1.1", "method": "GET", "path": ["/"],
                "headers": {"Host": [stream.get("host_header", "")]},
            }
        out["tcpSettings"] = {"header": header}
    elif network == "kcp":
        out["kcpSettings"] = {
            "mtu": 1350, "tti": 50, "uplinkCapacity": 12, "downlinkCapacity": 100,
            "congestion": False, "readBufferSize": 2, "writeBufferSize": 2,
            "header": {"type": stream.get("header_type", "none")},
        }
        if stream.get("seed"):
            out["kcpSettings"]["seed"] = stream["seed"]
    if security == "tls":
        out["tlsSettings"] = {
            "serverName": stream.get("sni", ""),
            "certificates": [{
                "certificateFile": stream.get("cert_file", ""),
                "keyFile": stream.get("key_file", ""),
            }],
            "alpn": ["h2", "http/1.1"],
        }
    elif security == "reality":
        out["realitySettings"] = {
            "show": False,
            "target": stream.get("dest", ""),
            "xver": 0,
            "serverNames": [stream.get("sni", "")],
            "privateKey": stream.get("reality_priv", ""),
            "shortIds": [stream.get("short_id", "")],
        }
    return out


def _inbound_json(inbound, users):
    protocol = inbound["protocol"]
    stream = inbound_stream(inbound)
    clients = []
    for user in users:
        if not user["enabled"] or not user_on_inbound(user, inbound):
            continue
        if protocol == "trojan":
            clients.append({"password": user["password"], "email": user["username"]})
        elif protocol == "vmess":
            clients.append({"id": user["uuid"], "email": user["username"], "alterId": 0})
        elif protocol == "shadowsocks":
            clients.append({
                "password": ss_user_key(
                    user, stream.get("ss_method", "2022-blake3-aes-256-gcm")),
                "email": user["username"],
            })
        else:  # vless
            client = {"id": user["uuid"], "email": user["username"]}
            if stream.get("flow"):
                client["flow"] = stream["flow"]
            clients.append(client)
    if protocol == "shadowsocks":
        settings = {
            "method": stream.get("ss_method", "2022-blake3-aes-256-gcm"),
            "password": ss_server_key(inbound),
            "network": "tcp,udp",
            "clients": clients,
        }
    else:
        settings = {"clients": clients}
        if protocol == "vless":
            settings["decryption"] = "none"
    return {
        "tag": f"in-{inbound['id']}", "listen": "0.0.0.0",
        "port": int(inbound["port"]), "protocol": protocol,
        "settings": settings, "streamSettings": _stream_settings(inbound),
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def xray_sync_users(users):
    """Rebuild the whole Xray inbound list from the panel database."""
    config = xray_load()
    generated = [
        _inbound_json(inbound, users)
        for inbound in list_inbounds() if inbound["enabled"]
    ]
    config["inbounds"] = [API_INBOUND] + generated
    xray_save(config)


def xray_inbounds_summary(users=None):
    if users is None:
        users = list_users_as_rows()
    summary = []
    for inbound in list_inbounds():
        clients = sum(
            1 for user in users
            if user["enabled"] and user_on_inbound(user, inbound)
        )
        stream = inbound_stream(inbound)
        summary.append({
            "id": inbound["id"], "remark": inbound["remark"],
            "protocol": inbound["protocol"], "port": inbound["port"],
            "network": inbound["network"], "path": inbound["path"],
            "security": inbound["security"], "enabled": bool(inbound["enabled"]),
            "clients": clients, "stream": stream,
            "flow": stream.get("flow", ""), "sni": stream.get("sni", ""),
            "max_clients": inbound["max_clients"] if "max_clients" in inbound.keys() else 0,
        })
    return summary


def _validate_inbound(data):
    protocol = data.get("protocol", "vless")
    if protocol not in INBOUND_PROTOCOLS:
        raise ValueError("Protocol must be vless, vmess, trojan or shadowsocks.")
    network = data.get("network", "ws")
    if network not in INBOUND_NETWORKS:
        raise ValueError("Transport must be tcp, ws, grpc, httpupgrade, xhttp or kcp.")
    security = data.get("security", "none")
    if security not in INBOUND_SECURITIES:
        raise ValueError("Security must be none, tls or reality.")
    if security == "reality":
        if protocol not in ("vless", "trojan"):
            raise ValueError("Reality works with VLESS and Trojan only.")
        if network not in ("tcp", "grpc", "xhttp"):
            raise ValueError("Reality needs TCP, gRPC or XHTTP transport.")
    if protocol == "shadowsocks" and security != "none":
        raise ValueError("Shadowsocks inbounds use their own encryption (security: none).")
    port = int(data.get("port") or 0)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    stream = {
        "path": (data.get("path") or "/ray").strip() or "/ray",
        "host_header": (data.get("host_header") or "").strip(),
        "service_name": (data.get("service_name") or "").strip(),
        "multi_mode": bool(data.get("multi_mode")),
        "xhttp_mode": data.get("xhttp_mode") or "auto",
        "header_type": data.get("header_type") or "none",
        "seed": (data.get("seed") or "").strip(),
        "flow": (data.get("flow") or "") if protocol == "vless" else "",
        "sni": (data.get("sni") or "").strip(),
        "fingerprint": data.get("fingerprint") or "chrome",
        "dest": (data.get("dest") or "").strip(),
        "ss_method": data.get("ss_method") or "2022-blake3-aes-256-gcm",
    }
    if stream["ss_method"] not in SS_METHODS:
        raise ValueError("Unknown Shadowsocks method.")
    if stream["flow"] not in ("", "xtls-rprx-vision"):
        raise ValueError("Unknown VLESS flow.")
    if stream["flow"] and (protocol != "vless" or security != "reality" or network != "tcp"):
        raise ValueError("xtls-rprx-vision requires VLESS + TCP + REALITY.")
    if security == "reality" and not stream["dest"]:
        stream["dest"] = "www.microsoft.com:443"
    if security == "reality":
        if ":" not in stream["dest"] or not stream["sni"] and not stream["dest"].split(":")[0]:
            raise ValueError("REALITY requires a valid destination host:port and SNI.")
    if security == "tls" and not stream["sni"]:
        raise ValueError("TLS inbound requires an SNI/server hostname.")
    max_clients = int(data.get("max_clients") or 0)
    if max_clients < 0:
        raise ValueError("Max clients cannot be negative.")
    return protocol, network, security, port, stream, max_clients


def _apply_security_material(inbound_id, security, stream):
    """Generate TLS certs / Reality keys for an inbound, in place on stream."""
    if security == "tls" and not stream.get("cert_file"):
        cert, key = gen_inbound_cert(inbound_id, stream.get("sni", ""))
        stream["cert_file"], stream["key_file"] = cert, key
    if security == "reality" and not stream.get("reality_priv"):
        priv, pub = gen_reality_keys()
        stream["reality_priv"], stream["reality_pub"] = priv, pub
        stream["short_id"] = secrets.token_hex(4)
        if not stream["dest"]:
            stream["dest"] = "www.microsoft.com:443"
        if not stream["sni"]:
            stream["sni"] = stream["dest"].split(":")[0]
    return stream


def port_is_listening(port):
    if MOCK:
        return False
    result = run(["ss", "-H", "-lntu"], timeout=8)
    if result.returncode != 0:
        raise RuntimeError("Unable to inspect listening ports; refusing unsafe inbound creation.")
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local = fields[4]
        try:
            bound_port = int(local.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if bound_port == int(port):
            return True
    return False


def create_inbound(data):
    protocol, network, security, port, stream, max_clients = _validate_inbound(data)
    conn = db()
    try:
        if conn.execute("SELECT 1 FROM inbounds WHERE port = ?", (port,)).fetchone():
            raise ValueError("Another inbound already uses that port.")
        if port_is_listening(port):
            raise ValueError(f"Port {port} is already occupied by another service.")
        cursor = conn.execute(
            "INSERT INTO inbounds (remark, protocol, port, network, path, security, "
            "enabled, stream_json, max_clients) VALUES (?, ?, ?, ?, ?, ?, 1, '{}', ?)",
            (data.get("remark") or f"{protocol.upper()} {port}", protocol, port,
             network, stream["path"], security, max_clients),
        )
        inbound_id = cursor.lastrowid
        stream = _apply_security_material(inbound_id, security, stream)
        conn.execute("UPDATE inbounds SET stream_json = ? WHERE id = ?",
                     (json.dumps(stream), inbound_id))
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    conn.close()
    try:
        xray_sync_users(list_users_as_rows())
    except Exception:
        rollback = db()
        rollback.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
        rollback.commit()
        rollback.close()
        raise
    return inbound_id


def update_inbound(inbound_id, data):
    conn = db()
    row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("Inbound not found.")
    original = dict(row)
    old_stream = inbound_stream(original)
    merged = dict(old_stream)
    merged.update({
        "protocol": row["protocol"], "network": row["network"],
        "security": row["security"], "port": row["port"],
        "max_clients": row["max_clients"] if "max_clients" in row.keys() else 0,
    })
    merged.update({k: v for k, v in data.items() if v is not None})
    protocol, network, security, port, stream, max_clients = _validate_inbound(merged)
    for keep in ("cert_file", "key_file", "reality_priv", "reality_pub", "short_id"):
        if old_stream.get(keep) and not data.get("regenerate"):
            stream[keep] = old_stream[keep]
    if conn.execute("SELECT 1 FROM inbounds WHERE port = ? AND id != ?",
                    (port, inbound_id)).fetchone():
        conn.close()
        raise ValueError("Another inbound already uses that port.")
    if port != original["port"] and port_is_listening(port):
        conn.close()
        raise ValueError(f"Port {port} is already occupied by another service.")
    stream = _apply_security_material(inbound_id, security, stream)
    conn.execute(
        "UPDATE inbounds SET remark = ?, protocol = ?, port = ?, network = ?, "
        "path = ?, security = ?, stream_json = ?, max_clients = ? WHERE id = ?",
        (data.get("remark") or row["remark"], protocol, port, network,
         stream["path"], security, json.dumps(stream), max_clients, inbound_id),
    )
    conn.commit()
    conn.close()
    try:
        xray_sync_users(list_users_as_rows())
    except Exception:
        restore = db()
        restore.execute(
            "UPDATE inbounds SET remark=?, protocol=?, port=?, network=?, path=?, "
            "security=?, enabled=?, stream_json=?, max_clients=? WHERE id=?",
            (original["remark"], original["protocol"], original["port"],
             original["network"], original["path"], original["security"],
             original["enabled"], original["stream_json"], original.get("max_clients", 0),
             inbound_id),
        )
        restore.commit()
        restore.close()
        raise
    return inbound_id


def delete_inbound(inbound_id):
    conn = db()
    row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("Inbound not found.")
    original = dict(row)
    conn.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
    conn.commit()
    conn.close()
    try:
        xray_sync_users(list_users_as_rows())
    except Exception:
        restore = db()
        columns = list(original.keys())
        names = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        restore.execute(
            f"INSERT INTO inbounds ({names}) VALUES ({placeholders})",
            tuple(original[k] for k in columns),
        )
        restore.commit()
        restore.close()
        raise


def xray_stats():
    """Return {email: (up, down)} cumulative bytes from the Xray API."""
    if MOCK:
        return {}
    result = run(
        ["xray", "api", "statsquery", f"--server={XRAY_API}"], timeout=15
    )
    stats = {}
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return stats
    for entry in data.get("stat", []):
        parts = entry.get("name", "").split(">>>")
        if len(parts) == 4 and parts[0] == "user":
            email, kind = parts[1], parts[3]
            up, down = stats.get(email, (0, 0))
            if kind == "uplink":
                up = int(entry.get("value", 0))
            elif kind == "downlink":
                down = int(entry.get("value", 0))
            stats[email] = (up, down)
    return stats


def inbound_link(inbound, user, settings):
    """Build the share link for one user on one inbound (3x-ui style)."""
    import base64
    from urllib.parse import quote
    host = server_host(settings)
    protocol = inbound["protocol"]
    port = int(inbound["port"])
    network = inbound["network"]
    stream = inbound_stream(inbound)
    security = inbound["security"] or "none"
    path = stream.get("path") or inbound["path"] or "/ray"
    name = quote(f"{inbound['remark']}-{user['username']}")
    if protocol == "shadowsocks":
        method = stream.get("ss_method", "2022-blake3-aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(
            f"{method}:{ss_user_key(user, method)}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port}#{name}"
    params = [("type", network)]
    if network == "ws":
        params.append(("path", path))
        if stream.get("host_header"):
            params.append(("host", stream["host_header"]))
    elif network == "grpc":
        params.append(("serviceName", stream.get("service_name", "")))
        params.append(("mode", "multi" if stream.get("multi_mode") else "gun"))
    elif network == "httpupgrade":
        params.append(("path", path))
        if stream.get("host_header"):
            params.append(("host", stream["host_header"]))
    elif network == "xhttp":
        params.append(("path", path))
        params.append(("mode", stream.get("xhttp_mode", "auto")))
    elif network == "tcp":
        params.append(("headerType", stream.get("header_type", "none")))
        if stream.get("header_type") == "http" and stream.get("host_header"):
            params.append(("host", stream["host_header"]))
    elif network == "kcp":
        params.append(("headerType", stream.get("header_type", "none")))
        if stream.get("seed"):
            params.append(("seed", stream["seed"]))
    params.append(("security", security))
    if security == "tls":
        if stream.get("sni"):
            params.append(("sni", stream["sni"]))
        params.append(("fp", stream.get("fingerprint", "chrome")))
        params.append(("alpn", "h2,http/1.1"))
    elif security == "reality":
        if stream.get("sni"):
            params.append(("sni", stream["sni"]))
        params.append(("fp", stream.get("fingerprint", "chrome")))
        params.append(("pbk", stream.get("reality_pub", "")))
        params.append(("sid", stream.get("short_id", "")))
        params.append(("spx", "/"))
    if protocol == "vless" and stream.get("flow"):
        params.append(("flow", stream["flow"]))
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params)
    if protocol == "vless":
        return f"vless://{user['uuid']}@{host}:{port}?encryption=none&{query}#{name}"
    if protocol == "trojan":
        return f"trojan://{quote(user['password'], safe='')}@{host}:{port}?{query}#{name}"
    payload = {
        "v": "2", "ps": f"{inbound['remark']}-{user['username']}", "add": host,
        "port": str(port), "id": user["uuid"], "aid": "0", "scy": "auto",
        "net": network,
        "type": (stream.get("header_type", "none") if network in ("tcp", "kcp") else ""),
        "host": stream.get("host_header", ""),
        "path": (path if network in ("ws", "httpupgrade", "xhttp")
                 else stream.get("service_name", "") if network == "grpc" else ""),
        "tls": security if security != "none" else "",
        "sni": stream.get("sni", ""),
        "alpn": "h2,http/1.1" if security == "tls" else "",
        "fp": stream.get("fingerprint", "chrome") if security != "none" else "",
    }
    if security == "reality":
        payload["pbk"] = stream.get("reality_pub", "")
        payload["sid"] = stream.get("short_id", "")
        payload["spx"] = "/"
    encoded = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()
    return f"vmess://{encoded}"


# --------------------------------------------------------------------------
# OpenVPN users
# --------------------------------------------------------------------------

def ovpn_create_user(username):
    run_shell(
        f"cd {OVPN_DIR}/easy-rsa && EASYRSA_BATCH=1 ./easyrsa build-client-full "
        f"{username} nopass",
        timeout=120,
    )


def ovpn_revoke_user(username):
    run_shell(
        f"cd {OVPN_DIR}/easy-rsa && EASYRSA_BATCH=1 ./easyrsa revoke {username} && "
        f"EASYRSA_BATCH=1 ./easyrsa gen-crl && "
        f"cp pki/crl.pem {OVPN_DIR}/crl.pem && systemctl restart openvpn-server@server || true",
        timeout=120,
    )


def ovpn_client_config(username, settings):
    host = server_host(settings)
    if MOCK:
        return f"# mock config for {username}\nremote {host} {settings['ovpn_port']}\n"
    def read(path):
        with open(path) as fh:
            return fh.read().strip()
    base = read(f"{OVPN_DIR}/client-common.txt") if os.path.exists(
        f"{OVPN_DIR}/client-common.txt") else (
        f"client\ndev tun\nproto {settings['ovpn_proto']}\n"
        f"remote {host} {settings['ovpn_port']}\nresolv-retry infinite\nnobind\n"
        "persist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\n"
        "verb 3\n")
    ca = read(f"{OVPN_DIR}/easy-rsa/pki/ca.crt")
    cert = read(f"{OVPN_DIR}/easy-rsa/pki/issued/{username}.crt")
    key = read(f"{OVPN_DIR}/easy-rsa/pki/private/{username}.key")
    cert_body = cert[cert.find("-----BEGIN CERTIFICATE-----"):]
    return (
        f"{base}\n<ca>\n{ca}\n</ca>\n<cert>\n{cert_body}\n</cert>\n"
        f"<key>\n{key}\n</key>\n"
    )


def ovpn_status_bytes():
    """Return {common_name: session_bytes} from the OpenVPN status log."""
    totals = {}
    if MOCK or not os.path.exists(OVPN_STATUS):
        return totals
    current = None
    received = sent = 0
    with open(OVPN_STATUS, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("CLIENT_LIST,"):
                fields = line.split(",")
                if len(fields) >= 5:
                    totals[fields[1]] = int(fields[2]) + int(fields[3])
    return totals


# --------------------------------------------------------------------------
# DNSTT
# --------------------------------------------------------------------------

def dnstt_info(settings):
    info = {
        "installed": MOCK or os.path.exists("/usr/local/bin/dnstt-server"),
        "active": service_active("dnstt"),
        "domain": settings.get("dnstt_domain", ""),
        "port": settings.get("dnstt_port", "53"),
        "pubkey": "",
    }
    pub = os.path.join(DNSTT_DIR, "server.pub")
    if os.path.exists(pub):
        with open(pub) as fh:
            info["pubkey"] = fh.read().strip()
    elif MOCK:
        info["pubkey"] = "(mock) ab12cd34..."
    return info


# --------------------------------------------------------------------------
# user records, accounting and enforcement
# --------------------------------------------------------------------------

def user_public(row, settings, online_ips=None):
    protocols = [p for p in row["protocols"].split(",") if p]
    expired = bool(row["expire_date"]) and row["expire_date"] < today().isoformat()
    data = {
        "id": row["id"],
        "username": row["username"],
        "protocols": protocols,
        "uuid": row["uuid"],
        "ip_limit": row["ip_limit"] if "ip_limit" in row.keys() else 0,
        "hwid_limit": row["hwid_limit"] if "hwid_limit" in row.keys() else 0,
        "hwids": [h for h in (row["hwids"] or "").split(",") if h]
        if "hwids" in row.keys() else [],
        "inbound_ids": user_inbound_ids(row),
        "quota_bytes": row["quota_bytes"],
        "used_bytes": row["used_bytes"],
        "quota_gb": round(row["quota_bytes"] / GB, 2) if row["quota_bytes"] else 0,
        "used_gb": round(row["used_bytes"] / GB, 3),
        "expire_date": row["expire_date"],
        "enabled": bool(row["enabled"]) and not expired,
        "locked": not bool(row["enabled"]),
        "expired": expired,
        "created_at": row["created_at"],
        "last_online": row["last_online"] if "last_online" in row.keys() else "",
        "note": row["note"],
        "percent": (
            round(100.0 * row["used_bytes"] / row["quota_bytes"], 1)
            if row["quota_bytes"] else 0
        ),
        "online_ips": online_ips or [],
    }
    host = server_host(settings)
    info = {}
    if "ssh" in protocols:
        cf_host = settings.get("cf_ws_host", "")
        info["1_direct"] = f"{host}:{settings['ssh_port']}"
        info["2_websocket"] = f"{host}:{settings['ws_port']}"
        info["3_ws_payload"] = (
            f"GET / HTTP/1.1[crlf]Host: {host}[crlf]"
            "Upgrade: websocket[crlf]Connection: Upgrade[crlf]"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]"
            "Sec-WebSocket-Version: 13[crlf][crlf]"
        )
        info["4_websocket_tls"] = (
            f"{host}:{settings['wss_port']}  (SNI: {settings.get('sni_host', '')})"
        )
        if cf_host:
            info["5_cloudflare_ws"] = f"{cf_host}:443"
            info["6_cf_payload"] = (
                f"GET / HTTP/1.1[crlf]Host: {cf_host}[crlf]"
                "Upgrade: websocket[crlf]Connection: Upgrade[crlf]"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]"
                "Sec-WebSocket-Version: 13[crlf][crlf]"
            )
    seen_protocols = set()
    for inbound in list_inbounds():
        protocol = inbound["protocol"]
        if not inbound["enabled"] or not user_on_inbound(row, inbound):
            continue
        if protocol in seen_protocols:
            key = f"{protocol}_link_{inbound['id']}"
        else:
            key = f"{protocol}_link"
            seen_protocols.add(protocol)
        info[key] = inbound_link(inbound, row, settings)
    if "ovpn" in protocols:
        info["ovpn_config"] = f"/api/users/{row['id']}/ovpn"
    if "dnstt" in protocols:
        info["dnstt_domain"] = settings.get("dnstt_domain", "")
    data["info"] = info
    return data


def list_users(settings):
    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    online = online_ip_map()
    return [user_public(row, settings, online.get(row["username"], []))
            for row in rows]


def user_inbound_ids(row):
    """Inbound ids this user is assigned to; empty list = all matching."""
    try:
        ids = json.loads(row["inbound_ids"] or "")
    except (ValueError, TypeError, KeyError):
        return []
    return [int(i) for i in ids] if isinstance(ids, list) else []


def user_on_inbound(row, inbound):
    if inbound["protocol"] not in row["protocols"].split(","):
        return False
    ids = user_inbound_ids(row)
    return not ids or inbound["id"] in ids


def clean_inbound_ids(data):
    ids = data.get("inbound_ids")
    if ids is None:
        return ""
    if not isinstance(ids, list):
        raise ValueError("inbound_ids must be an array of inbound IDs.")
    valid = {ib["id"] for ib in list_inbounds()}
    keep = set()
    for item in ids:
        if isinstance(item, bool) or not str(item).isdigit():
            raise ValueError("Inbound IDs must be positive integers.")
        inbound_id = int(item)
        if inbound_id not in valid:
            raise ValueError(f"Inbound {inbound_id} does not exist.")
        keep.add(inbound_id)
    # Empty array intentionally means all matching inbounds (legacy contract).
    return json.dumps(sorted(keep)) if keep else ""


def check_inbound_capacity(protocols, exclude_user_id=None, inbound_ids=""):
    """Raise if adding a client with these protocols would overflow an inbound."""
    selected = []
    if inbound_ids:
        try:
            selected = [int(i) for i in json.loads(inbound_ids)]
        except (ValueError, TypeError):
            selected = []
    rows = list_users_as_rows()
    for inbound in list_inbounds():
        if not inbound["enabled"]:
            continue
        max_clients = inbound["max_clients"] if "max_clients" in inbound.keys() else 0
        if not max_clients or inbound["protocol"] not in protocols:
            continue
        if selected and inbound["id"] not in selected:
            continue
        count = sum(
            1 for row in rows
            if row["enabled"] and row["id"] != exclude_user_id
            and user_on_inbound(row, inbound)
        )
        if count >= max_clients:
            raise ValueError(
                f"Inbound '{inbound['remark']}' is full "
                f"({count}/{max_clients} clients). Raise its client limit first.")


def create_user(data):
    username = (data.get("username") or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError("Username must be 3-32 chars, start with a letter, "
                         "and use lowercase letters, digits, - or _.")
    if username in ("root", "admin", "ubuntu"):
        raise ValueError("That username is reserved.")
    requested_protocols = data.get("protocols", ["ssh"])
    allowed_protocols = {"ssh", "vless", "vmess", "trojan", "shadowsocks", "ovpn", "dnstt"}
    if not isinstance(requested_protocols, list) or not requested_protocols:
        raise ValueError("Pick at least one protocol.")
    if any(p not in allowed_protocols for p in requested_protocols):
        raise ValueError("One or more selected protocols are unsupported.")
    protocols = list(dict.fromkeys(requested_protocols))
    inbound_ids = clean_inbound_ids(data)
    check_inbound_capacity(protocols, inbound_ids=inbound_ids)
    password = data.get("password") or secrets.token_urlsafe(12)
    if not isinstance(password, str) or not (8 <= len(password) <= 128) or any(
            ch in password for ch in ("\\n", "\\r", "\\x00")):
        raise ValueError("Credential must be 8-128 characters and contain no line breaks.")
    try:
        days = int(data.get("days") if data.get("days") is not None else 30)
        quota_gb = float(data.get("quota_gb") or 0)
        ip_limit = int(data.get("ip_limit") or 0)
        hwid_limit = int(data.get("hwid_limit") or 0)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Days, quota and limits must be valid numbers.")
    if not 0 <= days <= 3650:
        raise ValueError("Validity must be between 0 and 3650 days.")
    if not 0 <= quota_gb <= 1000000:
        raise ValueError("Quota must be between 0 and 1,000,000 GB.")
    if not 0 <= ip_limit <= 10000 or not 0 <= hwid_limit <= 10000:
        raise ValueError("IP and device limits must be between 0 and 10,000.")
    note = str(data.get("note", ""))
    if len(note) > 2000:
        raise ValueError("Note cannot exceed 2,000 characters.")
    expire = (today() + timedelta(days=days)).isoformat() if days > 0 else ""
    quota = int(round(quota_gb * GB))
    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        conn.close()
        raise ValueError("A user with that name already exists in the panel.")
    cursor = conn.execute(
        "INSERT INTO users (username, password, protocols, uuid, quota_bytes, "
        "expire_date, created_at, note, ip_limit, hwid_limit, inbound_ids) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (username, password if ({"trojan", "shadowsocks"} & set(protocols)) else "",
         ",".join(protocols), str(uuidlib.uuid4()),
         quota, expire, datetime.now().isoformat(timespec="seconds"),
         note, ip_limit, hwid_limit, inbound_ids),
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    ssh_created = False
    ovpn_created = False
    try:
        if "ssh" in protocols:
            ssh_create_user(username, password, expire)
            ssh_created = True
        if "ovpn" in protocols:
            ovpn_create_user(username)
            ovpn_created = True
        xray_sync_users(list_users_as_rows())
    except Exception:
        # Compensate external resources in reverse order. Keep the original
        # failure visible; cleanup is best-effort and never hides it.
        if ovpn_created:
            try:
                ovpn_revoke_user(username)
            except Exception:
                pass
        if ssh_created:
            try:
                ssh_delete_user(username)
            except Exception:
                pass
        cleanup = db()
        cleanup.execute("DELETE FROM users WHERE id = ?", (user_id,))
        cleanup.commit()
        cleanup.close()
        try:
            xray_sync_users(list_users_as_rows())
        except Exception:
            pass
        raise
    settings = get_settings()
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    audit_event("user.create", "user", user_id,
                details={"username": username, "protocols": protocols})
    public = user_public(row, settings)
    # The initial SSH/Trojan/SS credentials are delivered once by the create
    # response. They are never included in subsequent list/detail responses.
    if set(protocols) & {"ssh", "trojan", "shadowsocks"}:
        public["credential_once"] = password
    return public


def list_users_as_rows():
    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_user(user_id, data):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("User not found.")
    row = dict(row)
    protocols = row["protocols"].split(",")
    if "protocols" in data:
        new_protocols = [p for p in data.get("protocols") or []
                         if p in ("ssh", "vless", "vmess", "trojan",
                                  "shadowsocks", "ovpn", "dnstt")]
        if new_protocols and new_protocols != protocols:
            check_inbound_capacity(new_protocols, exclude_user_id=user_id)
            added = [p for p in new_protocols if p not in protocols]
            if "ssh" in added and not ssh_user_exists(row["username"]):
                ssh_create_user(row["username"],
                                data.get("password") or row["password"],
                                row["expire_date"])
            if "ovpn" in added:
                ovpn_create_user(row["username"])
            protocols = new_protocols
            row["protocols"] = ",".join(new_protocols)
    if "inbound_ids" in data:
        row["inbound_ids"] = clean_inbound_ids(data)
        check_inbound_capacity(protocols, exclude_user_id=user_id,
                               inbound_ids=row["inbound_ids"])
    if "quota_gb" in data:
        row["quota_bytes"] = int(round(float(data["quota_gb"] or 0) * GB))
    if "days" in data:
        days = int(data["days"] or 0)
        row["expire_date"] = (
            (today() + timedelta(days=days)).isoformat() if days > 0 else ""
        )
    if "password" in data and data["password"]:
        row["password"] = data["password"]
        if "ssh" in protocols:
            proc = subprocess.run(
                ["chpasswd"], input=f"{row['username']}:{row['password']}\n",
                capture_output=True, text=True,
            ) if not MOCK else subprocess.CompletedProcess([], 0, "", "")
            if not MOCK and proc.returncode != 0:
                raise RuntimeError("chpasswd failed.")
    if "note" in data:
        row["note"] = data["note"]
    if "ip_limit" in data:
        row["ip_limit"] = int(data["ip_limit"] or 0)
    if "hwid_limit" in data:
        row["hwid_limit"] = int(data["hwid_limit"] or 0)
    if data.get("reset_hwids"):
        row["hwids"] = ""
    if "enabled" in data:
        if data["enabled"] and not row["enabled"]:
            check_inbound_capacity(protocols, exclude_user_id=user_id)
        row["enabled"] = 1 if data["enabled"] else 0
        row["auto_locked"] = 0
        apply_enabled_state(row)
    conn.execute(
        "UPDATE users SET quota_bytes = ?, expire_date = ?, password = ?, "
        "note = ?, enabled = ?, ip_limit = ?, hwid_limit = ?, hwids = ?, "
        "protocols = ?, auto_locked = ?, inbound_ids = ? WHERE id = ?",
        (row["quota_bytes"], row["expire_date"], row["password"],
         row["note"], row["enabled"], row["ip_limit"], row["hwid_limit"],
         row["hwids"], row["protocols"],
         row["auto_locked"] if "auto_locked" in row else 0,
         row["inbound_ids"] if "inbound_ids" in row else "", user_id),
    )
    if "ssh" in protocols and "days" in data:
        run(["chage", "-E", row["expire_date"] or "-1", row["username"]])
    conn.commit()
    fresh = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    xray_sync_users(list_users_as_rows())
    return user_public(fresh, get_settings())


def apply_enabled_state(row):
    protocols = row["protocols"].split(",")
    if "ssh" in protocols and ssh_user_exists(row["username"]):
        ssh_set_enabled(row["username"], bool(row["enabled"]))


def renew_user(user_id, days, reset_traffic):
    """Extend validity (3x-ui style renew) and optionally zero the traffic."""
    days = int(days or 0)
    if days <= 0:
        raise ValueError("Renewal days must be positive.")
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("User not found.")
    row = dict(row)
    base = today()
    if row["expire_date"]:
        try:
            current = date.fromisoformat(row["expire_date"])
            if current > base:
                base = current
        except ValueError:
            pass
    row["expire_date"] = (base + timedelta(days=days)).isoformat()
    if reset_traffic:
        row["used_bytes"] = 0
        if "ssh" in row["protocols"].split(","):
            row["ssh_last"] = ssh_chain_bytes(row["username"])
        up, down = xray_stats().get(row["username"], (0, 0))
        row["xray_up_last"], row["xray_down_last"] = up, down
        row["ovpn_last"] = ovpn_status_bytes().get(row["username"], 0)
    row["enabled"] = 1
    row["auto_locked"] = 0
    conn.execute(
        "UPDATE users SET expire_date = ?, used_bytes = ?, enabled = ?, "
        "ssh_last = ?, xray_up_last = ?, xray_down_last = ?, ovpn_last = ?, "
        "auto_locked = 0 WHERE id = ?",
        (row["expire_date"], row["used_bytes"], 1, row["ssh_last"],
         row["xray_up_last"], row["xray_down_last"], row["ovpn_last"], user_id),
    )
    conn.commit()
    apply_enabled_state(row)
    fresh = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if "ssh" in row["protocols"].split(",") and ssh_user_exists(row["username"]):
        run(["chage", "-E", row["expire_date"], row["username"]])
        ssh_set_enabled(row["username"], True)
    xray_sync_users(list_users_as_rows())
    return user_public(fresh, get_settings())


def ssh_online_sessions():
    """Map username -> [(ip, pid, start_time)] for live sshd sessions."""
    sessions = {}
    if MOCK:
        return sessions
    result = run(["ss", "-tnHp", "state", "established", "( sport = :22 )"])
    for line in result.stdout.splitlines():
        match = re.search(r'"sshd",pid=(\d+)', line)
        fields = line.split()
        if not match or len(fields) < 5:
            continue
        pid = int(match.group(1))
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                title = fh.read().replace(b"\x00", b" ").decode(errors="replace")
            user_match = re.search(r"sshd:\s+([a-z][a-z0-9_-]*)", title)
            if not user_match:
                continue
            start = os.stat(f"/proc/{pid}").st_ctime
        except OSError:
            continue
        ip = fields[4].rsplit(":", 1)[0].strip("[]")
        sessions.setdefault(user_match.group(1), []).append((ip, pid, start))
    return sessions


def xray_online_ips():
    """Map email -> [ip, ...] from the Xray statsonline API (best effort)."""
    online = {}
    if MOCK:
        return online
    result = run(["xray", "api", "statsonline", f"--server={XRAY_API}"], timeout=15)
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return online

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, list) and value and \
                        all(isinstance(item, str) for item in value):
                    online[key] = value
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return online


def touch_last_online(online_map):
    """Record last-seen timestamps for users who are online right now."""
    if not online_map:
        return
    now = datetime.now()
    stamp = now.isoformat(timespec="seconds")
    stale_before = (now - timedelta(seconds=50)).isoformat(timespec="seconds")
    try:
        conn = db()
        for username in online_map:
            conn.execute(
                "UPDATE users SET last_online = ? WHERE username = ? "
                "AND (last_online = '' OR last_online < ?)",
                (stamp, username, stale_before))
        conn.commit()
        conn.close()
    except Exception:
        pass


def online_ip_map():
    merged = {}
    for username, entries in ssh_online_sessions().items():
        merged.setdefault(username, set()).update(ip for ip, _, _ in entries)
    for email, ips in xray_online_ips().items():
        merged.setdefault(email, set()).update(ips)
    result = {user: sorted(ips) for user, ips in merged.items()}
    touch_last_online(result)
    return result


def online_payload():
    """Live online clients (SSH + Xray) plus a recently-seen list."""
    rows = list_users_as_rows()
    ssh_map = ssh_online_sessions()
    xray_map = xray_online_ips()
    online = []
    online_names = set()
    for row in rows:
        via, ips = [], set()
        if row["username"] in ssh_map:
            via.append("SSH")
            ips.update(ip for ip, _, _ in ssh_map[row["username"]])
        if row["username"] in xray_map:
            via.append("Xray")
            ips.update(xray_map[row["username"]])
        if not via:
            continue
        online_names.add(row["username"])
        online.append({
            "username": row["username"], "via": via, "ips": sorted(ips),
            "protocols": [p for p in row["protocols"].split(",") if p],
            "used_bytes": row["used_bytes"], "quota_bytes": row["quota_bytes"],
            "expire_date": row["expire_date"], "note": row["note"],
        })
    touch_last_online({row["username"]: [] for row in rows
                       if row["username"] in online_names})
    recent = [
        {"username": row["username"], "last_online": row["last_online"],
         "protocols": [p for p in row["protocols"].split(",") if p]}
        for row in rows
        if row["last_online"] and row["username"] not in online_names
    ]
    recent.sort(key=lambda item: item["last_online"], reverse=True)
    return {
        "online": online, "recent": recent[:10],
        "counts": {
            "online": len(online),
            "ssh": sum(1 for item in online if "SSH" in item["via"]),
            "xray": sum(1 for item in online if "Xray" in item["via"]),
        },
    }


def enforce_ip_limits(rows):
    """Kill or drop connections beyond each user's IP limit."""
    sessions = ssh_online_sessions()
    xray_ports = [int(ib["port"]) for ib in list_inbounds() if ib["enabled"]]
    drops = set()
    online = xray_online_ips()
    for row in rows:
        limit = int(row.get("ip_limit") or 0)
        if limit <= 0:
            continue
        username = row["username"]
        protocols = row["protocols"].split(",")
        if "ssh" in protocols:
            entries = sessions.get(username, [])
            distinct = []
            for ip, pid, start in sorted(entries, key=lambda e: e[2]):
                if ip not in distinct:
                    distinct.append(ip)
            excess = set(distinct[limit:])
            for ip, pid, _ in entries:
                if ip in excess:
                    run(["kill", str(pid)])
        if {"vless", "vmess", "trojan"} & set(protocols):
            ips = online.get(username, [])
            for ip in ips[limit:]:
                for port in xray_ports:
                    drops.add((ip, port))
    run(["iptables", "-N", "MP_LIMIT"])
    run(["iptables", "-F", "MP_LIMIT"])
    for ip, port in sorted(drops):
        run(["iptables", "-A", "MP_LIMIT", "-s", ip, "-p", "tcp",
             "--dport", str(port), "-j", "DROP"])
    while run(["iptables", "-D", "INPUT", "-j", "MP_LIMIT"]).returncode == 0 \
            and not MOCK:
        pass
    run(["iptables", "-A", "INPUT", "-j", "MP_LIMIT"])


def delete_user(user_id):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError("User not found.")
    row = dict(row)
    protocols = row["protocols"].split(",")
    # Remove the client from Xray before deleting the durable control-plane row.
    conn.execute("UPDATE users SET enabled=0, auto_locked=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    try:
        xray_sync_users(list_users_as_rows())
        if "ssh" in protocols and ssh_user_exists(row["username"]):
            ssh_delete_user(row["username"])
        if "ovpn" in protocols:
            ovpn_revoke_user(row["username"])
    except Exception:
        # Keep the record present but disabled so an operator can repair cleanup.
        raise
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    audit_event("user.delete", "user", user_id,
                details={"username": row["username"], "protocols": protocols})


def enforce():
    """One accounting pass: fold counters into used_bytes, lock abusers."""
    settings = get_settings()
    xstats = xray_stats()
    ostats = ovpn_status_bytes()
    conn = db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    changed = False
    all_rows = []
    for raw in rows:
        row = dict(raw)
        all_rows.append(row)
        used = row["used_bytes"]
        if "ssh" in row["protocols"].split(","):
            current = ssh_chain_bytes(row["username"])
            delta = current - row["ssh_last"] if current >= row["ssh_last"] else current
            used += max(delta, 0)
            row["ssh_last"] = current
        if {"vless", "vmess"} & set(row["protocols"].split(",")):
            up, down = xstats.get(row["username"], (0, 0))
            delta = (up - row["xray_up_last"] if up >= row["xray_up_last"] else up) \
                + (down - row["xray_down_last"] if down >= row["xray_down_last"] else down)
            used += max(delta, 0)
            row["xray_up_last"], row["xray_down_last"] = up, down
        if "ovpn" in row["protocols"].split(","):
            current = ostats.get(row["username"], 0)
            delta = current - row["ovpn_last"] if current >= row["ovpn_last"] else 0
            used += max(delta, 0)
            row["ovpn_last"] = current
        over_quota = row["quota_bytes"] and used >= row["quota_bytes"]
        expired = row["expire_date"] and row["expire_date"] < today().isoformat()
        should_enable = not over_quota and not expired
        # The enforcer only undoes its OWN locks. A manual admin lock
        # (auto_locked = 0 while disabled) is never auto-released.
        auto_locked = row["auto_locked"] if "auto_locked" in row else 0
        if not should_enable and row["enabled"]:
            row["enabled"] = 0
            row["auto_locked"] = 1
            apply_enabled_state(row)
            changed = True
        elif should_enable and not row["enabled"] and auto_locked:
            row["enabled"] = 1
            row["auto_locked"] = 0
            apply_enabled_state(row)
            changed = True
        conn.execute(
            "UPDATE users SET used_bytes = ?, ssh_last = ?, xray_up_last = ?, "
            "xray_down_last = ?, ovpn_last = ?, enabled = ?, auto_locked = ? "
            "WHERE id = ?",
            (used, row["ssh_last"], row["xray_up_last"], row["xray_down_last"],
             row["ovpn_last"], row["enabled"],
             row["auto_locked"] if "auto_locked" in row else 0, row["id"]),
        )
    conn.commit()
    conn.close()
    if changed:
        xray_sync_users(list_users_as_rows())
    enforce_ip_limits(all_rows)
    return True


def init_net():
    for row in list_users_as_rows():
        if "ssh" in row["protocols"].split(",") and ssh_user_exists(row["username"]):
            ssh_ensure_chain(row["username"])
    return True


# --------------------------------------------------------------------------
# services
# --------------------------------------------------------------------------

SERVICES = [
    ("ssh", "SSH Server", "OpenSSH on :22"),
    ("wsproxy", "WebSocket Proxy", "SSH over WS on :80"),
    ("stunnel-ssh", "Stunnel (WSS)", "SSH over TLS on :443"),
    ("xray", "Xray (V2Ray)", "VLESS + VMess over WS"),
    ("openvpn-server@server", "OpenVPN", "UDP tunnel"),
    ("dnstt", "DNSTT", "DNS tunnel"),
    ("mpanel", "This Panel", "Management portal"),
]


def services_list():
    return [
        {"id": sid, "name": name, "desc": desc, "active": service_active(sid),
         "installed": service_installed(sid)}
        for sid, name, desc in SERVICES
    ]


def service_action(service_id, action):
    allowed = {sid for sid, _, _ in SERVICES}
    if service_id not in allowed or action not in ("start", "stop", "restart"):
        raise ValueError("Unknown service or action.")
    if service_id == "mpanel" and action in ("stop",):
        raise ValueError("The panel cannot stop itself from the panel.")
    run(["systemctl", action, service_id], check=True)
    return True


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # -- plumbing ----------------------------------------------------------
    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def send_json(self, payload, status=200, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        for key, value in (headers or {}).items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    self.send_header(key, item)
            else:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status=200, content_type="text/html; charset=utf-8",
                  headers=None):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body_json(self):
        raw_length = self.headers.get("Content-Length") or "0"
        if not raw_length.isdigit():
            raise ValueError("Invalid Content-Length.")
        length = int(raw_length)
        if length > MAX_REQUEST_BODY:
            raise ValueError("Request body exceeds 1 MiB limit.")
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request body must be valid UTF-8 JSON.")
        if not isinstance(data, dict):
            raise ValueError("JSON request body must be an object.")
        return data

    def request_origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        host = (self.headers.get("Host") or "").lower()
        return parsed.scheme in ("https", "http") and parsed.netloc.lower() == host

    def session_user(self):
        cookie = self.headers.get("Cookie") or ""
        token = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("mpanel_session="):
                token = part.split("=", 1)[1]
        if not token or len(token) > 256:
            return None
        conn = db()
        row = conn.execute(
            "SELECT expires_at, revoked_at FROM sessions WHERE token_hash=?",
            (token_hash(token),),
        ).fetchone()
        conn.close()
        if row and not row["revoked_at"] and int(row["expires_at"]) > int(time.time()):
            return token
        return None

    def require_auth(self):
        if self.session_user():
            return True
        self.send_json({"error": "Not logged in."}, status=401)
        return False

    def require_csrf(self):
        token = self.session_user()
        if not token:
            self.send_json({"error": "Not logged in."}, status=401)
            return False
        if not self.request_origin_ok():
            self.send_json({"error": "Cross-origin request rejected."}, status=403)
            return False
        supplied = self.headers.get("X-CSRF-Token") or ""
        conn = db()
        row = conn.execute(
            "SELECT csrf_hash FROM sessions WHERE token_hash=? AND revoked_at IS NULL",
            (token_hash(token),),
        ).fetchone()
        conn.close()
        if not row or not supplied or not hmac.compare_digest(
                row["csrf_hash"], token_hash(supplied)):
            self.send_json({"error": "CSRF validation failed. Reload and sign in again."},
                           status=403)
            return False
        return True

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/":
                return self.send_text(INDEX_HTML)
            if path == "/api/me":
                return self.send_json({"logged_in": bool(self.session_user())})
            if path == "/api/dashboard":
                if not self.require_auth():
                    return
                settings = get_settings()
                users = list_users(settings)
                return self.send_json({
                    "stats": server_stats(settings),
                    "users_total": len(users),
                    "users_active": sum(1 for u in users if u["enabled"]),
                    "traffic_total": sum(u["used_bytes"] for u in users),
                    "services": services_list(),
                    "dnstt": dnstt_info(settings),
                    "inbounds": xray_inbounds_summary(),
                    "settings": settings,
                })
            if path == "/api/users":
                if not self.require_auth():
                    return
                return self.send_json({"users": list_users(get_settings())})
            if path == "/api/online":
                if not self.require_auth():
                    return
                return self.send_json(online_payload())
            match = re.fullmatch(r"/api/users/(\d+)/ovpn", path)
            if match:
                if not self.require_auth():
                    return
                settings = get_settings()
                conn = db()
                row = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (int(match.group(1)),)
                ).fetchone()
                conn.close()
                if not row:
                    return self.send_json({"error": "User not found."}, status=404)
                if "ovpn" not in row["protocols"].split(",") or not row["enabled"]:
                    return self.send_json({"error": "OpenVPN is not enabled for this active user."},
                                          status=403)
                audit_event("openvpn.profile_download", "user", row["id"],
                            request_id=self.headers.get("X-Request-ID", ""))
                config = ovpn_client_config(row["username"], settings)
                return self.send_text(
                    config, content_type="application/octet-stream",
                    headers={"Content-Disposition":
                             f'attachment; filename="{row["username"]}.ovpn"'},
                )
            if path == "/api/inbounds":
                if not self.require_auth():
                    return
                return self.send_json({"inbounds": xray_inbounds_summary()})
            if path == "/api/services":
                if not self.require_auth():
                    return
                return self.send_json({"services": services_list()})
            if path == "/api/settings":
                if not self.require_auth():
                    return
                return self.send_json({"settings": get_settings()})
            return self.send_json({"error": "Not found."}, status=404)
        except Exception as exc:  # keep the panel alive on any single failure
            return self.send_json({"error": str(exc)}, status=500)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/login":
                if not self.request_origin_ok():
                    return self.send_json({"error": "Cross-origin request rejected."}, status=403)
                data = self.body_json()
                source_key = self.client_address[0] if self.client_address else "unknown"
                locked, retry_after = login_lock_state(source_key)
                if locked:
                    return self.send_json(
                        {"error": "Too many login attempts. Try again later.",
                         "retry_after": retry_after}, status=429,
                        headers={"Retry-After": str(retry_after)})
                conn = db()
                admin = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
                conn.close()
                if admin and data.get("username") == admin["username"] and \
                        check_password(data.get("password", ""), admin["password_hash"]):
                    clear_login_failures(source_key)
                    token = secrets.token_urlsafe(32)
                    csrf = secrets.token_urlsafe(32)
                    now = int(time.time())
                    conn = db()
                    conn.execute(
                        "INSERT INTO sessions (token_hash, csrf_hash, created_at, expires_at) "
                        "VALUES (?, ?, ?, ?)",
                        (token_hash(token), token_hash(csrf), now, now + SESSION_TTL_SECONDS),
                    )
                    conn.commit()
                    conn.close()
                    audit_event("auth.login", request_id=self.headers.get("X-Request-ID", ""))
                    return self.send_json(
                        {"ok": True},
                        headers={"Set-Cookie": [
                            f"mpanel_session={token}; Path=/; HttpOnly; Secure; "
                            "SameSite=Strict; Max-Age=604800",
                            f"mpanel_csrf={csrf}; Path=/; Secure; SameSite=Strict; Max-Age=604800",
                        ]},
                    )
                record_login_failure(source_key)
                return self.send_json({"error": "Wrong username or password."},
                                      status=403)
            if path == "/api/logout":
                if not self.require_csrf():
                    return
                token = self.session_user()
                if token:
                    conn = db()
                    conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?",
                                 (int(time.time()), token_hash(token)))
                    conn.commit()
                    conn.close()
                    audit_event("auth.logout", request_id=self.headers.get("X-Request-ID", ""))
                return self.send_json(
                    {"ok": True},
                    headers={"Set-Cookie": [
                        "mpanel_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
                        "mpanel_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0",
                    ]},
                )
            if not self.require_auth():
                return
            if not self.require_csrf():
                return
            if path == "/api/users":
                user = create_user(self.body_json())
                return self.send_json({"user": user})
            match = re.fullmatch(r"/api/users/(\d+)/renew", path)
            if match:
                data = self.body_json()
                user = renew_user(int(match.group(1)), data.get("days"),
                                  bool(data.get("reset_traffic")))
                return self.send_json({"user": user})
            match = re.fullmatch(r"/api/users/(\d+)", path)
            if match:
                user = update_user(int(match.group(1)), self.body_json())
                return self.send_json({"user": user})
            if path == "/api/inbounds":
                inbound_id = create_inbound(self.body_json())
                return self.send_json({"ok": True, "id": inbound_id,
                                       "inbounds": xray_inbounds_summary()})
            match = re.fullmatch(r"/api/inbounds/(\d+)", path)
            if match:
                inbound_id = update_inbound(int(match.group(1)), self.body_json())
                return self.send_json({"ok": True, "id": inbound_id,
                                       "inbounds": xray_inbounds_summary()})
            match = re.fullmatch(r"/api/services/([\w@.-]+)/(\w+)", path)
            if match:
                service_action(match.group(1), match.group(2))
                return self.send_json({"ok": True, "services": services_list()})
            if path == "/api/settings":
                data = self.body_json()
                for key, value in data.items():
                    if key in DEFAULT_SETTINGS:
                        set_setting(key, value)
                if "dnstt_domain" in data and not MOCK:
                    try:
                        os.makedirs(DNSTT_DIR, exist_ok=True)
                        with open(os.path.join(DNSTT_DIR, "domain"), "w") as fh:
                            fh.write(str(data["dnstt_domain"]).strip())
                    except OSError:
                        pass
                return self.send_json({"settings": get_settings()})
            if path == "/api/admin/password":
                data = self.body_json()
                conn = db()
                admin = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
                if not check_password(data.get("current", ""), admin["password_hash"]):
                    conn.close()
                    return self.send_json({"error": "Current password is wrong."},
                                          status=403)
                new_password = data.get("new", "")
                if not isinstance(new_password, str) or len(new_password) < 12:
                    conn.close()
                    return self.send_json({"error": "New password must be at least 12 characters."},
                                          status=400)
                conn.execute(
                    "UPDATE admin SET password_hash = ? WHERE id = 1",
                    (hash_password(data["new"]),),
                )
                current_token = self.session_user()
                conn.execute(
                    "UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL AND token_hash != ?",
                    (int(time.time()), token_hash(current_token or "")),
                )
                conn.commit()
                conn.close()
                audit_event("auth.password_change", request_id=self.headers.get("X-Request-ID", ""))
                return self.send_json({"ok": True})
            if path == "/api/dnstt/restart":
                service_action("dnstt", "restart")
                return self.send_json({"ok": True})
            return self.send_json({"error": "Not found."}, status=404)
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            return self.send_json({"error": str(exc)}, status=500)

    def do_DELETE(self):
        path = urlparse(self.path).path
        try:
            if not self.require_auth():
                return
            if not self.require_csrf():
                return
            match = re.fullmatch(r"/api/users/(\d+)", path)
            if match:
                delete_user(int(match.group(1)))
                return self.send_json({"ok": True})
            match = re.fullmatch(r"/api/inbounds/(\d+)", path)
            if match:
                delete_inbound(int(match.group(1)))
                return self.send_json({"ok": True,
                                       "inbounds": xray_inbounds_summary()})
            return self.send_json({"error": "Not found."}, status=404)
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            return self.send_json({"error": str(exc)}, status=500)


# --------------------------------------------------------------------------
# frontend (single page app)
# --------------------------------------------------------------------------

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexo</title>
<style>
:root{
  --bg:#05070a; --panel:#0b0f16; --panel2:#0f1520; --panel3:#131b29;
  --line:#1b2637; --line2:#243145;
  --text:#eaf1f9; --dim:#8d9cb1; --dim2:#5f7089;
  --a1:#2f7bff; --a2:#00b3ff; --grad:linear-gradient(135deg,#2f7bff,#00b3ff);
  --danger:#ff5c6c; --warn:#ffb84d; --ok:#2ee6a8; --violet:#9a7bff;
  --radius:18px; --shadow:0 18px 50px rgba(0,0,0,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scrollbar-color:#22314a var(--bg)}
body{background:var(--bg);color:var(--text);min-height:100vh;
  font-family:"Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
::selection{background:rgba(0,194,168,.35)}
button{font-family:inherit;cursor:pointer}
input,select,textarea{font-family:inherit}
svg.ic{width:20px;height:20px;flex:none;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
svg.ic.sm{width:15px;height:15px}

/* ---------- login ---------- */
#loginView{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
  background:radial-gradient(700px 420px at 50% -80px,rgba(0,163,217,.13),transparent 65%),
             radial-gradient(560px 380px at 85% 110%,rgba(0,194,168,.10),transparent 60%),var(--bg)}
.login-card{width:100%;max-width:400px;background:linear-gradient(180deg,var(--panel2),var(--panel));
  border:1px solid var(--line);border-radius:26px;padding:38px 34px 30px;box-shadow:var(--shadow);
  animation:rise .5s cubic-bezier(.2,.8,.25,1)}
@keyframes rise{from{opacity:0;transform:translateY(16px) scale(.98)}to{opacity:1;transform:none}}
.logo-ring{width:76px;height:76px;margin:0 auto 16px;border-radius:24px;background:var(--grad);
  display:flex;align-items:center;justify-content:center;color:#fff;
  box-shadow:0 12px 34px rgba(0,178,190,.4)}
.logo-ring svg{width:40px;height:40px}
.login-card h1{text-align:center;font-size:23px;letter-spacing:.6px}
.login-card h1 span{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.login-sub{text-align:center;color:var(--dim);font-size:13px;margin:7px 0 26px}
.field{margin-bottom:15px}
.field label{display:block;font-size:12px;font-weight:600;letter-spacing:.5px;color:var(--dim);
  text-transform:uppercase;margin-bottom:7px}
.field input,.field select{width:100%;background:#0a0e15;border:1px solid var(--line);
  border-radius:12px;padding:12px 14px;color:var(--text);font-size:14.5px;outline:none;transition:.18s}
.field input:focus,.field select:focus{border-color:var(--a1);box-shadow:0 0 0 3px rgba(0,194,168,.16)}
.btn{border:none;border-radius:12px;padding:11px 18px;font-size:14px;font-weight:650;color:#04241f;
  background:var(--grad);color:#fff;transition:.18s;display:inline-flex;align-items:center;gap:8px;justify-content:center}
.btn:hover{filter:brightness(1.12);transform:translateY(-1px)}
.btn:active{transform:none}
.btn.block{width:100%;padding:13px}
.btn.ghost{background:var(--panel3);color:var(--text);border:1px solid var(--line2)}
.btn.ghost:hover{border-color:var(--a1);filter:none}
.btn.danger{background:transparent;color:var(--danger);border:1px solid rgba(255,92,108,.45)}
.btn.danger:hover{background:rgba(255,92,108,.1);filter:none}
.btn.small{padding:7px 12px;font-size:12.5px;border-radius:9px}
.btn.icon{padding:8px;border-radius:9px}
.err{color:var(--danger);font-size:13px;min-height:18px;text-align:center;margin-top:10px}
.login-foot{text-align:center;color:var(--dim2);font-size:12px;margin-top:22px}

/* ---------- shell ---------- */
#appView{display:none}
.shell{display:flex;min-height:100vh}
aside{width:250px;flex:none;background:linear-gradient(180deg,#0a0e15,#070a0f);
  border-right:1px solid var(--line);padding:22px 14px;display:flex;flex-direction:column;gap:4px;
  position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:11px;padding:2px 8px 20px}
.brand .mark{width:42px;height:42px;border-radius:13px;background:var(--grad);color:#fff;
  display:flex;align-items:center;justify-content:center;box-shadow:0 8px 22px rgba(0,178,190,.35)}
.brand .mark svg{width:24px;height:24px}
.brand b{font-size:16.5px;letter-spacing:.4px;display:block;line-height:1.15}
.brand small{color:var(--dim);font-size:11px;letter-spacing:1.2px;text-transform:uppercase}
.nav-label{font-size:10.5px;letter-spacing:1.6px;color:var(--dim2);text-transform:uppercase;
  padding:14px 10px 7px;font-weight:700}
.nav-item{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:12px;
  color:var(--dim);font-size:14.5px;font-weight:550;cursor:pointer;border:1px solid transparent;
  transition:.16s;user-select:none}
.nav-item:hover{color:var(--text);background:var(--panel2)}
.nav-item.active{color:#fff;background:linear-gradient(90deg,rgba(0,194,168,.17),rgba(0,163,217,.07));
  border-color:rgba(0,194,168,.3)}
.nav-item.active svg{color:var(--a1)}
.side-foot{margin-top:auto;background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:13px 14px}
.side-foot .row{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--dim)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);flex:none}
.dot.off{background:var(--danger);box-shadow:0 0 8px var(--danger)}
.dot.na{background:#5b6b80;box-shadow:none;animation:none}
.pill.na{color:#8d9cb1;border-color:rgba(141,156,177,.35);background:rgba(141,156,177,.08)}
.ulink{display:flex;align-items:center;gap:8px;margin-top:6px;font-size:11.5px;font-weight:700;
  letter-spacing:.06em;color:var(--a2)}
.ulink .copy{margin-left:2px}
.dot.warn{background:var(--warn);box-shadow:0 0 8px var(--warn)}
main{flex:1;min-width:0;padding:26px 30px 44px;max-width:1280px;margin:0 auto;width:100%}
.topbar{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;margin-bottom:22px;flex-wrap:wrap}
.topbar h2{font-size:25px;letter-spacing:.2px}
.topbar .sub{color:var(--dim);font-size:13px;margin-top:3px}
.top-actions{display:flex;gap:9px;align-items:center}
.chip{display:inline-flex;align-items:center;gap:7px;background:var(--panel2);border:1px solid var(--line);
  border-radius:999px;padding:7px 13px;font-size:12.5px;color:var(--dim)}
.chip b{color:var(--text);font-weight:650}
.page{display:none;animation:fade .3s ease}
.page.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ---------- cards & dashboard ---------- */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:15px}
.kpi{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
  border-radius:var(--radius);padding:17px 18px;display:flex;align-items:center;gap:15px}
.ring{position:relative;width:76px;height:76px;flex:none}
.ring svg{transform:rotate(-90deg)}
.ring .bgc{stroke:#1a2536}
.ring .fgc{stroke:url(#ringGrad);transition:stroke-dashoffset .8s cubic-bezier(.2,.8,.25,1)}
.ring .val{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  font-size:18px;font-weight:800}
.kpi .meta small{display:block;color:var(--dim);font-size:11px;letter-spacing:1.1px;
  text-transform:uppercase;font-weight:700;margin-bottom:4px}
.kpi .meta b{font-size:18px;display:block}
.kpi .meta span{color:var(--dim);font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:15px}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
  border-radius:var(--radius);padding:20px}
.card h3{font-size:15px;display:flex;align-items:center;gap:9px;margin-bottom:14px}
.card h3 svg{color:var(--a1)}
.card h3 .right{margin-left:auto;font-size:12px;color:var(--dim);font-weight:500}
#netChart{width:100%;height:172px;display:block}
.legend{display:flex;gap:16px;font-size:12px;color:var(--dim);margin-top:9px}
.legend i{width:9px;height:9px;border-radius:3px;display:inline-block;margin-right:5px;vertical-align:-1px}
.syslist{display:grid;grid-template-columns:1fr 1fr;gap:9px 18px;font-size:13.5px}
.syslist .k{color:var(--dim)}
.syslist .v{text-align:right;font-weight:600;word-break:break-all}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:11px}
.svc{background:var(--panel3);border:1px solid var(--line);border-radius:14px;padding:14px 15px}
.svc .top{display:flex;align-items:center;gap:8px;font-weight:650;font-size:14px}
.svc .desc{color:var(--dim);font-size:12px;margin:5px 0 11px}
.svc .acts{display:flex;gap:6px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--dim2);font-size:11px;letter-spacing:1.1px;text-transform:uppercase;
  font-weight:700;padding:9px 10px;border-bottom:1px solid var(--line)}
td{padding:12px 10px;border-bottom:1px solid rgba(27,38,55,.6);vertical-align:middle}
tbody tr{transition:background .13s}
tbody tr:hover{background:rgba(255,255,255,.022)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:650;
  padding:4px 10px;border-radius:999px;border:1px solid var(--line2);color:var(--dim);white-space:nowrap}
.pill.ok{color:var(--ok);border-color:rgba(46,230,168,.35);background:rgba(46,230,168,.07)}
.pill.bad{color:var(--danger);border-color:rgba(255,92,108,.35);background:rgba(255,92,108,.07)}
.pill.warn{color:var(--warn);border-color:rgba(255,184,77,.35);background:rgba(255,184,77,.07)}
.pill.proto{color:#7dd7f5;border-color:rgba(0,163,217,.3);background:rgba(0,163,217,.06);text-transform:uppercase;letter-spacing:.4px}
.bar{height:7px;border-radius:99px;background:#182233;overflow:hidden;min-width:110px}
.bar i{display:block;height:100%;border-radius:99px;background:var(--grad);transition:width .6s ease}
.bar.hot i{background:linear-gradient(90deg,#ff9a3d,#ff5c6c)}
.uavatar{width:36px;height:36px;border-radius:12px;background:var(--grad);color:#fff;font-weight:750;
  display:inline-flex;align-items:center;justify-content:center;font-size:15px;flex:none}
.ucell{display:flex;align-items:center;gap:11px}
.ucell .n{font-weight:650}
.ucell .s{color:var(--dim);font-size:12px}
.rowacts{display:flex;gap:6px;flex-wrap:wrap}
.searchbar{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap}
.searchbar .grow{flex:1;min-width:200px;position:relative}
.searchbar input{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:12px;
  padding:11px 14px 11px 38px;color:var(--text);font-size:14px;outline:none}
.searchbar input:focus{border-color:var(--a1)}
.searchbar .sic{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--dim2)}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12.5px}
.muted{color:var(--dim)}
.dnstt-key{background:#0a0e15;border:1px dashed var(--line2);border-radius:12px;padding:12px 14px;
  word-break:break-all;font-size:12.5px}

/* ---------- modals ---------- */
.modal-wrap{position:fixed;inset:0;background:rgba(2,4,7,.72);display:none;align-items:flex-start;
  justify-content:center;padding:26px 14px;z-index:60;overflow-y:auto}
.modal{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line2);
  border-radius:22px;width:100%;max-width:520px;padding:26px;box-shadow:var(--shadow);
  max-height:calc(100dvh - 52px);overflow-y:auto;overscroll-behavior:contain;
  animation:pop .28s cubic-bezier(.2,.8,.25,1)}
.modal.wide{max-width:640px}
@keyframes pop{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:none}}
.modal h2{font-size:19px;margin-bottom:18px;display:flex;align-items:center;gap:10px}
.modal h2 svg{color:var(--a1)}
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.fgrid .full{grid-column:1/-1}
.checks{display:flex;flex-wrap:wrap;gap:8px}
.checks label{display:inline-flex;align-items:center;gap:7px;background:#0a0e15;border:1px solid var(--line);
  padding:8px 12px;border-radius:10px;font-size:13px;cursor:pointer;transition:.15s}
.checks label:has(input:checked){border-color:var(--a1);background:rgba(0,194,168,.09);color:#fff}
.checks input{accent-color:var(--a1)}
.modal .foot{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.info-sec{margin-bottom:17px}
.info-sec h4{font-size:11px;letter-spacing:1.3px;text-transform:uppercase;color:var(--dim2);
  margin-bottom:9px;font-weight:700}
.kv{display:flex;gap:10px;align-items:flex-start;background:#0a0e15;border:1px solid var(--line);
  border-radius:11px;padding:10px 12px;margin-bottom:7px}
.kv .k{color:var(--dim);font-size:12px;min-width:118px;padding-top:2px}
.kv .v{flex:1;word-break:break-all;font-size:13px}
.copy{flex:none;background:var(--panel3);border:1px solid var(--line2);color:var(--dim);
  border-radius:8px;padding:5px 9px;font-size:11.5px;font-weight:600}
.copy:hover{color:#fff;border-color:var(--a1)}
#toast{position:fixed;bottom:24px;left:50%;transform:translate(-50%,20px);background:#101a29;
  border:1px solid var(--a1);color:var(--text);padding:12px 20px;border-radius:13px;font-size:14px;
  opacity:0;pointer-events:none;transition:.3s;z-index:99;box-shadow:var(--shadow);max-width:92vw;text-align:center}
#toast.show{opacity:1;transform:translate(-50%,0)}
.dot{animation:pulse 2.2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(46,230,168,.45)}70%{box-shadow:0 0 0 7px rgba(46,230,168,0)}100%{box-shadow:0 0 0 0 rgba(46,230,168,0)}}
.dot.off,.dot.warn{animation:none}
#bottomNav{display:none}
.itabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:15px;overflow-x:auto}
.itabs button{background:none;border:none;color:var(--dim);font-size:13.5px;font-weight:600;
  padding:9px 14px;border-bottom:2px solid transparent;white-space:nowrap}
.itabs button.on{color:var(--a2);border-bottom-color:var(--a1)}
.tabhidden{display:none !important}
.spark{width:100%;height:30px;display:block;margin-top:7px}
.avgpeak{font-size:11px !important;letter-spacing:.4px}
.statstrip{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.statchip{flex:1;min-width:120px;background:var(--panel2);border:1px solid var(--line);
  border-radius:16px;padding:12px 15px;display:flex;align-items:center;gap:11px}
.statchip .n{font-size:21px;font-weight:800;line-height:1}
.statchip .l{font-size:11px;color:var(--dim);letter-spacing:.7px;text-transform:uppercase;font-weight:700}
.statchip .cdot{width:9px;height:9px;border-radius:50%;flex:none}
.ibpick{display:grid;gap:7px;max-height:190px;overflow:auto}
.ibopt{display:flex;gap:9px;align-items:center;background:var(--panel3);
  border:1px solid var(--line);padding:9px 12px;border-radius:12px;font-size:13px;cursor:pointer}
.ibopt input{accent-color:var(--a1);width:16px;height:16px}
#page-dashboard.loading .kpi{position:relative;overflow:hidden}
#page-dashboard.loading .kpi::after{content:"";position:absolute;inset:0;
  background:linear-gradient(100deg,transparent 30%,rgba(255,255,255,.05) 50%,transparent 70%);
  animation:shimmer 1.3s infinite}
@keyframes shimmer{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
@media(max-width:1020px){.kpis{grid-template-columns:repeat(2,1fr)}}
@media(max-width:860px){
  .shell{flex-direction:column}
  aside{display:none}
  main{padding:16px 12px 108px}
  .grid2{grid-template-columns:1fr}.fgrid{grid-template-columns:1fr}
  .kpis{grid-template-columns:repeat(2,1fr);gap:10px}
  .kpi{padding:13px;gap:10px}
  .ring{width:60px;height:60px}.ring svg{width:60px;height:60px}
  .ring .val{font-size:13px}
  .topbar h2{font-size:21px}
  .card{padding:15px;border-radius:20px}
  /* tables become cards */
  .tblwrap{overflow:visible}
  .tblwrap table,.tblwrap tbody,.tblwrap tr,.tblwrap td{display:block;width:100%}
  .tblwrap thead{display:none}
  .tblwrap tr{background:var(--panel3);border:1px solid var(--line);border-radius:16px;
    padding:10px 13px;margin:10px 0}
  .tblwrap td{border:none;padding:6px 0;display:flex;justify-content:space-between;
    align-items:center;gap:12px;text-align:right}
  .tblwrap td::before{content:attr(data-label);color:var(--dim2);font-size:11px;
    letter-spacing:.8px;text-transform:uppercase;font-weight:700;text-align:left}
  .tblwrap td:first-child{justify-content:flex-start}
  .tblwrap td:first-child::before{display:none}
  .tblwrap td .rowacts{justify-content:flex-end}
  /* bottom navigation (app style) */
  #bottomNav{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:55;
    background:rgba(9,13,20,.94);backdrop-filter:blur(16px);
    border-top:1px solid var(--line);justify-content:space-around;
    padding:7px 4px calc(7px + env(safe-area-inset-bottom))}
  #bottomNav .nav-item{flex-direction:column;gap:3px;font-size:10px;font-weight:600;
    padding:7px 9px;border-radius:14px;border:none}
  #bottomNav .nav-item svg{width:21px;height:21px}
  #bottomNav .nav-item .pill{position:absolute;margin:-8px 0 0 26px;padding:1px 6px;font-size:9.5px}
  /* modals become bottom sheets */
  .modal-wrap{align-items:flex-end;padding:0}
  .modal{border-radius:24px 24px 0 0;max-width:100%;padding:22px 18px calc(20px + env(safe-area-inset-bottom));
    max-height:94dvh;overflow-y:auto;animation:sheet .32s cubic-bezier(.2,.8,.25,1)}
  @keyframes sheet{from{transform:translateY(46px);opacity:.4}to{transform:none;opacity:1}}
  .searchbar .btn{width:100%}
}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute">
  <defs>
    <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#2f7bff"/><stop offset="1" stop-color="#00b3ff"/>
    </linearGradient>
  </defs>
</svg>

<!-- ================= LOGIN ================= -->
<div id="loginView">
  <form class="login-card" id="loginForm">
    <div class="logo-ring">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4.5 13.5H11L9.5 22 19 10h-6.5L13 2z"/></svg>
    </div>
    <h1>NEXO <span>Panel</span></h1>
    <p class="login-sub">Premium VPS management — sign in to continue</p>
    <div class="field"><label>Username</label><input id="loginUser" autocomplete="username" required></div>
    <div class="field"><label>Password</label><input id="loginPass" type="password" autocomplete="current-password" required></div>
    <button class="btn block" type="submit">Sign in</button>
    <div class="err" id="loginError"></div>
    <p class="login-foot">Secure admin portal</p>
  </form>
</div>

<!-- ================= APP ================= -->
<div id="appView">
  <div class="shell">
    <aside>
      <div class="brand">
        <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4.5 13.5H11L9.5 22 19 10h-6.5L13 2z"/></svg></div>
        <div><b>NEXO</b><small>Panel</small></div>
      </div>
      <div class="nav-label">Main</div>
      <div class="nav-item active" data-page="dashboard">
        <svg class="ic" viewBox="0 0 24 24"><rect x="3" y="3" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="2"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2"/></svg>
        <span>Dashboard</span>
      </div>
      <div class="nav-item" data-page="users">
        <svg class="ic" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M3.5 20c.6-3.2 2.8-5 5.5-5s4.9 1.8 5.5 5"/><path d="M16 5.2a3.5 3.5 0 0 1 0 5.9M17.8 15.4c1.5.7 2.4 2.2 2.7 4.6"/></svg>
        <span>Users</span>
      </div>
      <div class="nav-item" data-page="online">
        <svg class="ic" viewBox="0 0 24 24"><path d="M2.5 9a15 15 0 0 1 19 0M5.5 12.5a10.5 10.5 0 0 1 13 0M8.6 16a6 6 0 0 1 6.8 0"/><circle cx="12" cy="19.4" r="1.3" fill="currentColor"/></svg>
        <span>Online</span>
        <span class="pill ok" id="onlineBadge" style="margin-left:auto;display:none">0</span>
      </div>
      <div class="nav-item" data-page="inbounds">
        <svg class="ic" viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/></svg>
        <span>Inbounds</span>
      </div>
      <div class="nav-label">System</div>
      <div class="nav-item" data-page="services">
        <svg class="ic" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
        <span>Services</span>
      </div>
      <div class="nav-item" data-page="settings">
        <svg class="ic" viewBox="0 0 24 24"><path d="M4 8h10M18 8h2M4 16h4M12 16h8"/><circle cx="16" cy="8" r="2.2"/><circle cx="10" cy="16" r="2.2"/></svg>
        <span>Settings</span>
      </div>
      <div class="side-foot">
        <div class="row"><span class="dot" id="sideDot"></span><span id="sideStatus">Server online</span></div>
        <div class="row" style="margin-top:6px"><span class="muted">Host</span><b class="mono" id="sideHost" style="color:var(--text)">—</b></div>
      </div>
    </aside>

    <main>
      <div class="topbar">
        <div>
          <h2 id="pageTitle">Dashboard</h2>
          <div class="sub" id="dashSub">Loading server status…</div>
        </div>
        <div class="top-actions">
          <span class="chip"><span class="dot"></span> <span id="clockChip">Live</span></span>
          <button class="btn ghost small" id="refreshBtn" type="button">Refresh</button>
          <button class="btn ghost small" id="logoutBtn" type="button">Log out</button>
        </div>
      </div>

      <!-- ===== Dashboard ===== -->
      <section class="page active loading" id="page-dashboard">
        <div class="kpis">
          <div class="kpi">
            <div class="ring"><svg width="76" height="76"><circle class="bgc" cx="38" cy="38" r="32" fill="none" stroke-width="7"/><circle class="fgc" id="ringCpu" cx="38" cy="38" r="32" fill="none" stroke-width="7" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="val" id="valCpu">–</div></div>
            <div class="meta"><small>CPU</small><b id="loadTxt">load —</b><canvas class="spark" id="sparkCpu" width="300" height="60"></canvas><span class="avgpeak muted" id="cpuAvg"></span></div>
          </div>
          <div class="kpi">
            <div class="ring"><svg width="76" height="76"><circle class="bgc" cx="38" cy="38" r="32" fill="none" stroke-width="7"/><circle class="fgc" id="ringRam" cx="38" cy="38" r="32" fill="none" stroke-width="7" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="val" id="valRam">–</div></div>
            <div class="meta"><small>RAM</small><b id="ramTxt">—</b><canvas class="spark" id="sparkRam" width="300" height="60"></canvas><span class="avgpeak muted" id="ramAvg"></span></div>
          </div>
          <div class="kpi">
            <div class="ring"><svg width="76" height="76"><circle class="bgc" cx="38" cy="38" r="32" fill="none" stroke-width="7"/><circle class="fgc" id="ringDisk" cx="38" cy="38" r="32" fill="none" stroke-width="7" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="val" id="valDisk">–</div></div>
            <div class="meta"><small>Disk</small><b id="diskTxt">—</b><span>storage used</span></div>
          </div>
          <div class="kpi">
            <div class="ring"><svg width="76" height="76"><circle class="bgc" cx="38" cy="38" r="32" fill="none" stroke-width="7"/><circle class="fgc" id="ringUsers" cx="38" cy="38" r="32" fill="none" stroke-width="7" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="201"/></svg><div class="val" id="valUsers">–</div></div>
            <div class="meta"><small>Users</small><b id="usersTxt">—</b><span id="trafficTxt">traffic —</span></div>
          </div>
        </div>

        <div class="grid2" style="margin-bottom:15px">
          <div class="card">
            <h3><svg class="ic sm" viewBox="0 0 24 24"><path d="M3 17l5-6 4 3 6-8 3 4"/></svg>Network speed<span class="right" id="speedNow">—</span></h3>
            <div style="position:relative">
              <canvas id="netChart"></canvas>
              <div id="chartTip" style="position:absolute;display:none;pointer-events:none;background:#0d1522;border:1px solid var(--line2);border-radius:10px;padding:8px 11px;font-size:12px;box-shadow:var(--shadow);white-space:nowrap;z-index:5"></div>
            </div>
            <div class="legend">
              <span><i style="background:#2ee6a8"></i>Download</span>
              <span><i style="background:#2f7bff"></i>Upload</span>
              <span style="margin-left:auto" id="netTotals">—</span>
            </div>
          </div>
          <div class="card">
            <h3><svg class="ic sm" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>System info</h3>
            <div class="syslist" id="sysInfo"></div>
          </div>
        </div>

        <div class="card" style="margin-bottom:15px">
          <h3><svg class="ic sm" viewBox="0 0 24 24"><path d="M13 2 4.5 13.5H11L9.5 22 19 10h-6.5L13 2z"/></svg>Services<span class="right">full control in Services page</span></h3>
          <div class="svc-grid" id="dashServices"></div>
        </div>

        <div class="grid2">
          <div class="card">
            <h3><svg class="ic sm" viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/></svg>V2Ray inbounds</h3>
            <div class="tblwrap"><table>
              <thead><tr><th>Remark</th><th>Protocol</th><th>Port</th><th>Clients</th></tr></thead>
              <tbody id="dashInbounds"></tbody>
            </table></div>
          </div>
          <div class="card">
            <h3><svg class="ic sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3.5 9h17M3.5 15h17M12 3c2.5 2.5 3.7 5.6 3.7 9S14.5 18.5 12 21c-2.5-2.5-3.7-5.6-3.7-9S9.5 5.5 12 3z"/></svg>DNSTT</h3>
            <div id="dashDnstt"></div>
          </div>
        </div>
      </section>

      <!-- ===== Users ===== -->
      <section class="page" id="page-users">
        <div class="statstrip" id="userStats"></div>
        <div class="searchbar">
          <div class="grow">
            <svg class="ic sm sic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>
            <input id="userSearch" placeholder="Search users by name or note…">
          </div>
          <button class="btn" id="newUserBtn" type="button">+ New user</button>
        </div>
        <div class="card" style="padding:8px 14px">
          <div class="tblwrap"><table>
            <thead><tr><th>User</th><th>Protocols</th><th style="min-width:170px">Traffic</th><th>Expires</th><th>Status</th><th>Online</th><th>Actions</th></tr></thead>
            <tbody id="userRows"></tbody>
          </table></div>
        </div>
      </section>

      <!-- ===== Online ===== -->
      <section class="page" id="page-online">
        <div class="kpis" style="grid-template-columns:repeat(3,1fr)">
          <div class="kpi"><div class="meta"><small>Online now</small><b id="onTotal" style="font-size:24px">0</b><span>clients connected</span></div></div>
          <div class="kpi"><div class="meta"><small>Via SSH</small><b id="onSsh" style="font-size:24px">0</b><span>direct / WS / WSS sessions</span></div></div>
          <div class="kpi"><div class="meta"><small>Via Xray</small><b id="onXray" style="font-size:24px">0</b><span>VLESS / VMess / Trojan / SS</span></div></div>
        </div>
        <div class="card" style="padding:8px 14px;margin-bottom:15px">
          <div class="tblwrap"><table>
            <thead><tr><th>Client</th><th>Connected via</th><th>IP addresses</th><th>Traffic used</th><th>Expires</th></tr></thead>
            <tbody id="onlineRows"></tbody>
          </table></div>
        </div>
        <div class="card" style="padding:20px">
          <h3><svg class="ic sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>Recently seen</h3>
          <div id="recentList" class="muted" style="font-size:13.5px">—</div>
        </div>
      </section>

      <!-- ===== Inbounds ===== -->
      <section class="page" id="page-inbounds">
        <div class="searchbar">
          <div class="grow" style="display:flex;align-items:center"><span class="muted" style="font-size:13.5px">Xray inbounds are generated from this list — every enabled user appears as a client on the inbounds of their protocol.</span></div>
          <button class="btn" id="newInboundBtn" type="button">+ New inbound</button>
        </div>
        <div class="card" style="padding:8px 14px">
          <div class="tblwrap"><table>
            <thead><tr><th>Remark</th><th>Protocol</th><th>Port</th><th>Transport</th><th>Security</th><th>Clients</th><th>Actions</th></tr></thead>
            <tbody id="inboundRows"></tbody>
          </table></div>
        </div>
      </section>

      <!-- ===== Services ===== -->
      <section class="page" id="page-services">
        <div class="svc-grid" id="serviceList" style="grid-template-columns:repeat(auto-fill,minmax(255px,1fr))"></div>
      </section>

      <!-- ===== Settings ===== -->
      <section class="page" id="page-settings">
        <form class="card" id="settingsForm">
          <h3><svg class="ic sm" viewBox="0 0 24 24"><path d="M4 8h10M18 8h2M4 16h4M12 16h8"/><circle cx="16" cy="8" r="2.2"/><circle cx="10" cy="16" r="2.2"/></svg>Server &amp; client settings</h3>
          <div class="fgrid">
            <div class="field"><label>Public host / IP (shown to clients)</label><input name="server_host"></div>
            <div class="field"><label>Panel port</label><input name="panel_port"></div>
            <div class="field"><label>SSH port</label><input name="ssh_port"></div>
            <div class="field"><label>WebSocket port</label><input name="ws_port"></div>
            <div class="field"><label>Stunnel (WSS) port</label><input name="wss_port"></div>
            <div class="field"><label>Xray VLESS port</label><input name="xray_port"></div>
            <div class="field"><label>Xray VMess port</label><input name="xray_vmess_port"></div>
            <div class="field"><label>Xray WS path</label><input name="xray_path"></div>
            <div class="field"><label>Cloudflare WS host</label><input name="cf_ws_host"></div>
            <div class="field"><label>Default SNI host (bug host)</label><input name="sni_host"></div>
            <div class="field"><label>OpenVPN port</label><input name="ovpn_port"></div>
            <div class="field"><label>DNSTT domain (NS delegated)</label><input name="dnstt_domain"></div>
            <div class="field"><label>DNSTT port</label><input name="dnstt_port"></div>
            <div class="field"><label>Brand</label><input name="brand"></div>
            <div class="field full"><label>Telegram link</label><input name="telegram"></div>
          </div>
          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            <button class="btn" type="submit">Save settings</button>
            <span class="muted" style="font-size:12.5px">Changes apply to client info right away; listening ports change on reinstall or service reconfigure.</span>
          </div>
        </form>
        <form class="card" id="passwordForm" style="margin-top:15px">
          <h3><svg class="ic sm" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>Admin password</h3>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <input id="pwCurrent" type="password" placeholder="Current password" style="flex:1;min-width:180px;background:#0a0e15;border:1px solid var(--line);border-radius:12px;padding:12px 14px;color:var(--text);outline:none">
            <input id="pwNew" type="password" placeholder="New admin password" style="flex:1;min-width:180px;background:#0a0e15;border:1px solid var(--line);border-radius:12px;padding:12px 14px;color:var(--text);outline:none">
            <button class="btn ghost" type="submit">Change password</button>
          </div>
        </form>
      </section>
    </main>
  </div>
</div>

<nav id="bottomNav">
    <div class="nav-item active" data-page="dashboard">
      <svg class="ic" viewBox="0 0 24 24"><rect x="3" y="3" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="2"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="2"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2"/></svg>
      <span>Home</span>
    </div>
    <div class="nav-item" data-page="users">
      <svg class="ic" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M3.5 20c.6-3.2 2.8-5 5.5-5s4.9 1.8 5.5 5"/><path d="M16 5.2a3.5 3.5 0 0 1 0 5.9M17.8 15.4c1.5.7 2.4 2.2 2.7 4.6"/></svg>
      <span>Users</span>
    </div>
    <div class="nav-item" data-page="online">
      <svg class="ic" viewBox="0 0 24 24"><path d="M2.5 9a15 15 0 0 1 19 0M5.5 12.5a10.5 10.5 0 0 1 13 0M8.6 16a6 6 0 0 1 6.8 0"/><circle cx="12" cy="19.4" r="1.3" fill="currentColor"/></svg>
      <span>Online</span>
    </div>
    <div class="nav-item" data-page="inbounds">
      <svg class="ic" viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/></svg>
      <span>Inbounds</span>
    </div>
    <div class="nav-item" data-page="services">
      <svg class="ic" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
      <span>Services</span>
    </div>
    <div class="nav-item" data-page="settings">
      <svg class="ic" viewBox="0 0 24 24"><path d="M4 8h10M18 8h2M4 16h4M12 16h8"/><circle cx="16" cy="8" r="2.2"/><circle cx="10" cy="16" r="2.2"/></svg>
      <span>Settings</span>
    </div>
  </nav>

<!-- ================= MODALS ================= -->
<div class="modal-wrap" id="userModalWrap">
  <form class="modal" id="userForm">
    <h2 id="userModalTitle">New user</h2>
    <input type="hidden" id="ufId">
    <div class="fgrid">
      <div class="field"><label>Username</label><input id="ufName" required></div>
      <div class="field" id="ufPassWrap"><label>Password (SSH login)</label><input id="ufPass">
        <div class="muted" style="font-size:11.5px;margin-top:5px">Only needed for SSH. V2Ray clients connect with their UUID / link — no password.</div></div>
      <div class="field"><label>Quota (GB, 0 = unlimited)</label><input id="ufQuota" type="number" step="0.5" min="0" value="100"></div>
      <div class="field"><label>Validity (days)</label><input id="ufDays" type="number" min="1" value="30"></div>
      <div class="field"><label>IP limit (0 = unlimited)</label><input id="ufIpLimit" type="number" min="0" value="0"></div>
      <div class="field"><label>Device / HWID limit (0 = unlimited)</label><input id="ufHwidLimit" type="number" min="0" value="0"></div>
      <div class="field full"><label>Note</label><input id="ufNote" placeholder="Customer name, phone, package…"></div>
    </div>
    <div class="field" style="margin-top:4px"><label>Protocols</label>
      <div class="checks">
        <label><input type="checkbox" class="ufProto" value="ssh" checked> SSH</label>
        <label><input type="checkbox" class="ufProto" value="vless"> VLESS</label>
        <label><input type="checkbox" class="ufProto" value="vmess"> VMess</label>
        <label><input type="checkbox" class="ufProto" value="trojan"> Trojan</label>
        <label><input type="checkbox" class="ufProto" value="shadowsocks"> Shadowsocks</label>
        <label><input type="checkbox" class="ufProto" value="ovpn"> OpenVPN</label>
        <label><input type="checkbox" class="ufProto" value="dnstt"> DNSTT</label>
      </div>
    </div>
    <div class="field" id="ufIbWrap" style="margin-top:10px;display:none"><label>Inbounds — this client is added to the ticked inbounds</label>
      <div class="ibpick" id="ufInbounds"></div>
      <div class="muted" style="font-size:11.5px;margin-top:5px">All ticked = the client joins every matching inbound (same as before).</div>
    </div>
    <div class="foot">
      <button class="btn ghost" type="button" id="userCancel">Cancel</button>
      <button class="btn" type="submit">Save user</button>
    </div>
  </form>
</div>

<div class="modal-wrap" id="infoModalWrap">
  <div class="modal wide">
    <h2 id="infoTitle">User info</h2>
    <div id="infoBody"></div>
    <div class="foot"><button class="btn" type="button" id="infoClose">Close</button></div>
  </div>
</div>

<div class="modal-wrap" id="inboundModalWrap">
  <form class="modal wide" id="inboundForm">
    <h2 id="inboundModalTitle">New inbound</h2>
    <input type="hidden" id="ibId">
    <div class="itabs">
      <button type="button" data-itab="basics" class="on">Basics</button>
      <button type="button" data-itab="protocol">Protocol</button>
      <button type="button" data-itab="stream">Stream</button>
      <button type="button" data-itab="security">Security</button>
    </div>
    <div class="fgrid">
      <div class="field full" id="ibGRemark"><label>Remark</label><input id="ibRemark" placeholder="e.g. VLESS Reality main"></div>
      <div class="field" id="ibGProtocol"><label>Protocol</label>
        <select id="ibProtocol">
          <option value="vless">VLESS</option><option value="vmess">VMess</option>
          <option value="trojan">Trojan</option><option value="shadowsocks">Shadowsocks</option>
        </select></div>
      <div class="field" id="ibGPort"><label>Port</label><input id="ibPort" type="number" min="1" max="65535" required></div>
      <div class="field" id="ibGMax"><label>Max clients (0 = unlimited)</label><input id="ibMaxClients" type="number" min="0" value="0"></div>
      <div class="field" id="ibGTransport"><label>Transport (network)</label>
        <select id="ibNetwork">
          <option value="tcp">TCP (RAW)</option><option value="ws">WebSocket</option>
          <option value="grpc">gRPC</option><option value="httpupgrade">HTTPUpgrade</option>
          <option value="xhttp">XHTTP (SplitHTTP)</option><option value="kcp">mKCP</option>
        </select></div>
      <div class="field" id="ibGSecurity"><label>Security</label>
        <select id="ibSecurity">
          <option value="none">None</option><option value="tls">TLS</option>
          <option value="reality">Reality</option>
        </select></div>
      <div class="field" id="ibGFlow"><label>VLESS flow</label>
        <select id="ibFlow">
          <option value="">None</option>
          <option value="xtls-rprx-vision">xtls-rprx-vision</option>
        </select></div>
      <div class="field" id="ibGSs"><label>Shadowsocks method (2022)</label>
        <select id="ibSsMethod">
          <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
          <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
          <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
        </select></div>
      <div class="field" id="ibGPath"><label>Path</label><input id="ibPath" value="/ray"></div>
      <div class="field" id="ibGHost"><label>Host header</label><input id="ibHost" placeholder="cdn.example.com"></div>
      <div class="field" id="ibGGrpcSvc"><label>gRPC service name</label><input id="ibService" placeholder="myservice"></div>
      <div class="field" id="ibGGrpcMode"><label>gRPC mode</label>
        <select id="ibMulti"><option value="">Gun (single)</option><option value="1">Multi</option></select></div>
      <div class="field" id="ibGXhttp"><label>XHTTP mode</label>
        <select id="ibXMode">
          <option value="auto">Auto</option><option value="packet-up">Packet-up</option>
          <option value="stream-up">Stream-up</option><option value="stream-one">Stream-one</option>
        </select></div>
      <div class="field" id="ibGHeader"><label>Header type (camouflage)</label>
        <select id="ibHeader"></select></div>
      <div class="field" id="ibGSeed"><label>mKCP seed (optional)</label><input id="ibSeed" placeholder="password-like seed"></div>
      <div class="field" id="ibGTls"><label>TLS server name (SNI)</label><input id="ibSni" placeholder="www.example.com"></div>
      <div class="field" id="ibGDest"><label>Reality target (dest)</label><input id="ibDest" placeholder="www.microsoft.com:443"></div>
      <div class="field" id="ibGSni"><label>Reality server name (SNI)</label><input id="ibRSni" placeholder="www.microsoft.com"></div>
      <div class="field" id="ibGFp"><label>Client fingerprint (uTLS)</label>
        <select id="ibFp">
          <option value="chrome">Chrome</option><option value="firefox">Firefox</option>
          <option value="safari">Safari</option><option value="ios">iOS</option>
          <option value="random">Random</option>
        </select></div>
    </div>
    <p class="muted" id="ibNoteReality" style="font-size:12.5px;margin-top:10px;display:none">
      Reality X25519 keys and a short ID are generated automatically and stored with the inbound.
      On edit, tick “regenerate keys” only if you want fresh ones (old client links will break).</p>
    <div class="checks" id="ibGRegen" style="margin-top:10px;display:none">
      <label><input type="checkbox" id="ibRegen"> Regenerate Reality keys / TLS cert</label>
    </div>
    <p class="muted" id="ibNoteTls" style="font-size:12.5px;margin-top:10px;display:none">
      A self-signed TLS certificate for the SNI name is generated automatically on the server.</p>
    <div class="foot">
      <button class="btn ghost" type="button" id="inboundCancel">Cancel</button>
      <button class="btn" type="submit" id="inboundSubmit">Save inbound</button>
    </div>
  </form>
</div>

<div class="modal-wrap" id="renewModalWrap">
  <form class="modal" id="renewForm">
    <h2 id="renewTitle">Renew</h2>
    <input type="hidden" id="rnId">
    <div class="field"><label>Add days</label><input id="rnDays" type="number" min="1" value="30"></div>
    <div class="checks"><label><input type="checkbox" id="rnReset"> Reset used traffic to 0</label></div>
    <div class="foot">
      <button class="btn ghost" type="button" id="renewCancel">Cancel</button>
      <button class="btn" type="submit">Renew</button>
    </div>
  </form>
</div>

<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const GB = 1073741824;
function fmtBytes(b){ b = Number(b)||0; const u=["B","KB","MB","GB","TB"]; let i=0;
  while(b>=1024 && i<u.length-1){ b/=1024; i++; } return b.toFixed(i?2:0)+" "+u[i]; }
function fmtSpeed(b){ return fmtBytes(b)+"/s"; }
function toast(msg){ const t=$("#toast"); t.textContent=msg; t.classList.add("show");
  clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove("show"),2600); }
function readCookie(name){
  const part = document.cookie.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return part ? decodeURIComponent(part.slice(name.length+1)) : "";
}
async function api(path, options={}){
  const method = (options.method || "GET").toUpperCase();
  const headers = {"Content-Type":"application/json", ...(options.headers||{})};
  if(method!=="GET" && path!=="/api/login"){
    const csrf = readCookie("mpanel_csrf");
    if(csrf) headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch(path, {...options, method, headers, credentials:"same-origin"});
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.error || ("HTTP "+res.status));
  return data;
}
function copyText(txt, btn){
  const done = () => { if(btn){ const o=btn.textContent; btn.textContent="Copied"; setTimeout(()=>btn.textContent=o,1200);} };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(done).catch(()=>fallbackCopy(txt, done));
  } else fallbackCopy(txt, done);
}
function fallbackCopy(txt, done){
  const ta=document.createElement("textarea"); ta.value=txt; document.body.appendChild(ta);
  ta.select(); try{ document.execCommand("copy"); }catch(e){} ta.remove(); done();
}
document.addEventListener("click", e => {
  const b = e.target.closest("[data-copy]"); if(b) copyText(b.getAttribute("data-copy"), b);
});

/* ---------- navigation ---------- */
const PAGE_TITLES = {dashboard:"Dashboard", users:"Users", online:"Online clients",
  inbounds:"Inbounds", services:"Services", settings:"Settings"};
function gotoPage(name){
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page===name));
  $$(".page").forEach(p => p.classList.toggle("active", p.id==="page-"+name));
  $("#pageTitle").textContent = PAGE_TITLES[name] || name;
  if(name==="users") loadUsers();
  if(name==="online") loadOnline();
  if(name==="inbounds") loadInbounds();
  if(name==="services") loadServices();
  if(name==="dashboard") loadDashboard();
}
$$(".nav-item").forEach(n => n.addEventListener("click", () => gotoPage(n.dataset.page)));

/* ---------- auth ---------- */
$("#loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  $("#loginError").textContent = "";
  try{
    await api("/api/login", {method:"POST", body: JSON.stringify({
      username: $("#loginUser").value, password: $("#loginPass").value})});
    showApp();
  }catch(err){ $("#loginError").textContent = err.message; }
});
$("#logoutBtn").addEventListener("click", async () => {
  try{ await api("/api/logout", {method:"POST"}); }catch(e){}
  location.reload();
});
$("#refreshBtn").addEventListener("click", () => {
  loadDashboard(); loadUsers(); loadInbounds(); loadServices(); toast("Refreshed.");
});
function showApp(){
  $("#loginView").style.display = "none";
  $("#appView").style.display = "block";
  loadDashboard(); loadUsers(); loadInbounds(); loadServices(); loadOnline();
}

/* ---------- online clients ---------- */
async function loadOnline(){
  let d;
  try{ d = await api("/api/online"); }catch(e){ return; }
  const c = d.counts || {online:0, ssh:0, xray:0};
  $("#onTotal").textContent = c.online;
  $("#onSsh").textContent = c.ssh;
  $("#onXray").textContent = c.xray;
  const badge = $("#onlineBadge");
  badge.style.display = c.online ? "" : "none";
  badge.textContent = c.online;
  $("#onlineRows").innerHTML = (d.online||[]).map(o => `<tr>
    <td><div class="ucell"><span class="uavatar">${esc(o.username.slice(0,1).toUpperCase())}</span>
      <div><div class="n">${esc(o.username)}</div><div class="s">${esc(o.note||"")}</div></div></div></td>
    <td data-label="Via">${o.via.map(v => `<span class="pill ok"><span class="dot"></span>${esc(v)}</span>`).join(" ")}</td>
    <td data-label="IPs" class="mono">${o.ips.map(esc).join("<br>") || "—"}</td>
    <td data-label="Traffic">${fmtBytes(o.used_bytes)}${o.quota_bytes ? ' <span class="muted">/ '+fmtBytes(o.quota_bytes)+'</span>' : ''}</td>
    <td data-label="Expires">${esc(o.expire_date || "Never")}</td></tr>`).join("")
    || '<tr><td colspan="5" class="muted">Nobody is online right now.</td></tr>';
  $("#recentList").innerHTML = (d.recent||[]).map(r =>
    `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(27,38,55,.5)">
       <span><b style="color:var(--text)">${esc(r.username)}</b>
       <span class="muted">· ${r.protocols.map(esc).join(", ")}</span></span>
       <span class="muted">${esc(String(r.last_online).replace("T"," "))}</span></div>`).join("")
    || "No history yet — last-seen times appear after clients connect.";
}

/* ---------- dashboard ---------- */
let SETTINGS_FILLED = false;
let LAST_NET = null, SAMPLES = [];
function tweenVal(el, to, suffix){
  const from = el._v || 0; el._v = to;
  const t0 = performance.now();
  const step = t => {
    const p = Math.min(1, (t - t0)/550), e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from)*e) + suffix;
    if(p < 1 && el._v === to) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const cpuHist = [], ramHist = [];
function pushSpark(arr, v){ arr.push(v); if(arr.length > 40) arr.shift(); }
function drawSpark(id, arr, color){
  const cv = document.getElementById(id); if(!cv || arr.length < 2) return;
  const ctx = cv.getContext("2d"), W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  const pts = arr.map((v, i) => [i/(arr.length - 1)*(W - 4) + 2, H - 3 - (v/100)*(H - 8)]);
  ctx.beginPath();
  pts.forEach((p, i) => i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]));
  ctx.strokeStyle = color; ctx.lineWidth = 2.5; ctx.stroke();
  ctx.lineTo(pts[pts.length - 1][0], H); ctx.lineTo(pts[0][0], H); ctx.closePath();
  ctx.fillStyle = color + "2e"; ctx.fill();
}
function avgPeak(id, arr){
  const el = document.getElementById(id); if(!el || !arr.length) return;
  const avg = arr.reduce((a, b) => a + b, 0)/arr.length;
  el.textContent = "AVG " + avg.toFixed(0) + "% · PEAK " + Math.max(...arr).toFixed(0) + "%";
}
function setRing(id, valId, pct, label){
  const c = 201, p = Math.max(0, Math.min(100, pct));
  const ring = document.getElementById(id);
  if(ring) ring.style.strokeDashoffset = String(c - c*p/100);
  const v = document.getElementById(valId);
  if(v){
    const m = String(label).match(/^(\d+(?:\.\d+)?)(.*)$/);
    if(m) tweenVal(v, parseFloat(m[1]), m[2]); else v.textContent = label;
  }
}
function svcCard(s, withActions){
  const missing = s.installed === false;
  const state = missing ? "Not installed" : (s.active ? "Running" : "Stopped");
  return `<div class="svc">
    <div class="top"><span class="dot ${s.active?"":(missing?"na":"off")}"></span>${esc(s.name)}</div>
    <div class="desc">${esc(s.desc||"")}</div>
    ${missing
      ? `<span class="pill na">${state}</span><div class="muted" style="font-size:12px;margin-top:7px">Re-run the installer to install this service.</div>`
      : withActions ? `<div class="acts">
      <button class="btn ghost small" onclick="svc('${esc(s.id)}','start')">Start</button>
      <button class="btn ghost small" onclick="svc('${esc(s.id)}','restart')">Restart</button>
      <button class="btn ghost small" onclick="svc('${esc(s.id)}','stop')">Stop</button>
    </div>` : `<span class="pill ${s.active?"ok":"bad"}">${state}</span>`}
  </div>`;
}
async function loadDashboard(){
  let d;
  try{ d = await api("/api/dashboard"); }catch(e){ return; }
  $("#page-dashboard").classList.remove("loading");
  const s = d.stats || {};
  const cpu = Number(s.cpu||0);
  setRing("ringCpu", "valCpu", cpu, cpu.toFixed(0)+"%");
  $("#loadTxt").textContent = "load " + (s.load || "—");
  pushSpark(cpuHist, cpu); drawSpark("sparkCpu", cpuHist, "#3b8bff"); avgPeak("cpuAvg", cpuHist);
  const ramPct = s.ram_total ? 100*(s.ram_used||0)/s.ram_total : 0;
  setRing("ringRam", "valRam", ramPct, ramPct.toFixed(0)+"%");
  pushSpark(ramHist, ramPct); drawSpark("sparkRam", ramHist, "#9a7bff"); avgPeak("ramAvg", ramHist);
  $("#ramTxt").textContent = fmtBytes(s.ram_used) + " / " + fmtBytes(s.ram_total);
  const diskPct = s.disk_total ? 100*(s.disk_used||0)/s.disk_total : 0;
  setRing("ringDisk", "valDisk", diskPct, diskPct.toFixed(0)+"%");
  $("#diskTxt").textContent = fmtBytes(s.disk_used) + " / " + fmtBytes(s.disk_total);
  const uPct = d.users_total ? 100*(d.users_active||0)/d.users_total : 0;
  setRing("ringUsers", "valUsers", uPct, String(d.users_active||0));
  $("#usersTxt").textContent = (d.users_active||0) + " of " + (d.users_total||0) + " users";
  $("#trafficTxt").textContent = "traffic " + fmtBytes(d.traffic_total);
  $("#dashSub").textContent = "Host " + (s.host||"—") + " · uptime " + (s.uptime||"—");
  $("#sideHost").textContent = s.host || "—";
  $("#sysInfo").innerHTML = [
    ["Host", s.host||"—"], ["Uptime", s.uptime||"—"],
    ["Load average", s.load||"—"], ["CPU", cpu.toFixed(1)+"%"],
    ["Memory", fmtBytes(s.ram_used)+" / "+fmtBytes(s.ram_total)],
    ["Disk", fmtBytes(s.disk_used)+" / "+fmtBytes(s.disk_total)],
    ["Downloaded", fmtBytes(s.net_rx)], ["Uploaded", fmtBytes(s.net_tx)],
  ].map(([k,v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join("");
  $("#dashServices").innerHTML = (d.services||[]).map(x => svcCard(x, false)).join("");
  $("#dashInbounds").innerHTML = (d.inbounds||[]).map(ib => `<tr>
    <td><b>${esc(ib.remark)}</b></td>
    <td><span class="pill proto">${esc(ib.protocol)}</span></td>
    <td>${esc(ib.port)}</td><td>${esc(ib.clients)}${ib.max_clients ? ' <span class="muted">/ '+esc(ib.max_clients)+'</span>' : ''}</td></tr>`).join("")
    || '<tr><td colspan="4" class="muted">No inbounds yet.</td></tr>';
  const dn = d.dnstt || {};
  $("#dashDnstt").innerHTML = dn.installed ? `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:11px">
      <span class="pill ${dn.active?"ok":"bad"}">${dn.active?"Running":"Stopped"}</span>
      <span class="pill">Domain · <b class="mono">${esc(dn.domain||"—")}</b></span>
      <span class="pill">UDP ${esc(dn.port||"53")}</span>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:6px">Server public key</div>
    <div class="dnstt-key mono">${esc(dn.pubkey||"—")}</div>
    <button class="copy" style="margin-top:9px" data-copy="${esc(dn.pubkey||"")}">Copy key</button>`
    : '<p class="muted">DNSTT is not installed on this server.</p>';
  /* live speed chart sampling */
  const now = performance.now();
  if(LAST_NET){
    const dt = (now - LAST_NET.t)/1000;
    if(dt > 0.5){
      SAMPLES.push({t: Date.now(), rx: Math.max(0,(s.net_rx-LAST_NET.rx)/dt),
                    tx: Math.max(0,(s.net_tx-LAST_NET.tx)/dt)});
      if(SAMPLES.length > 160) SAMPLES.shift();
      drawChart();
      const last = SAMPLES[SAMPLES.length-1];
      $("#speedNow").textContent = "↓ " + fmtSpeed(last.rx) + " · ↑ " + fmtSpeed(last.tx);
    }
  }
  LAST_NET = {rx: s.net_rx||0, tx: s.net_tx||0, t: now};
  $("#netTotals").textContent = "Session ↓ " + fmtBytes(s.net_rx) + " · ↑ " + fmtBytes(s.net_tx);
  if(!SETTINGS_FILLED && d.settings){
    SETTINGS_FILLED = true;
    $$("#settingsForm input[name]").forEach(inp => {
      if(d.settings[inp.name] !== undefined) inp.value = d.settings[inp.name];
    });
  }
}
let HOVER_IDX = -1;
function chartGeom(){
  const cv = $("#netChart");
  const w = cv.clientWidth, h = cv.clientHeight;
  return {w, h, L: 52, R: 8, T: 8, B: 20,
          iw: w - 52 - 8, ih: h - 8 - 20};
}
function drawChart(){
  const cv = $("#netChart"); if(!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const {w, h, L, T, iw, ih} = chartGeom();
  if(cv.width !== Math.round(w*dpr)){ cv.width = w*dpr; cv.height = h*dpr; }
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.font = "10.5px system-ui"; ctx.fillStyle = "#5f7089";
  if(SAMPLES.length < 2){
    ctx.fillText("Collecting traffic data…", L + 6, T + 16);
    return;
  }
  let max = Math.max(1024, ...SAMPLES.map(p => Math.max(p.rx, p.tx)));
  max *= 1.15;
  const X = i => L + iw * (SAMPLES.length < 2 ? 0 : i/(159)) + (iw - iw*(SAMPLES.length-1)/159);
  const Xp = i => L + (iw * i / 159) + (iw - iw * Math.min(SAMPLES.length-1,159) / 159);
  const Y = v => T + ih - (v/max)*ih;
  /* grid + y labels */
  ctx.strokeStyle = "rgba(36,49,69,.55)"; ctx.lineWidth = 1;
  for(let g = 0; g <= 4; g++){
    const y = T + ih*g/4;
    ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L+iw, y); ctx.stroke();
    ctx.fillText(fmtSpeed(max*(1-g/4)), 2, y + 3);
  }
  /* x time labels */
  const tfmt = t => new Date(t).toTimeString().slice(0,8);
  ctx.fillText(tfmt(SAMPLES[0].t), L, h - 5);
  const midT = tfmt(SAMPLES[Math.floor(SAMPLES.length/2)].t);
  ctx.fillText(midT, L + iw/2 - 18, h - 5);
  const lastT = tfmt(SAMPLES[SAMPLES.length-1].t);
  ctx.fillText(lastT, L + iw - 42, h - 5);
  const smooth = key => {
    const pts = SAMPLES.map((p,i) => [Xp(i), Y(p[key])]);
    ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
    for(let i = 0; i < pts.length-1; i++){
      const xc = (pts[i][0]+pts[i+1][0])/2, yc = (pts[i][1]+pts[i+1][1])/2;
      ctx.quadraticCurveTo(pts[i][0], pts[i][1], xc, yc);
    }
    ctx.lineTo(pts[pts.length-1][0], pts[pts.length-1][1]);
    return pts;
  };
  const area = (key, color, grad) => {
    const pts = smooth(key);
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
    const last = pts[pts.length-1], first = pts[0];
    ctx.lineTo(last[0], T+ih); ctx.lineTo(first[0], T+ih); ctx.closePath();
    const g = ctx.createLinearGradient(0, T, 0, T+ih);
    g.addColorStop(0, grad); g.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = g; ctx.fill();
    return pts;
  };
  const ptsRx = area("rx", "#00c2a8", "rgba(0,194,168,.22)");
  const ptsTx = area("tx", "#2f7bff", "rgba(47,123,255,.16)");
  if(HOVER_IDX >= 0 && HOVER_IDX < SAMPLES.length){
    const i = HOVER_IDX, x = ptsRx[i][0];
    ctx.strokeStyle = "rgba(233,239,247,.35)";
    ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T+ih); ctx.stroke();
    [[ptsRx, "#2ee6a8"], [ptsTx, "#2f7bff"]].forEach(([pts, c]) => {
      ctx.beginPath(); ctx.arc(x, pts[i][1], 4, 0, Math.PI*2);
      ctx.fillStyle = c; ctx.fill();
      ctx.strokeStyle = "#0b0f16"; ctx.lineWidth = 1.5; ctx.stroke();
    });
  }
}
document.addEventListener("DOMContentLoaded", () => {
  const cv = $("#netChart"); if(!cv) return;
  const tip = $("#chartTip");
  cv.addEventListener("mousemove", e => {
    if(SAMPLES.length < 2) return;
    const rect = cv.getBoundingClientRect();
    const {L, iw} = chartGeom();
    const rel = (e.clientX - rect.left - L) / iw;
    const idx = Math.round(rel * 159 - (159 - (SAMPLES.length-1)));
    HOVER_IDX = Math.max(0, Math.min(SAMPLES.length-1, idx));
    const p = SAMPLES[HOVER_IDX];
    tip.style.display = "block";
    tip.innerHTML = `<div class="muted" style="margin-bottom:3px">${new Date(p.t).toTimeString().slice(0,8)}</div>`
      + `<div><span style="color:#00c2a8">●</span> Download <b>${fmtSpeed(p.rx)}</b></div>`
      + `<div><span style="color:#00a3d9">●</span> Upload <b>${fmtSpeed(p.tx)}</b></div>`;
    const x = L + iw * HOVER_IDX / 159 + (iw - iw*(SAMPLES.length-1)/159);
    tip.style.left = Math.min(rect.width - 150, Math.max(0, x + 12)) + "px";
    tip.style.top = "6px";
    drawChart();
  });
  cv.addEventListener("mouseleave", () => { HOVER_IDX = -1; tip.style.display = "none"; drawChart(); });
});

/* ---------- users ---------- */
let USERS = [];
function daysLeft(exp){
  if(!exp) return null;
  const today = new Date(); today.setHours(0,0,0,0);
  const d = new Date(exp+"T00:00:00");
  return Math.round((d - today)/86400000);
}
function statusPill(u){
  if(u.expired) return '<span class="pill warn"><span class="dot warn"></span>Expired</span>';
  if(!u.enabled) return '<span class="pill bad"><span class="dot off"></span>Locked</span>';
  return '<span class="pill ok"><span class="dot"></span>Active</span>';
}
function renderUsers(){
  const chip = (n, l, c) => `<div class="statchip"><span class="cdot" style="background:${c}"></span><div><div class="n">${n}</div><div class="l">${l}</div></div></div>`;
  $("#userStats").innerHTML =
    chip(USERS.length, "Clients", "#3b8bff")
    + chip(USERS.filter(u => u.enabled && !u.expired).length, "Active", "#2ee6a8")
    + chip(USERS.filter(u => u.online_ips && u.online_ips.length).length, "Online", "#00b3ff")
    + chip(USERS.filter(u => u.expired).length, "Ended", "#ff5c6c")
    + chip(USERS.filter(u => !u.enabled && !u.expired).length, "Disabled", "#8d9cb1");
  const q = ($("#userSearch").value || "").toLowerCase();
  const rows = USERS.filter(u => !q || u.username.toLowerCase().includes(q)
    || (u.note||"").toLowerCase().includes(q));
  $("#userRows").innerHTML = rows.map(u => {
    const dl = daysLeft(u.expire_date);
    const expTxt = u.expire_date
      ? esc(u.expire_date) + (dl===null ? "" : dl < 0
          ? ' · <span style="color:var(--danger)">expired</span>'
          : ` · <span class="muted">${dl}d left</span>`)
      : "Never";
    const pct = u.quota_bytes ? Math.min(100, u.percent||0) : 0;
    const linkKeys = Object.keys(u.info || {}).filter(k => k.includes("link"));
    const linkChips = linkKeys.map(k =>
      `<div class="ulink"><span>${esc(k.replace(/_link.*$/, "").toUpperCase())}</span><button class="copy" data-copy="${esc(u.info[k])}">Copy link</button></div>`).join("");
    return `<tr>
    <td><div class="ucell"><span class="uavatar">${esc(u.username.slice(0,1).toUpperCase())}</span>
      <div><div class="n">${esc(u.username)}</div><div class="s">${esc(u.note||"")}</div>${linkChips}</div></div></td>
    <td data-label="Protocols">${u.protocols.map(p => `<span class="pill proto">${esc(p)}</span>`).join(" ")}</td>
    <td data-label="Traffic"><div style="flex:1;max-width:230px"><div class="bar ${pct>=90?"hot":""}"><i style="width:${pct}%"></i></div>
      <div class="muted" style="font-size:12px;margin-top:5px;text-align:left">${fmtBytes(u.used_bytes)} of ${u.quota_bytes?fmtBytes(u.quota_bytes):"∞"}</div></div></td>
    <td data-label="Expires">${expTxt}</td>
    <td data-label="Status">${statusPill(u)}</td>
    <td data-label="Online">${(u.online_ips&&u.online_ips.length) ? `<span class="pill ok">${u.online_ips.length} online</span>` : '<span class="muted">—</span>'}</td>
    <td data-label="Actions"><div class="rowacts">
      <button class="btn ghost small" onclick="showInfo(${u.id})">Info</button>
      ${u.protocols.includes("ovpn") ? `<a class="btn ghost small" style="text-decoration:none" href="/api/users/${u.id}/ovpn">.ovpn</a>` : ""}
      <button class="btn ghost small" onclick="editUser(${u.id})">Edit</button>
      <button class="btn ghost small" onclick="openRenew(${u.id})">Renew</button>
      <button class="btn ghost small" onclick="toggleUser(${u.id})">${u.enabled?"Lock":"Unlock"}</button>
      <button class="btn danger small" onclick="removeUser(${u.id})">Delete</button>
    </div></td></tr>`;
  }).join("") || '<tr><td colspan="7" class="muted">No users found.</td></tr>';
}
async function loadUsers(){
  try{ const d = await api("/api/users"); USERS = d.users || []; renderUsers(); }
  catch(e){ /* not logged in yet */ }
}
$("#userSearch").addEventListener("input", renderUsers);
let UF_IB_SELECTED = null;
function ufXrayChecked(){
  return $$(".ufProto").filter(c => c.checked).map(c => c.value)
    .some(p => ["vless", "vmess", "trojan", "shadowsocks"].includes(p));
}
function renderUfInbounds(){
  const protos = $$(".ufProto").filter(c => c.checked).map(c => c.value);
  const list = INBOUNDS.filter(ib => protos.includes(ib.protocol));
  $("#ufInbounds").innerHTML = list.map(ib => {
    const on = !UF_IB_SELECTED || UF_IB_SELECTED.includes(ib.id);
    return `<label class="ibopt"><input type="checkbox" class="ufIb" value="${ib.id}" ${on ? "checked" : ""}><span><b>${esc(ib.remark)}</b> · ${esc(ib.protocol)} · :${esc(ib.port)}</span></label>`;
  }).join("") || '<div class="muted">No matching inbound yet — create one on the Inbounds page first.</div>';
}
function syncUfForm(){
  const protos = $$(".ufProto").filter(c => c.checked).map(c => c.value);
  const ssh = protos.includes("ssh");
  $("#ufPassWrap").style.display = ssh ? "" : "none";
  $("#ufPass").required = ssh && !$("#ufId").value;
  const xray = ufXrayChecked();
  $("#ufIbWrap").style.display = xray ? "" : "none";
  if(xray) renderUfInbounds();
}
$$(".ufProto").forEach(c => c.addEventListener("change", () => {
  const cur = $$(".ufIb");
  if(cur.length) UF_IB_SELECTED = cur.filter(x => x.checked).map(x => parseInt(x.value));
  syncUfForm();
}));
$("#newUserBtn").addEventListener("click", () => {
  $("#userForm").reset();
  $("#ufId").value = "";
  $$(".ufProto").forEach(c => c.checked = c.value==="ssh");
  UF_IB_SELECTED = null; syncUfForm();
  $("#userModalTitle").textContent = "New user";
  $("#userModalWrap").style.display = "flex";
});
$("#userCancel").addEventListener("click", () => $("#userModalWrap").style.display = "none");
window.editUser = id => {
  const u = USERS.find(x => x.id===id); if(!u) return;
  $("#ufId").value = u.id; $("#ufName").value = u.username;
  $("#ufPass").value = ""; $("#ufPass").required = false;
  $("#ufPass").placeholder = "Leave blank to keep current";
  $("#ufQuota").value = u.quota_gb ?? 0; $("#ufDays").value = 30;
  $("#ufIpLimit").value = u.ip_limit||0; $("#ufHwidLimit").value = u.hwid_limit||0;
  $("#ufNote").value = u.note||"";
  $$(".ufProto").forEach(c => c.checked = u.protocols.includes(c.value));
  UF_IB_SELECTED = (u.inbound_ids && u.inbound_ids.length) ? u.inbound_ids : null;
  syncUfForm();
  $("#userModalTitle").textContent = "Edit user — " + u.username;
  $("#userModalWrap").style.display = "flex";
};
$("#userForm").addEventListener("submit", async e => {
  e.preventDefault();
  const id = $("#ufId").value;
  const payload = {username: $("#ufName").value.trim(),
    protocols: $$(".ufProto").filter(c => c.checked).map(c => c.value),
    quota_gb: parseFloat($("#ufQuota").value||0), days: parseInt($("#ufDays").value||30),
    ip_limit: parseInt($("#ufIpLimit").value||0), hwid_limit: parseInt($("#ufHwidLimit").value||0),
    note: $("#ufNote").value};
  const pw = $("#ufPass").value;
  if(pw) payload.password = pw;
  if(ufXrayChecked()){
    const boxes = $$(".ufIb");
    const checked = boxes.filter(x => x.checked).map(x => parseInt(x.value));
    if(boxes.length && !checked.length){ toast("Tick at least one inbound for the V2Ray client."); return; }
    payload.inbound_ids = (boxes.length && checked.length === boxes.length) ? [] : checked;
  }
  try{
    const result = await api(id ? "/api/users/"+id : "/api/users",
      {method:"POST", body: JSON.stringify(payload)});
    $("#userModalWrap").style.display = "none";
    if(!id && result.user && result.user.credential_once){
      const secret = result.user.credential_once;
      delete result.user.credential_once;
      alert("One-time credential for " + result.user.username + ":\\n\\n" + secret +
        "\\n\\nCopy it now. It will not be shown again.");
    }
    toast(id ? "User updated." : "User created."); loadUsers(); loadDashboard();
  }catch(err){ toast(err.message); }
});
window.toggleUser = async id => {
  const u = USERS.find(x => x.id===id); if(!u) return;
  try{ await api("/api/users/"+id, {method:"POST", body: JSON.stringify({enabled: !u.enabled})});
    toast(u.enabled ? "User locked." : "User unlocked."); loadUsers(); loadDashboard(); }
  catch(err){ toast(err.message); }
};
window.removeUser = async id => {
  const u = USERS.find(x => x.id===id);
  if(!confirm("Delete user " + (u?u.username:id) + "? This removes the account everywhere.")) return;
  try{ await api("/api/users/"+id, {method:"DELETE"}); toast("User deleted."); loadUsers(); loadDashboard(); }
  catch(err){ toast(err.message); }
};
window.showInfo = id => {
  const u = USERS.find(x => x.id===id); if(!u) return;
  $("#infoTitle").textContent = "User info — " + u.username;
  const kv = (k,v,copy) => `<div class="kv"><div class="k">${esc(k)}</div><div class="v mono">${esc(v)}</div>${copy?`<button class="copy" data-copy="${esc(v)}">Copy</button>`:""}</div>`;
  let accountHtml = '<div class="info-sec"><h4>Account</h4>'
    + kv("Username", u.username, true)
    + (u.uuid ? kv("UUID", u.uuid, true) : "")
    + kv("Expires", u.expire_date || "Never") + kv("Traffic", fmtBytes(u.used_bytes) + " / " + (u.quota_bytes?fmtBytes(u.quota_bytes):"Unlimited"))
    + kv("IP limit", u.ip_limit ? u.ip_limit+" IPs" : "Unlimited")
    + kv("Device (HWID) limit", u.hwid_limit ? String(u.hwid_limit) : "Unlimited")
    + ((u.hwids&&u.hwids.length) ? kv("Registered HWIDs", u.hwids.join(", ")) : "")
    + ((u.online_ips&&u.online_ips.length) ? kv("Online IPs", u.online_ips.join(", ")) : "")
    + "</div>";
  const sshKeys = [], linkKeys = [], otherKeys = [];
  Object.keys(u.info||{}).forEach(k => {
    if(/^\d+_/.test(k)) sshKeys.push(k);
    else if(k.includes("link")) linkKeys.push(k);
    else otherKeys.push(k);
  });
  const label = k => k.replace(/^\d+_/, "").replace(/_/g, " ");
  let html = "";
  if(linkKeys.length) html += '<div class="info-sec"><h4>Share links</h4>'
    + linkKeys.map(k => kv(label(k), u.info[k], true)).join("") + "</div>";
  if(sshKeys.length) html += '<div class="info-sec"><h4>SSH access</h4>'
    + sshKeys.map(k => kv(label(k), u.info[k], true)).join("") + "</div>";
  html += accountHtml;
  if(otherKeys.length) html += '<div class="info-sec"><h4>Connection details</h4>'
    + otherKeys.map(k => kv(label(k), u.info[k], true)).join("") + "</div>";
  if(u.protocols.includes("ovpn"))
    html += `<a class="btn block" style="text-decoration:none" href="/api/users/${u.id}/ovpn">Download .ovpn config</a>`;
  $("#infoBody").innerHTML = html;
  $("#infoModalWrap").style.display = "flex";
};
$("#infoClose").addEventListener("click", () => $("#infoModalWrap").style.display = "none");

/* ---------- renew ---------- */
window.openRenew = id => {
  const u = USERS.find(x => x.id===id); if(!u) return;
  $("#rnId").value = id;
  $("#renewTitle").textContent = "Renew — " + u.username + " (expires " + (u.expire_date||"never") + ")";
  $("#renewModalWrap").style.display = "flex";
};
$("#renewCancel").addEventListener("click", () => $("#renewModalWrap").style.display = "none");
$("#renewForm").addEventListener("submit", async e => {
  e.preventDefault();
  try{
    await api("/api/users/"+$("#rnId").value+"/renew", {method:"POST",
      body: JSON.stringify({days: parseInt($("#rnDays").value||30), reset_traffic: $("#rnReset").checked})});
    $("#renewModalWrap").style.display = "none";
    toast("Renewed."); loadUsers(); loadDashboard();
  }catch(err){ toast(err.message); }
});

/* ---------- inbounds ---------- */
let INBOUNDS = [];
function secPill(sec){
  if(sec==="reality") return '<span class="pill" style="color:var(--violet);border-color:rgba(154,123,255,.4);background:rgba(154,123,255,.08)">Reality</span>';
  if(sec==="tls") return '<span class="pill ok">TLS</span>';
  return '<span class="pill">None</span>';
}
function transportTxt(ib){
  const st = ib.stream || {};
  let detail = "";
  if(ib.network==="ws" || ib.network==="httpupgrade" || ib.network==="xhttp") detail = st.path || ib.path || "";
  if(ib.network==="grpc") detail = st.service_name || "";
  if(ib.network==="tcp" && st.header_type && st.header_type!=="none") detail = "http header";
  const netName = ib.network==="tcp" ? "RAW (TCP)" : ib.network;
  return `<span style="text-transform:capitalize">${esc(netName)}</span>` +
    (detail ? `<div class="muted mono" style="font-size:11.5px">${esc(detail)}</div>` : "") +
    (st.flow ? `<div class="muted" style="font-size:11.5px">${esc(st.flow)}</div>` : "");
}
async function loadInbounds(){
  try{
    const d = await api("/api/inbounds");
    INBOUNDS = d.inbounds || [];
    $("#inboundRows").innerHTML = INBOUNDS.map(ib => `<tr>
      <td><b>${esc(ib.remark)}</b></td>
      <td data-label="Protocol"><span class="pill proto">${esc(ib.protocol)}</span></td>
      <td data-label="Port">${esc(ib.port)}</td><td data-label="Transport">${transportTxt(ib)}</td>
      <td data-label="Security">${secPill(ib.security)}</td>
      <td data-label="Clients">${ib.max_clients
        ? `<div style="min-width:90px"><div class="bar ${ib.clients>=ib.max_clients?"hot":""}"><i style="width:${Math.min(100, 100*ib.clients/ib.max_clients)}%"></i></div><div class="muted" style="font-size:11.5px;margin-top:4px">${esc(ib.clients)} / ${esc(ib.max_clients)} clients</div></div>`
        : `${esc(ib.clients)} <span class="muted">/ ∞</span>`}</td>
      <td data-label="Actions"><div class="rowacts">
        <button class="btn ghost small" onclick="editInbound(${ib.id})">Edit</button>
        <button class="btn danger small" onclick="removeInbound(${ib.id})">Delete</button>
      </div></td>
    </tr>`).join("") || '<tr><td colspan="7" class="muted">No inbounds yet.</td></tr>';
  }catch(e){}
}
function ibSyncVis(){
  const proto = $("#ibProtocol").value, net = $("#ibNetwork").value, sec = $("#ibSecurity").value;
  const show = (id, on) => { const el = document.getElementById(id); if(el) el.style.display = on ? "" : "none"; };
  show("ibGPath", ["ws","httpupgrade","xhttp"].includes(net));
  show("ibGHost", ["ws","httpupgrade"].includes(net) || (net==="tcp"));
  show("ibGGrpcSvc", net==="grpc"); show("ibGGrpcMode", net==="grpc");
  show("ibGXhttp", net==="xhttp");
  show("ibGHeader", ["tcp","kcp"].includes(net));
  show("ibGSeed", net==="kcp");
  show("ibGFlow", proto==="vless");
  show("ibGSs", proto==="shadowsocks");
  show("ibGTls", sec==="tls");
  show("ibGDest", sec==="reality"); show("ibGSni", sec==="reality");
  show("ibGFp", sec!=="none");
  $("#ibNoteReality").style.display = sec==="reality" ? "" : "none";
  $("#ibNoteTls").style.display = sec==="tls" ? "" : "none";
  $("#ibGRegen").style.display = ($("#ibId").value && sec!=="none") ? "" : "none";
  const hdr = $("#ibHeader");
  const opts = net==="kcp"
    ? ["none","srtp","utp","wechat-video","dtls","wireguard"]
    : ["none","http"];
  const cur = hdr.value;
  hdr.innerHTML = opts.map(o => `<option value="${o}">${o}</option>`).join("");
  if(opts.includes(cur)) hdr.value = cur;
  if(proto==="shadowsocks" && sec!=="none"){ $("#ibSecurity").value = "none"; ibSyncVis(); }
}
["ibProtocol","ibNetwork","ibSecurity"].forEach(id =>
  document.getElementById(id).addEventListener("change", ibSyncVis));
const ITAB_GROUPS = {
  basics: ["ibGRemark", "ibGProtocol", "ibGPort", "ibGMax"],
  protocol: ["ibGFlow", "ibGSs"],
  stream: ["ibGTransport", "ibGPath", "ibGHost", "ibGGrpcSvc", "ibGGrpcMode",
           "ibGXhttp", "ibGHeader", "ibGSeed"],
  security: ["ibGSecurity", "ibGTls", "ibGDest", "ibGSni", "ibGFp",
             "ibGRegen", "ibNoteReality", "ibNoteTls"]
};
function setITab(name){
  $$(".itabs button").forEach(b => b.classList.toggle("on", b.dataset.itab === name));
  Object.values(ITAB_GROUPS).flat().forEach(id => {
    const el = document.getElementById(id); if(el) el.classList.add("tabhidden");
  });
  (ITAB_GROUPS[name] || []).forEach(id => {
    const el = document.getElementById(id); if(el) el.classList.remove("tabhidden");
  });
}
$$(".itabs button").forEach(b => b.addEventListener("click", () => setITab(b.dataset.itab)));
function openInboundModal(ib){
  $("#inboundForm").reset();
  setITab("basics");
  $("#ibId").value = ib ? ib.id : "";
  $("#inboundModalTitle").textContent = ib ? "Edit inbound — " + ib.remark : "New inbound";
  $("#inboundSubmit").textContent = ib ? "Save changes" : "Create inbound";
  if(ib){
    const st = ib.stream || {};
    $("#ibRemark").value = ib.remark; $("#ibProtocol").value = ib.protocol;
    $("#ibPort").value = ib.port; $("#ibMaxClients").value = ib.max_clients || 0;
    $("#ibNetwork").value = ib.network;
    $("#ibSecurity").value = ib.security || "none";
    $("#ibPath").value = st.path || ib.path || "/ray";
    $("#ibHost").value = st.host_header || "";
    $("#ibService").value = st.service_name || "";
    $("#ibMulti").value = st.multi_mode ? "1" : "";
    $("#ibXMode").value = st.xhttp_mode || "auto";
    $("#ibSeed").value = st.seed || "";
    $("#ibFlow").value = st.flow || "";
    $("#ibSni").value = st.sni || ""; $("#ibRSni").value = st.sni || "";
    $("#ibDest").value = st.dest || "";
    $("#ibFp").value = st.fingerprint || "chrome";
    $("#ibSsMethod").value = st.ss_method || "2022-blake3-aes-256-gcm";
    $("#ibRegen").checked = false;
    ibSyncVis();
    $("#ibHeader").value = st.header_type || "none";
  } else {
    $("#ibProtocol").value = "vless"; $("#ibNetwork").value = "ws";
    $("#ibSecurity").value = "none"; $("#ibPath").value = "/ray";
    ibSyncVis();
  }
  $("#inboundModalWrap").style.display = "flex";
}
$("#newInboundBtn").addEventListener("click", () => openInboundModal(null));
window.editInbound = id => {
  const ib = INBOUNDS.find(x => x.id===id); if(ib) openInboundModal(ib);
};
$("#inboundCancel").addEventListener("click", () => $("#inboundModalWrap").style.display = "none");
$("#inboundForm").addEventListener("submit", async e => {
  e.preventDefault();
  const id = $("#ibId").value;
  const sec = $("#ibSecurity").value;
  const payload = {
    remark: $("#ibRemark").value, protocol: $("#ibProtocol").value,
    port: parseInt($("#ibPort").value), max_clients: parseInt($("#ibMaxClients").value || 0),
    network: $("#ibNetwork").value,
    security: sec, path: $("#ibPath").value, host_header: $("#ibHost").value,
    service_name: $("#ibService").value, multi_mode: $("#ibMulti").value==="1",
    xhttp_mode: $("#ibXMode").value, header_type: $("#ibHeader").value,
    seed: $("#ibSeed").value, flow: $("#ibFlow").value,
    sni: sec==="reality" ? $("#ibRSni").value : $("#ibSni").value,
    dest: $("#ibDest").value, fingerprint: $("#ibFp").value,
    ss_method: $("#ibSsMethod").value, regenerate: $("#ibRegen").checked,
  };
  try{
    await api(id ? "/api/inbounds/"+id : "/api/inbounds",
      {method:"POST", body: JSON.stringify(payload)});
    $("#inboundModalWrap").style.display = "none";
    toast(id ? "Inbound updated." : "Inbound created."); loadInbounds(); loadDashboard();
  }catch(err){ toast(err.message); }
});
window.removeInbound = async id => {
  if(!confirm("Delete this inbound? Client links for it will stop working.")) return;
  try{ await api("/api/inbounds/"+id, {method:"DELETE"}); loadInbounds(); loadDashboard(); }
  catch(err){ toast(err.message); }
};

/* ---------- services ---------- */
async function loadServices(){
  try{
    const d = await api("/api/services");
    $("#serviceList").innerHTML = (d.services||[]).map(s => svcCard(s, true)).join("");
  }catch(e){}
}
window.svc = async (id, action) => {
  try{ await api(`/api/services/${id}/${action}`, {method:"POST"});
    toast(id + " " + action + " sent."); setTimeout(()=>{ loadServices(); loadDashboard(); }, 600); }
  catch(err){ toast(err.message); }
};

/* ---------- settings ---------- */
$("#settingsForm").addEventListener("submit", async e => {
  e.preventDefault();
  const payload = {};
  $$("#settingsForm input[name]").forEach(inp => payload[inp.name] = inp.value);
  try{ await api("/api/settings", {method:"POST", body: JSON.stringify(payload)});
    toast("Settings saved."); loadDashboard(); }
  catch(err){ toast(err.message); }
});
$("#passwordForm").addEventListener("submit", async e => {
  e.preventDefault();
  try{ await api("/api/admin/password", {method:"POST", body: JSON.stringify({
      current: $("#pwCurrent").value, new: $("#pwNew").value})});
    $("#pwCurrent").value = ""; $("#pwNew").value = "";
    toast("Admin password changed."); }
  catch(err){ toast(err.message); }
});

/* ---------- boot ---------- */
(async () => {
  try{
    const me = await api("/api/me");
    if(me.logged_in) showApp();
  }catch(e){}
  let tick = 0;
  setInterval(() => {
    if($("#appView").style.display!=="block") return;
    loadDashboard();
    tick++;
    if(tick % 3 === 0){
      loadOnline();
      if($("#page-users").classList.contains("active")) loadUsers();
    }
  }, 2000);
})();
</script>
</body>
</html>
"""

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    init_db()
    if "--set-admin" in args:
        idx = args.index("--set-admin")
        password = args[idx + 1]
        conn = db()
        conn.execute("UPDATE admin SET password_hash = ? WHERE id = 1",
                     (hash_password(password),))
        conn.commit()
        conn.close()
        print("Admin password updated.")
        return
    if "--enforce" in args:
        enforce()
        print("Enforce pass complete.")
        return
    if "--init-net" in args:
        init_net()
        print("Accounting chains ready.")
        return
    if "--sync-xray" in args:
        xray_sync_users(list_users_as_rows())
        print("Xray config rebuilt from panel database.")
        return
    settings = get_settings()
    port = int(settings.get("panel_port", "8443"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) and not MOCK:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
    print(f"Nexo listening on {scheme}://0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
