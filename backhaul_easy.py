#!/usr/bin/env python3
"""Backhaul Easy by alirezaw. Python 3.10+, standard library only.

Configuration is deliberately generated from a closed, validated schema. The
upstream binary does the tunnelling; this program owns only its named files.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
import uuid

VERSION = "1.0.0"
OWNER = "backhaul-easy"
MARKER = "# Managed by backhaul-easy (alirezaw)"
ETC_DIR = Path("/etc/backhaul-easy")
STATE_PATH = ETC_DIR / "state.json"
CONFIG_PATH = ETC_DIR / "config.toml"
CERT_PATH = ETC_DIR / "tls.crt"
KEY_PATH = ETC_DIR / "tls.key"
TRAFFIC_PATH = ETC_DIR / "traffic.json"
LIB_DIR = Path("/usr/local/lib/backhaul-easy")
BINARY_PATH = LIB_DIR / "backhaul"
MANAGER_PATH = LIB_DIR / "backhaul_easy.py"
RECEIPT_PATH = LIB_DIR / "install.json"
LAUNCHER_PATH = Path("/usr/local/sbin/backhaul-easy")
UNIT_PATH = Path("/etc/systemd/system/backhaul-easy.service")
LOCK_PATH = Path("/run/lock/backhaul-easy.lock")
SERVICE = "backhaul-easy.service"
TRANSPORTS = ("tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "udp")
MAX_PORTS = 128
MAX_JSON = 65536
MAX_PAIRING = 131072

# skip_optz avoids system-wide tuning. Monitoring is off unless explicitly
# enabled; upstream pprof listeners are never enabled by this manager.
COMMON_ADVANCED = {
    "nodelay": (bool, True),
    "keepalive_period": (int, 75, 1, 3600),
    "log_level": (str, "info", ("debug", "info", "warn", "error", "fatal")),
    "mux_version": (int, 1, 1, 2),
    "mux_framesize": (int, 32768, 1024, 65535),
    "mux_recievebuffer": (int, 4194304, 65536, 67108864),
    "mux_streambuffer": (int, 65536, 1024, 16777216),
    "mss": (int, 0, 0, 65535),
    "so_rcvbuf": (int, 0, 0, 67108864),
    "so_sndbuf": (int, 0, 0, 67108864),
    "web_port": (int, 0, 0, 65535),
    "sniffer": (bool, False),
    "sniffer_log": (str, str(TRAFFIC_PATH), (str(TRAFFIC_PATH),)),
}
SERVER_ADVANCED = {
    "heartbeat": (int, 40, 1, 3600),
    "channel_size": (int, 2048, 1, 65536),
    "mux_con": (int, 8, 1, 256),
    "accept_udp": (bool, False),
    "proxy_protocol": (bool, False),
}
CLIENT_ADVANCED = {
    "connection_pool": (int, 8, 1, 1024),
    "retry_interval": (int, 3, 1, 300),
    "dial_timeout": (int, 10, 1, 300),
    "aggressive_pool": (bool, False),
    "edge_ip": (str, "", "ip"),
}


class UserError(ValueError):
    """An actionable, safe-to-display validation or lifecycle error."""


def bounded_int(value, label, low=1, high=65535):
    if type(value) is not int or not low <= value <= high:
        raise UserError(f"{label} must be an integer from {low} to {high}.")
    return value


def host(value, label="Host", bind=False):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise UserError(f"{label} must be a valid IP address or DNS name.")
    if value != value.strip() or any(c.isspace() or ord(c) < 32 for c in value):
        raise UserError(f"{label} cannot contain whitespace or control characters.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if bind or ":" in value or "%" in value or re.fullmatch(r"[\d.]+", value):
            raise UserError(f"{label} is not a valid IP address.") from None
        labels = value.rstrip(".").split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in labels):
            raise UserError(f"{label} must be an IP address or a complete DNS name.")
        return value.lower().rstrip(".")
    if address.is_multicast or (address.is_unspecified and not bind):
        raise UserError(f"{label} cannot be multicast or an unspecified destination.")
    return str(address)


def address(hostname, port):
    return f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"


def advanced_specs(role):
    return COMMON_ADVANCED | (SERVER_ADVANCED if role == "server" else CLIENT_ADVANCED)


def validate_state(state):
    """Validate and return a normalized independent configuration dictionary."""
    if type(state) is not dict:
        raise UserError("Settings must be a JSON object.")
    required = {"schema_version", "version", "owner", "role", "mode", "endpoint", "tunnel_port", "transport", "token", "ports"}
    allowed = required | {"advanced", "tls_cert", "tls_key", "proxy_uuid", "tunnel_bind"}
    if set(state) - allowed or not required <= set(state):
        raise UserError("Settings have missing or unsupported fields.")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1 or state["owner"] != OWNER or state["version"] != VERSION:
        raise UserError("Unsupported settings owner, schema, or version.")
    if state["role"] not in ("server", "client") or state["transport"] not in TRANSPORTS:
        raise UserError("Unsupported server role or transport.")
    if state["mode"] not in ("panel", "forward"):
        raise UserError("Choose panel or forward mode.")
    result = dict(state)
    result["endpoint"] = host(state["endpoint"], "Iran endpoint")
    if "tunnel_bind" in state:
        if state["role"] != "server":
            raise UserError("Tunnel listening IP belongs only to Iran.")
        result["tunnel_bind"] = host(state["tunnel_bind"], "Tunnel listening IP", bind=True)
    bounded_int(state["tunnel_port"], "Tunnel port")
    if not isinstance(state["token"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", state["token"]):
        raise UserError("The shared token must contain 32–128 URL-safe letters, digits, '-' or '_'.")
    if type(state["ports"]) is not list or not 1 <= len(state["ports"]) <= MAX_PORTS:
        raise UserError(f"Configure between 1 and {MAX_PORTS} forwarded ports.")
    ports = []
    for raw in state["ports"]:
        if type(raw) is not dict or set(raw) != {"bind", "public", "target", "local"}:
            raise UserError("Each port needs bind, public, target and local fields.")
        entry = {"bind": host(raw["bind"], "Listening IP", bind=True),
                 "public": bounded_int(raw["public"], "Iran service port"),
                 "target": host(raw["target"], "Outside destination"),
                 "local": bounded_int(raw["local"], "Outside destination port")}
        if ":" in entry["target"]:
            raise UserError("This upstream version does not support IPv6 forwarding destinations; use an IPv4 address or DNS name.")
        if state["transport"] == "udp" and len(address(entry["target"], entry["local"]).encode("utf-8")) > 47:
            raise UserError("UDP destination host:port must be at most 47 bytes for this upstream version.")
        if entry["public"] == state["tunnel_port"]:
            raise UserError("A forwarded Iran service port cannot equal the tunnel control port.")
        for previous in ports:
            if previous["public"] == entry["public"] and (previous["bind"] == entry["bind"] or previous["bind"] in ("0.0.0.0", "::") or entry["bind"] in ("0.0.0.0", "::")):
                raise UserError("Forwarded listening ports overlap; give each listener a distinct address and port.")
        ports.append(entry)
    result["ports"] = ports
    if state["mode"] == "panel":
        if state["transport"] == "udp":
            raise UserError("UDP-only transport cannot carry the panel's TCP proxy connection. Choose one of the other six transports.")
        if len(ports) != 1 or ports[0]["bind"] != "127.0.0.1" or ports[0]["target"] != "127.0.0.1":
            raise UserError("Panel mode requires exactly one localhost-to-localhost mapping.")
        try:
            if not isinstance(state.get("proxy_uuid"), str) or str(uuid.UUID(state["proxy_uuid"])) != state["proxy_uuid"]:
                raise ValueError
        except ValueError as exc:
            raise UserError("Panel mode requires a canonical proxy UUID.") from exc
    elif "proxy_uuid" in state:
        raise UserError("A proxy UUID belongs only to panel mode.")
    adv = state.get("advanced", {})
    specs = advanced_specs(state["role"])
    if type(adv) is not dict or set(adv) - set(specs):
        raise UserError("Unsupported advanced settings for this role.")
    normalized = {}
    for name, value in adv.items():
        spec = specs[name]
        if type(value) is not spec[0]:
            raise UserError(f"{name} must be {spec[0].__name__}.")
        if spec[0] is int:
            bounded_int(value, name, spec[2], spec[3])
        elif spec[0] is str and spec[2] == "ip":
            value = host(value, name, bind=True) if value else ""
            if value and (":" in value or ipaddress.ip_address(value).is_unspecified):
                raise UserError("edge_ip must be a destination IPv4 address; upstream does not support IPv6 here.")
        elif spec[0] is str and value not in spec[2]:
            raise UserError(f"Unsupported value for {name}.")
        normalized[name] = value
    if adv.get("accept_udp") and state["transport"] != "tcp":
        raise UserError("accept_udp is supported only with the TCP transport.")
    if adv.get("proxy_protocol") and state["transport"] not in ("tcp", "tcpmux", "wsmux", "wssmux"):
        raise UserError("PROXY protocol is supported only for TCP, TCP mux, WS mux and WSS mux.")
    if adv.get("edge_ip") and state["transport"] not in ("ws", "wsmux", "wss", "wssmux"):
        raise UserError("edge_ip applies only to WebSocket transports.")
    if adv.get("mux_streambuffer", COMMON_ADVANCED["mux_streambuffer"][1]) > adv.get("mux_recievebuffer", COMMON_ADVANCED["mux_recievebuffer"][1]):
        raise UserError("The mux stream buffer cannot exceed the mux receive buffer.")
    if state["mode"] == "panel" and (adv.get("proxy_protocol") or adv.get("accept_udp")):
        raise UserError("Panel proxy mode does not accept PROXY headers or UDP payload listeners.")
    monitor_port = adv.get("web_port", 0)
    if monitor_port and (monitor_port == state["tunnel_port"] or any(monitor_port == p["public"] for p in ports) or state["mode"] == "panel" and monitor_port == ports[0]["local"]):
        raise UserError("The monitoring port cannot overlap a tunnel or service port.")
    result["advanced"] = normalized
    tls = state["role"] == "server" and state["transport"] in ("wss", "wssmux")
    if tls:
        if state.get("tls_cert") != str(CERT_PATH) or state.get("tls_key") != str(KEY_PATH):
            raise UserError("WSS server settings require the managed TLS certificate and key paths.")
    elif "tls_cert" in state or "tls_key" in state:
        raise UserError("TLS certificate fields belong only to a WSS server.")
    return result


def parse_ports(text):
    """Parse P, P:L or equal-size P1-P2:L1-L2 ranges, separated by commas."""
    if not isinstance(text, str) or len(text) > 8192 or not text.strip() or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise UserError("Enter a comma-separated list such as 443,8080:80,9000-9002:8000-8002.")
    entries = []
    seen = set()
    for piece in text.split(","):
        match = re.fullmatch(r"\s*(\d{1,5})(?:-(\d{1,5}))?(?::(\d{1,5})(?:-(\d{1,5}))?)?\s*", piece)
        if not match:
            raise UserError("Invalid port mapping. Use 443, 8080:80, or 9000-9002:8000-8002.")
        p0, p1, l0, l1 = (int(v) if v else None for v in match.groups())
        p1 = p1 if p1 is not None else p0
        l0 = l0 if l0 is not None else p0
        l1 = l1 if l1 is not None else (l0 + p1 - p0 if match.group(3) is None else l0)
        for v in (p0, p1, l0, l1):
            bounded_int(v, "Port")
        if p1 < p0 or l1 < l0 or p1 - p0 != l1 - l0:
            raise UserError("Port ranges must ascend and contain the same number of ports.")
        if len(entries) + p1 - p0 + 1 > MAX_PORTS:
            raise UserError(f"At most {MAX_PORTS} forwarded ports are supported.")
        for public, local in zip(range(p0, p1 + 1), range(l0, l1 + 1)):
            if public in seen:
                raise UserError("Public port ranges overlap.")
            seen.add(public)
            entries.append({"bind": "0.0.0.0", "public": public, "target": "127.0.0.1", "local": local})
    return entries


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise UserError("Duplicate JSON fields are not allowed.")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(UserError("Non-finite JSON numbers are not allowed.")))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise UserError("Invalid or excessively nested JSON settings.") from exc


def encode_pairing(state):
    state = validate_state(state)
    payload = {key: state[key] for key in ("schema_version", "mode", "endpoint", "tunnel_port", "transport", "token", "ports")}
    payload["advanced"] = {key: value for key, value in state["advanced"].items() if key in COMMON_ADVANCED and key not in ("web_port", "sniffer", "sniffer_log")}
    if state["mode"] == "panel":
        payload["proxy_uuid"] = state["proxy_uuid"]
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).decode("ascii").rstrip("=")
    return "BHE1." + encoded + "." + hashlib.sha256(encoded.encode("ascii")).hexdigest()[:16]


def decode_pairing(text):
    if not isinstance(text, str) or len(text) > MAX_PAIRING or not re.fullmatch(r"BHE1\.[A-Za-z0-9_-]+\.[a-f0-9]{16}", text):
        raise UserError("Paste one complete BHE1 pairing code without spaces or newlines.")
    _, encoded, check = text.split(".")
    if not hmac.compare_digest(check, hashlib.sha256(encoded.encode("ascii")).hexdigest()[:16]):
        raise UserError("Pairing checksum mismatch; copy the complete code again.")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(raw) > MAX_JSON:
            raise UserError("Pairing payload exceeds the settings size limit.")
        payload = strict_json(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise UserError("Invalid pairing payload.") from exc
    required = {"schema_version", "mode", "endpoint", "tunnel_port", "transport", "token", "ports", "advanced"}
    if type(payload) is not dict or set(payload) - (required | {"proxy_uuid"}) or not required <= set(payload):
        raise UserError("Unsupported pairing fields.")
    if type(payload["advanced"]) is not dict or set(payload["advanced"]) - (set(COMMON_ADVANCED) - {"web_port", "sniffer", "sniffer_log"}):
        raise UserError("Pairing advanced fields must be shared transport settings.")
    return validate_state(payload | {"version": VERSION, "owner": OWNER, "role": "client"})


def toml_value(value):
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    return json.dumps(value, ensure_ascii=True)


def render_config(state):
    state = validate_state(state)
    role = state["role"]
    settings = {
        "bind_addr" if role == "server" else "remote_addr": address(state.get("tunnel_bind", "::" if ":" in state["endpoint"] else "0.0.0.0") if role == "server" else state["endpoint"], state["tunnel_port"]),
        "transport": state["transport"], "token": state["token"], "skip_optz": True,
        "sniffer": False, "web_port": 0, "pprof": False,
    }
    settings.update({name: spec[1] for name, spec in advanced_specs(role).items()})
    settings.update(state["advanced"])
    if role == "server":
        settings["ports"] = [f"{address(p['bind'], p['public'])}={address(p['target'], p['local'])}" for p in state["ports"]]
        if state["transport"] in ("wss", "wssmux"):
            settings.update(tls_cert=state["tls_cert"], tls_key=state["tls_key"])
    lines = [MARKER, "# Edit through backhaul-easy; this file contains a secret token.", f"[{role}]"]
    lines.extend(f"{name} = {toml_value(value)}" for name, value in settings.items())
    return "\n".join(lines) + "\n"


def render_unit():
    return f"""{MARKER}
[Unit]
Description=Backhaul Easy by alirezaw
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={BINARY_PATH} -c {CONFIG_PATH}
Restart=on-failure
RestartSec=3
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={ETC_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


def safe_path(path, regular=False):
    path = Path(path)
    if not path.is_absolute():
        raise UserError(f"An absolute path is required: {path}")
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise UserError(f"Refusing a symbolic-link location: {candidate}")
    if regular and path.exists() and not path.is_file():
        raise UserError(f"Expected a regular file: {path}")
    if path.exists() and regular and path.stat().st_nlink != 1:
        raise UserError(f"Refusing a multiply-linked file: {path}")
    return path


def private_directory(path):
    safe_path(path)
    if path.exists():
        st = path.stat()
        if not path.is_dir() or st.st_uid != 0 or st.st_mode & 0o022:
            raise UserError(f"Directory must be owned by root and not writable by other users: {path}")
    else:
        path.mkdir(mode=0o700)


def read_bytes(path, limit=MAX_JSON):
    safe_path(path, regular=True)
    if path.stat().st_size > limit:
        raise UserError(f"File is unexpectedly large: {path}")
    return path.read_bytes()


def atomic_write(path, data, mode=0o600):
    safe_path(path, regular=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".bhe-", dir=str(path.parent))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(name, *arguments, check=True, timeout=20, data=None):
    executable = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise UserError(f"Required command not installed: {name}")
    try:
        result = subprocess.run([executable, *map(str, arguments)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise UserError(f"{name} timed out; inspect the service status before retrying.") from exc
    if check and result.returncode:
        raise UserError(f"{name} failed (exit {result.returncode}). Run backhaul-easy logs for details.")
    return result


def ctl(*arguments, **kwargs):
    return command("systemctl", *arguments, **kwargs)


def require_linux(root=False):
    if not sys.platform.startswith("linux") or not Path("/run/systemd/system").is_dir():
        raise UserError("This action requires Linux with systemd running.")
    if root and os.geteuid() != 0:
        raise UserError("Run sudo backhaul-easy to change this setup.")


@contextlib.contextmanager
def lifecycle_lock():
    require_linux(root=True)
    import fcntl
    safe_path(LOCK_PATH, regular=True)
    descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise UserError("Unsafe lifecycle lock file.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UserError("Another Backhaul Easy action is running; try again when it finishes.") from exc
        yield
    finally:
        os.close(descriptor)


def load_state(optional=False):
    safe_path(STATE_PATH, regular=True)
    if not STATE_PATH.exists():
        if optional:
            return None
        raise UserError("No setup found. Choose Set up a tunnel first.")
    return validate_state(strict_json(read_bytes(STATE_PATH)))


def assert_owned_setup(allow_empty=False):
    for path in (ETC_DIR, LIB_DIR, UNIT_PATH, STATE_PATH, CONFIG_PATH, CERT_PATH, KEY_PATH, TRAFFIC_PATH, BINARY_PATH, MANAGER_PATH, LAUNCHER_PATH, RECEIPT_PATH):
        safe_path(path, regular=path not in (ETC_DIR, LIB_DIR))
    for path in (ETC_DIR, LIB_DIR):
        if path.exists():
            private_directory(path)
    state = load_state(optional=True)
    if state is None and not allow_empty:
        raise UserError("No owned setup found; refusing to manage another service.")
    if CONFIG_PATH.exists() and (state is None or not read_bytes(CONFIG_PATH).startswith((MARKER + "\n").encode())):
        raise UserError("The existing config is not owned by Backhaul Easy.")
    if UNIT_PATH.exists() and read_bytes(UNIT_PATH).decode("utf-8") != render_unit():
        raise UserError("An unrelated or manually modified service uses this name; no changes were made.")
    dropins = ctl("show", SERVICE, "--property=DropInPaths", "--value", check=False).stdout.decode().strip()
    fragment = ctl("show", SERVICE, "--property=FragmentPath", "--value", check=False).stdout.decode().strip()
    if dropins or (fragment and fragment != str(UNIT_PATH)):
        raise UserError("This service has external overrides or another owner; no changes were made.")
    if state is None and UNIT_PATH.exists():
        raise UserError("A service exists without owned settings; repair it manually before continuing.")
    if state is None and any(path.exists() for path in (CERT_PATH, KEY_PATH, TRAFFIC_PATH)):
        raise UserError("Unowned TLS or monitoring files already exist in the configuration directory.")
    return state


def active():
    return ctl("is-active", "--quiet", SERVICE, check=False).returncode == 0


def sanitize_output(text, state=None):
    if state:
        text = text.replace(state["token"], "[shared token hidden]")
        if state.get("proxy_uuid"):
            text = text.replace(state["proxy_uuid"], "[proxy UUID hidden]")
    text = re.sub(r"BHE1\.[A-Za-z0-9_-]+\.[a-f0-9]{16}", "[pairing code hidden]", text)
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)


def tls_material(cert, key):
    cert, key = safe_path(Path(cert), regular=True), safe_path(Path(key), regular=True)
    if not cert.is_file() or not key.is_file():
        raise UserError("Both certificate and private key must be existing regular files.")
    cert_bytes, key_bytes = read_bytes(cert, 262144), read_bytes(key, 262144)
    command("openssl", "x509", "-in", cert, "-noout", "-checkend", "0")
    cert_public = command("openssl", "x509", "-in", cert, "-pubkey", "-noout").stdout
    cert_der = command("openssl", "pkey", "-pubin", "-outform", "DER", data=cert_public).stdout
    key_der = command("openssl", "pkey", "-in", key, "-passin", "pass:", "-pubout", "-outform", "DER").stdout
    if not hmac.compare_digest(cert_der, key_der):
        raise UserError("The certificate and private key do not match.")
    return {CERT_PATH: cert_bytes, KEY_PATH: key_bytes}


def create_self_signed(endpoint):
    """Generate private staged files without changing system trust stores."""
    endpoint = host(endpoint, "Certificate endpoint")
    try:
        ipaddress.ip_address(endpoint)
        san = "IP:" + endpoint
    except ValueError:
        san = "DNS:" + endpoint
    with tempfile.TemporaryDirectory(prefix="backhaul-easy-tls-") as temporary:
        cert = Path(temporary) / "tls.crt"
        key = Path(temporary) / "tls.key"
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "3650", "-subj", "/CN=Backhaul Easy", "-addext", "subjectAltName=" + san, "-keyout", key, "-out", cert, timeout=60)
        key.chmod(0o600)
        cert.chmod(0o600)
        return tls_material(cert, key)


def apply_state(state, tls_files=None):
    """Commit config/state/unit together; restore previous setup if startup fails."""
    state = validate_state(state)
    previous_state = assert_owned_setup(allow_empty=True)
    panel = None
    panel_transaction = None
    panel_removal = False
    if (state["role"] == "client" and state["mode"] == "panel") or (previous_state and previous_state["role"] == "client" and previous_state["mode"] == "panel") or (ETC_DIR / "panel-receipt.json").exists():
        try:
            import panel_support as panel
        except ImportError as exc:
            raise UserError("The panel helper is missing; rerun the installer to repair it.") from exc
        if state["role"] == "client" and state["mode"] == "panel":
            try:
                panel_transaction = panel.prepare_panel(state)
            except ValueError as exc:
                raise UserError(str(exc)) from exc
        else:
            try:
                panel_transaction = panel.prepare_panel_removal()
                panel_removal = True
            except ValueError as exc:
                raise UserError(str(exc)) from exc
    if not safe_path(BINARY_PATH, regular=True).is_file() or not os.access(BINARY_PATH, os.X_OK):
        raise UserError("The Backhaul binary is missing. Run the bundled installer first.")
    private_directory(ETC_DIR)
    changes = {STATE_PATH: (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(), CONFIG_PATH: render_config(state).encode(), UNIT_PATH: render_unit().encode()}
    changes.update(tls_files or {})
    if state["role"] == "server" and state["transport"] in ("wss", "wssmux") and not tls_files:
        for path in (CERT_PATH, KEY_PATH):
            if not safe_path(path, regular=True).is_file():
                raise UserError("Managed TLS files are missing; run setup and supply the certificate again.")
    backups = {path: read_bytes(path, 262144) if path.exists() else None for path in changes}
    was_active = active()
    was_enabled = ctl("is-enabled", "--quiet", SERVICE, check=False).returncode == 0
    try:
        # Release existing listeners before a role change or helper replacement.
        # This also prevents upstream's mtime watcher reloading mid-transaction.
        if was_active:
            ctl("stop", SERVICE)
        for path, data in changes.items():
            atomic_write(path, data, 0o644 if path == UNIT_PATH else 0o600)
        ctl("daemon-reload")
        if panel_transaction is not None:
            if panel_removal:
                panel.apply_panel_removal(panel_transaction)
            else:
                panel.apply_panel(panel_transaction)
        ctl("enable", SERVICE)
        ctl("restart", SERVICE)
        time.sleep(2)
        if not active():
            raise UserError("The new Backhaul process did not stay running.")
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        rollback_errors = []
        if panel_transaction is not None:
            # A newly started Iran listener may occupy the old Outside proxy's
            # port. Release it before restoring and starting the previous proxy.
            try:
                if ctl("stop", SERVICE, check=False).returncode:
                    rollback_errors.append("Could not stop the replacement Backhaul process before panel rollback.")
            except UserError as error:
                rollback_errors.append(str(error))
            try:
                panel.rollback_panel(panel_transaction)
            except (OSError, ValueError) as error:
                rollback_errors.append(str(error))
        for path, previous in backups.items():
            try:
                if previous is None:
                    safe_path(path, regular=True).unlink(missing_ok=True)
                else:
                    atomic_write(path, previous, 0o644 if path == UNIT_PATH else 0o600)
            except (OSError, UserError) as error:
                rollback_errors.append(str(error))
        try:
            ctl("daemon-reload")
            enable_result = ctl("enable" if was_enabled else "disable", SERVICE, check=False)
            if was_enabled and enable_result.returncode:
                rollback_errors.append("Could not restore automatic service startup.")
            restart_result = ctl("restart" if was_active else "stop", SERVICE, check=False)
            if was_active and restart_result.returncode:
                rollback_errors.append("Could not restart the previous service configuration.")
        except UserError as error:
            rollback_errors.append(str(error))
        suffix = " Previous files restored." if not rollback_errors else " Rollback needs attention: " + "; ".join(rollback_errors)
        raise UserError(str(exc) + suffix) from exc
    print("Settings saved. The service process is running; end-to-end application readiness still needs a real application test.")


def color(text, code="36"):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else text


def ask(label, default=None):
    print(color("\n" + label, "1;36"))
    if default is not None and str(default):
        print("Press Enter to use " + color(str(default), "1;33") + ", or type a different value.")
    value = input(color("> ", "36")).strip()
    return str(default) if not value and default is not None else value


def yes(label, default=False):
    return ask(label + " (yes/no)", "no" if not default else "yes").lower() in ("yes", "y")


def show_plan(state):
    print(f"\nRole: {'Iran / server' if state['role'] == 'server' else 'Outside / client'}")
    print("Purpose: " + ("Iran 3x-ui panel, Outside internet egress" if state["mode"] == "panel" else "Forward existing applications"))
    print(f"Tunnel: {address(state['endpoint'], state['tunnel_port'])} — {state['transport']}")
    print("Outside connects back to Iran. The tunnel port is separate from forwarded service ports.")
    if state["mode"] == "panel":
        print("Panel user traffic: TCP and UDP, carried inside the VLESS TCP connection.")
    else:
        print("Forwarded application protocol: " + ("UDP only" if state["transport"] == "udp" else "TCP and UDP" if state.get("advanced", {}).get("accept_udp") else "TCP"))
    for p in state["ports"]:
        print(f"  Iran {address(p['bind'], p['public'])} -> Outside {address(p['target'], p['local'])}")
    if state["transport"] in ("wss", "wssmux"):
        print("WSS limitation: upstream encrypts traffic but does NOT verify the server certificate. It does not provide authenticated TLS server identity.")
    print("This manager does not change firewalls, routes or system network tuning.")


def network_instructions(state):
    kind = "TCP and UDP" if state["transport"] == "udp" else "TCP"
    print(f"Allow inbound {kind} port {state['tunnel_port']} on Iran for the tunnel; restrict it to the Outside IP when possible.")
    if state["role"] == "server":
        print("Allow intended users to reach only the public service ports above. A 127.0.0.1 listener is local to Iran.")
    else:
        print("Allow outbound tunnel traffic from Outside to Iran, and make each destination application reachable from Outside.")


def prompt_ports(default=None):
    print("Forwarded ports: 443 (same port), 8080:80 (Iran:Outside), or 9000-9002:8000-8002.")
    mappings = parse_ports(ask("Forwarded ports", default))
    if yes("Customize the listening IP or Outside destination", False):
        bind = host(ask("Iran listening IP (127.0.0.1 for a local panel outbound)", "0.0.0.0"), bind=True)
        target = host(ask("Destination IP or domain reachable from Outside", "127.0.0.1"))
        for p in mappings:
            p.update(bind=bind, target=target)
        if len(mappings) > 1 and yes("Customize destination/listening IP for each mapping", False):
            for p in mappings:
                p["bind"] = host(ask(f"Iran port {p['public']} listening IP", p["bind"]), bind=True)
                p["target"] = host(ask(f"Outside port {p['local']} destination", p["target"]))
    return mappings


def prompt_advanced(state):
    print("Advanced settings are optional. Enter keeps the displayed value.")
    print("TCP multiplexing values must be compatible on both servers; pair these values manually when changed.")
    advanced = dict(state.get("advanced", {}))
    for name, spec in advanced_specs(state["role"]).items():
        if name in ("web_port", "sniffer", "sniffer_log"):
            continue
        if name.startswith("mux_") and "mux" not in state["transport"]:
            continue
        if name == "accept_udp" and state["transport"] != "tcp":
            continue
        if name in ("accept_udp", "proxy_protocol") and state["mode"] == "panel":
            continue
        if name == "proxy_protocol" and state["transport"] not in ("tcp", "tcpmux", "wsmux", "wssmux"):
            continue
        if name == "edge_ip" and state["transport"] not in ("ws", "wsmux", "wss", "wssmux"):
            continue
        if name in ("mss", "so_rcvbuf", "so_sndbuf") and state["transport"] not in ("tcp", "tcpmux"):
            continue
        current = advanced.get(name, spec[1])
        raw = ask(name, str(current).lower() if type(current) is bool else current)
        if spec[0] is bool:
            if raw not in ("true", "false"):
                raise UserError(f"{name}: enter true or false.")
            advanced[name] = raw == "true"
        elif spec[0] is int:
            if not raw.isdigit():
                raise UserError(f"{name}: enter a whole number.")
            advanced[name] = int(raw)
        else:
            advanced[name] = raw
    if yes("Configure optional traffic monitoring", False):
        print("Upstream's monitor binds on all network interfaces WITHOUT authentication. Restrict access in your firewall before enabling it.")
        print("Traffic counters will be stored in the managed traffic file. pprof remains disabled.")
        current = advanced.get("web_port", 0)
        raw = ask("Monitor web port (0 disables it)", current)
        if not raw.isdigit():
            raise UserError("Monitoring port must be a whole number.")
        web_port = bounded_int(int(raw), "Monitor web port", 0, 65535)
        if web_port and ask("Type ENABLE PUBLIC MONITORING to accept this exposure") != "ENABLE PUBLIC MONITORING":
            raise UserError("Monitoring was not enabled.")
        advanced["web_port"] = web_port
        advanced["sniffer"] = yes("Enable traffic counters", bool(web_port))
        advanced["sniffer_log"] = str(TRAFFIC_PATH)
    updated = state | {"advanced": advanced}
    if state["role"] == "server":
        updated["tunnel_bind"] = host(ask("Tunnel listening IP", state.get("tunnel_bind", "::" if ":" in state["endpoint"] else "0.0.0.0")), bind=True)
    return validate_state(updated)


def setup():
    with lifecycle_lock():
        existing = assert_owned_setup(allow_empty=True)
        if existing and ask("Existing setup will be replaced. Type REPLACE to continue") != "REPLACE":
            print("Setup cancelled.")
            return
        print("Set up Iran first, then paste its pairing code on Outside.")
        print("1) Iran — accept tunnel connections\n2) Outside — connect back to Iran")
        choice = ask("Server role", "1")
        tls_files = None
        if choice == "1":
            print("1) 3x-ui panel on Iran, internet egress through Outside (recommended)\n2) Forward existing TCP/UDP applications")
            mode_choice = ask("Purpose", "1")
            if mode_choice not in ("1", "2"):
                raise UserError("Choose purpose 1 or 2.")
            mode = "panel" if mode_choice == "1" else "forward"
            endpoint = host(ask("Iran IP address or domain reachable from Outside"), "Iran endpoint")
            print("Transport: 1 TCP (default), 2 TCP mux, 3 WebSocket, 4 WebSocket mux, 5 WSS, 6 WSS mux, 7 UDP")
            transport_choice = ask("Transport", "1")
            if not transport_choice.isdigit() or not 1 <= int(transport_choice) <= len(TRANSPORTS):
                raise UserError("Choose a transport from 1 to 7.")
            transport = TRANSPORTS[int(transport_choice) - 1]
            raw_port = ask("Tunnel control port (not a forwarded service port)", "3080")
            if not raw_port.isdigit():
                raise UserError("Tunnel port must be a whole number.")
            if mode == "panel":
                print("The panel connects to a private local listener on Iran. A local proxy on Outside provides internet egress.")
                raw_proxy_port = ask("Local panel bridge port on both servers", "1080")
                if not raw_proxy_port.isdigit():
                    raise UserError("Bridge port must be a whole number.")
                proxy_port = bounded_int(int(raw_proxy_port), "Panel bridge port")
                mappings = [{"bind": "127.0.0.1", "public": proxy_port, "target": "127.0.0.1", "local": proxy_port}]
            else:
                mappings = prompt_ports()
            state = {"schema_version": 1, "version": VERSION, "owner": OWNER, "role": "server", "mode": mode, "endpoint": endpoint,
                     "tunnel_port": int(raw_port), "transport": transport, "token": secrets.token_urlsafe(32), "ports": mappings, "advanced": {}}
            if mode == "panel":
                state["proxy_uuid"] = str(uuid.uuid4())
            if transport in ("wss", "wssmux"):
                print("WARNING: Outside does not verify the certificate. WSS is encrypted but server identity is not authenticated.")
                if yes("Generate a self-signed certificate automatically", True):
                    tls_files = create_self_signed(endpoint)
                else:
                    tls_files = tls_material(ask("Absolute certificate file path"), ask("Absolute unencrypted private key file path"))
                state.update(tls_cert=str(CERT_PATH), tls_key=str(KEY_PATH))
        elif choice == "2":
            print("The pairing code contains your shared secret. Paste visibly here; do not share it publicly.")
            state = decode_pairing(ask("Pairing code from Iran"))
        else:
            raise UserError("Choose role 1 or 2.")
        state = validate_state(state)
        if yes("Open advanced transport settings", False):
            state = prompt_advanced(state)
        show_plan(state)
        network_instructions(state)
        if not yes("Save these settings and start Backhaul", True):
            print("Setup cancelled.")
            return
        apply_state(state, tls_files)
        if state["role"] == "server":
            print_pairing(state)
            if state["mode"] == "panel":
                panel_output(state)


def edit_ports():
    with lifecycle_lock():
        state = assert_owned_setup()
        if state["role"] != "server":
            raise UserError("Forwarded ports are controlled on Iran. Edit them there; Outside receives destinations automatically.")
        if state["mode"] == "panel":
            raise UserError("Panel mode uses one paired localhost bridge port. Use setup on both machines to change that port safely.")
        print("Current mappings:")
        show_plan(state)
        updated = validate_state(state | {"ports": prompt_ports()})
        show_plan(updated)
        if yes("Apply these ports and restart the tunnel", False):
            apply_state(updated)
            print("Outside receives new forwarding destinations automatically. Existing connections may reconnect.")


def edit_advanced():
    with lifecycle_lock():
        state = assert_owned_setup()
        updated = prompt_advanced(state)
        if yes("Apply advanced settings and restart", False):
            apply_state(updated)


def print_pairing(state=None):
    state = state or load_state()
    if state["role"] != "server":
        raise UserError("Display the pairing code on Iran; this machine is the Outside client.")
    print("\nSECRET pairing code — copy into Outside setup. Anyone with it can join this tunnel.")
    print("Its checksum detects copying mistakes; it is not encryption or an identity signature.")
    print(encode_pairing(state))


def panel_output(state=None):
    state = state or load_state()
    if state["mode"] != "panel" or state["role"] != "server":
        raise UserError("The 3x-ui outbound is available on Iran in panel mode.")
    try:
        import panel_support
        output = panel_support.panel_outbound(state)
    except (ImportError, ValueError) as exc:
        raise UserError(f"Cannot create the panel outbound: {exc}") from exc
    print("\n3x-ui outbound configuration for the Iran panel (contains your private proxy UUID):")
    print(json.dumps(output, indent=2) if isinstance(output, dict) else output)
    print("Add this outbound in the panel's Xray configuration, then route the intended user inbounds to its tag. Save and restart Xray in the panel after Outside setup succeeds.")
    print("A Backhaul process alone does not reroute panel users. The panel must select this outbound; verify the public egress IP through an actual connected user.")


def status():
    require_linux()
    state = load_state(optional=True)
    if not state:
        print("No Backhaul Easy setup is configured.")
        return
    print(f"Role: {state['role']} | transport: {state['transport']} | tunnel port: {state['tunnel_port']}")
    print("Service process: " + ("active" if active() else "inactive or failed"))
    print("An active process alone does not prove a control connection or a working application.")
    result = ctl("show", SERVICE, "--property=ActiveState,SubState,MainPID,ExecMainStatus,ActiveEnterTimestamp", check=False)
    print(sanitize_output(result.stdout.decode(errors="replace"), state).strip())


def logs():
    require_linux()
    state = load_state(optional=True)
    result = command("journalctl", "-u", SERVICE, "-n", "100", "--no-pager", "-o", "short-iso", check=False)
    print(sanitize_output(result.stdout.decode(errors="replace"), state))


def doctor():
    require_linux()
    state = load_state()
    print("Backhaul Easy doctor")
    running = active()
    print("1. Service process: " + ("ACTIVE" if running else "NOT ACTIVE"))
    invocation = ctl("show", SERVICE, "--property=InvocationID", "--value", check=False).stdout.decode().strip()
    journal = ""
    if re.fullmatch(r"[a-fA-F0-9]{32}", invocation):
        result = command("journalctl", "-u", SERVICE, "_SYSTEMD_INVOCATION_ID=" + invocation, "-n", "200", "--no-pager", "-o", "cat", check=False)
        journal = result.stdout.decode(errors="replace")
    observed = bool(re.search(r"control (?:channel|connection).*(?:established|connected)|(?:established|connected).*control (?:channel|connection)", journal, flags=re.IGNORECASE))
    print("2. Control link: " + ("connection evidence found for this service invocation; this is historical, not a live guarantee." if observed else "NOT CONFIRMED for this service invocation."))
    if state["role"] == "client":
        print("3. Outside destination checks:")
        destinations = list(dict.fromkeys((p["target"], p["local"]) for p in state["ports"]))
        for destination in destinations[:16] if state["transport"] != "udp" else []:
            try:
                with socket.create_connection(destination, timeout=2):
                    print(f"   {address(*destination)} — TCP connection accepted")
            except OSError:
                print(f"   {address(*destination)} — TCP connection failed")
        if len(destinations) > 16:
            print(f"   Checked first 16 of {len(destinations)} destinations.")
        if state["transport"] == "udp":
            print("   UDP readiness requires a protocol-aware application request; a socket connect cannot establish it.")
    print("4. Actual application readiness: NOT VERIFIED. Request the intended application through an Iran forwarded port from its intended caller and check the application response.")
    if state["role"] == "server" and any(p["bind"] == "127.0.0.1" for p in state["ports"]):
        print("   Loopback listeners must be tested from Iran itself (for example, from the panel's outbound).")
    network_instructions(state)
    if not running:
        print("Use Logs to inspect startup errors, then Start after correcting them.")
    if state["transport"] in ("wss", "wssmux"):
        print("WSS warning: upstream clients do not verify TLS server certificates.")


def service_action(action):
    with lifecycle_lock():
        assert_owned_setup()
        ctl(action, SERVICE)
        print(f"Requested {action}. " + ("Process is active; use Doctor and an application test to verify the tunnel." if active() else "Process is not active."))


def uninstall():
    with lifecycle_lock():
        state = assert_owned_setup(allow_empty=True)
        print("This removes only Backhaul Easy's owned configuration, service and unchanged installed files.")
        if ask("Type REMOVE to uninstall") != "REMOVE":
            print("Uninstall cancelled.")
            return
        # Validate all paths and ownership before stopping the service or deleting anything.
        installed = []
        if RECEIPT_PATH.exists():
            receipt = strict_json(read_bytes(RECEIPT_PATH))
            expected = {str(BINARY_PATH), str(MANAGER_PATH), str(LAUNCHER_PATH), str(LIB_DIR / "panel_support.py"), str(LIB_DIR / "bootstrap.py"), str(LIB_DIR / "install.sh")}
            if type(receipt) is not dict or receipt.get("owner") != OWNER or type(receipt.get("files")) is not dict or set(receipt["files"]) != expected:
                raise UserError("The installer receipt has an unexpected owner or file list.")
            for name, digest in receipt["files"].items():
                path = safe_path(Path(name), regular=True)
                if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise UserError("Invalid installer receipt checksum.")
                if path.exists():
                    with path.open("rb") as source:
                        actual = hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(source.read()).hexdigest()
                    if hmac.compare_digest(digest, actual):
                        installed.append(path)
                    else:
                        print(f"Preserving a file changed since installation: {path}")
        else:
            print("No installer receipt found; installed program files will be preserved.")
        if (ETC_DIR / "panel-receipt.json").exists() or state and state["role"] == "client" and state["mode"] == "panel":
            try:
                import panel_support
                panel_support.remove_panel_service()
            except (ImportError, ValueError) as exc:
                raise UserError(f"Cannot safely remove the owned panel egress service: {exc}") from exc
        if state:
            ctl("stop", SERVICE)
            ctl("disable", SERVICE, check=False)
            for path in (CONFIG_PATH, STATE_PATH, CERT_PATH, KEY_PATH, TRAFFIC_PATH, UNIT_PATH):
                safe_path(path, regular=True).unlink(missing_ok=True)
            ctl("daemon-reload")
            ctl("reset-failed", SERVICE, check=False)
        for path in installed:
            path.unlink()
        if RECEIPT_PATH.exists():
            RECEIPT_PATH.unlink()
        for path in (ETC_DIR, LIB_DIR):
            safe_path(path)
            if path.exists():
                try:
                    path.rmdir()
                except OSError:
                    print(f"Preserved non-empty directory: {path}")
        print("Backhaul Easy uninstalled. System packages, firewall rules and network settings were left intact.")


def upgrade():
    require_linux(root=True)
    installer = safe_path(LIB_DIR / "install.sh", regular=True)
    receipt = strict_json(read_bytes(RECEIPT_PATH))
    if type(receipt) is not dict or receipt.get("owner") != OWNER or type(receipt.get("files")) is not dict:
        raise UserError("A valid installer receipt is required for update/repair.")
    expected = receipt["files"].get(str(installer))
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise UserError("The bundled installer is not recorded in the receipt.")
    actual = hashlib.sha256(read_bytes(installer, 16777216)).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise UserError("The bundled installer changed after installation; use a trusted original installer.")
    print("This reinstalls/repairs the bundled pinned release and preserves your settings. A newer release requires its newer installer.")
    if not yes("Run the bundled installer now", False):
        print("Update cancelled.")
        return
    shell = shutil.which("bash", path="/usr/bin:/bin")
    if not shell:
        raise UserError("bash is required to run the bundled installer.")
    result = subprocess.run([shell, str(installer), "--upgrade"], check=False)
    if result.returncode:
        raise UserError(f"Installer exited with code {result.returncode}; inspect its output before retrying.")
    print("Bundled release repaired. Reopen Backhaul Easy to use the installed manager.")


def banner():
    print(color("\n" + "=" * 68, "36"))
    print(color(f"  BACKHAUL EASY  /  {VERSION}", "1;36"))
    print("  Official Backhaul engine | Installation and management by alirezaw")
    print("  GitHub   https://github.com/itsalirezaw")
    print("  YouTube  https://www.youtube.com/@ialirezaw")
    print(color("=" * 68, "36"))


def menu():
    actions = {"1": setup, "2": status, "3": lambda: service_action("start"), "4": lambda: service_action("stop"),
               "5": lambda: service_action("restart"), "6": edit_ports, "7": print_pairing, "8": logs, "9": doctor,
               "10": edit_advanced, "11": uninstall, "12": panel_output, "13": upgrade}
    while True:
        banner()
        print("1) Set up Iran / Outside    2) Status\n3) Start                   4) Stop\n5) Restart                 6) Edit forwarded ports (Iran)\n7) Show pairing code       8) Logs\n9) Doctor                 10) Advanced settings\n11) Uninstall             12) 3x-ui outbound guide\n13) Update / repair        0) Exit")
        choice = ask("Choose", "0")
        if choice == "0":
            return
        if choice not in actions:
            print("Choose a listed number.")
            continue
        try:
            actions[choice]()
        except (UserError, PermissionError, OSError) as exc:
            print(color(f"Error: {exc}", "31"))
        if choice == "11" and not MANAGER_PATH.exists():
            return
        ask("Press Enter to return to the menu", "")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Backhaul Easy by alirezaw — configure Iran first, then Outside.")
    parser.add_argument("command", nargs="?", default="menu", choices=("menu", "setup", "status", "start", "stop", "restart", "ports", "advanced", "pairing", "logs", "doctor", "panel", "upgrade", "uninstall"))
    parser.add_argument("--version", action="version", version=f"Backhaul Easy {VERSION} by alirezaw")
    args = parser.parse_args(argv)
    handlers = {"menu": menu, "setup": setup, "status": status, "ports": edit_ports, "advanced": edit_advanced, "pairing": print_pairing, "logs": logs, "doctor": doctor, "panel": panel_output, "upgrade": upgrade, "uninstall": uninstall}
    try:
        if args.command in ("start", "stop", "restart"):
            service_action(args.command)
        else:
            handlers[args.command]()
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 130
    except (UserError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
