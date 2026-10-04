"""Dedicated, receipt-owned outside VLESS egress for Backhaul Easy.

No existing panel configuration, Xray installation, or network rules are edited.
All mutation entry points require root and a validated outside panel state.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile

XRAY_VERSION = "26.3.27"
ASSETS = {
    "x86_64": ("Xray-linux-64.zip", "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"),
    "aarch64": ("Xray-linux-arm64-v8a.zip", "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"),
}
OWNER = "backhaul-easy-panel"
ETC_DIR = Path("/etc/backhaul-easy")
LIB_DIR = Path("/usr/local/lib/backhaul-easy")
XRAY_PATH = LIB_DIR / "xray"
CONFIG_PATH = ETC_DIR / "xray.json"
RECEIPT_PATH = ETC_DIR / "panel-receipt.json"
STATE_PATH = ETC_DIR / "state.json"
UNIT_PATH = Path("/etc/systemd/system/backhaul-easy-egress.service")
SERVICE = "backhaul-easy-egress.service"
MARKER = "# Managed by backhaul-easy-panel"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


class PanelError(ValueError):
    """Safe-to-display error that never includes credentials or config contents."""


def _state(state, role):
    if type(state) is not dict or state.get("mode") != "panel" or state.get("role") != role:
        raise PanelError("This action requires {} panel mode.".format("Outside" if role == "client" else "Iran"))
    if state.get("transport") not in ("tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux"):
        raise PanelError("Panel egress requires a Backhaul transport that carries TCP.")
    try:
        identifier = str(uuid.UUID(state["proxy_uuid"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise PanelError("Panel mode requires a valid proxy UUID.") from None
    ports = state.get("ports")
    if type(ports) is not list or len(ports) != 1 or type(ports[0]) is not dict:
        raise PanelError("Panel mode requires exactly one loopback port mapping.")
    mapping = ports[0]
    if mapping.get("bind") != "127.0.0.1" or mapping.get("target") != "127.0.0.1":
        raise PanelError("Panel proxy listeners and destinations must use 127.0.0.1.")
    for key in ("public", "local"):
        if type(mapping.get(key)) is not int or not 1 <= mapping[key] <= 65535:
            raise PanelError("Panel proxy ports must be integers from 1 to 65535.")
    return identifier, mapping


def render_xray_config(state):
    identifier, mapping = _state(state, "client")
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [{"tag": "backhaul-egress-in", "listen": "127.0.0.1", "port": mapping["local"],
                      "protocol": "vless", "settings": {"clients": [{"id": identifier}], "decryption": "none"},
                      "streamSettings": {"network": "tcp", "security": "none"}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv4"}}],
    }


def panel_outbound(state):
    identifier, mapping = _state(state, "server")
    return {"tag": "backhaul-out", "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": mapping["public"],
                                     "users": [{"id": identifier, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"}}


def _root():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise PanelError("Panel service management requires root on Linux.")


def _secure(path, directory=False, missing=False):
    path = Path(path)
    for ancestor in reversed((path,) + tuple(path.parents)):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            if missing and ancestor == path:
                return False
            raise PanelError("A required managed parent directory is missing.") from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PanelError("Managed paths must be root-owned, without symlinks or writable parent directories.")
        if ancestor != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise PanelError("A managed directory path is not a directory.")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PanelError("Managed files must be ordinary files without hard links.")
    return True


def _directories():
    for path in (ETC_DIR, LIB_DIR):
        if not _secure(path, directory=True, missing=True):
            path.mkdir(mode=0o700)
    _secure(UNIT_PATH.parent, directory=True)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _atomic(path, data, mode):
    _secure(path.parent, directory=True)
    _secure(path, missing=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".panel-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _run(arguments, check=True, timeout=30):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise PanelError("A panel service command could not complete.") from None
    if check and result.returncode:
        raise PanelError("A panel service command failed; configuration and credentials were not printed.")
    return result


def _systemctl(*args, check=True):
    return _run(["systemctl", *args], check=check)


def _receipt():
    expected = {str(XRAY_PATH), str(CONFIG_PATH), str(UNIT_PATH)}
    receipt = None
    if _secure(RECEIPT_PATH, missing=True):
        if RECEIPT_PATH.stat().st_size > 16384:
            raise PanelError("The panel ownership receipt is too large.")
        try:
            receipt = json.loads(RECEIPT_PATH.read_bytes())
        except (ValueError, UnicodeError):
            raise PanelError("The panel ownership receipt is invalid.") from None
        if (type(receipt) is not dict or set(receipt) != {"owner", "schema", "version", "files"}
                or receipt.get("owner") != OWNER or receipt.get("schema") != 1
                or type(receipt.get("files")) is not dict
                or set(receipt["files"]) not in ({str(XRAY_PATH)}, expected)):
            raise PanelError("The panel ownership receipt has unexpected fields.")
    owned = receipt["files"] if receipt else {}
    for path in (XRAY_PATH, CONFIG_PATH, UNIT_PATH):
        exists = _secure(path, missing=True)
        if exists and str(path) not in owned:
            raise PanelError("An unowned file occupies a dedicated panel service path.")
        if str(path) in owned:
            digest = owned[str(path)]
            if (not exists or not isinstance(digest, str) or len(digest) != 64
                    or _sha(path.read_bytes()) != digest):
                raise PanelError("A managed panel file has changed or is missing; refusing to overwrite it.")
    return receipt


def _service_guard(receipt):
    fragment = _systemctl("show", SERVICE, "-p", "FragmentPath", "--value", check=False).stdout.decode().strip()
    dropins = _systemctl("show", SERVICE, "-p", "DropInPaths", "--value", check=False).stdout.decode().strip()
    if dropins or (fragment and (fragment != str(UNIT_PATH) or not receipt or str(UNIT_PATH) not in receipt["files"])):
        raise PanelError("An unowned service or override occupies the dedicated panel service name.")


def _download_binary():
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if machine not in ASSETS:
        raise PanelError("The panel helper supports Linux amd64 and arm64.")
    name, digest = ASSETS[machine]
    url = "https://github.com/XTLS/Xray-core/releases/download/v{}/{}".format(XRAY_VERSION, name)
    request = urllib.request.Request(url, headers={"User-Agent": "backhaul-easy/0.1"})
    try:
        with tempfile.TemporaryFile() as archive:
            with urllib.request.urlopen(request, timeout=45) as response:
                if not response.geturl().startswith("https://"):
                    raise PanelError("The Xray download redirected to an insecure address.")
                length, hasher = 0, hashlib.sha256()
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > MAX_ARCHIVE:
                        raise PanelError("The Xray archive exceeds the allowed download size.")
                    hasher.update(chunk)
                    archive.write(chunk)
            if hasher.hexdigest() != digest:
                raise PanelError("The Xray archive does not match its pinned SHA-256 checksum.")
            archive.seek(0)
            with zipfile.ZipFile(archive) as bundle:
                members = [member for member in bundle.infolist() if member.filename == "xray"]
                if len(members) != 1:
                    raise PanelError("The Xray archive must contain exactly one xray executable.")
                member = members[0]
                filetype = stat.S_IFMT(member.external_attr >> 16)
                if (member.is_dir() or filetype not in (0, stat.S_IFREG)
                        or member.file_size > MAX_BINARY or member.file_size < 4):
                    raise PanelError("The Xray executable archive member is invalid.")
                # Never extractall: only the verified exact member becomes bytes.
                binary = bundle.read(member)
                if not binary.startswith(b"\x7fELF"):
                    raise PanelError("The Xray archive member is not a Linux executable.")
                return binary
    except PanelError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile):
        raise PanelError("The pinned Xray archive could not be downloaded or read.") from None


def _unit():
    return (MARKER + "\n" + """[Unit]
Description=Backhaul Easy dedicated outside egress
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/lib/backhaul-easy/xray run -config /etc/backhaul-easy/xray.json
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
""").encode("utf-8")


def _snapshot(paths):
    result = {}
    for path in paths:
        if _secure(path, missing=True):
            result[path] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        else:
            result[path] = None
    return result


class PanelTransaction:
    def __init__(self, state, previous, desired, active, enabled, operation="install"):
        self.state = state
        self.previous = previous
        self.desired = desired
        self.active = active
        self.enabled = enabled
        self.operation = operation
        self.changed = False
        self.rolled_back = False


def prepare_panel(state):
    """Validate and stage panel files; return an opaque rollback-capable token."""
    _state(state, "client")
    _root()
    _directories()
    receipt = _receipt()
    _service_guard(receipt)
    previous = _snapshot((XRAY_PATH, CONFIG_PATH, UNIT_PATH, RECEIPT_PATH))
    binary = previous[XRAY_PATH][0] if receipt and receipt.get("version") == XRAY_VERSION else _download_binary()
    config = _json(render_xray_config(state))
    with tempfile.TemporaryDirectory(prefix=".panel-validate-", dir=str(ETC_DIR)) as temporary:
        binary_path, config_path = Path(temporary) / "xray", Path(temporary) / "config.json"
        binary_path.write_bytes(binary)
        binary_path.chmod(0o700)
        config_path.write_bytes(config)
        config_path.chmod(0o600)
        version = _run([str(binary_path), "version"]).stdout.decode("utf-8", errors="replace").splitlines()
        if not version or not version[0].startswith("Xray " + XRAY_VERSION + " "):
            raise PanelError("The dedicated Xray executable has an unexpected version.")
        _run([str(binary_path), "run", "-test", "-config", str(config_path)])
    desired = {XRAY_PATH: (binary, 0o755), CONFIG_PATH: (config, 0o600), UNIT_PATH: (_unit(), 0o644)}
    ownership = {"owner": OWNER, "schema": 1, "version": XRAY_VERSION,
                 "files": {str(path): _sha(contents[0]) for path, contents in desired.items()}}
    desired[RECEIPT_PATH] = (_json(ownership), 0o600)
    active = _systemctl("is-active", "--quiet", SERVICE, check=False).returncode == 0
    enabled = _systemctl("is-enabled", "--quiet", SERVICE, check=False).returncode == 0
    return PanelTransaction(json.loads(json.dumps(state)), previous, desired, active, enabled)


def _unchanged(transaction):
    for path, old in transaction.previous.items():
        current = path.read_bytes() if _secure(path, missing=True) else None
        desired = transaction.desired[path]
        permitted = {old[0] if old else None, desired[0] if desired else None}
        if current not in permitted:
            raise PanelError("A panel file changed during installation; refusing to overwrite it.")


def rollback_panel(transaction):
    """Restore only the snapshots belonging to a previously prepared transaction."""
    _root()
    if not isinstance(transaction, PanelTransaction):
        raise PanelError("Invalid panel rollback token.")
    if not transaction.changed or transaction.rolled_back:
        return
    _unchanged(transaction)
    _systemctl("stop", SERVICE, check=False)
    _systemctl("disable", SERVICE, check=False)
    for path, previous in transaction.previous.items():
        if previous is None:
            if _secure(path, missing=True):
                path.unlink()
        else:
            _atomic(path, previous[0], previous[1])
    _systemctl("daemon-reload")
    if transaction.enabled:
        _systemctl("enable", SERVICE)
    if transaction.active:
        _systemctl("start", SERVICE)
    transaction.rolled_back = True


def _receive(stream, size):
    output = bytearray()
    while len(output) < size:
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise OSError("Proxy closed the connection")
        output.extend(chunk)
    return bytes(output)


def _proxy_roundtrip(port, identifier, udp=False):
    """Prove UUID authentication and actual TCP/UDP forwarding through Xray."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as echo:
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(3)
        if not udp:
            echo.listen(1)
        destination = echo.getsockname()[1]
        payload = secrets.token_bytes(96)

        def respond():
            try:
                if udp:
                    data, source = echo.recvfrom(4096)
                    echo.sendto(data, source)
                else:
                    connection, _ = echo.accept()
                    with connection:
                        connection.settimeout(3)
                        connection.sendall(_receive(connection, len(payload)))
            except OSError:
                pass

        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as proxy:
                proxy.settimeout(3)
                header = b"\x00" + uuid.UUID(identifier).bytes + b"\x00" + bytes([2 if udp else 1])
                header += struct.pack("!H", destination) + b"\x01\x7f\x00\x00\x01"
                proxy.sendall(header + (struct.pack("!H", len(payload)) if udp else b"") + payload)
                version, addon_length = _receive(proxy, 2)
                if version != 0:
                    raise OSError("Unexpected VLESS response version")
                _receive(proxy, addon_length)
                size = struct.unpack("!H", _receive(proxy, 2))[0] if udp else len(payload)
                if size != len(payload) or _receive(proxy, size) != payload:
                    raise OSError("Proxy payload validation failed")
        finally:
            worker.join(timeout=3.2)


def verify_panel_payload(state, timeout=12):
    """Local helper readiness only; this does not claim the Iran tunnel is ready."""
    identifier, mapping = _state(state, "client")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _proxy_roundtrip(mapping["local"], identifier)
            _proxy_roundtrip(mapping["local"], identifier, udp=True)
            return True
        except OSError:
            time.sleep(0.25)
    raise PanelError("Dedicated outside proxy failed its local TCP/UDP payload checks.")


def apply_panel(transaction):
    _root()
    if not isinstance(transaction, PanelTransaction) or transaction.rolled_back or transaction.operation != "install":
        raise PanelError("Invalid panel installation token.")
    _state(transaction.state, "client")
    _unchanged(transaction)
    _service_guard(_receipt())
    try:
        transaction.changed = True
        for path, contents in transaction.desired.items():
            _atomic(path, contents[0], contents[1])
        _systemctl("daemon-reload")
        _systemctl("enable", SERVICE)
        _systemctl("restart", SERVICE)
        verify_panel_payload(transaction.state)
    except (Exception, KeyboardInterrupt) as original:
        try:
            rollback_panel(transaction)
        except Exception:
            raise PanelError("Panel installation failed and rollback needs manual attention; credentials were not printed.") from None
        if isinstance(original, KeyboardInterrupt):
            raise
        raise PanelError("Panel installation failed; previous dedicated panel files and service state were restored.") from None
    return transaction


def install_panel_service(state):
    return apply_panel(prepare_panel(state))


def ensure_xray():
    """Ensure the binary for an already configured Outside panel; do not start it."""
    _root()
    _secure(STATE_PATH)
    try:
        state = json.loads(STATE_PATH.read_bytes())
    except (ValueError, UnicodeError):
        raise PanelError("Existing panel settings are invalid.") from None
    _state(state, "client")
    _directories()
    receipt = _receipt()
    _service_guard(receipt)
    if receipt and receipt.get("version") == XRAY_VERSION:
        return XRAY_PATH
    binary = _download_binary()
    previous = _snapshot((XRAY_PATH, RECEIPT_PATH))
    files = dict(receipt["files"]) if receipt else {}
    files[str(XRAY_PATH)] = _sha(binary)
    desired_receipt = _json({"owner": OWNER, "schema": 1, "version": XRAY_VERSION, "files": files})
    try:
        _atomic(XRAY_PATH, binary, 0o755)
        _atomic(RECEIPT_PATH, desired_receipt, 0o600)
    except (Exception, KeyboardInterrupt):
        for path, old in previous.items():
            if old is None:
                if _secure(path, missing=True):
                    path.unlink()
            else:
                _atomic(path, old[0], old[1])
        raise
    return XRAY_PATH


def remove_panel_service():
    """Remove an owned helper, restoring it if removal cannot finish."""
    transaction = prepare_panel_removal()
    if transaction is None:
        return False
    apply_panel_removal(transaction)
    return True


def prepare_panel_removal():
    """Preflight ownership and snapshot the helper without stopping or deleting it."""
    _root()
    if not ETC_DIR.exists():
        return None
    _secure(ETC_DIR, directory=True)
    if not _secure(RECEIPT_PATH, missing=True):
        _service_guard(None)
        return None
    receipt = _receipt()
    _service_guard(receipt)
    previous = _snapshot((XRAY_PATH, CONFIG_PATH, UNIT_PATH, RECEIPT_PATH))
    desired = {path: None for path in previous}
    active = _systemctl("is-active", "--quiet", SERVICE, check=False).returncode == 0
    enabled = _systemctl("is-enabled", "--quiet", SERVICE, check=False).returncode == 0
    return PanelTransaction(None, previous, desired, active, enabled, operation="remove")


def apply_panel_removal(transaction):
    """Remove the snapshotted helper; retain its token for enclosing rollback."""
    _root()
    if not isinstance(transaction, PanelTransaction) or transaction.rolled_back or transaction.operation != "remove":
        raise PanelError("Invalid panel removal token.")
    _unchanged(transaction)
    _service_guard(_receipt())
    try:
        transaction.changed = True
        if transaction.previous[UNIT_PATH] is not None:
            _systemctl("stop", SERVICE)
            _systemctl("disable", SERVICE)
        for path in transaction.desired:
            if _secure(path, missing=True):
                path.unlink()
        _systemctl("daemon-reload")
    except (Exception, KeyboardInterrupt) as original:
        try:
            rollback_panel(transaction)
        except Exception:
            raise PanelError("Panel removal failed and rollback needs manual attention; credentials were not printed.") from None
        if isinstance(original, KeyboardInterrupt):
            raise
        raise PanelError("Panel removal failed; previous dedicated panel files and service state were restored.") from None
    return transaction
