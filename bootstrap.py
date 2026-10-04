#!/usr/bin/env python3
"""Install the bundled manager and a verified official Backhaul release."""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

OWNER = "backhaul-easy"
VERSION = "1.0.0"
BACKHAUL_VERSION = "v0.7.2"
HASHES = {
    "x86_64": ("amd64", "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc"),
    "aarch64": ("arm64", "9a424c97ff16fc3f682e8314c418790d2b5bf3136e008edbb6cd402ea00999f6"),
}
LIB = Path("/usr/local/lib/backhaul-easy")
RECEIPT = LIB / "install.json"
WRAPPER = Path("/usr/local/sbin/backhaul-easy")
LOCK = Path("/run/lock/backhaul-easy.lock")
SOURCES = ("backhaul_easy.py", "panel_support.py", "bootstrap.py")
ALLOWED = {LIB / p for p in (*SOURCES, "backhaul", "install.sh")} | {WRAPPER}


def check_path(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f"Refusing symbolic link: {part}")
        if part.exists() and part.stat().st_uid != 0:
            raise ValueError(f"Expected root ownership: {part}")
        if part.exists() and part.is_dir() and part.stat().st_mode & 0o022:
            if not (path == LOCK and part == LOCK.parent):
                raise ValueError(f"Refusing a group/world-writable installation directory: {part}")
    if path.exists() and not path.is_file():
        raise ValueError(f"Expected a regular file: {path}")
    return path


def atomic_write(path, data, mode):
    check_path(path)
    fd, temporary = tempfile.mkstemp(prefix=".install-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def fetch_binary():
    if platform.machine() not in HASHES:
        raise ValueError("Supported architectures: Linux amd64 and arm64.")
    arch, expected = HASHES[platform.machine()]
    url = f"https://github.com/Musixal/Backhaul/releases/download/{BACKHAUL_VERSION}/backhaul_linux_{arch}.tar.gz"
    data = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "backhaul-easy/1.0"})
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.url.split(":", 1)[0] != "https":
                    raise ValueError("Download redirect must use HTTPS.")
                data = response.read(100 * 1024 * 1024 + 1)
            break
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Official Backhaul archive SHA-256 verification failed.")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.name in ("backhaul", "./backhaul")]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 80 * 1024 * 1024:
            raise ValueError("Unexpected executable in the official archive.")
        binary = archive.extractfile(members[0]).read()
    with tempfile.TemporaryDirectory(prefix="backhaul-verify-") as folder:
        probe = Path(folder) / "backhaul"
        probe.write_bytes(binary)
        probe.chmod(0o700)
        result = subprocess.run([str(probe), "-v"], capture_output=True, timeout=10, check=True)
        if BACKHAUL_VERSION.encode() not in result.stdout + result.stderr:
            raise ValueError("Unexpected Backhaul executable version.")
    return binary


def service_active(name):
    return subprocess.run(["systemctl", "is-active", "--quiet", name], capture_output=True).returncode == 0


def verify_receipt():
    check_path(RECEIPT)
    if not RECEIPT.exists():
        if LIB.exists() and any(LIB.iterdir()):
            raise ValueError(f"Unrecognized existing installation at {LIB}; preserved.")
        for path in ALLOWED:
            if path.exists():
                raise ValueError(f"Existing unowned file preserved: {path}")
        return None
    if RECEIPT.stat().st_size > 65536:
        raise ValueError("Invalid installation receipt.")
    receipt = json.loads(RECEIPT.read_text())
    if type(receipt) is not dict or receipt.get("owner") != OWNER or type(receipt.get("files")) is not dict:
        raise ValueError("Invalid installation receipt.")
    for raw_path, expected in receipt["files"].items():
        path = Path(raw_path)
        if path not in ALLOWED:
            raise ValueError("Receipt contains an unexpected path.")
        check_path(path)
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Locally modified file preserved: {path}. Back it up and resolve the change before upgrading.")
    for path in ALLOWED:
        check_path(path)
        if path.exists() and str(path) not in receipt["files"]:
            raise ValueError(f"Unowned file preserved: {path}")
    return receipt


def reconstruct_installer(source, bundle):
    encoded = bundle.read_text().strip()
    base64.b64decode(encoded, validate=True)
    return (source.joinpath("install-header.sh").read_text() + "\nBUNDLE='" + encoded + "'\n" + source.joinpath("install-footer.sh").read_text()).encode()


def install(source, bundle, upgrade=False, check=False):
    for name in SOURCES:
        compile((source / name).read_bytes(), name, "exec")
    binary = fetch_binary()
    print(f"Official Backhaul {BACKHAUL_VERSION}: checksum and executable verified.")
    if check:
        print("Installer check passed; nothing installed.")
        return
    if os.geteuid() != 0:
        raise ValueError("Run the installer as root.")
    import fcntl
    check_path(LOCK)
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise ValueError("Unsafe lifecycle lock file.")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = verify_receipt()
        if receipt and not upgrade:
            print("Already installed. Opening the existing menu. Use a newer installer with --upgrade to update.")
            return
        spec = importlib.util.spec_from_file_location("new_manager", source / "backhaul_easy.py")
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
        manager.assert_owned_setup(allow_empty=True)
        files = {LIB / name: ((source / name).read_bytes(), 0o644) for name in SOURCES}
        files[LIB / "backhaul"] = (binary, 0o755)
        files[LIB / "install.sh"] = (reconstruct_installer(source, bundle), 0o700)
        files[WRAPPER] = (b'#!/bin/sh\nexec /usr/bin/python3 -B /usr/local/lib/backhaul-easy/backhaul_easy.py "$@"\n', 0o755)
        manifest = {"owner": OWNER, "version": VERSION, "backhaul_version": BACKHAUL_VERSION,
                    "files": {str(p): hashlib.sha256(data).hexdigest() for p, (data, _) in files.items()}}
        files[RECEIPT] = ((json.dumps(manifest, indent=2) + "\n").encode(), 0o600)
        for directory in (LIB, WRAPPER.parent):
            if directory.is_symlink():
                raise ValueError(f"Refusing symbolic link: {directory}")
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        backups = {p: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) if p.exists() else None for p in files}
        running = [name for name in ("backhaul-easy.service", "backhaul-easy-egress.service") if service_active(name)]
        try:
            for path, (data, mode) in files.items():
                atomic_write(path, data, mode)
            # The tunnel binary changes only in our own named service.
            if "backhaul-easy.service" in running:
                subprocess.run(["systemctl", "restart", "backhaul-easy.service"], check=True, timeout=40)
                time.sleep(2)
                if not service_active("backhaul-easy.service"):
                    raise ValueError("Updated service failed to remain active.")
        except (Exception, KeyboardInterrupt):
            for path, backup in backups.items():
                if backup is None:
                    check_path(path).unlink(missing_ok=True)
                else:
                    atomic_write(path, *backup)
            if "backhaul-easy.service" in running:
                subprocess.run(["systemctl", "restart", "backhaul-easy.service"], timeout=40, check=False)
            raise
    print(f"Backhaul Easy {VERSION} installed. Open the menu with: backhaul-easy")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--upgrade", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--no-menu", action="store_true")
    args = parser.parse_args()
    try:
        install(args.source, args.bundle, args.upgrade, args.check)
        if not args.check and not args.upgrade and not args.no_menu:
            os.execv(str(WRAPPER), [str(WRAPPER)])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Installation stopped: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Installation cancelled; any started file transaction was rolled back.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
