#!/usr/bin/env python3
"""Exercise the pinned Backhaul binary using isolated loopback echo services.

Usage: python3 integration_backhaul.py --binary /verified/path/to/backhaul
The caller verifies the downloaded archive. This test checks its version, starts
only temporary child processes, and performs no installation or service changes.
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


TRANSPORTS = ("tcp", "tcpmux", "udp", "ws", "wss", "wsmux", "wssmux")
LOOPBACK = "127.0.0.1"


class EchoService:
    """Bind TCP and UDP echo listeners to the same temporary loopback port."""

    def __init__(self):
        self.tcp, self.udp = reserve_port_pair()
        self.port = self.tcp.getsockname()[1]
        self.tcp.listen(16)
        self.tcp.settimeout(0.2)
        self.udp.settimeout(0.2)
        self.stopped = threading.Event()
        self.threads = []

    def start(self):
        for target in (self._accept, self._datagrams):
            worker = threading.Thread(target=target, daemon=True)
            worker.start()
            self.threads.append(worker)
        return self

    def _accept(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self._stream, args=(conn,), daemon=True)
            worker.start()
            self.threads.append(worker)

    def _stream(self, conn):
        with conn:
            conn.settimeout(0.2)
            while not self.stopped.is_set():
                try:
                    payload = conn.recv(65536)
                    if not payload:
                        return
                    conn.sendall(payload)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def _datagrams(self):
        while not self.stopped.is_set():
            try:
                payload, sender = self.udp.recvfrom(65535)
                self.udp.sendto(payload, sender)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stopped.set()
        self.tcp.close()
        self.udp.close()
        for worker in self.threads:
            worker.join(timeout=0.5)


def reserve_port_pair():
    """Reserve a high TCP+UDP loopback port without changing socket reuse rules."""
    for _ in range(128):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind((LOOPBACK, 0))
            port = tcp.getsockname()[1]
            if port < 1024:
                tcp.close()
                udp.close()
                continue
            udp.bind((LOOPBACK, port))
            return tcp, udp
        except OSError:
            tcp.close()
            udp.close()
    raise RuntimeError("Could not reserve a free high loopback TCP+UDP port")


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)


def write_config(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def quote(value):
    # JSON string escaping is compatible with the basic strings used here.
    return json.dumps(str(value))


def tcp_roundtrip(port, payload):
    with socket.create_connection((LOOPBACK, port), timeout=1.5) as conn:
        conn.settimeout(1.5)
        conn.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = conn.recv(min(65536, len(payload) - len(received)))
            if not chunk:
                raise OSError("TCP stream closed before the full response")
            received.extend(chunk)
        if bytes(received) != payload:
            raise AssertionError("TCP echo payload differs from the sent bytes")


def udp_roundtrip(port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(1.5)
        conn.connect((LOOPBACK, port))
        conn.send(payload)
        received = conn.recv(65535)
        if received != payload:
            raise AssertionError("UDP echo payload differs from the sent bytes")


def wait_for_roundtrip(kind, port, children, timeout):
    deadline = time.monotonic() + timeout
    last_error = "No reply received"
    # A fresh random challenge ensures a successful connect or a stale packet
    # cannot be mistaken for a working complete forwarding path.
    while time.monotonic() < deadline:
        for label, process in children:
            if process.poll() is not None:
                raise RuntimeError("{} exited with code {}".format(label, process.returncode))
        payload = secrets.token_bytes(131071 if kind == "tcp" else 1200)
        try:
            (tcp_roundtrip if kind == "tcp" else udp_roundtrip)(port, payload)
            return
        except OSError as exc:
            last_error = str(exc)
            time.sleep(0.2)
    raise RuntimeError("{} payload test on {} timed out: {}".format(kind.upper(), port, last_error))


def create_certificate(directory, openssl):
    cert, key = directory / "server.crt", directory / "server.key"
    result = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost"],
        cwd=str(directory), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    if result.returncode:
        raise RuntimeError("OpenSSL could not generate the temporary test certificate: " +
                           result.stderr.decode("utf-8", errors="replace")[-2000:])
    key.chmod(0o600)
    return cert, key


def run_transport(binary, transport, timeout, openssl):
    token = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="backhaul-smoke-{}-".format(transport)) as temp:
        directory = Path(temp)
        children = []
        logs = []
        try:
            with contextlib.ExitStack() as stack:
                # Two separate mappings catch accidental same-port forwarding.
                echoes = []
                for _ in range(2):
                    echo = EchoService()
                    stack.callback(echo.close)
                    echoes.append(echo.start())
                reservations = []
                for _ in range(3):
                    pair = reserve_port_pair()
                    reservations.append(pair)
                    for reserved in pair:
                        stack.callback(reserved.close)
                tunnel_port = reservations[0][0].getsockname()[1]
                public_ports = [pair[0].getsockname()[1] for pair in reservations[1:]]
                common = (
                    "transport = {}\ntoken = {}\nskip_optz = true\n"
                    "sniffer = false\nweb_port = 0\npprof = false\n"
                    "log_level = \"debug\"\nkeepalive_period = 10\nnodelay = true\n"
                ).format(quote(transport), quote(token))
                mappings = ["127.0.0.1:{}=127.0.0.1:{}".format(port, echo.port)
                            for port, echo in zip(public_ports, echoes)]
                server = "[server]\n" + common + (
                    "bind_addr = {}\nheartbeat = 2\nchannel_size = 64\nports = [{}]\n"
                ).format(quote("127.0.0.1:{}".format(tunnel_port)),
                         ", ".join(quote(mapping) for mapping in mappings))
                if transport == "tcp":
                    server += "accept_udp = true\n"
                if transport in ("wss", "wssmux"):
                    cert, key = create_certificate(directory, openssl)
                    server += "tls_cert = {}\ntls_key = {}\n".format(quote(cert), quote(key))
                client = "[client]\n" + common + (
                    "remote_addr = {}\nconnection_pool = 4\nretry_interval = 1\n"
                    "dial_timeout = 3\naggressive_pool = false\n"
                ).format(quote("127.0.0.1:{}".format(tunnel_port)))
                for role, config in (("server", server), ("client", client)):
                    write_config(directory / (role + ".toml"), config)
                # Backhaul must own these listeners; reservations only narrow
                # the normal free-port race and cannot eliminate it entirely.
                for pair in reservations:
                    for reserved in pair:
                        reserved.close()
                for role in ("server", "client"):
                    log_path = directory / (role + ".log")
                    log_handle = stack.enter_context(log_path.open("wb"))
                    logs.append((role, log_path))
                    child = subprocess.Popen(
                        [str(binary), "-c", str(directory / (role + ".toml"))],
                        cwd=str(directory), stdin=subprocess.DEVNULL,
                        stdout=log_handle, stderr=subprocess.STDOUT,
                    )
                    children.append((role, child))
                    stack.callback(stop_process, child)
                kinds = ("udp",) if transport == "udp" else ("tcp", "udp") if transport == "tcp" else ("tcp",)
                for kind in kinds:
                    for port in public_ports:
                        wait_for_roundtrip(kind, port, children, timeout)
                print("PASS {}: two mappings, {} payload round trips".format(
                    transport, "+".join(kind.upper() for kind in kinds)), flush=True)
        except Exception:
            # ExitStack has already stopped our children and closed their logs.
            for role, log_path in logs:
                if log_path.exists():
                    log = log_path.read_text(encoding="utf-8", errors="replace")
                    log = log.replace(token, "<redacted-token>")
                    print("--- {} {} log (last 12000 characters) ---\n{}".format(
                        transport, role, log[-12000:]), file=sys.stderr, flush=True)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path,
                        help="Path to an already downloaded and verified Backhaul binary")
    parser.add_argument("--transports", nargs="+", choices=TRANSPORTS, default=list(TRANSPORTS))
    parser.add_argument("--timeout", type=float, default=25.0,
                        help="Maximum startup/payload retry seconds per mapping (default: 25)")
    parser.add_argument("--expect-version", default="v0.7.2")
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("This integration test requires Linux")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    binary = args.binary.expanduser().resolve()
    if not binary.is_file() or not os.access(str(binary), os.X_OK):
        parser.error("--binary must name an executable file")
    openssl = shutil.which("openssl")
    if any(mode in ("wss", "wssmux") for mode in args.transports) and not openssl:
        parser.error("openssl is required to test WSS transports")
    version = subprocess.run([str(binary), "-v"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=5, check=True,
                             universal_newlines=True).stdout.strip()
    if version != args.expect_version:
        parser.error("Binary version {} differs from expected {}".format(version, args.expect_version))
    print("Testing Backhaul {} using temporary loopback processes".format(version), flush=True)
    failures = []
    for transport in dict.fromkeys(args.transports):
        try:
            run_transport(binary, transport, args.timeout, openssl)
        except Exception as exc:
            failures.append(transport)
            print("FAIL {}: {}".format(transport, exc), file=sys.stderr, flush=True)
    if failures:
        print("Failed transports: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All requested transport payload tests passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted; test child processes were stopped.", file=sys.stderr)
        sys.exit(130)
