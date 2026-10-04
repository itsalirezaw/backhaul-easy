"""Offline installer tests; downloaded bytes and all process calls are mocked."""

import base64
import ast
import contextlib
import hashlib
import io
import json
import importlib.util
from pathlib import Path
import sys
import re
import runpy
import shlex
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap as installer


def archive_bytes(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            member.linkname = "../../outside"
            archive.addfile(member, io.BytesIO(content) if member.size else None)
    return result.getvalue()


class ArchiveVerificationTests(unittest.TestCase):
    def fetch(self, data, digest=None, response_url="https://release-assets.githubusercontent.com/example", version=None):
        digest = digest or hashlib.sha256(data).hexdigest()
        response = io.BytesIO(data)
        response.url = response_url
        result = SimpleNamespace(returncode=0, stdout=version or installer.BACKHAUL_VERSION.encode(), stderr=b"")
        with mock.patch.object(installer.platform, "machine", return_value="x86_64"), \
                mock.patch.dict(installer.HASHES, {"x86_64": ("amd64", digest)}), \
                mock.patch.object(installer.urllib.request, "urlopen", return_value=response), \
                mock.patch.object(installer.subprocess, "run", return_value=result) as run:
            self.probe = run
            return installer.fetch_binary()

    def test_verified_archive_returns_only_exact_binary_member(self):
        binary = b"\x7fELFverified test fixture; never executed"
        archive = archive_bytes([
            ("../../should-not-be-extracted", b"bad", tarfile.REGTYPE),
            ("backhaul", binary, tarfile.REGTYPE),
            ("README.md", b"docs", tarfile.REGTYPE),
        ])
        self.assertEqual(self.fetch(archive), binary)
        self.assertEqual(self.probe.call_count, 1)
        self.assertEqual(self.probe.call_args.args[0][-1], "-v")

    def test_corrupted_download_is_rejected_before_any_executable_is_run(self):
        archive = archive_bytes([("backhaul", b"\x7fELFtest", tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            self.fetch(archive, digest="0" * 64)
        self.probe.assert_not_called()

    def test_insecure_redirect_is_rejected_before_any_executable_is_run(self):
        archive = archive_bytes([("backhaul", b"\x7fELFtest", tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            self.fetch(archive, response_url="http://example.test/file")
        self.probe.assert_not_called()

    def test_archive_requires_one_regular_binary_not_a_link_or_ambiguous_duplicate(self):
        for entries in (
            [("backhaul", b"", tarfile.SYMTYPE)],
            [("backhaul", b"", tarfile.LNKTYPE)],
            [("backhaul", b"a", tarfile.REGTYPE), ("./backhaul", b"b", tarfile.REGTYPE)],
            [("nested/backhaul", b"a", tarfile.REGTYPE)],
            [("../backhaul", b"a", tarfile.REGTYPE)],
        ):
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    self.fetch(archive_bytes(entries))
                self.probe.assert_not_called()

    def test_wrong_executable_version_is_rejected(self):
        archive = archive_bytes([("backhaul", b"\x7fELFtest", tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            self.fetch(archive, version=b"Backhaul v0.0.0")


class InstallerFilesFixture(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.lib = self.root / "lib"
        self.lib.mkdir()
        self.wrapper = self.root / "bin" / "backhaul-easy"
        self.wrapper.parent.mkdir()
        self.receipt = self.lib / "install.json"
        self.allowed = {self.lib / name for name in (*installer.SOURCES, "backhaul", "install.sh")} | {self.wrapper}
        for name, value in {"LIB": self.lib, "WRAPPER": self.wrapper, "RECEIPT": self.receipt, "ALLOWED": self.allowed, "LOCK": self.root / "lock"}.items():
            self.stack.enter_context(mock.patch.object(installer, name, value))
        # Isolate Unix UID/symlink behavior from archive and ownership-receipt
        # semantics on Windows; check_path itself is tested separately.
        self.stack.enter_context(mock.patch.object(installer, "check_path", side_effect=lambda path: path))

    def seed_receipt(self):
        for path in self.allowed:
            path.write_bytes(("owned old bytes:" + path.name).encode())
        receipt = {
            "owner": "backhaul-easy", "version": installer.VERSION,
            "backhaul_version": installer.BACKHAUL_VERSION,
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in self.allowed},
        }
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
        return receipt


class ReceiptOwnershipTests(InstallerFilesFixture):
    def test_matching_owned_installation_can_be_recognized(self):
        receipt = self.seed_receipt()
        self.assertEqual(installer.verify_receipt(), receipt)

    def test_modified_owned_file_is_preserved(self):
        self.seed_receipt()
        path = self.lib / "backhaul_easy.py"
        path.write_bytes(b"local user modifications")
        with self.assertRaises(ValueError):
            installer.verify_receipt()
        self.assertEqual(path.read_bytes(), b"local user modifications")

    def test_unowned_existing_wrapper_or_library_file_is_preserved(self):
        for path in (self.wrapper, self.lib / "unknown.txt"):
            with self.subTest(path=path):
                path.write_bytes(b"unrelated content")
                with self.assertRaises(ValueError):
                    installer.verify_receipt()
                self.assertEqual(path.read_bytes(), b"unrelated content")
                path.unlink()

    def test_receipt_cannot_claim_an_unrelated_path(self):
        receipt = self.seed_receipt()
        unrelated = self.root / "important.txt"
        unrelated.write_bytes(b"do not touch")
        receipt["files"][str(unrelated)] = hashlib.sha256(unrelated.read_bytes()).hexdigest()
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaises(ValueError):
            installer.verify_receipt()
        self.assertEqual(unrelated.read_bytes(), b"do not touch")

    def test_nonobject_or_wrong_owner_receipt_has_a_controlled_error(self):
        for receipt in ([], None, "string", {"owner": "foreign", "files": {}}, {"owner": "backhaul-easy", "files": []}):
            with self.subTest(receipt=receipt):
                self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
                with self.assertRaises(ValueError):
                    installer.verify_receipt()


class BootstrapRollbackTests(InstallerFilesFixture):
    def source_fixture(self):
        source = self.root / "source"
        source.mkdir()
        for name in installer.SOURCES:
            source.joinpath(name).write_text("# syntax-valid bundled source fixture\n", encoding="utf-8")
        source.joinpath("backhaul_easy.py").write_text("def assert_owned_setup(allow_empty=False):\n    return None\n", encoding="utf-8")
        source.joinpath("install-header.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        source.joinpath("install-footer.sh").write_text("exit 0\n", encoding="utf-8")
        bundle = self.root / "bundle"
        bundle.write_text(base64.b64encode(b"inert test fixture").decode(), encoding="ascii")
        return source, bundle

    def prepare_install(self):
        self.stack.enter_context(mock.patch.object(installer, "fetch_binary", return_value=b"new binary fixture; never executed"))
        self.stack.enter_context(mock.patch.object(installer.os, "geteuid", return_value=0, create=True))
        self.stack.enter_context(mock.patch.object(installer.os, "O_NOFOLLOW", getattr(installer.os, "O_NOFOLLOW", 0), create=True))
        self.stack.enter_context(mock.patch.object(installer.os, "fchmod", create=True))
        self.stack.enter_context(mock.patch.object(installer.time, "sleep"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(mock.patch.dict(sys.modules, {"fcntl": SimpleNamespace(flock=mock.Mock(), LOCK_EX=2, LOCK_NB=4)}))
        return self.source_fixture()

    def test_failed_upgrade_restores_every_file_and_receipt_byte_for_byte(self):
        self.seed_receipt()
        watched = self.allowed | {self.receipt}
        before = {path: path.read_bytes() for path in watched}
        source, bundle = self.prepare_install()
        def atomic(path, data, mode):
            path.write_bytes(data)
        self.stack.enter_context(mock.patch.object(installer, "atomic_write", side_effect=atomic))
        self.stack.enter_context(mock.patch.object(installer, "service_active", side_effect=lambda name: name == "backhaul-easy.service"))
        failure = installer.subprocess.CalledProcessError(1, ["systemctl", "restart"])
        run = self.stack.enter_context(mock.patch.object(installer.subprocess, "run", side_effect=[failure, SimpleNamespace(returncode=0)]))
        with self.assertRaises(installer.subprocess.CalledProcessError):
            installer.install(source, bundle, upgrade=True)
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call.args[0] == ["systemctl", "restart", "backhaul-easy.service"] for call in run.call_args_list))

    def test_check_mode_does_not_write_files_acquire_lock_or_manage_services(self):
        source, bundle = self.prepare_install()
        with mock.patch.object(installer, "atomic_write") as write, mock.patch.object(installer, "service_active") as service, mock.patch.object(installer, "verify_receipt") as receipt:
            installer.install(source, bundle, check=True)
        write.assert_not_called()
        service.assert_not_called()
        receipt.assert_not_called()
        self.assertFalse(installer.LOCK.exists())

    def test_keyboard_interrupt_during_upgrade_restores_every_file_and_receipt(self):
        self.seed_receipt()
        watched = self.allowed | {self.receipt}
        before = {path: path.read_bytes() for path in watched}
        source, bundle = self.prepare_install()
        writes = 0
        def interrupted_write(path, data, mode):
            nonlocal writes
            writes += 1
            if writes == 3:
                raise KeyboardInterrupt
            path.write_bytes(data)
        self.stack.enter_context(mock.patch.object(installer, "atomic_write", side_effect=interrupted_write))
        self.stack.enter_context(mock.patch.object(installer, "service_active", side_effect=lambda name: name == "backhaul-easy.service"))
        run = self.stack.enter_context(mock.patch.object(installer.subprocess, "run", return_value=SimpleNamespace(returncode=0)))
        with self.assertRaises(KeyboardInterrupt):
            installer.install(source, bundle, upgrade=True)
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        run.assert_called_once_with(["systemctl", "restart", "backhaul-easy.service"], timeout=40, check=False)

    def test_installed_wrapper_disables_bytecode_for_imported_local_helpers(self):
        source, bundle = self.prepare_install()
        source.joinpath("backhaul_easy.py").write_text(
            "def assert_owned_setup(allow_empty=False):\n    return None\n"
            "if __name__ == '__main__':\n"
            "    import panel_support\n"
            "    import sys\n"
            "    print(sys.dont_write_bytecode)\n",
            encoding="utf-8",
        )
        self.stack.enter_context(mock.patch.object(installer, "atomic_write", side_effect=lambda path, data, mode: path.write_bytes(data)))
        self.stack.enter_context(mock.patch.object(installer, "service_active", return_value=False))
        installer.install(source, bundle)
        # Execute the installed wrapper's Python invocation with platform paths
        # relocated into this disposable directory; no shell/service is run.
        lines = self.wrapper.read_text(encoding="utf-8").splitlines()
        command = shlex.split(lines[1])
        self.assertEqual(command, ["exec", "/usr/bin/python3", "-B", "/usr/local/lib/backhaul-easy/backhaul_easy.py", "$@"])
        result = installer.subprocess.run(
            [sys.executable, *command[2:3], str(self.lib / "backhaul_easy.py")],
            capture_output=True, text=True, check=True, timeout=10,
        )
        self.assertEqual(result.stdout.strip(), "True")
        self.assertFalse(list(self.lib.rglob("__pycache__")))
        self.assertFalse(list(self.lib.rglob("*.pyc")))


class StandaloneBundleTests(unittest.TestCase):
    def test_standalone_build_is_deterministic_and_embeds_current_python310_compatible_sources(self):
        project = Path(__file__).resolve().parents[1]
        names = {"bootstrap.py", "backhaul_easy.py", "panel_support.py", "install-header.sh", "install-footer.sh"}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "tools").mkdir()
            for name in names | {"tools/build_installer.py"}:
                root.joinpath(name).write_bytes(project.joinpath(name).read_bytes())
            builder = root / "tools" / "build_installer.py"
            with contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(builder))
                first = root.joinpath("install.sh").read_bytes()
                runpy.run_path(str(builder))
                second = root.joinpath("install.sh").read_bytes()
            self.assertEqual(first, second)
            self.assertNotIn(b"\r\n", first)
            match = re.search(rb"\nBUNDLE='([A-Za-z0-9+/=]+)'\n", first)
            self.assertIsNotNone(match)
            payload = base64.b64decode(match.group(1), validate=True)
            embedded = root / "embedded"
            embedded.mkdir()
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                self.assertEqual(set(archive.namelist()), names)
                self.assertEqual(len(archive.infolist()), len(names))
                for name in names:
                    data = archive.read(name)
                    self.assertEqual(data, project.joinpath(name).read_text(encoding="utf-8").replace("\r\n", "\n").encode())
                    embedded.joinpath(name).write_bytes(data)
                    if name.endswith(".py"):
                        ast.parse(data.decode(), filename=name, feature_version=(3, 10))
            spec = importlib.util.spec_from_file_location("embedded_backhaul_easy", embedded / "backhaul_easy.py")
            manager = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(manager)
            fixture = {
                "schema_version": 1, "version": manager.VERSION, "owner": "backhaul-easy",
                "mode": "forward", "role": "server", "endpoint": "iran.example.test",
                "tunnel_port": 3080, "transport": "tcp", "token": "A" * 48,
                "ports": [{"bind": "0.0.0.0", "public": 1443, "target": "127.0.0.1", "local": 8443}],
            }
            client = manager.decode_pairing(manager.encode_pairing(fixture))
            self.assertEqual(client["role"], "client")
            self.assertEqual(client["token"], fixture["token"])
            self.assertIn("skip_optz = true", manager.render_config(client))

            # Exercise real extracted sources in a fresh interpreter, where the
            # parent test process's dont_write_bytecode flag cannot mask a bug.
            runtime = root / "runtime"
            runtime.mkdir()
            for name in ("backhaul_easy.py", "panel_support.py"):
                runtime.joinpath(name).write_bytes(embedded.joinpath(name).read_bytes())
            probe = (
                "import pathlib, runpy, sys; "
                "sys.path.insert(0, sys.argv[1]); "
                "runpy.run_path(str(pathlib.Path(sys.argv[1]) / 'backhaul_easy.py')); "
                "import panel_support; print(sys.dont_write_bytecode)"
            )
            completed = installer.subprocess.run([sys.executable, "-c", probe, str(runtime)], capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual(completed.stdout.strip(), "True")
            self.assertFalse(list(runtime.rglob("__pycache__")))
            self.assertFalse(list(runtime.rglob("*.pyc")))


if __name__ == "__main__":
    unittest.main()
