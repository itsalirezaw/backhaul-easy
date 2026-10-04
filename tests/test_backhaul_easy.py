"""Offline contract and security tests; no services or network are contacted.

Run from backhaul-easy with Python 3.11+ (tested using Python 3.12):
    python -m unittest discover -s tests -v
The installed manager itself targets Python 3.10+.
"""

import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import backhaul_easy as app
import panel_support as panel


# These are the official v0.7.2 config/config.go TOML field names. Keeping
# a separate contract catches plausible-looking keys upstream would ignore.
SERVER_FIELDS = set("""
bind_addr transport token nodelay keepalive_period channel_size log_level ports
pprof mux_session mux_version mux_framesize mux_recievebuffer mux_streambuffer
sniffer web_port sniffer_log tls_cert tls_key heartbeat mux_con accept_udp
skip_optz mss so_rcvbuf so_sndbuf proxy_protocol
""".split())
CLIENT_FIELDS = set("""
remote_addr transport token connection_pool retry_interval nodelay
keepalive_period log_level pprof mux_session mux_version mux_framesize
mux_recievebuffer mux_streambuffer sniffer web_port sniffer_log dial_timeout
aggressive_pool edge_ip skip_optz mss so_rcvbuf so_sndbuf
""".split())
TRANSPORTS = ("tcp", "tcpmux", "udp", "ws", "wsmux", "wss", "wssmux")


def sample_state(role="server", transport="tcp"):
    state = {
        "schema_version": 1,
        "version": app.VERSION,
        "owner": "backhaul-easy",
        "mode": "forward",
        "role": role,
        "endpoint": "iran.example.test",
        "tunnel_port": 3080,
        "transport": transport,
        "token": "test-only_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ports": [
            {"bind": "0.0.0.0", "public": 1443,
             "target": "127.0.0.1", "local": 8443},
        ],
        "advanced": {},
    }
    if transport in ("wss", "wssmux") and role == "server":
        state["tls_cert"] = str(app.CERT_PATH)
        state["tls_key"] = str(app.KEY_PATH)
    return state


class StateValidationTests(unittest.TestCase):
    def test_supported_roles_and_all_seven_transports_are_valid(self):
        for role in ("server", "client"):
            for transport in TRANSPORTS:
                with self.subTest(role=role, transport=transport):
                    app.validate_state(sample_state(role, transport))

    def test_invalid_top_level_values_are_rejected_before_rendering(self):
        cases = {
            "owner": ("another-manager", "", None),
            "schema_version": (0, 2, True, "1"),
            "role": ("iran", "outside", "both", ""),
            "transport": ("quic", "TCP", "tcp\n[client]", ""),
            "mode": ("vpn", "", None),
            "tunnel_port": (0, -1, 65536, True, 1.5, "3080"),
            "endpoint": ("", "http://iran.example.test", "host;id", "host\n", "-host", "host/path"),
            "token": ("", "short", "A" * 32 + "\n", "A" * 32 + "\x00"),
        }
        for key, values in cases.items():
            for value in values:
                state = sample_state()
                state[key] = value
                with self.subTest(key=key, value=repr(value)):
                    with self.assertRaises(ValueError):
                        app.validate_state(state)

    def test_unknown_state_and_advanced_keys_do_not_silently_do_nothing(self):
        for container, key, value in (
            (None, "shell_hook", "touch /tmp/example"),
            ("advanced", "tcp_fast_open", True),
            ("advanced", "mux_receivebuffer", 4194304),
            ("advanced", "skip_optz", False),
        ):
            state = sample_state()
            target = state if container is None else state[container]
            target[key] = value
            with self.subTest(container=container, key=key):
                with self.assertRaises(ValueError):
                    app.validate_state(state)

    def test_mappings_require_valid_ports_hosts_and_complete_keys(self):
        cases = [
            [],
            [None],
            [{"bind": "0.0.0.0", "public": True, "target": "127.0.0.1", "local": 8443}],
            [{"bind": "0.0.0.0", "public": 443, "target": "127.0.0.1", "local": 65536}],
            [{"bind": "0.0.0.0", "public": 443, "target": "127.0.0.1"}],
            [{"bind": "0.0.0.0", "public": 443, "target": "127.0.0.1\n", "local": 8443}],
            [{"bind": "0.0.0.0", "public": 443, "target": "127.0.0.1", "local": 8443, "command": "id"}],
        ]
        for ports in cases:
            state = sample_state()
            state["ports"] = ports
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    app.validate_state(state)

    def test_duplicate_public_ports_and_tunnel_collision_are_rejected(self):
        for second in (
            {"bind": "0.0.0.0", "public": 1443, "target": "127.0.0.1", "local": 9443},
            {"bind": "127.0.0.1", "public": 1443, "target": "127.0.0.1", "local": 9443},
            {"bind": "0.0.0.0", "public": 3080, "target": "127.0.0.1", "local": 9443},
        ):
            state = sample_state()
            state["ports"].append(second)
            with self.subTest(second=second):
                with self.assertRaises(ValueError):
                    app.validate_state(state)

    def test_certificate_paths_cannot_inject_config_or_escape_expected_format(self):
        for key in ("tls_cert", "tls_key"):
            for value in ("relative.pem", "/tmp/cert\n.pem", "/tmp/a\x00.pem", "../../root/key.pem"):
                state = sample_state(transport="wss")
                state[key] = value
                with self.subTest(key=key, value=repr(value)):
                    with self.assertRaises(ValueError):
                        app.validate_state(state)

    def test_advanced_settings_enforce_types_ranges_and_role(self):
        for role, transport, setting in (
            ("server", "tcp", {"nodelay": "false"}),
            ("server", "tcp", {"heartbeat": True}),
            ("server", "tcp", {"heartbeat": 0}),
            ("client", "tcp", {"connection_pool": 0}),
            ("client", "tcp", {"dial_timeout": -1}),
            ("server", "tcp", {"mux_version": 3}),
            ("server", "tcp", {"log_level": "silent"}),
            ("server", "tcp", {"connection_pool": 8}),
            ("client", "tcp", {"accept_udp": True}),
            ("server", "tcpmux", {"accept_udp": True}),
            ("server", "ws", {"accept_udp": True}),
            ("client", "tcp", {"edge_ip": "example.test"}),
        ):
            state = sample_state(role, transport)
            state["advanced"] = setting
            with self.subTest(role=role, transport=transport, setting=setting):
                with self.assertRaises(ValueError):
                    app.validate_state(state)

    def test_shared_destination_ports_are_valid_for_distinct_public_listeners(self):
        state = sample_state()
        state["ports"].append(
            {"bind": "0.0.0.0", "public": 2443, "target": "127.0.0.1", "local": 8443}
        )
        validated = app.validate_state(state)
        self.assertEqual([p["local"] for p in validated["ports"]], [8443, 8443])

    def test_validation_returns_an_independent_normalized_state(self):
        state = sample_state()
        state["endpoint"] = "IRAN.EXAMPLE.TEST."
        before = copy.deepcopy(state)
        validated = app.validate_state(state)
        self.assertEqual(validated["endpoint"], "iran.example.test")
        validated["ports"][0]["local"] = 9999
        validated["advanced"]["nodelay"] = False
        self.assertEqual(state, before)

    def test_udp_destination_cannot_overflow_upstream_address_field(self):
        for length, accepted in ((38, True), (39, False)):
            state = sample_state(transport="udp")
            # 38 letters + '.test' + ':8443' is exactly the 47-byte limit.
            state["ports"][0]["target"] = "a" * (length - 1) + ".test"
            actual_length = len((state["ports"][0]["target"] + ":8443").encode())
            self.assertEqual(actual_length, 47 if accepted else 48)
            if accepted:
                app.validate_state(state)
            else:
                with self.assertRaises(ValueError):
                    app.validate_state(state)

    def test_tls_fields_are_required_only_for_secure_websocket_servers(self):
        for transport in ("wss", "wssmux"):
            for missing in ("tls_cert", "tls_key"):
                state = sample_state(transport=transport)
                del state[missing]
                with self.subTest(transport=transport, missing=missing):
                    with self.assertRaises(ValueError):
                        app.validate_state(state)
        for role, transport in (("client", "wss"), ("server", "tcp")):
            state = sample_state(role, transport)
            state["tls_key"] = str(app.KEY_PATH)
            with self.assertRaises(ValueError):
                app.validate_state(state)

    def test_monitoring_is_opt_in_and_cannot_steal_a_service_or_tunnel_port(self):
        for collision in (3080, 1443):
            state = sample_state()
            state["advanced"] = {"web_port": collision}
            with self.subTest(collision=collision):
                with self.assertRaises(ValueError):
                    app.validate_state(state)
        state = sample_state()
        state["advanced"] = {"web_port": 2060, "sniffer": True}
        config = tomllib.loads(app.render_config(state))["server"]
        self.assertEqual(config["web_port"], 2060)
        self.assertIs(config["sniffer"], True)
        self.assertIs(config["skip_optz"], True)
        self.assertFalse(config.get("pprof", False))
        state["advanced"]["sniffer_log"] = "/etc/ssh/sshd_config"
        with self.assertRaises(ValueError):
            app.validate_state(state)

    def test_tunnel_bind_is_a_server_ip_and_does_not_change_pairing_destination(self):
        state = sample_state()
        state["tunnel_bind"] = "192.0.2.10"
        self.assertEqual(tomllib.loads(app.render_config(state))["server"]["bind_addr"], "192.0.2.10:3080")
        client = app.decode_pairing(app.encode_pairing(state))
        self.assertEqual(client["endpoint"], "iran.example.test")
        self.assertNotIn("tunnel_bind", client)
        for role, value in (("server", "host.example.test"), ("server", "0.0.0.0\n"), ("client", "127.0.0.1")):
            state = sample_state(role)
            state["tunnel_bind"] = value
            with self.subTest(role=role, value=value):
                with self.assertRaises(ValueError):
                    app.validate_state(state)


class PortParserTests(unittest.TestCase):
    def test_mixed_identity_remap_and_ranges_preserve_intent(self):
        ports = app.parse_ports(" 443, 8080:80,9000-9002:8000-8002,10000-10001 ")
        self.assertEqual(
            [(p["public"], p["local"]) for p in ports],
            [(443, 443), (8080, 80), (9000, 8000), (9001, 8001),
             (9002, 8002), (10000, 10000), (10001, 10001)],
        )
        self.assertTrue(all(p["bind"] == "0.0.0.0" and p["target"] == "127.0.0.1" for p in ports))

    def test_boundary_ports_work_and_never_wrap(self):
        self.assertEqual([p["public"] for p in app.parse_ports("1,65535")], [1, 65535])
        for text in ("0", "-1", "65536", "65535-65536", "1:0", "1:65536"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    app.parse_ports(text)

    def test_overlapping_reversed_mismatched_or_unbounded_ranges_fail(self):
        for text in ("443,443", "1000-1003,1002-1004", "3-1", "1-3:8-9", "1-3:9", "1-129", "1-65535"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    app.parse_ports(text)

    def test_malformed_and_shell_or_toml_injection_inputs_fail(self):
        for text in ("", " ", "443,", ",443", "443,,80", "443=80", "443;id", "$(id)", "443\n80", "443\x00", "443\r", "[server]", "0.0.0.0:443", None, True):
            with self.subTest(text=repr(text)):
                with self.assertRaises(ValueError):
                    app.parse_ports(text)

    def test_capacity_limit_is_consistent_between_parser_and_state(self):
        ports = app.parse_ports("10000-10127")
        self.assertEqual(len(ports), 128)
        state = sample_state()
        state["ports"] = ports
        app.validate_state(state)
        state["ports"].append({"bind": "0.0.0.0", "public": 11000, "target": "127.0.0.1", "local": 11000})
        with self.assertRaises(ValueError):
            app.validate_state(state)


class RenderConfigTests(unittest.TestCase):
    def test_toml_parses_for_every_role_and_transport_without_unknown_fields(self):
        for role in ("server", "client"):
            for transport in TRANSPORTS:
                with self.subTest(role=role, transport=transport):
                    state = sample_state(role, transport)
                    parsed = tomllib.loads(app.render_config(state))
                    self.assertEqual(set(parsed), {role})
                    config = parsed[role]
                    allowed = SERVER_FIELDS if role == "server" else CLIENT_FIELDS
                    self.assertLessEqual(set(config), allowed)
                    self.assertEqual(config["transport"], transport)
                    self.assertEqual(config["token"], state["token"])
                    self.assertIs(config["skip_optz"], True)
                    self.assertFalse(config.get("pprof", False))
                    self.assertEqual(config.get("web_port", 0), 0)

    def test_server_maps_to_services_on_the_client_without_changing_ports(self):
        state = sample_state()
        state["ports"].append(
            {"bind": "127.0.0.1", "public": 1555, "target": "10.10.0.5", "local": 9555}
        )
        config = tomllib.loads(app.render_config(state))["server"]
        self.assertEqual(config["bind_addr"], "0.0.0.0:3080")
        self.assertIn("0.0.0.0:1443=127.0.0.1:8443", config["ports"])
        self.assertIn("127.0.0.1:1555=10.10.0.5:9555", config["ports"])

    def test_client_uses_the_iran_endpoint_and_does_not_create_public_listeners(self):
        config = tomllib.loads(app.render_config(sample_state("client")))["client"]
        self.assertEqual(config["remote_addr"], "iran.example.test:3080")
        self.assertNotIn("bind_addr", config)
        self.assertNotIn("ports", config)

    def test_rendering_does_not_mutate_saved_state(self):
        state = sample_state(transport="tcpmux")
        before = copy.deepcopy(state)
        app.render_config(state)
        self.assertEqual(state, before)

    def test_ipv6_endpoint_and_bind_are_bracketed_and_unsupported_target_is_rejected(self):
        state = sample_state("client")
        state["endpoint"] = "2001:db8::10"
        self.assertEqual(tomllib.loads(app.render_config(state))["client"]["remote_addr"], "[2001:db8::10]:3080")
        state = sample_state()
        state["ports"][0].update(bind="::1")
        self.assertEqual(tomllib.loads(app.render_config(state))["server"]["ports"], ["[::1]:1443=127.0.0.1:8443"])
        state["ports"][0]["target"] = "2001:db8::20"
        with self.assertRaises(ValueError):
            app.validate_state(state)

    def test_custom_mux_fields_and_udp_over_tcp_survive_toml_parsing(self):
        state = sample_state(transport="tcpmux")
        state["advanced"] = {"mux_version": 2, "mux_framesize": 16384, "mux_recievebuffer": 8388608, "mux_streambuffer": 131072}
        config = tomllib.loads(app.render_config(state))["server"]
        for key, value in state["advanced"].items():
            self.assertEqual(config[key], value)
        state = sample_state()
        state["advanced"] = {"accept_udp": True}
        self.assertIs(tomllib.loads(app.render_config(state))["server"]["accept_udp"], True)

    def test_render_rejects_invalid_settings_instead_of_emitting_a_partial_config(self):
        state = sample_state()
        state["token"] = '\"\n[client]\ntransport = \"udp'
        with self.assertRaises(ValueError):
            app.render_config(state)


def forged_pairing(raw):
    if not isinstance(raw, bytes):
        raw = json.dumps(raw, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    checksum = hashlib.sha256(encoded.encode()).hexdigest()[:16]
    return f"BHE1.{encoded}.{checksum}"


def pairing_payload():
    encoded = app.encode_pairing(sample_state()).split(".")[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


class PairingTests(unittest.TestCase):
    def test_roundtrip_retains_connection_contract_for_every_transport(self):
        for transport in TRANSPORTS:
            with self.subTest(transport=transport):
                server = sample_state(transport=transport)
                encoded = app.encode_pairing(server)
                self.assertIsInstance(encoded, str)
                decoded = app.decode_pairing(encoded)
                for key in ("endpoint", "tunnel_port", "transport", "token", "mode"):
                    self.assertEqual(decoded[key], server[key])
                self.assertNotIn("tls_key", decoded)
                self.assertNotIn("tls_cert", decoded)
                self.assertEqual(decoded["role"], "client")
                app.validate_state(decoded)

    def test_invalid_pairing_input_has_controlled_validation_errors(self):
        for value in ("", " ", "not-a-pairing-code", "A" * 100000, "\x00", "[]", "{}"):
            with self.subTest(value=repr(value[:40])):
                with self.assertRaises(ValueError):
                    app.decode_pairing(value)

    def test_truncated_or_corrupted_checksum_fails(self):
        code = app.encode_pairing(sample_state())
        changed = code[:-1] + ("0" if code[-1] != "0" else "1")
        for value in (code[:-1], changed, code + "\n", " " + code):
            with self.subTest(value=value[-20:]):
                with self.assertRaises(ValueError):
                    app.decode_pairing(value)

    def test_recomputed_checksum_is_not_a_bypass_for_untrusted_payload_validation(self):
        for key, value in (
            ("role", "server"), ("schema_version", True), ("transport", "quic"),
            ("endpoint", "example.test;id"), ("token", "a" * 32 + "\n"),
            ("tunnel_port", 65536), ("tls_key", "/root/key.pem"),
        ):
            payload = pairing_payload()
            payload[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    app.decode_pairing(forged_pairing(payload))

    def test_duplicate_nonfinite_nonobject_and_nested_json_fail_cleanly(self):
        valid = json.dumps(pairing_payload(), separators=(",", ":")).encode()
        duplicate = valid[:-1] + b',"tunnel_port":4444}'
        for raw in (duplicate, b"[]", b"null", b"NaN", b"\xff", b"[" * 1100 + b"]" * 1100):
            with self.subTest(payload=repr(raw[:50])):
                with self.assertRaises(ValueError):
                    app.decode_pairing(forged_pairing(raw))

    def test_mux_pairing_preserves_protocol_compatibility(self):
        state = sample_state(transport="tcpmux")
        state["advanced"] = {"mux_version": 2, "mux_framesize": 16384, "mux_recievebuffer": 8388608, "mux_streambuffer": 131072}
        decoded = app.decode_pairing(app.encode_pairing(state))
        for key, value in state["advanced"].items():
            self.assertEqual(decoded["advanced"].get(key), value)


class PanelModeTests(unittest.TestCase):
    def state(self):
        state = sample_state()
        state["mode"] = "panel"
        state["proxy_uuid"] = "1a6e226c-9fb0-4571-8c2e-73b27e582bed"
        state["ports"][0].update(bind="127.0.0.1", target="127.0.0.1")
        return state

    def test_panel_contract_roundtrips_without_exposing_the_outside_proxy(self):
        state = self.state()
        app.validate_state(state)
        client = app.decode_pairing(app.encode_pairing(state))
        self.assertEqual(client["mode"], "panel")
        self.assertEqual(client["proxy_uuid"], state["proxy_uuid"])
        self.assertEqual(client["ports"], state["ports"])

    def test_panel_rejects_udp_missing_uuid_and_public_proxy_destinations(self):
        bad_states = []
        state = self.state()
        state["transport"] = "udp"
        bad_states.append(state)
        state = self.state()
        del state["proxy_uuid"]
        bad_states.append(state)
        state = self.state()
        state["proxy_uuid"] = "invalid;id"
        bad_states.append(state)
        for field in ("bind", "target"):
            state = self.state()
            state["ports"][0][field] = "192.0.2.10"
            bad_states.append(state)
        for state in bad_states:
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    app.validate_state(state)


class UnitAndCommandTests(unittest.TestCase):
    def test_service_denies_system_network_admin_and_kernel_tuning(self):
        unit = app.render_unit()
        directives = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line and not line.startswith("#"))
        self.assertEqual(directives["ExecStart"], f"{app.BINARY_PATH} -c {app.CONFIG_PATH}")
        self.assertEqual(directives["CapabilityBoundingSet"], "CAP_NET_BIND_SERVICE")
        self.assertEqual(directives["ProtectKernelTunables"], "true")
        self.assertEqual(directives["NoNewPrivileges"], "true")
        self.assertEqual(directives["UMask"], "0077")
        self.assertNotIn("CAP_NET_ADMIN", unit)
        self.assertNotIn("ExecStartPre", directives)
        self.assertNotIn("ExecStartPost", directives)

    def test_command_passes_literal_arguments_without_a_shell(self):
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        argument = "literal;$(touch never-created)"
        with mock.patch.object(app.shutil, "which", return_value="/usr/bin/systemctl"), mock.patch.object(app.subprocess, "run", return_value=completed) as run:
            app.command("systemctl", argument)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", argument])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_status_output_redacts_token_and_pairing_and_strips_terminal_controls(self):
        state = sample_state()
        code = app.encode_pairing(state)
        output = app.sanitize_output(f"{state['token']} {code}\x00\x1b[2J\nready", state)
        self.assertNotIn(state["token"], output)
        self.assertNotIn(code, output)
        self.assertNotIn("\x00", output)
        self.assertNotIn("\x1b", output)
        self.assertIn("\nready", output)


class IsolatedLifecycleTests(unittest.TestCase):
    """Run lifecycle logic against disposable files and mocked system services."""

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        etc, lib, units = root / "etc", root / "lib", root / "units"
        for directory in (etc, lib, units):
            directory.mkdir()
        locations = {
            "ETC_DIR": etc, "LIB_DIR": lib,
            "STATE_PATH": etc / "state.json", "CONFIG_PATH": etc / "config.toml",
            "CERT_PATH": etc / "tls.crt", "KEY_PATH": etc / "tls.key", "TRAFFIC_PATH": etc / "traffic.json",
            "BINARY_PATH": lib / "backhaul", "MANAGER_PATH": lib / "backhaul_easy.py",
            "RECEIPT_PATH": lib / "install.json", "LAUNCHER_PATH": root / "backhaul-easy",
            "UNIT_PATH": units / "backhaul-easy.service",
        }
        for name, value in locations.items():
            self.stack.enter_context(mock.patch.object(app, name, value))
        app.BINARY_PATH.write_bytes(b"test double; never executed")
        self.success = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.ctl = self.stack.enter_context(mock.patch.object(app, "ctl", return_value=self.success))
        # POSIX ownership/permission checks have their own tests; Windows cannot
        # reproduce root UID and Unix directory permission semantics.
        self.stack.enter_context(mock.patch.object(app, "private_directory"))

    def seed_owned_state(self, state=None):
        state = sample_state() if state is None else state
        app.STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
        app.CONFIG_PATH.write_bytes(app.render_config(state).encode("utf-8"))
        app.UNIT_PATH.write_bytes(app.render_unit().encode("utf-8"))
        return state

    def allow_simulated_install(self):
        self.stack.enter_context(mock.patch.object(app, "private_directory"))
        self.stack.enter_context(mock.patch.object(app.os, "access", return_value=True))
        self.stack.enter_context(mock.patch.object(app.time, "sleep"))
        self.stack.enter_context(mock.patch.object(app, "atomic_write", side_effect=lambda path, data, mode=0o600: path.write_bytes(data)))

    def test_foreign_configuration_is_rejected_without_mutations(self):
        self.seed_owned_state()
        app.CONFIG_PATH.write_text("[server]\ntoken = 'foreign'\n", encoding="utf-8")
        with mock.patch.object(app, "atomic_write") as write:
            with self.assertRaises(ValueError):
                app.apply_state(sample_state())
            write.assert_not_called()
        self.assertEqual(self.ctl.call_count, 0)

    def test_systemd_external_override_is_rejected_without_mutations(self):
        self.seed_owned_state()
        self.ctl.return_value = SimpleNamespace(returncode=0, stdout=b"/etc/systemd/system/backhaul-easy.service.d/foreign.conf\n", stderr=b"")
        with mock.patch.object(app, "atomic_write") as write:
            with self.assertRaises(ValueError):
                app.apply_state(sample_state())
            write.assert_not_called()
        self.assertTrue(all(call.args[0] == "show" for call in self.ctl.call_args_list))

    def test_failed_update_restores_old_bytes_and_prior_service_state(self):
        old = self.seed_owned_state()
        watched = (app.STATE_PATH, app.CONFIG_PATH, app.UNIT_PATH)
        before = {path: path.read_bytes() for path in watched}
        self.allow_simulated_install()
        new = copy.deepcopy(old)
        new["token"] = "B" * 48
        with mock.patch.object(app, "active", side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, "restored"):
                app.apply_state(new)
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        self.assertEqual(self.ctl.call_args_list[-1].args, ("restart", app.SERVICE))
        self.assertEqual(self.ctl.call_args_list[-2].args, ("enable", app.SERVICE))

    def test_failed_first_install_removes_new_files_and_stops_new_service(self):
        self.allow_simulated_install()
        def systemctl(*args, **kwargs):
            return SimpleNamespace(returncode=1 if args[0] == "is-enabled" else 0, stdout=b"", stderr=b"")
        self.ctl.side_effect = systemctl
        with mock.patch.object(app, "active", side_effect=[False, False]):
            with self.assertRaisesRegex(ValueError, "restored"):
                app.apply_state(sample_state())
        for path in (app.STATE_PATH, app.CONFIG_PATH, app.UNIT_PATH):
            self.assertFalse(path.exists())
        self.assertTrue(app.BINARY_PATH.exists())
        self.assertEqual(self.ctl.call_args_list[-1].args, ("stop", app.SERVICE))
        self.assertEqual(self.ctl.call_args_list[-2].args, ("disable", app.SERVICE))

    def test_existing_directory_in_place_of_managed_file_is_rejected(self):
        app.CONFIG_PATH.mkdir()
        with self.assertRaises(ValueError):
            app.assert_owned_setup(allow_empty=True)

    def seed_owned_panel_transition(self):
        state = sample_state("client")
        state.update(mode="panel", proxy_uuid="1a6e226c-9fb0-4571-8c2e-73b27e582bed")
        state["ports"][0].update(bind="127.0.0.1", target="127.0.0.1")
        self.seed_owned_state(state)
        locations = {
            "ETC_DIR": app.ETC_DIR, "LIB_DIR": app.LIB_DIR,
            "XRAY_PATH": app.LIB_DIR / "xray", "CONFIG_PATH": app.ETC_DIR / "xray.json",
            "UNIT_PATH": app.UNIT_PATH.parent / "backhaul-easy-egress.service",
            "RECEIPT_PATH": app.ETC_DIR / "panel-receipt.json",
        }
        for name, value in locations.items():
            self.stack.enter_context(mock.patch.object(panel, name, value))
        owned = (panel.XRAY_PATH, panel.CONFIG_PATH, panel.UNIT_PATH)
        for path in owned:
            path.write_bytes(("owned panel bytes:" + path.name).encode())
        receipt = {
            "owner": panel.OWNER, "schema": 1, "version": panel.XRAY_VERSION,
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in owned},
        }
        panel.RECEIPT_PATH.write_text(json.dumps(receipt), encoding="utf-8")
        self.panel_paths = (*owned, panel.RECEIPT_PATH)
        self.stack.enter_context(mock.patch.object(panel, "_root"))
        self.stack.enter_context(mock.patch.object(panel, "_secure", side_effect=lambda path, **kwargs: path.exists()))
        self.stack.enter_context(mock.patch.object(panel, "_atomic", side_effect=lambda path, data, mode: path.write_bytes(data)))
        self.panel_ctl = self.stack.enter_context(mock.patch.object(panel, "_systemctl", return_value=self.success))
        self.allow_simulated_install()
        return state

    def test_panel_to_forward_failure_restores_both_tunnel_and_removed_panel(self):
        self.seed_owned_panel_transition()
        watched = (app.STATE_PATH, app.CONFIG_PATH, app.UNIT_PATH, *self.panel_paths)
        before = {path: path.read_bytes() for path in watched}
        observed_removal = []
        service_events = []
        def tunnel_ctl(*args, **kwargs):
            service_events.append("tunnel-" + args[0])
            if args[0] == "restart":
                observed_removal.append(all(not path.exists() for path in self.panel_paths))
            return self.success
        def panel_ctl(*args, **kwargs):
            service_events.append("panel-" + args[0])
            return self.success
        self.ctl.side_effect = tunnel_ctl
        self.panel_ctl.side_effect = panel_ctl
        with mock.patch.object(app, "active", side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, "restored"):
                app.apply_state(sample_state("client"))
        self.assertEqual(observed_removal, [True, False])
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        self.assertEqual(self.panel_ctl.call_args_list[-2].args, ("enable", panel.SERVICE))
        self.assertEqual(self.panel_ctl.call_args_list[-1].args, ("start", panel.SERVICE))
        self.assertLess(service_events.index("tunnel-stop"), service_events.index("panel-start"))
        self.assertLess(service_events.index("panel-start"), len(service_events) - 1)
        self.assertEqual(service_events[-1], "tunnel-restart")

    def test_panel_removal_preflight_failure_preserves_newly_edited_panel_and_tunnel(self):
        self.seed_owned_panel_transition()
        panel.CONFIG_PATH.write_bytes(b"concurrent custom panel edit")
        watched = (app.STATE_PATH, app.CONFIG_PATH, app.UNIT_PATH, *self.panel_paths)
        before = {path: path.read_bytes() for path in watched}
        with mock.patch.object(app, "atomic_write") as write:
            with self.assertRaisesRegex(ValueError, "changed"):
                app.apply_state(sample_state("client"))
        write.assert_not_called()
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        self.assertTrue(all(call.args[0] == "show" for call in self.ctl.call_args_list))
        self.panel_ctl.assert_not_called()

    def test_successful_panel_to_forward_switch_removes_owned_helper_and_receipt(self):
        self.seed_owned_panel_transition()
        unrelated = app.ETC_DIR / "existing-user-panel.json"
        unrelated.write_bytes(b"unrelated panel settings")
        with mock.patch.object(app, "active", side_effect=[True, True]), contextlib.redirect_stdout(io.StringIO()):
            app.apply_state(sample_state("client"))
        self.assertTrue(all(not path.exists() for path in self.panel_paths))
        self.assertEqual(json.loads(app.STATE_PATH.read_bytes())["mode"], "forward")
        self.assertEqual(unrelated.read_bytes(), b"unrelated panel settings")
        self.assertIn(mock.call("stop", panel.SERVICE), self.panel_ctl.call_args_list)
        self.assertIn(mock.call("disable", panel.SERVICE), self.panel_ctl.call_args_list)

    def test_leftover_owned_panel_receipt_is_cleaned_even_when_saved_mode_is_forward(self):
        self.seed_owned_panel_transition()
        self.seed_owned_state(sample_state("client"))
        with mock.patch.object(app, "active", side_effect=[True, True]), contextlib.redirect_stdout(io.StringIO()):
            app.apply_state(sample_state("client"))
        self.assertTrue(all(not path.exists() for path in self.panel_paths))

    def test_iran_to_outside_role_change_stops_old_listener_before_helper_and_restores_on_failure(self):
        old = sample_state("server")
        old.update(mode="panel", proxy_uuid="1a6e226c-9fb0-4571-8c2e-73b27e582bed")
        old["ports"][0].update(bind="127.0.0.1", target="127.0.0.1", public=1080, local=1080)
        self.seed_owned_state(old)
        new = copy.deepcopy(old)
        new["role"] = "client"
        watched = (app.STATE_PATH, app.CONFIG_PATH, app.UNIT_PATH)
        before = {path: path.read_bytes() for path in watched}
        self.allow_simulated_install()
        events = []
        def tunnel_ctl(*args, **kwargs):
            events.append("tunnel-" + args[0])
            return self.success
        self.ctl.side_effect = tunnel_ctl
        token = object()
        with mock.patch.object(panel, "prepare_panel", return_value=token), \
                mock.patch.object(panel, "apply_panel", side_effect=lambda transaction: events.append("helper-apply")) as apply, \
                mock.patch.object(panel, "rollback_panel", side_effect=lambda transaction: events.append("helper-rollback")) as rollback, \
                mock.patch.object(app, "active", side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, "restored"):
                app.apply_state(new)
        apply.assert_called_once_with(token)
        rollback.assert_called_once_with(token)
        self.assertLess(events.index("tunnel-stop"), events.index("helper-apply"))
        self.assertEqual(events[events.index("helper-rollback") - 1], "tunnel-stop")
        self.assertEqual(events[-1], "tunnel-restart")
        self.assertEqual({path: path.read_bytes() for path in watched}, before)


if __name__ == "__main__":
    unittest.main()
