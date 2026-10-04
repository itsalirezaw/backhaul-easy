"""Panel contracts and rollback behavior; no network or actual services."""

import contextlib
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import panel_support as panel


def panel_state(role):
    return {
        "mode": "panel", "role": role, "transport": "tcp",
        "proxy_uuid": "1a6e226c-9fb0-4571-8c2e-73b27e582bed",
        "ports": [{"bind": "127.0.0.1", "public": 11080, "target": "127.0.0.1", "local": 21080}],
    }


class PanelContractTests(unittest.TestCase):
    def test_outside_proxy_is_authenticated_loopback_with_ipv4_egress(self):
        state = panel_state("client")
        config = panel.render_xray_config(state)
        self.assertEqual(len(config["inbounds"]), 1)
        listener = config["inbounds"][0]
        self.assertEqual(listener["listen"], "127.0.0.1")
        self.assertEqual(listener["port"], 21080)
        self.assertEqual(listener["protocol"], "vless")
        self.assertEqual(listener["settings"]["clients"], [{"id": state["proxy_uuid"]}])
        self.assertEqual(config["outbounds"], [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv4"}}])
        self.assertNotIn("routing", config)
        self.assertNotIn("api", config)

    def test_iran_outbound_uses_local_forwarded_port_and_matching_credentials(self):
        state = panel_state("server")
        outbound = panel.panel_outbound(state)
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["tag"], "backhaul-out")
        destination, = outbound["settings"]["vnext"]
        self.assertEqual(destination["address"], "127.0.0.1")
        self.assertEqual(destination["port"], 11080)
        self.assertEqual(destination["users"], [{"id": state["proxy_uuid"], "encryption": "none"}])
        self.assertNotIn("routing", outbound)
        self.assertNotIn("inbounds", outbound)

    def test_invalid_states_cannot_create_a_public_or_unauthenticated_proxy(self):
        for role, render in (("client", panel.render_xray_config), ("server", panel.panel_outbound)):
            mutations = [
                {"role": "server" if role == "client" else "client"},
                {"mode": "forward"}, {"transport": "udp"},
                {"proxy_uuid": ""}, {"proxy_uuid": "credential\ncommand"},
                {"proxy_uuid": None}, {"ports": []},
                {"ports": panel_state(role)["ports"] * 2},
            ]
            for field, value in (("bind", "0.0.0.0"), ("target", "192.0.2.10"), ("public", True), ("local", 0), ("local", 65536)):
                ports = copy.deepcopy(panel_state(role)["ports"])
                ports[0][field] = value
                mutations.append({"ports": ports})
            for mutation in mutations:
                state = panel_state(role)
                state.update(mutation)
                with self.subTest(role=role, mutation=mutation):
                    with self.assertRaises(ValueError):
                        render(state)

    def test_every_tcp_capable_transport_uses_the_same_loopback_proxy_contract(self):
        for transport in ("tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux"):
            with self.subTest(transport=transport):
                state = panel_state("client")
                state["transport"] = transport
                self.assertEqual(panel.render_xray_config(state)["inbounds"][0]["listen"], "127.0.0.1")

    def test_generated_artifacts_do_not_mutate_input_state(self):
        for role, render in (("client", panel.render_xray_config), ("server", panel.panel_outbound)):
            state = panel_state(role)
            before = copy.deepcopy(state)
            result = render(state)
            result["tag"] = "changed only in result"
            self.assertEqual(state, before)


class PanelTransactionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.paths = [root / name for name in ("xray", "xray.json", "egress.service", "receipt.json")]
        self.stack.enter_context(mock.patch.object(panel, "_root"))
        self.stack.enter_context(mock.patch.object(panel, "_secure", side_effect=lambda path, **kwargs: path.exists()))
        self.stack.enter_context(mock.patch.object(panel, "_receipt", return_value=None))
        self.stack.enter_context(mock.patch.object(panel, "_service_guard"))
        self.write = self.stack.enter_context(mock.patch.object(panel, "_atomic", side_effect=lambda path, data, mode: path.write_bytes(data)))
        self.systemctl = self.stack.enter_context(mock.patch.object(panel, "_systemctl", return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")))
        self.verify = self.stack.enter_context(mock.patch.object(panel, "verify_panel_payload", side_effect=ValueError("simulated payload failure")))

    def transaction(self, existing=True):
        previous, desired = {}, {}
        for path in self.paths:
            if existing:
                old = ("old:" + path.name).encode()
                path.write_bytes(old)
                previous[path] = (old, 0o600)
            else:
                previous[path] = None
            desired[path] = (("new:" + path.name).encode(), 0o600)
        return panel.PanelTransaction(panel_state("client"), previous, desired, existing, existing)

    def test_payload_failure_restores_old_files_receipt_and_service_state(self):
        transaction = self.transaction()
        before = {path: path.read_bytes() for path in self.paths}
        with self.assertRaisesRegex(ValueError, "restored"):
            panel.apply_panel(transaction)
        self.assertEqual({path: path.read_bytes() for path in self.paths}, before)
        self.assertTrue(transaction.rolled_back)
        self.assertEqual(self.systemctl.call_args_list[-2].args, ("enable", panel.SERVICE))
        self.assertEqual(self.systemctl.call_args_list[-1].args, ("start", panel.SERVICE))
        self.assertTrue(all(call.args == ("daemon-reload",) or call.args[-1] == panel.SERVICE for call in self.systemctl.call_args_list))

    def test_failed_first_install_removes_only_transaction_files(self):
        transaction = self.transaction(existing=False)
        unrelated = self.paths[0].parent / "existing-panel.json"
        unrelated.write_bytes(b"existing user panel")
        with self.assertRaisesRegex(ValueError, "restored"):
            panel.apply_panel(transaction)
        self.assertTrue(all(not path.exists() for path in self.paths))
        self.assertEqual(unrelated.read_bytes(), b"existing user panel")
        self.assertNotIn(mock.call("enable", panel.SERVICE), self.systemctl.call_args_list[3:])

    def test_concurrent_edit_before_apply_is_preserved_without_service_actions(self):
        transaction = self.transaction()
        self.paths[1].write_bytes(b"concurrent user edit")
        with self.assertRaisesRegex(ValueError, "changed"):
            panel.apply_panel(transaction)
        self.assertEqual(self.paths[1].read_bytes(), b"concurrent user edit")
        self.write.assert_not_called()
        self.systemctl.assert_not_called()

    def test_concurrent_edit_during_failed_start_is_preserved_and_reported(self):
        transaction = self.transaction()
        def failure(state):
            self.paths[1].write_bytes(b"concurrent user edit after install")
            raise ValueError("simulated failed payload")
        self.verify.side_effect = failure
        with self.assertRaisesRegex(ValueError, "manual attention"):
            panel.apply_panel(transaction)
        self.assertEqual(self.paths[1].read_bytes(), b"concurrent user edit after install")
        self.assertFalse(transaction.rolled_back)

    def test_repeated_rollback_is_idempotent(self):
        transaction = self.transaction()
        with self.assertRaises(ValueError):
            panel.apply_panel(transaction)
        self.write.reset_mock()
        self.systemctl.reset_mock()
        panel.rollback_panel(transaction)
        self.write.assert_not_called()
        self.systemctl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
