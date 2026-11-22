import contextlib
import io
import subprocess
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "app"), str(ROOT / "tools")]
import preflight
import server


class ApiControls(unittest.TestCase):
    def setUp(self):
        self.handler = object.__new__(server.Handler)
        self.handler.path = "/api/subscription/add"
        self.handler.session = Mock(return_value={"csrf": "sample"})
        self.handler.headers = {"Origin": "http://console.example", "Host": "console.example",
                                "X-CSRF-Token": "sample"}
        self.handler.reply = Mock()
        self.send = self.enterContext(patch.object(server, "send_agent", return_value={"enabled": False}))

    def post(self):
        body = json.dumps({"action": "controller_activate", "name": "Demo",
                           "url": "https://feed.example/fake-secret"}).encode()
        self.handler.rfile = io.BytesIO(body)
        self.handler.headers["Content-Length"] = str(len(body))
        self.handler.do_POST()

    def test_authenticated_route_controls_dispatch_and_rate(self):
        for _ in range(13):
            self.post()
        self.assertEqual(self.send.call_count, 12)
        self.send.assert_called_with("subscription_add", name="Demo", url="https://feed.example/fake-secret")
        self.assertEqual(self.handler.reply.call_args.args[1], 429)
        self.assertNotIn("fake-secret", str(self.handler.reply.call_args_list))

    def test_subscription_forms_keep_url_out_of_navigation_and_dom(self):
        subprocess.run(["node", str(ROOT/"tests/subscription_form.cjs")], check=True, timeout=5)

    def test_web_access_log_omits_secrets(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            self.handler.log_message("%s", "fake-secret")
        self.assertEqual(output.getvalue(), "")

    def test_recovery_retry_preserves_committed_cleanup_result(self):
        self.handler.path = "/api/recovery/retry"
        self.handler.rfile = io.BytesIO(b"{}")
        self.handler.headers["Content-Length"] = "2"
        self.send.return_value = {"applied":True,"outcome":"applied","cleanup_pending":True,
                                  "message":"已应用，收据待清理"}
        self.handler.do_POST()
        self.send.assert_called_once_with("recovery_retry")
        self.handler.reply.assert_called_once_with(self.send.return_value)

    def test_csrf_denied_before_agent(self):
        for key in ("Origin", "X-CSRF-Token"):
            with patch.dict(self.handler.headers, {key: "invalid"}):
                self.post()
                self.assertEqual(self.handler.reply.call_args.args[1], 403)
        self.send.assert_not_called()


class Inventory(unittest.TestCase):
    def test_requires_evidence_for_each_check(self):
        supplied = {"os": "HOUZZkit OS", "arch": "arm64", "kernel": "Linux 6.8",
                    "occupied_tcp_ports": [], "resources_verified": True,
                    "private_volume_writable": True}
        self.assertTrue(all(preflight.assess(supplied).values()))
        for key in supplied:
            with self.subTest(key=key):
                self.assertFalse(all(preflight.assess({k:v for k,v in supplied.items() if k!=key}).values()))
        self.assertFalse(all(preflight.assess({**supplied, "occupied_tcp_ports": [17681]}).values()))
