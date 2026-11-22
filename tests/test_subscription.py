import concurrent.futures
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import agent
import subscription

URL = "https://feed.example/private-marker?key=fake-secret"
BODY = b"proxies: [{name: Sample, type: trojan, password: fake-node}]"


class Transport(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(contextlib.ExitStack())
        self.dns = stack.enter_context(patch("subscription.resolve"))
        self.socket = stack.enter_context(patch("socket.socket"))
        self.raw = self.socket.return_value.__enter__.return_value
        self.wrap = stack.enter_context(patch.object(ssl.SSLContext, "wrap_socket", autospec=True))
        self.tls = self.wrap.return_value.__enter__.return_value
        stack.enter_context(patch.dict(os.environ, {"HTTPS_PROXY": "http://invalid.example"}))
        self.use_address(socket.AF_INET, ("93.184.216.34", 443))
        self.respond()

    def use_address(self, family, address):
        self.address = address
        self.dns.side_effect = [[(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]]

    def respond(self, body=BODY, status=200, headers=b""):
        self.tls.makefile.return_value = io.BytesIO(
            f"HTTP/1.1 {status} Reply\r\n".encode() + headers + b"\r\n" + body)

    def test_pinned_ipv4_ipv6_single_dns_and_verified_tls(self):
        for family, address in [(socket.AF_INET, self.address),
                                (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))]:
            self.use_address(family, address)
            self.respond(headers=b"Subscription-Userinfo: upload=1; download=2; total=50\r\n")
            info = subscription.fetch(URL)
            self.assertEqual(info["usage"]["total"], 50)
            self.raw.connect.assert_called_with(address)
            self.dns.assert_called_once()
            self.dns.reset_mock()
            args, kwargs = self.wrap.call_args
            self.assertTrue(args[0].check_hostname)
            self.assertEqual(args[0].verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(kwargs["server_hostname"], "feed.example")
            request = self.tls.sendall.call_args.args[0]
            self.assertIn(b"Host: feed.example\r\n", request)
            self.assertIn(b"GET /private-marker?key=fake-secret HTTP", request)
            self.assertNotIn("fake-", str(info))

    def test_mixed_dns_denied_before_connect(self):
        self.dns.side_effect = None
        self.dns.return_value = [(socket.AF_INET, 1, 6, "", (ip, 443))
                                 for ip in ("93.184.216.34", "127.0.0.1")]
        with self.assertRaises(subscription.Notice):
            subscription.fetch(URL)
        self.socket.assert_not_called()

    def test_bad_urls_stop_before_dns(self):
        for url in ("https://u@feed.example", "https://@feed.example", "http://feed.example",
                    "https://feed.example:444/", "https://[::1]", "https://feed.example/a#b",
                    "https://feed.example/\na", "https://a.internal/", "https://127.0.0.1/"):
            with self.subTest(url=url), self.assertRaises(subscription.Notice):
                subscription.fetch(url)
        self.dns.assert_not_called()

    def test_redirect_rejected_without_followup(self):
        self.respond(status=302, headers=b"Location: https://other.example/fake-secret\r\n")
        with self.assertRaises(subscription.Notice) as error:
            subscription.fetch(URL)
        self.assertNotIn("fake-secret", str(error.exception))
        self.dns.assert_called_once()

    def test_oversize_and_malformed_body(self):
        for body in (b"x"*2_000_001, b"secret: [", b"proxies: [{}]", b"proxies: &a [*a]"):
            self.respond(body)
            self.use_address(socket.AF_INET, self.address)
            with self.assertRaises(subscription.Notice):
                subscription.fetch(URL)

    def test_offline_and_certificate_errors_masked(self):
        for target in (self.raw.connect, self.wrap):
            self.use_address(socket.AF_INET, self.address)
            target.side_effect = OSError("fake-secret")
            with self.assertRaises(subscription.Notice) as error:
                subscription.fetch(URL)
            self.assertNotIn("fake-secret", str(error.exception))
            target.side_effect = None

    def test_agent_request_to_private_catalog_and_public_listing(self):
        from unittest.mock import Mock
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT)))
        config = root/"config.yaml"
        config.write_text("proxy-groups: []")
        self.enterContext(patch.object(agent, "CONFIG", config))
        self.enterContext(patch.object(agent, "STATE", root/"private"))
        def request(action, **params):
            handler = object.__new__(agent.Handler)
            handler.connection = Mock()
            handler.rfile = io.BytesIO(json.dumps({"action": action, **params}).encode())
            handler.wfile = io.BytesIO()
            handler.handle()
            reply = handler.wfile.getvalue()
            for marker in (b"private-marker", b"fake-secret", b"fake-node"):
                self.assertNotIn(marker, reply)
            return json.loads(reply)
        self.assertTrue(request("subscription_add", name="Demo", url=URL)["ok"])
        self.assertEqual(request("subscriptions")["data"][0]["count"], 1)
        self.use_address(socket.AF_INET, self.address)
        self.respond(b"proxies: [fake-secret")
        self.assertFalse(request("subscription_update", name="Demo", url=URL+"2")["ok"])
        self.assertEqual(agent.saved_subscriptions()["Demo"]["url"], URL)
        self.assertTrue(request("subscription_delete", name="Demo")["ok"])
        self.assertFalse(request("subscriptions")["data"])

    def test_missing_or_ambiguous_usage(self):
        for header in (None, "upload=0;download=1", "upload=1;upload=2;download=3;total=5"):
            self.assertIsNone(subscription.usage(header))


class Changes(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT)))
        cfg_dir = root / "config"
        cfg_dir.mkdir()
        for attr, value in dict(BASE=root, CFG_DIR=cfg_dir, CONFIG=cfg_dir/"config.yaml",
                                STATE=root/"state").items():
            self.enterContext(patch.object(agent, attr, value))
        groups = ["REGION_" + r for r in ("SG", "JP", "TW", "US")]
        self.order = list(reversed(groups))
        self.config = {"mixed-port": 18880, "proxy-providers": {"Legacy": {"type": "file"}},
                       "proxy-groups": [{"name": "NON_HK_REGION", "proxies": groups},
                                        {"name": "AI_FIXED_US", "proxies": ["AI-US-DEDICATED"]},
                                        {"name": "AIRPORT_GENERAL", "include-all": True}],
                       "rules": ["MATCH,AIRPORT_GENERAL"]}
        agent.CONFIG.write_text(yaml.safe_dump(self.config))
        agent.CONFIG.chmod(0o600)
        self.before = agent.CONFIG.read_bytes()
        self.info = {"count": 1, "host": "feed.example", "usage": None}
        self.fetch = self.enterContext(patch.object(agent, "fetch", return_value=self.info))
        self.connect = self.enterContext(patch("socket.create_connection"))
        self.enterContext(patch("socket.getaddrinfo", side_effect=AssertionError("offline")))
        bindir = root / "bin"
        bindir.mkdir()
        self.cli = bindir / "mihomo"
        self.cli.write_text('#!/bin/sh\ntest "$1" = -t && test -f "$5"\n')
        self.cli.chmod(0o700)
        self.system = bindir / "systemctl"
        self.system.write_text('#!/bin/sh\necho active\n')
        self.system.chmod(0o700)
        self.enterContext(patch.dict(os.environ, {"PATH": str(bindir)}))

    def test_saved_lifecycle_protected_config_and_permissions(self):
        add = agent.subscription_edit("Demo", URL, False)
        self.assertFalse(add["enabled"])
        registry = agent.STATE/"subscriptions.json"
        initial = registry.stat()
        for name in ("Demo", "Other"):
            with self.assertRaises(subscription.Notice):
                agent.subscription_edit(name, URL, False)
        agent.subscription_edit("Demo", URL+"2", True)
        self.assertEqual(registry.stat().st_mode & 0o777, 0o600)
        self.assertEqual((initial.st_uid, initial.st_gid), (registry.stat().st_uid, registry.stat().st_gid))
        self.assertIn(URL+"2", registry.read_text())
        self.assertNotIn("private-marker", json.dumps(agent.subscriptions()))
        for op in (lambda: agent.subscription_delete("Legacy"),
                   lambda: agent.subscription_edit("Legacy", URL, True)):
            with self.assertRaises(subscription.Notice):
                op()
        agent.subscription_delete("Demo")
        self.assertEqual(agent.saved_subscriptions(), {})
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        self.connect.assert_not_called()

    def test_failed_update_preserves_saved_address(self):
        agent.subscription_edit("Demo", URL, False)
        self.fetch.side_effect = subscription.Notice("订阅不可用")
        with self.assertRaises(subscription.Notice):
            agent.subscription_edit("Demo", URL+"2", True)
        self.assertEqual(agent.saved_subscriptions()["Demo"]["url"], URL)

    def test_concurrent_distinct_adds(self):
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            list(pool.map(lambda n: agent.subscription_edit("Demo"+str(n), URL+str(n), False), range(4)))
        self.assertEqual(len(agent.saved_subscriptions()), 4)

    def test_catalog_commit_failure_preserves_old_file(self):
        agent.subscription_edit("Demo", URL, False)
        catalog = agent.STATE/"subscriptions.json"
        before = catalog.read_bytes()
        with patch.object(os, "replace", side_effect=OSError), self.assertRaises(OSError):
            agent.subscription_edit("Demo", URL+"2", True)
        self.assertEqual(catalog.read_bytes(), before)
        self.assertEqual(list(agent.STATE.glob(".f1console-*")), [])

    def test_concurrent_same_name_has_single_winner(self):
        import threading
        rendezvous = threading.Barrier(2)
        def fetch_once(url):
            rendezvous.wait(timeout=2)
            return self.info
        self.fetch.side_effect = fetch_once
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            attempts = [pool.submit(agent.subscription_edit, "Demo", URL+str(i), False)
                        for i in range(2)]
        self.assertEqual(sum(f.exception() is None for f in attempts), 1)
        self.assertEqual(list(agent.saved_subscriptions()), ["Demo"])

    def test_ingress_failure_restarts_and_rechecks_old_config(self):
        self.connect.side_effect = [OSError(), OSError(), contextlib.nullcontext()]
        now = [0.0]
        def expire(_):
            now[0] += 15
        with patch("agent.time.monotonic", side_effect=lambda: now[0]), patch(
                "agent.time.sleep", side_effect=expire), self.assertRaisesRegex(subscription.Notice, "已恢复"):
            agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        self.assertEqual(self.connect.call_count, 3)

    def test_preflight_failure_preserves_exact_bytes(self):
        self.cli.write_text("#!/bin/sh\nexit 1\n")
        with self.assertRaisesRegex(subscription.Notice, "预检"):
            agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        self.assertEqual(list(agent.CFG_DIR.glob(".console-*")), [])
        self.connect.assert_not_called()

    def test_restart_failure_restores_old_bytes_and_checks_recovery(self):
        marker = agent.BASE/"attempt"
        self.system.write_text(f'#!/bin/sh\nif test ! -f "{marker}"; then echo 1 > "{marker}"; exit 1; fi\necho active\n')
        with self.assertRaisesRegex(subscription.Notice, "已恢复"):
            agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        self.connect.assert_called_once_with(("127.0.0.1", 18880), timeout=2)
        self.assertFalse((agent.STATE/"last-change.json").exists())

    def test_double_restart_failure_reported(self):
        self.system.write_text("#!/bin/sh\nexit 1\n")
        with self.assertRaisesRegex(subscription.Notice, "恢复未能确认"):
            agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)

    def test_rollback_lan_when_loopback_fails(self):
        def connect(address, timeout):
            if address==("198.51.100.23", 18880):
                return contextlib.nullcontext()
            raise OSError
        self.connect.side_effect=connect
        with patch("agent.ingress.configured_hosts",return_value=["127.0.0.1","198.51.100.23"]):
            marker=agent.BASE/"first"
            self.system.write_text(f'#!/bin/sh\nif test ! -f "{marker}"; then echo 1 > "{marker}"; exit 1; fi\necho active\n')
            with self.assertRaisesRegex(subscription.Notice,"已恢复"):
                agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(),self.before)
        self.assertEqual([c.args[0][0] for c in self.connect.call_args_list],["127.0.0.1","198.51.100.23"])

    def test_restart_after_interrupt_before_commit(self):
        with patch("agent.restart_checked", side_effect=SystemExit), self.assertRaises(SystemExit):
            agent.reorder(self.order)
        receipt=agent.STATE/"pending.json"
        self.assertTrue(receipt.exists())
        self.assertNotEqual(agent.CONFIG.read_bytes(),self.before)
        self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
        agent.recover_pending()
        self.assertEqual(agent.CONFIG.read_bytes(),self.before)
        self.assertFalse(receipt.exists())

    def test_interrupt_after_confirmation_keeps_committed_config(self):
        with patch("agent.clear_pending",side_effect=SystemExit), self.assertRaises(SystemExit):
            agent.reorder(self.order)
        committed=agent.CONFIG.read_bytes()
        with patch("agent.restart_checked") as restart:
            agent.recover_pending()
            restart.assert_not_called()
        self.assertEqual(agent.CONFIG.read_bytes(),committed)
        self.assertFalse((agent.STATE/"pending.json").exists())

    def test_external_edit_during_restart_preserved_and_locked(self):
        foreign=b"external: edit"
        with patch("agent.restart_checked",side_effect=lambda _:agent.CONFIG.write_bytes(foreign)):
            with self.assertRaisesRegex(subscription.Notice,"未能确认"):
                agent.reorder(self.order)
        with self.assertRaisesRegex(subscription.Notice,"外部配置"):
            agent.recover_pending()
        with self.assertRaisesRegex(subscription.Notice,"等待恢复"):
            agent.apply({}, "region_priority")
        self.assertEqual(agent.CONFIG.read_bytes(),foreign)

    def test_no_space_before_receipt_leaves_original_intact(self):
        import errno
        save=agent.save_atomic
        def full(path,data):
            if path.name=="pending.json":raise OSError(errno.ENOSPC,"fake")
            save(path,data)
        with patch("agent.save_atomic",side_effect=full), self.assertRaises(OSError):
            agent.reorder(self.order)
        self.assertEqual(agent.CONFIG.read_bytes(),self.before)
        self.connect.assert_not_called()

    def test_new_token_excluded_from_receipts_and_rollback_backup(self):
        agent.subscription_edit("Demo",URL,False)
        agent.reorder(self.order)
        for path in agent.STATE.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(path.stat().st_uid,os.geteuid())
            if path.name!="subscriptions.json":
                self.assertNotIn(b"fake-secret",path.read_bytes())

    def kill_transaction(self, point):
        child = subprocess.run([sys.executable, str(ROOT/"tests/crash_worker.py"), str(agent.BASE), point],
                               capture_output=True, timeout=5)
        self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
        self.assertTrue(agent.has_pending())

    def test_sigkill_before_replace_healthy_old_skips_restart(self):
        self.kill_transaction("before_replace")
        with patch("agent.restart_checked") as restart:
            self.assertEqual(agent.retry_recovery()["outcome"], "rolled_back")
            restart.assert_not_called()
        self.connect.assert_called_once()
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        self.assertFalse(agent.has_pending())

    def test_old_file_unhealthy_restarted_before_clearing(self):
        self.kill_transaction("before_replace")
        with patch("agent.require_running", side_effect=[subscription.Notice("未就绪"),None]) as check:
            self.assertFalse(agent.retry_recovery()["applied"])
        self.assertEqual(check.call_count, 2)

    def test_sigkill_after_replace_restores_exact_bytes(self):
        self.kill_transaction("after_replace")
        with patch("agent.restart_checked") as restart:
            self.assertFalse(agent.retry_recovery()["applied"])
            restart.assert_called_once_with(self.config)
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)

    def test_sigkill_after_commit_does_not_repeat_activation(self):
        self.kill_transaction("after_commit")
        committed = agent.CONFIG.read_bytes()
        with patch("agent.restart_checked") as restart:
            self.assertTrue(agent.retry_recovery()["applied"])
            restart.assert_not_called()
        self.assertEqual(agent.CONFIG.read_bytes(), committed)
        self.assertEqual(agent.retry_recovery()["outcome"], "unchanged")

    def test_committed_cleanup_errors_are_retryable(self):
        with patch("agent.clear_pending", side_effect=PermissionError):
            result = agent.reorder(self.order)
            self.assertTrue(result["applied"])
            self.assertTrue(result["cleanup_pending"])
            self.assertTrue(agent.retry_recovery()["cleanup_pending"])
        with patch("agent.restart_checked") as restart:
            self.assertFalse(agent.retry_recovery()["cleanup_pending"])
            restart.assert_not_called()
        self.assertFalse(agent.has_pending())

    def test_unlink_done_directory_sync_failed(self):
        def fail_sync():
            (agent.STATE/"pending.json").unlink()
            raise OSError("injected fsync failure")
        with patch("agent.clear_pending", side_effect=fail_sync):
            self.assertTrue(agent.reorder(self.order)["cleanup_pending"])
        self.assertTrue(agent.has_pending())
        self.assertTrue(agent.retry_recovery()["applied"])
        self.assertFalse(agent.has_pending())

    def test_restored_cleanup_retry_keeps_healthy_old_service(self):
        self.kill_transaction("after_replace")
        with patch("agent.clear_pending", side_effect=OSError):
            first = agent.retry_recovery()
        self.assertEqual(first["outcome"], "rolled_back")
        self.assertTrue(first["cleanup_pending"])
        with patch("agent.restart_checked") as restart:
            result = agent.retry_recovery()
        restart.assert_not_called()
        self.assertFalse(result["cleanup_pending"])
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)

    def test_unknown_old_bytes_during_interrupted_rollback_require_restart(self):
        self.kill_transaction("after_replace")
        with patch("agent.restart_checked", side_effect=SystemExit), self.assertRaises(SystemExit):
            agent.retry_recovery()
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)
        with patch("agent.restart_checked") as restart:
            self.assertFalse(agent.retry_recovery()["applied"])
            restart.assert_called_once()

    def test_legacy_receipt_recovered_conservatively(self):
        self.kill_transaction("before_replace")
        path = agent.STATE/"pending.json"
        receipt = json.loads(path.read_bytes())
        del receipt["phase"]
        path.write_text(json.dumps(receipt))
        with patch("agent.restart_checked") as restart:
            self.assertFalse(agent.retry_recovery()["applied"])
            restart.assert_called_once()

    def test_mismatched_commit_digest_retains_receipt(self):
        self.kill_transaction("after_commit")
        path = agent.STATE/"last-change.json"
        marker = json.loads(path.read_bytes())
        marker["new"] = marker["new"][::-1]
        path.write_text(json.dumps(marker))
        with self.assertRaisesRegex(subscription.Notice,"不一致"):
            agent.retry_recovery()
        self.assertTrue(agent.has_pending())
        self.connect.assert_not_called()

    def test_external_edit_during_recovery_check_preserved(self):
        self.kill_transaction("after_commit")
        with patch("agent.require_running", side_effect=lambda c:agent.CONFIG.write_bytes(b"foreign")):
            with self.assertRaisesRegex(subscription.Notice,"外部修改"):
                agent.retry_recovery()
        self.assertTrue(agent.has_pending())
        self.assertEqual(agent.CONFIG.read_bytes(), b"foreign")

    def test_disk_full_on_commit_restores_old_config(self):
        import errno
        save = agent.save_atomic
        def full(path, data):
            if path.name=="last-change.json":
                raise OSError(errno.ENOSPC, "injected")
            save(path,data)
        with patch("agent.save_atomic",side_effect=full), self.assertRaisesRegex(subscription.Notice,"已恢复"):
            agent.reorder(self.order)
        self.assertFalse(agent.has_pending())
        self.assertEqual(agent.CONFIG.read_bytes(), self.before)

    def test_success_reorders_only_selected_group(self):
        self.assertTrue(agent.reorder(self.order)["applied"])
        self.config["proxy-groups"][0]["proxies"] = self.order
        self.assertEqual(agent.cfg(), self.config)
        self.assertEqual(next(agent.STATE.glob("backup-*")).read_bytes(), self.before)
