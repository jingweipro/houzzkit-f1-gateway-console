import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
import arm64_preflight as lab


class LabEvidence(unittest.TestCase):
    def setUp(self):
        self.proc = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT)))
        (self.proc/"self/ns").mkdir(parents=True)
        (self.proc/"23/ns").mkdir(parents=True)
        self.self_ns = self.proc/"self/ns/net"
        self.target_ns = self.proc/"23/ns/net"
        self.self_ns.touch()
        os.link(self.self_ns, self.target_ns)
        (self.proc/"23/net").mkdir()
        (self.proc/"23/fd").mkdir()
        (self.proc/"23/fd/5").symlink_to("socket:[123]")
        (self.proc/"23/net/tcp").write_text(
            "header\n0: 00000000:49C0 0 0A 0 0 0 0 0 123\n")

    def inspect(self, address):
        return lab.inspect(23, 0x49C0, ipaddress.ip_address(address), self.proc)

    def test_raw_wildcard_distinguished_from_loopback(self):
        self.assertTrue(self.inspect("0.0.0.0")["监听匹配"])
        self.assertFalse(self.inspect("127.0.0.1")["监听匹配"])

    def test_namespace_mismatch_blocks_even_same_pid_and_port(self):
        self.target_ns.unlink()
        self.target_ns.touch()
        with patch.object(lab,"bound_listeners") as read:
            self.assertFalse(self.inspect("0.0.0.0")["监听匹配"])
            read.assert_not_called()

    def test_different_user_never_reads_socket_table(self):
        with patch("os.geteuid",return_value=os.geteuid()+1), patch.object(lab,"bound_listeners") as read:
            self.assertFalse(self.inspect("0.0.0.0")["监听匹配"])
            read.assert_not_called()

    def test_mac_preflight_returns_unverified_without_proc_access(self):
        with patch("platform.system",return_value="Darwin"), patch.object(lab,"inspect") as read, patch.object(
                sys,"argv",["preflight","--pid","1","--port","18880","--bind","127.0.0.1"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(lab.main(),1)
            self.assertFalse(json.loads(output.getvalue())["通过"])
            read.assert_not_called()
