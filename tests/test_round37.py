import contextlib
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import agent
import ingress
import resolve_host
import subscription


class ListenerEvidence(unittest.TestCase):
    def setUp(self):
        self.proc = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT)))
        (self.proc/"fd").mkdir()
        (self.proc/"net").mkdir()
        (self.proc/"fd"/"4").symlink_to("socket:[42]")
        (self.proc/"net"/"tcp").write_text("header\n")
        (self.proc/"net"/"tcp6").write_text("header\n")

    def listen(self, ip, port, inode):
        v6 = ":" in ip
        packed = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, ip)
        hexip = "".join(f"{int.from_bytes(packed[i:i+4], sys.byteorder):08X}"
                        for i in range(0, len(packed), 4))
        with (self.proc/"net"/("tcp6" if v6 else "tcp")).open("a") as table:
            table.write(f"0: {hexip}:{port:04X} 0 0A 0 0 0 0 0 {inode}\n")

    def test_lan_listener_found_despite_default_config(self):
        self.listen("198.51.100.23", 18111, 42)
        self.listen("127.0.0.1", 17896, 42)
        self.listen("127.0.0.1", 18111, 99)
        owned_listeners = ingress.owned_listeners
        with patch("agent.run", side_effect=[Mock(returncode=0, stdout="active"),
                                          Mock(returncode=0, stdout="42")]), patch(
                "agent.ingress.owned_listeners", side_effect=lambda _, p: owned_listeners(self.proc, p)), patch(
                "socket.create_connection", side_effect=self.lan_only) as connect:
            agent.require_running({"mixed-port":18111,"external-controller":"127.0.0.1:17896"})
        self.assertEqual(connect.call_args.args[0], ("198.51.100.23", 18111))

    @staticmethod
    def lan_only(address, timeout):
        if address != ("198.51.100.23", 18111):
            raise OSError
        return contextlib.nullcontext()

    def test_wildcard_ipv4_ipv6_and_other_process_exclusion(self):
        self.listen("0.0.0.0", 10001, 42)
        self.listen("::", 10001, 42)
        self.listen("::1", 10002, 99)
        self.assertEqual(ingress.owned_listeners(self.proc, 10001), ["127.0.0.1", "::1"])
        self.assertEqual(ingress.owned_listeners(self.proc, 10002), [])

    def test_config_fallback_rejects_unowned_address_and_hostnames(self):
        config = {"allow-lan":True, "bind-address":"198.51.100.23"}
        with patch("socket.socket") as sock:
            self.assertEqual(ingress.configured_hosts(config), ["198.51.100.23"])
            sock.return_value.__enter__.return_value.bind.side_effect = OSError()
            self.assertEqual(ingress.configured_hosts(config), [])
        self.assertEqual(ingress.configured_hosts({**config,"bind-address":"unknown.example"}), [])
        self.assertEqual(ingress.configured_hosts({"allow-lan":True}), ["127.0.0.1","::1"])

    def test_no_probe_of_control_port(self):
        with patch("socket.create_connection") as connect, self.assertRaises(subscription.Notice):
            agent.require_running({"mixed-port":1234,"external-controller":"127.0.0.1:1234"})
        connect.assert_not_called()


class ResolverLifecycle(unittest.TestCase):
    def test_stalled_resolver_is_reaped_and_slot_reusable(self):
        children = []
        popen = subprocess.Popen
        def observe(*a, **kw):
            child = popen(*a, **kw)
            children.append(child)
            return child
        with patch.object(subscription, "DNS_COMMAND", (sys.executable,"-I","-S","-c",
                                                       "import time; time.sleep(30)")), patch.object(
                subscription, "DNS_TIMEOUT", 0.1), patch("subprocess.Popen", side_effect=observe), patch(
                "agent.cfg", return_value={}), patch("agent.saved_subscriptions", return_value={}):
            for _ in range(5):
                with self.assertRaisesRegex(subscription.Notice, "解析超时"):
                    agent.subscription_edit("Demo","https://demo.example/fake",False)
        self.assertEqual(len(children), 5)
        self.assertTrue(all(p.returncode is not None and p.returncode != 0 for p in children))

    def test_worker_receives_hostname_only_and_parses_ipv6(self):
        result = Mock(stdout='[[10,1,6,"",["2606:4700:4700::1111",443,0,0]]]')
        with patch("subprocess.run", return_value=result) as run:
            self.assertEqual(subscription.resolve("demo.example")[0][4],
                             ("2606:4700:4700::1111",443,0,0))
            self.assertEqual(run.call_args.kwargs["input"], "demo.example")
        with patch("socket.getaddrinfo") as dns:
            resolve_host.lookup("demo.example")
            dns.assert_called_once_with("demo.example.",443,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
