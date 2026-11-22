"""Private snapshot storage and process ownership. All mutations are serialized by UI."""
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

import yaml
import subscription


def parse_snapshot(body):
    nodes = []
    for raw in yaml.safe_load(body)["proxies"]:
        # No provider-controlled dialers, local file paths, plugins or routing.
        if raw["type"] not in ("socks5", "http") or set(raw) - {
            "type", "name", "server", "port", "username", "password", "tls"
        }:
            raise ValueError()
        address = str(ipaddress.ip_address(raw["server"]))
        if not subscription.public_address(address) or type(raw["port"]) is not int or not 1 <= raw["port"] <= 65535:
            raise ValueError()
        if type(raw.get("tls", False)) is not bool:
            raise ValueError()
        node = dict(raw, name=f"upstream-{len(nodes)+1}", server=address)
        if any(not isinstance(node[k], str) for k in ("username", "password") if k in node):
            raise ValueError()
        nodes.append(node)
    return nodes


def save(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(json.dumps(value).encode())
            f.flush()
            os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


class Runtime:
    def __init__(self, directory):
        self.dir = Path(directory)
        self.proc = None
        self.path = self.dir / "state.json"
        if not self.path.exists():
            save(self.path, dict(admin=secrets.token_urlsafe(24), proxy=secrets.token_urlsafe(24),
                                 saved=[], active=[]))
        self.state = json.loads(self.path.read_text())
        if self.state["active"]:
            try:
                self.start(self.state["active"])
            except (OSError, ValueError, subprocess.SubprocessError):
                self.stop()

    def commit(self, **changes):
        state = self.state | changes
        save(self.path, state)
        self.state = state

    def config(self, nodes):
        return {"mixed-port": 17890, "allow-lan": True, "authentication": ["client:"+self.state["proxy"]],
                "mode": "rule", "log-level": "silent", "proxies": nodes,
                "rules": ["MATCH,"+nodes[0]["name"]], "ipv6": False}

    def check(self, nodes):
        cfg = self.dir / "candidate.json"
        save(cfg, self.config(nodes))
        try:
            subprocess.run(["mihomo", "-t", "-d", str(self.dir), "-f", str(cfg)], check=True,
                           timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            cfg.unlink(missing_ok=True)

    def healthy(self):
        if not self.proc or self.proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", 17890), .3) as sock:
                sock.sendall(b"\x05\x01\x02")
                with sock.makefile("rb") as stream:
                    return stream.read(2) == b"\x05\x02"
        except OSError:
            return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def start(self, nodes):
        cfg = self.dir / "running.json"
        save(cfg, self.config(nodes))
        self.proc = subprocess.Popen(["mihomo", "-d", str(self.dir), "-f", str(cfg)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.healthy():
                return
            if self.proc.poll() is not None:
                break
            time.sleep(.1)
        self.stop()
        raise ValueError()

    def switch(self, nodes):
        old = self.state["active"]
        if nodes:
            self.check(nodes)
        self.stop()
        try:
            if nodes:
                self.start(nodes)
            self.commit(active=nodes)
        except Exception:
            self.stop()
            if old:
                self.start(old)
            raise
