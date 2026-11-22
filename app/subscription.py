"""Fetch subscription metadata without giving the transport a second DNS lookup."""
from contextlib import closing, contextmanager
import http.client
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import re
import socket
import ssl
import threading
import urllib.parse

import yaml


class Notice(ValueError):
    """Fixed, public-facing error text."""


def public_address(address):
    ip = ipaddress.ip_address(address)
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return False
    if ip.version == 6:
        return (ip in ipaddress.ip_network("2000::/3") and not ip.sixtofour
                and not ip.teredo and not ip.ipv4_mapped)
    return True


def endpoint(url):
    if not isinstance(url, str) or len(url) > 3000 or not url.isascii() or re.search(r"[\x00-\x20\x7f\\#]", url):
        raise Notice("请输入有效的 HTTPS 订阅地址")
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (parts.scheme != "https" or len(host) > 253 or
            not re.fullmatch(label + r"(?:\." + label + r")+", host) or
            parts.netloc.lower() not in (host, host + ":443") or
            host.endswith((".local", ".lan", ".internal", ".localhost")) or
            host.rsplit(".", 1)[1].isdigit()):
        raise Notice("仅支持无登录信息的公网 HTTPS 域名和 443 端口")
    return host, (parts.path or "/") + ("?" + parts.query if parts.query else "")


def usage(header):
    values = {}
    for item in (header or "").split(";"):
        match = re.fullmatch(r"\s*(upload|download|total)=(\d{1,15})\s*", item, re.ASCII)
        if match:
            key, value = match.groups()
            if key in values:
                return None
            values[key] = int(value)
    if len(values) == 3:
        return values
    return None


def node_count(body):
    # Reject aliases/merges and deeply nested input before constructing objects.
    depth = events = 0
    for event in yaml.parse(body):
        events += 1
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
        if getattr(event, "anchor", None) or depth > 32 or events > 100000:
            raise Notice("订阅 YAML 结构过于复杂")
    data = yaml.safe_load(body)
    nodes = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 1200 or not all(
        isinstance(node, dict) and all(isinstance(node.get(k), str) and node[k].strip()
                                      for k in ("name", "type")) for node in nodes
    ):
        raise Notice("订阅需包含 1 至 1200 个具备名称和协议的节点")
    return len(nodes)


@contextmanager
def read_deadline(tls):
    expired = threading.Event()

    def interrupt():
        expired.set()
        try:
            tls.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    timer = threading.Timer(20, interrupt)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        timer.join()
    if expired.is_set():
        raise Notice("订阅读取超时")


DNS_COMMAND = (sys.executable, "-I", "-S", str(Path(__file__).with_name("resolve_host.py")))
DNS_TIMEOUT = 5


def resolve(host):
    try:
        # run() kills and waits for this child on timeout, including a stuck libc call.
        result = subprocess.run(DNS_COMMAND, input=host, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=DNS_TIMEOUT, check=True)
        return [(family, kind, proto, cname, tuple(addr))
                for family, kind, proto, cname, addr in json.loads(result.stdout)]
    except subprocess.TimeoutExpired:
        raise Notice("订阅域名解析超时") from None


def fetch(url, *, parse=None):
    try:
        host, target = endpoint(url)
        addresses = resolve(host)
        if not addresses or not all(f in (socket.AF_INET, socket.AF_INET6) and
                                    a[1] == 443 and public_address(a[0])
                                    for f, _, _, _, a in addresses):
            raise Notice("订阅域名包含非公网地址")
        family, kind, proto, _, addr = addresses[0]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        with socket.socket(family, kind, proto) as raw:
            raw.settimeout(15)
            raw.connect(addr)
            with context.wrap_socket(raw, server_hostname=host) as tls:
                with read_deadline(tls), closing(http.client.HTTPSConnection(host, context=context)) as conn:
                    conn.auto_open = False
                    conn.sock = tls
                    conn.request("GET", target, headers={"User-Agent": "clash.meta", "Connection": "close"})
                    with conn.getresponse() as response:
                        if response.status != 200:
                            raise Notice("订阅未返回成功响应；请使用最终地址")
                        expected = response.length
                        body = response.read(2_000_001)
                        if len(body) > 2_000_000:
                            raise Notice("订阅超过 2 MB")
                        if expected is not None and len(body) != expected:
                            raise Notice("订阅下载不完整")
                        if parse is not None:
                            node_count(body)
                            return parse(body)
                        return {"host": host, "count": node_count(body),
                                "usage": usage(response.getheader("Subscription-Userinfo"))}
    except Notice:
        raise
    except Exception:
        raise Notice("订阅读取失败，请检查地址、证书和 YAML 格式") from None
