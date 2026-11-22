"""Find numeric mixed-port listeners owned by the service in its network namespace."""
import ipaddress
import socket
import sys


def loopbacks(address):
    if address == "0.0.0.0":
        return ["127.0.0.1"]
    if address == "::":
        return ["::1"]
    return [address]


def bound_listeners(process_dir, port):
    # None means process evidence is unavailable. An observed empty set means
    # the service has not opened a matching socket yet.
    try:
        inodes = set()
        for fd in (process_dir / "fd").iterdir():
            try:
                inodes.add(fd.readlink().name)
            except FileNotFoundError:
                continue
        hosts = []
        for table, family in (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6)):
            try:
                lines = (process_dir / "net" / table).read_text().splitlines()[1:]
            except FileNotFoundError:
                if table == "tcp6":
                    continue
                raise
            for line in lines:
                fields = line.split()
                if fields[3] != "0A" or f"socket:[{fields[9]}]" not in inodes:
                    continue
                raw, hexport = fields[1].split(":")
                if int(hexport, 16) != port:
                    continue
                packed = b"".join(int(raw[i:i+8], 16).to_bytes(4, sys.byteorder)
                                  for i in range(0, len(raw), 8))
                hosts.append(socket.inet_ntop(family, packed))
        return list(dict.fromkeys(hosts))
    except (OSError, IndexError, ValueError):
        return None


def owned_listeners(process_dir, port):
    bound = bound_listeners(process_dir, port)
    if bound is None:
        return None
    return list(dict.fromkeys(host for addr in bound for host in loopbacks(addr)))


def configured_hosts(config):
    bind = config.get("bind-address", "*")
    if not config.get("allow-lan", False):
        return ["127.0.0.1", "::1"]
    if bind == "*":
        return ["127.0.0.1", "::1"]
    if not isinstance(bind, str):
        return []
    try:
        ip = ipaddress.ip_address(bind.strip("[]"))
        if ip.is_multicast or ip.is_link_local:
            return []
        if not ip.is_unspecified and not ip.is_loopback:
            # Never turn an unverified configuration value into a remote probe.
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
            with socket.socket(family, socket.SOCK_STREAM) as check:
                check.bind((str(ip), 0))
        return loopbacks(str(ip))
    except (ValueError, OSError):
        return []
