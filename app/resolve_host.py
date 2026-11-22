"""One isolated libc lookup. Input is a hostname, never the subscription URL."""
import json
import socket
import sys


def lookup(host):
    return socket.getaddrinfo(host + ".", 443, type=socket.SOCK_STREAM,
                              proto=socket.IPPROTO_TCP)


if __name__ == "__main__":
    try:
        rows = lookup(sys.stdin.read(254))
        if not 1 <= len(rows) <= 256:
            sys.exit(1)
        json.dump(rows, sys.stdout)
    except (ValueError, OSError):
        sys.exit(1)
