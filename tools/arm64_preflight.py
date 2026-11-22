"""Read-only evidence for a lab listener. No connections or service operations."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from ingress import bound_listeners


def inspect(pid, port, expected, proc=Path("/proc")):
    target = proc / str(pid)
    same_namespace = os.path.samefile(proc/"self/ns/net", target/"ns/net")
    same_user = target.stat().st_uid == os.geteuid()
    addresses = bound_listeners(target, port) if same_namespace and same_user else None
    return {"同一网络命名空间": same_namespace, "同一用户": same_user,
            "实际监听地址": addresses, "端口": port,
            "监听匹配": addresses is not None and set(addresses) == {str(expected)}}


def main():
    parser = argparse.ArgumentParser(description="只读核对隔离 ARM64 Linux 中的指定进程监听")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", type=ipaddress.ip_address, required=True)
    args = parser.parse_args()
    if args.pid <= 0 or not 1 <= args.port <= 65535:
        parser.error("PID 或端口超出范围")
    arm = platform.system() == "Linux" and platform.machine().lower() in ("aarch64","arm64")
    report = {"ARM64 Linux": arm, "通过": False}
    if arm:
        try:
            report.update(inspect(args.pid, args.port, args.bind))
            report["通过"] = report["监听匹配"]
        except OSError:
            report["原因"] = "进程不存在或无法读取进程证据"
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["通过"] else 1


if __name__ == "__main__":
    sys.exit(main())
