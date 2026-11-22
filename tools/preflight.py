"""Evaluate a supplied HOS inventory on stdin without probing the machine or network."""
import json
import sys


def assess(inv):
    if not isinstance(inv, dict):
        raise ValueError
    ports = inv.get("occupied_tcp_ports")
    known_ports = isinstance(ports, list) and all(type(p) is int and 0 < p <= 65535 for p in ports)
    return {
        "目标系统为 HOUZZkit OS": inv.get("os") == "HOUZZkit OS",
        "处理器为 ARM64": inv.get("arch") in ("aarch64", "arm64"),
        "已记录 Linux 内核版本": isinstance(inv.get("kernel"), str) and
                                    inv["kernel"].startswith("Linux ") and len(inv["kernel"]) > 6,
        "模板管理端口 17681 可用": known_ports and 17681 not in ports,
        "非特权账户可写独立数据卷": inv.get("private_volume_writable") is True,
        "初始化资源完整": inv.get("resources_verified") is True,
    }


if __name__ == "__main__":
    try:
        checks = assess(json.load(sys.stdin))
    except (ValueError, TypeError):
        sys.exit("请输入设备清单 JSON 对象")
    for label, ok in checks.items():
        print(label, "通过" if ok else "未通过或缺少证据")
    sys.exit(0 if all(checks.values()) else 1)
