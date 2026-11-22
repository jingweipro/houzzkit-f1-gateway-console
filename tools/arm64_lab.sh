#!/usr/bin/env bash
# Run in a disposable offline ARM64 Linux VM. The outer process changes no networking.
set -eu
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || { echo '需要隔离 ARM64 Linux'; exit 1; }
if [[ ${1:-} != --inside ]]; then
    [[ $EUID != 0 ]] || { echo '请使用普通测试用户'; exit 1; }
    mode=${1:-fake}
    [[ $mode == fake || $mode == mihomo ]] || exit 2
    exec unshare --user --map-root-user --net -- bash tools/arm64_lab.sh --inside "$(readlink /proc/self/ns/net)" "$mode"
fi
# Require a fresh namespace with only a down loopback device before changing its addresses.
[[ $EUID == 0 && $(readlink /proc/self/ns/net) != "$2" && $(ip -o link show | cut -d: -f2 | xargs) == lo ]] || exit 1
[[ $(ip -o link show lo) != *"<"*UP*">"* ]] || { echo '需要全新且未启用的回环接口'; exit 1; }
read -r inner outer length < /proc/self/uid_map
[[ $inner == 0 && $outer != 0 && $length == 1 ]] || { echo '需要普通用户创建的用户命名空间'; exit 1; }
mode=$3
[[ $mode == fake || $mode == mihomo ]] || exit 2
ip link set lo up
ip addr add 192.0.2.10/32 dev lo
lab=$(mktemp -d "$PWD/.round38-lab.XXXXXX")
origin=''
listener=''
cleanup() {
    for child in "$listener" "$origin"; do
        if [[ -n $child ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
    done
    rm -rf -- "$lab"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
mkdir "$lab/site"
echo round38-fixture > "$lab/site/check"
python3 -B -m http.server 18881 --bind 127.0.0.1 --directory "$lab/site" >"$lab/origin.log" 2>&1 &
origin=$!
for bind in 127.0.0.1 192.0.2.10 0.0.0.0; do
    host=$bind
    [[ $bind != 0.0.0.0 ]] || host=127.0.0.1
    if [[ $mode == fake ]]; then
        python3 -B -m http.server 18880 --bind "$bind" --directory "$lab/site" >"$lab/service.log" 2>&1 &
    else
        cat > "$lab/config.yaml" <<EOF
mixed-port: 18880
allow-lan: true
bind-address: "$bind"
mode: direct
log-level: warning
dns: {enable: false}
rules: ["MATCH,DIRECT"]
EOF
        "${MIHOMO_BIN:?需要测试环境中已核验的 Mihomo 绝对路径}" -d "$lab" -f "$lab/config.yaml" >"$lab/service.log" 2>&1 &
    fi
    listener=$!
    for ((i=0;i<50;i++)); do
        kill -0 "$listener"
        if python3 -B tools/arm64_preflight.py --pid "$listener" --port 18880 --bind "$bind" >"$lab/preflight.json"; then break; fi
        sleep .2
    done
    python3 -B tools/arm64_preflight.py --pid "$listener" --port 18880 --bind "$bind"
    if [[ $mode == fake ]]; then
        [[ $(curl -q -fsS --max-time 4 --noproxy '*' "http://$host:18880/check") == round38-fixture ]]
    else
        for protocol in http socks5h; do
            [[ $(curl -q -fsS --max-time 4 --noproxy '' --proxy "$protocol://$host:18880" http://127.0.0.1:18881/check) == round38-fixture ]]
        done
    fi
    echo "$mode $bind 验收通过"
    kill "$listener"; wait "$listener" || true; listener=''
done
