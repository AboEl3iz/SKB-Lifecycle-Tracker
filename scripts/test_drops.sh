#!/usr/bin/env bash
# scripts/test_drops.sh
# Scenario 4: Generating Drops and Observing kfree_skb with Drop Reasons
# Generates packets dropped via Netfilter/iptables rules and tc netem qdisc.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP="10.0.0.2"
DROP_PORT="7777"

echo "==> [Scenario 4] Generating Kernel Drops and Drop Reasons (kfree_skb)..."

cleanup() {
    echo "--> Cleaning up drop rules..."
    ip netns exec ns_server iptables -D INPUT -p tcp --dport "${DROP_PORT}" -j DROP 2>/dev/null || true
    ip netns exec ns_server tc qdisc del dev veth_server root 2>/dev/null || true
}
trap cleanup EXIT

# 4A. Netfilter Drop (SKB_DROP_REASON_NETFILTER_DROP)
echo "--> Method A: Netfilter drop via iptables on port ${DROP_PORT}..."
ip netns exec ns_server iptables -A INPUT -p tcp --dport "${DROP_PORT}" -j DROP

echo "--> Sending SYN probes to trigger Netfilter drop..."
ip netns exec ns_client python3 -c "
import socket
for _ in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('${SERVER_IP}', ${DROP_PORT}))
    except Exception:
        pass
    finally:
        s.close()
"
echo "    Netfilter drop packets sent."

# 4B. Qdisc Drop via tc netem (SKB_DROP_REASON_QDISC_DROP)
echo "--> Method B: Qdisc drop via tc netem (50% random loss on veth_server)..."
ip netns exec ns_server tc qdisc add dev veth_server root netem drop 50% 2>/dev/null || \
ip netns exec ns_server tc qdisc change dev veth_server root netem drop 50%

echo "--> Sending UDP datagrams to trigger Qdisc drops..."
ip netns exec ns_client python3 "${DIR}/traffic_generator.py" udp_flood --host "${SERVER_IP}" --port 8888 --duration 3 --size 1024

echo "==> Scenario 4 complete. Expect SKB_OP_DROP events with drop reasons in skb-tracer."
