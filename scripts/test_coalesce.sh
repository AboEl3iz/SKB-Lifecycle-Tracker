#!/usr/bin/env bash
# scripts/test_coalesce.sh
# Scenario 2: Forcing tcp_try_coalesce — The Slow Reader Trick
# Starts a slow-reading socket server in ns_server while rapidly blasting packets from ns_client.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP="10.0.0.2"
PORT="9999"

echo "==> [Scenario 2] Forcing TCP Coalescing (tcp_try_coalesce)..."

# 1. Force client to send small 1500-byte packets so they accumulate in socket queue
echo "--> Disabling TSO/GSO/GRO on veth_client (MTU 1500)..."
ip netns exec ns_client ethtool -K veth_client tso off gso off gro off 2>/dev/null || true
ip netns exec ns_client ip link set dev veth_client mtu 1500
ip netns exec ns_server ip link set dev veth_server mtu 1500

# 2. Start the slow-reading server in ns_server
echo "--> Starting slow TCP server (100ms sleep between reads) in ns_server..."
ip netns exec ns_server python3 "${DIR}/traffic_generator.py" slow_server --host "${SERVER_IP}" --port "${PORT}" --delay 0.1 >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill -9 "${SERVER_PID}" 2>/dev/null || true' EXIT

sleep 0.5

# 2. Push continuous high-speed stream from ns_client
echo "--> Blasting data rapidly from ns_client to fill the socket receive queue..."
ip netns exec ns_client python3 "${DIR}/traffic_generator.py" fast_sender --host "${SERVER_IP}" --port "${PORT}" --duration 5

echo "==> Scenario 2 complete. Expect SKB_OP_TCP_COALESCE events in skb-tracer."
