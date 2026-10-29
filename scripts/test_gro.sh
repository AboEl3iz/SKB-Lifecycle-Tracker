#!/usr/bin/env bash
# scripts/test_gro.sh
# Scenario 3: Forcing GRO Aggregation (Generic Receive Offload)
# Enables GRO and sets flush timeout to encourage NAPI packet coalescing.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP="10.0.0.2"
PORT="5201"

echo "==> [Scenario 3] Forcing GRO Aggregation (skb_gro_receive)..."

# 1. Force sender to segment into 1500-byte wire packets so receiver GRO can merge them
echo "--> Disabling TSO/GSO/GRO on veth_client and ensuring MTU 1500..."
ip netns exec ns_client ethtool -K veth_client tso off gso off gro off 2>/dev/null || true
ip netns exec ns_client ip link set dev veth_client mtu 1500
ip netns exec ns_server ip link set dev veth_server mtu 1500

# 2. Ensure GRO is enabled on receiving interface and tune flush timeout
echo "--> Enabling GRO and tuning flush timeout on veth_server..."
ip netns exec ns_server ethtool -K veth_server gro on 2>/dev/null || true
ip netns exec ns_server ip link set dev veth_server gro_flush_timeout 20000 2>/dev/null || true

# 3. Start sink receiver
echo "--> Starting sink receiver in ns_server..."
if command -v iperf3 >/dev/null 2>&1; then
    ip netns exec ns_server iperf3 -s -p "${PORT}" -1 >/dev/null 2>&1 &
    SERVER_PID=$!
else
    ip netns exec ns_server python3 "${DIR}/traffic_generator.py" sink_server --host "${SERVER_IP}" --port "${PORT}" >/dev/null 2>&1 &
    SERVER_PID=$!
fi
trap 'kill -9 "${SERVER_PID}" 2>/dev/null || true' EXIT

sleep 0.5

# 3. Generate high packet rate traffic
echo "--> Generating high packet arrival rate from ns_client..."
if command -v iperf3 >/dev/null 2>&1; then
    ip netns exec ns_client iperf3 -c "${SERVER_IP}" -p "${PORT}" -P 4 -t 6
else
    ip netns exec ns_client python3 "${DIR}/traffic_generator.py" gso_client --host "${SERVER_IP}" --port "${PORT}" --chunk 1448 --duration 6
fi

echo "==> Scenario 3 complete. Expect SKB_OP_GRO_MERGE events in skb-tracer."
