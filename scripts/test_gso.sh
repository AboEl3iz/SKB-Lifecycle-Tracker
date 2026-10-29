#!/usr/bin/env bash
# scripts/test_gso.sh
# Scenario 1: Forcing GSO Segmentation and skb_split
# Disables TSO/GSO on veth_client and transmits 64KB buffers to force software segmentation.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP="10.0.0.2"
PORT="5201"

echo "==> [Scenario 1] Forcing GSO Segmentation (skb_gso_segment / skb_split)..."

# 1. Disable TSO and GSO on the transmitting interface
echo "--> Disabling TSO and GSO on veth_client..."
ip netns exec ns_client ethtool -K veth_client tso off gso off 2>/dev/null || true

# 2. Start receiver inside ns_server
echo "--> Starting TCP sink server in ns_server on port ${PORT}..."
if command -v iperf3 >/dev/null 2>&1; then
    ip netns exec ns_server iperf3 -s -p "${PORT}" -1 >/dev/null 2>&1 &
    SERVER_PID=$!
else
    ip netns exec ns_server python3 "${DIR}/traffic_generator.py" sink_server --host "${SERVER_IP}" --port "${PORT}" >/dev/null 2>&1 &
    SERVER_PID=$!
fi

trap 'kill -9 "${SERVER_PID}" 2>/dev/null || true' EXIT
sleep 0.5

# 3. Transmit large buffers from ns_client
echo "--> Transmitting 64KB buffers from ns_client to ${SERVER_IP}:${PORT}..."
if command -v iperf3 >/dev/null 2>&1; then
    ip netns exec ns_client iperf3 -c "${SERVER_IP}" -p "${PORT}" -l 64K -t 5
else
    ip netns exec ns_client python3 "${DIR}/traffic_generator.py" gso_client --host "${SERVER_IP}" --port "${PORT}" --chunk 65536 --duration 5
fi

echo "==> Scenario 1 complete. Expect SKB_OP_GSO_SEGMENT events in skb-tracer."
