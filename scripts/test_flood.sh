#!/usr/bin/env bash
# scripts/test_flood.sh
# Scenario 5: Maximum Stress Test — High-rate UDP Flood
# Tests the Ring Buffer consumer and DAG engine under high packet throughput.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP="10.0.0.2"
PORT="5201"

echo "==> [Scenario 5] Maximum Stress Test (UDP Flood)..."

echo "--> Pushing maximum UDP traffic rate from ns_client to ns_server..."
if command -v iperf3 >/dev/null 2>&1; then
    ip netns exec ns_server iperf3 -s -p "${PORT}" -1 >/dev/null 2>&1 &
    SERVER_PID=$!
    trap 'kill -9 "${SERVER_PID}" 2>/dev/null || true' EXIT
    sleep 0.5
    ip netns exec ns_client iperf3 -c "${SERVER_IP}" -p "${PORT}" -u -b 0 -l 1400 -t 5
else
    ip netns exec ns_client python3 "${DIR}/traffic_generator.py" udp_flood --host "${SERVER_IP}" --port "${PORT}" --duration 5 --size 1400
fi

echo "==> Scenario 5 complete. Check skb-tracer session summary for event throughput and ring buffer health."
