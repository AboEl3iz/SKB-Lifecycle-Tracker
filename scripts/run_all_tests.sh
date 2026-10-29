#!/usr/bin/env bash
# scripts/run_all_tests.sh
# Runs all 5 kernel mutation test scenarios sequentially against the isolated netns environment.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "    eBPF SKB Tracer — Kernel Mutation Test Suite"
echo "============================================================"

# Ensure network environment is ready
bash "${DIR}/netns_setup.sh"

echo ""
echo "--> Note: Ensure 'skb-tracer' is running in another terminal:"
echo "    sudo ./target/debug/skb-tracer"
echo "    (or: sudo ./target/debug/skb-tracer -i veth_server)"
echo ""
read -r -t 5 -p "Starting test suite in 5 seconds (press Enter to start immediately)..." || true
echo ""

echo ""
bash "${DIR}/test_gso.sh"
sleep 1

echo ""
bash "${DIR}/test_coalesce.sh"
sleep 1

echo ""
bash "${DIR}/test_gro.sh"
sleep 1

echo ""
bash "${DIR}/test_drops.sh"
sleep 1

echo ""
bash "${DIR}/test_flood.sh"

echo ""
echo "============================================================"
echo "  All 5 test scenarios completed successfully!"
echo "  Run 'make env-teardown' when finished to clean up namespaces."
echo "============================================================"
