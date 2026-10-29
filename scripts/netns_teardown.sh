#!/usr/bin/env bash
# scripts/netns_teardown.sh
# Destroys ns_client and ns_server namespaces, automatically removing veth interfaces.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

echo "==> Cleaning up network namespaces..."
ip netns del ns_client 2>/dev/null || true
ip netns del ns_server 2>/dev/null || true

echo "==> Teardown complete. All namespaces and veth pairs removed."
