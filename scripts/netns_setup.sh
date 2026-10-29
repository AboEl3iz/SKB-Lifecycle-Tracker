#!/usr/bin/env bash
# scripts/netns_setup.sh
# Sets up isolated network namespaces (ns_client <-> ns_server) connected via a veth pair.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

echo "==> Setting up network namespaces (ns_client <-> ns_server)..."

# Check if namespaces and veth pair already exist and are functional
if ip netns list | grep -qw "ns_server" && ip netns list | grep -qw "ns_client" && \
   ip -n ns_server link show veth_server >/dev/null 2>&1 && \
   ip -n ns_client link show veth_client >/dev/null 2>&1; then
    echo "==> Network namespaces (ns_client <-> ns_server) already active and functional."
    echo "    Preserving existing interfaces to maintain running tracer attachments."
else
    # 0. Clean up any broken/stale state
    ip netns del ns_client 2>/dev/null || true
    ip netns del ns_server 2>/dev/null || true

    # 1. Create the Namespaces
    ip netns add ns_client
    ip netns add ns_server

    # 2. Create the veth pair
    ip link add veth_client type veth peer name veth_server

    # 3. Move each side into its Namespace
    ip link set veth_client netns ns_client
    ip link set veth_server netns ns_server

    # 4. Configure IPs, MTU, and bring interfaces up
    ip netns exec ns_client ip addr add 10.0.0.1/24 dev veth_client
    ip netns exec ns_client ip link set dev veth_client mtu 1500
    ip netns exec ns_client ip link set veth_client up
    ip netns exec ns_client ip link set lo up

    ip netns exec ns_server ip addr add 10.0.0.2/24 dev veth_server
    ip netns exec ns_server ip link set dev veth_server mtu 1500
    ip netns exec ns_server ip link set veth_server up
    ip netns exec ns_server ip link set lo up
fi

# 5. Disable TSO, GSO, and GRO on the client so it segments into 1500-byte packets
# This allows the receiver's GRO and TCP Coalescing engines to merge real individual packets
echo "--> Disabling TSO/GSO/GRO on veth_client (forcing 1500-byte wire packets)..."
ip netns exec ns_client ethtool -K veth_client tso off gso off gro off 2>/dev/null || true

# 6. Verify connectivity
echo "==> Verifying connectivity between namespaces..."
if ip netns exec ns_client ping -c 2 -W 1 10.0.0.2 >/dev/null 2>&1; then
    echo "==> Setup complete! Topology:"
    echo "    ns_client (10.0.0.1/24 on veth_client, MTU 1500, offloads OFF)"
    echo "       <== veth ==>"
    echo "    ns_server (10.0.0.2/24 on veth_server, MTU 1500, GRO ON)"
else
    echo "==> Warning: ping check failed, please verify kernel network configuration."
fi
