TARGET = target/release/skb-tracer
BPF_DIR = src/bpf
BPF_SRC = $(BPF_DIR)/skb_tracer.bpf.c
VMLINUX = $(BPF_DIR)/vmlinux.h

.PHONY: all build release vmlinux test check clean run help \
        run-server run-client \
        env-setup env-teardown test-all test-gso test-coalesce test-gro test-drops test-flood

all: build

## Dump kernel BTF to vmlinux.h
vmlinux:
	@echo "==> Dumping /sys/kernel/btf/vmlinux into $(VMLINUX)..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > $(VMLINUX)

## Build debug binary
build:
	cargo build

## Build production release binary
release:
	cargo build --release

## Run cargo check
check:
	cargo check

## Run unit and integration tests
test:
	cargo test

## Run skb-tracer with root privileges (sudo)
run: build
	sudo ./target/debug/skb-tracer

## Run skb-tracer inside ns_server attached to veth_server
run-server: build
	sudo ip netns exec ns_server sh -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true; ./target/debug/skb-tracer -i veth_server'

## Run skb-tracer inside ns_client attached to veth_client
run-client: build
	sudo ip netns exec ns_client sh -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true; ./target/debug/skb-tracer -i veth_client'

## Environment setup & teardown
env-setup:
	@sudo ./scripts/netns_setup.sh

env-teardown:
	@sudo ./scripts/netns_teardown.sh

## Kernel mutation test scenarios
test-all: env-setup
	@sudo ./scripts/run_all_tests.sh

test-gso:
	@sudo ./scripts/test_gso.sh

test-coalesce:
	@sudo ./scripts/test_coalesce.sh

test-gro:
	@sudo ./scripts/test_gro.sh

test-drops:
	@sudo ./scripts/test_drops.sh

test-flood:
	@sudo ./scripts/test_flood.sh

## Clean build artifacts
clean:
	cargo clean
	rm -f $(BPF_DIR)/*.o

help:
	@echo "Usage: make [target]"
	@echo "  build         - Compile debug binary"
	@echo "  release       - Compile optimized release binary"
	@echo "  check         - Type check without codegen"
	@echo "  test          - Run Rust unit tests"
	@echo "  run           - Build and run skb-tracer with sudo (all interfaces)"
	@echo "  run-server    - Run skb-tracer inside ns_server filtered to veth_server"
	@echo "  run-client    - Run skb-tracer inside ns_client filtered to veth_client"
	@echo "  clean         - Clean build artifacts"
	@echo "  vmlinux       - Generate src/bpf/vmlinux.h from running kernel"
	@echo ""
	@echo "Testing Environment Targets:"
	@echo "  env-setup     - Create ns_client & ns_server namespaces with veth pair"
	@echo "  env-teardown  - Destroy test namespaces and veth interfaces"
	@echo "  test-all      - Run all 5 mutation scenarios sequentially"
	@echo "  test-gso      - Scenario 1: Force GSO Segmentation & skb_split (64KB buffer)"
	@echo "  test-coalesce - Scenario 2: Force tcp_try_coalesce (Slow Reader trick)"
	@echo "  test-gro      - Scenario 3: Force GRO aggregation (NAPI coalescing)"
	@echo "  test-drops    - Scenario 4: Force packet drops via iptables & tc netem"
	@echo "  test-flood    - Scenario 5: Maximum throughput stress test (UDP flood)"
