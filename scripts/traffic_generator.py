#!/usr/bin/env python3
"""
scripts/traffic_generator.py
Self-contained, dependency-free traffic generator for kernel SKB mutation testing.
"""

import argparse
import socket
import sys
import time


def run_slow_server(host: str, port: int, delay_s: float = 0.1):
    """Scenario 2: Slow reader server to accumulate data in socket receive queue."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    print(f"[*] Slow server listening on {host}:{port} (delay={delay_s*1000:.0f}ms/recv)...")
    
    try:
        conn, addr = s.accept()
        print(f"[*] Accepted connection from {addr}")
        total_bytes = 0
        while True:
            time.sleep(delay_s)
            data = conn.recv(4096)
            if not data:
                break
            total_bytes += len(data)
        print(f"[*] Connection closed. Read {total_bytes} bytes.")
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


def run_fast_sender(host: str, port: int, duration_s: float = 5.0):
    """Scenario 2: Fast TCP sender pushing continuous data."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"[*] Connected to {host}:{port}, blasting data for {duration_s}s...")
    chunk = b"X" * 65536
    start = time.time()
    total_bytes = 0
    try:
        while time.time() - start < duration_s:
            s.sendall(chunk)
            total_bytes += len(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        s.close()
    print(f"[*] Sender finished. Sent {total_bytes / (1024*1024):.2f} MB in {time.time() - start:.2f}s.")


def run_echo_server(host: str, port: int):
    """Fast sink server for GSO and GRO tests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"[*] Sink server listening on {host}:{port}...")
    try:
        while True:
            conn, _ = s.accept()
            while True:
                data = conn.recv(65536)
                if not data:
                    break
            conn.close()
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


def run_large_buffer_client(host: str, port: int, chunk_size: int = 65536, duration_s: float = 5.0):
    """Scenario 1: Send large chunks (e.g. 64KB) over TCP to force GSO segmentation."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((host, port))
    print(f"[*] Sending {chunk_size}-byte buffers to {host}:{port} for {duration_s}s...")
    chunk = b"\xAA" * chunk_size
    start = time.time()
    total = 0
    while time.time() - start < duration_s:
        s.sendall(chunk)
        total += len(chunk)
    s.close()
    print(f"[*] Finished sending {total / (1024*1024):.2f} MB.")


def run_udp_flood(host: str, port: int, duration_s: float = 5.0, packet_size: int = 1400):
    """Scenario 5: UDP blast at maximum throughput."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"U" * packet_size
    print(f"[*] Flooding UDP to {host}:{port} with {packet_size}-byte datagrams for {duration_s}s...")
    start = time.time()
    count = 0
    while time.time() - start < duration_s:
        s.sendto(payload, (host, port))
        count += 1
    s.close()
    elapsed = time.time() - start
    mb_sent = (count * packet_size) / (1024 * 1024)
    print(f"[*] Sent {count} packets ({mb_sent:.2f} MB) in {elapsed:.2f}s ({count/elapsed:.0f} pkts/s).")


def main():
    parser = argparse.ArgumentParser(description="SKB Tracer Network Traffic Generator")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Slow server (for coalesce)
    p_slow = subparsers.add_parser("slow_server", help="Run slow TCP receiver to force tcp_try_coalesce")
    p_slow.add_argument("--host", default="10.0.0.2")
    p_slow.add_argument("--port", type=int, default=9999)
    p_slow.add_argument("--delay", type=float, default=0.1)

    # Fast sender (for coalesce)
    p_fast = subparsers.add_parser("fast_sender", help="Run fast TCP sender to fill socket queue")
    p_fast.add_argument("--host", default="10.0.0.2")
    p_fast.add_argument("--port", type=int, default=9999)
    p_fast.add_argument("--duration", type=float, default=5.0)

    # Sink server (for GSO/GRO)
    p_sink = subparsers.add_parser("sink_server", help="Run high-speed sink TCP receiver")
    p_sink.add_argument("--host", default="10.0.0.2")
    p_sink.add_argument("--port", type=int, default=5201)

    # GSO client (large buffers)
    p_gso = subparsers.add_parser("gso_client", help="Send 64KB TCP buffers to trigger GSO segmentation")
    p_gso.add_argument("--host", default="10.0.0.2")
    p_gso.add_argument("--port", type=int, default=5201)
    p_gso.add_argument("--chunk", type=int, default=65536)
    p_gso.add_argument("--duration", type=float, default=5.0)

    # UDP flood
    p_udp = subparsers.add_parser("udp_flood", help="Send rapid UDP packets for stress testing")
    p_udp.add_argument("--host", default="10.0.0.2")
    p_udp.add_argument("--port", type=int, default=5201)
    p_udp.add_argument("--duration", type=float, default=5.0)
    p_udp.add_argument("--size", type=int, default=1400)

    args = parser.parse_args()

    if args.mode == "slow_server":
        run_slow_server(args.host, args.port, args.delay)
    elif args.mode == "fast_sender":
        run_fast_sender(args.host, args.port, args.duration)
    elif args.mode == "sink_server":
        run_echo_server(args.host, args.port)
    elif args.mode == "gso_client":
        run_large_buffer_client(args.host, args.port, args.chunk, args.duration)
    elif args.mode == "udp_flood":
        run_udp_flood(args.host, args.port, args.duration, args.size)


if __name__ == "__main__":
    main()
