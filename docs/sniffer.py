"""
IDS Real-Time Packet Sniffer & System Metrics Agent
====================================================
⚠️  DEPRECATED — This is the legacy sniffer module.

For full IDS functionality including port scan detection, DoS detection,
flow analysis, and dynamic rule sync, use ids_agent.py instead:

    sudo python docs/ids_agent.py

This script is kept for reference only. It captures raw network packets
and sends them to the Supabase edge function but does NOT perform any
local detection or rule-based analysis.

Prerequisites:
    pip install scapy psutil requests

Usage (requires admin/root):
    sudo python sniffer.py
"""

import warnings
import time
import json
import threading
import queue
import requests
import psutil

warnings.warn(
    "sniffer.py is deprecated. Use ids_agent.py for full IDS functionality.",
    DeprecationWarning,
    stacklevel=2,
)

# Try importing scapy - guide user if not installed
try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy")
    exit(1)

# ============================================================
# CONFIGURATION — Update these values before running
# ============================================================
SUPABASE_URL = "https://saeofugyscjfgqqnqowk.supabase.co"
EDGE_FUNCTION_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = "REPLACE_WITH_YOUR_SECRET_KEY"  # Must match the secret in Supabase
SEND_INTERVAL = 2  # seconds between batches
# ============================================================

packet_queue = queue.Queue(maxsize=200)


def packet_callback(packet):
    """Extract fields from each captured packet."""
    if IP not in packet:
        return

    data = {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
        "packet_size": len(packet),
        "flags": [],
        "port": 0,
    }

    if TCP in packet:
        data["port"] = packet[TCP].dport
        flags = packet[TCP].flags
        if flags.S:
            data["flags"].append("SYN")
        if flags.A:
            data["flags"].append("ACK")
        if flags.F:
            data["flags"].append("FIN")
        if flags.R:
            data["flags"].append("RST")
        if flags.P:
            data["flags"].append("PSH")
    elif UDP in packet:
        data["port"] = packet[UDP].dport

    if packet_queue.full():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            pass
    packet_queue.put(data)


def start_sniffing():
    """Run the packet sniffer (blocking — runs in its own thread)."""
    print("[*] Packet sniffer started — capturing IP traffic...")
    sniff(filter="ip", prn=packet_callback, store=0)


def get_system_metrics():
    """Collect current system metrics using psutil."""
    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    net_counters = psutil.net_io_counters()
    connections = len(psutil.net_connections(kind="inet"))

    err_rate = (
        (net_counters.errin + net_counters.errout)
        / max(net_counters.packets_recv + net_counters.packets_sent, 1)
        * 100
    )
    network_health = max(0, min(100, 100 - err_rate))

    return {
        "cpu_usage": round(cpu, 1),
        "memory_usage": round(mem, 1),
        "disk_usage": round(disk, 1),
        "network_health": round(network_health, 1),
        "active_connections": connections,
    }


def send_batch():
    """Drain the packet queue and POST to the edge function."""
    packets = []
    while not packet_queue.empty():
        try:
            packets.append(packet_queue.get_nowait())
        except queue.Empty:
            break

    metrics = get_system_metrics()

    payload = {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "system_metrics": metrics,
    }

    try:
        resp = requests.post(
            EDGE_FUNCTION_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        pkt_count = len(packets)
        print(
            f"[+] Sent {pkt_count} packets | CPU {metrics['cpu_usage']}% | "
            f"MEM {metrics['memory_usage']}% | Status {resp.status_code}"
        )
    except requests.exceptions.RequestException as e:
        print(f"[!] Send failed: {e}")


def main():
    print("=" * 60)
    print("  ⚠️  DEPRECATED: Use ids_agent.py instead!")
    print("  This script does not perform local detection.")
    print("=" * 60)

    if AGENT_API_KEY == "REPLACE_WITH_YOUR_SECRET_KEY":
        print("ERROR: Please set AGENT_API_KEY in sniffer.py before running.")
        exit(1)

    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    print(f"[*] Sending data to {EDGE_FUNCTION_URL} every {SEND_INTERVAL}s")
    print("[*] Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(SEND_INTERVAL)
            send_batch()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
