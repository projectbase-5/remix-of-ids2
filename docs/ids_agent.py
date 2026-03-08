"""
IDS Real-Time Agent — Port Scan, DoS & Flow Anomaly Detection
==============================================================
Main entry point for the local IDS agent.

Architecture:
    1. A daemon thread runs scapy's ``sniff()`` to capture IP packets.
    2. Each packet is immediately fed to all detection modules:
       - PortScanDetector  (15+ unique ports in 10 s)
       - DoSDetector       (100+ pps or 3x traffic spike, burst/sustained)
       - FlowAggregator    (per-flow statistics + anomaly detection)
    3. Every SEND_INTERVAL seconds the main loop:
       a) Drains the packet queue
       b) Calls ``check()`` on each detector to harvest alerts
       c) Calls ``detect_anomalies()`` on FlowAggregator
       d) Evaluates regex rules against payload previews
       e) Passes alerts through AlertManager for 60-s deduplication
       f) POSTs packets, alerts, flow summaries, and system metrics
          to the ``ingest-traffic`` Supabase edge function
    4. Every RULE_REFRESH_INTERVAL seconds, detection rules are
       fetched from the Supabase ``detection_rules`` table and
       detector thresholds are updated dynamically.

Prerequisites:
    pip install scapy psutil requests

Usage (requires admin/root for raw socket capture):
    sudo python docs/ids_agent.py

Configuration:
    Set SUPABASE_URL and AGENT_API_KEY below (or via environment vars).
"""

import os
import re
import time
import hashlib
import threading
import queue
import psutil

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy")
    exit(1)

from port_scan_detector import PortScanDetector
from dos_detector import DoSDetector
from flow_aggregator import FlowAggregator
from malware_behavior_detector import MalwareBehaviorDetector
from alert_manager import AlertManager
from rule_fetcher import RuleFetcher

# ============================================================
# CONFIGURATION — Update these values or set env vars
# ============================================================
SUPABASE_URL = os.environ.get(
    "SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co"
)
EDGE_FUNCTION_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = os.environ.get(
    "AGENT_API_KEY", "REPLACE_WITH_YOUR_SECRET_KEY"
)
SEND_INTERVAL = 2  # seconds between batch sends to Supabase
RULE_REFRESH_INTERVAL = 30  # seconds between rule refreshes
# ============================================================

# Thread-safe queue holding parsed packet dicts until the next send cycle.
packet_queue = queue.Queue(maxsize=500)

# Instantiate detection modules with their thresholds
port_scan_detector = PortScanDetector(threshold=15, window_seconds=10)
dos_detector = DoSDetector(pps_threshold=100, window_seconds=10)
flow_aggregator = FlowAggregator(window_seconds=10)
malware_detector = MalwareBehaviorDetector(window_seconds=60)

# AlertManager handles 60-second deduplication and HTTP dispatch
alert_manager = AlertManager(
    edge_function_url=EDGE_FUNCTION_URL,
    api_key=AGENT_API_KEY,
    dedup_window=60,
)

# Rule fetcher for dynamic rule sync from Supabase
rule_fetcher = RuleFetcher(SUPABASE_URL)
last_rule_refresh = 0.0

# Active regex rules (populated by refresh_rules)
active_regex_rules = []


def refresh_rules():
    """Fetch rules from Supabase and update detector configs."""
    global last_rule_refresh, active_regex_rules
    try:
        config = rule_fetcher.fetch()

        # Update port scan detector
        ps = config["port_scan"]
        if ps["threshold"] is not None or ps["window_seconds"] is not None:
            port_scan_detector.update_config(
                threshold=ps["threshold"],
                window_seconds=ps["window_seconds"],
            )
            print(f"[~] Port scan config updated: threshold={port_scan_detector.threshold}, window={port_scan_detector.window_seconds}s")

        # Update DoS detector
        dos = config["dos"]
        if dos["pps_threshold"] is not None or dos["spike_factor"] is not None:
            dos_detector.update_config(
                pps_threshold=dos["pps_threshold"],
                spike_factor=dos["spike_factor"],
            )
            print(f"[~] DoS config updated: pps_threshold={dos_detector.pps_threshold}, spike_factor={dos_detector.spike_factor}")

        # Update active regex rules
        active_regex_rules = config["regex_patterns"]

        rule_count = len(config["raw_rules"])
        regex_count = len(active_regex_rules)
        if rule_count > 0:
            print(f"[~] Loaded {rule_count} rules ({regex_count} regex patterns active)")

        last_rule_refresh = time.time()
    except Exception as e:
        print(f"[!] Rule refresh failed: {e}")


def evaluate_regex_rules(packet_data):
    """
    Evaluate active regex rules against packet payload.
    Returns a list of alert dicts for matched rules.
    """
    alerts = []
    payload = packet_data.get("payload_preview", "")
    if not payload or not active_regex_rules:
        return alerts

    now = time.time()
    window_key = int(now / 60)

    for rule in active_regex_rules:
        try:
            if re.search(rule["pattern"], payload, re.IGNORECASE):
                dedupe_key = hashlib.md5(
                    f"regex_{rule['name']}_{packet_data.get('source_ip', '')}_{window_key}".encode()
                ).hexdigest()
                alerts.append({
                    "alert_type": "Regex Match",
                    "severity": rule.get("severity", "medium"),
                    "source_ip": packet_data.get("source_ip", "0.0.0.0"),
                    "description": (
                        f"Regex rule '{rule['name']}' matched payload from "
                        f"{packet_data.get('source_ip', '?')} → "
                        f"{packet_data.get('destination_ip', '?')}:{packet_data.get('port', '?')}"
                    ),
                    "detection_module": "regex_engine",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "matched_rule": rule["name"],
                        "rule_id": rule.get("rule_id", ""),
                        "pattern": rule["pattern"],
                        "payload_snippet": payload[:200],
                    },
                })
        except re.error:
            # Skip invalid regex silently (already validated in fetcher)
            pass

    return alerts


def packet_callback(packet):
    """
    Scapy callback — invoked for every captured IP packet.

    Extracts source/dest IPs, protocol, port, flags, payload preview,
    then feeds the dict to each detector and enqueues it for batch sending.
    """
    if IP not in packet:
        return

    ts = time.time()

    data = {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
        "packet_size": len(packet),
        "flags": [],
        "port": 0,
        "timestamp": ts,
        "payload_preview": "",
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

    # Extract payload preview for regex matching
    if Raw in packet:
        try:
            raw_bytes = bytes(packet[Raw].load)
            data["payload_preview"] = raw_bytes[:256].decode("utf-8", errors="replace")
        except Exception:
            pass

    # Feed to all detectors in real time
    port_scan_detector.ingest(data)
    dos_detector.ingest(data)
    flow_aggregator.ingest(data)
    malware_detector.ingest(data)

    # Enqueue for batch sending; drop oldest if queue is full
    if packet_queue.full():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            pass
    packet_queue.put(data)


def start_sniffing():
    """Run scapy's blocking sniffer — meant to be called in a daemon thread."""
    print("[*] Packet sniffer started — capturing IP traffic...")
    sniff(filter="ip", prn=packet_callback, store=0)


def get_system_metrics():
    """Collect current CPU, memory, disk, and network health via psutil."""
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
    """
    Drain the packet queue, run detectors, and POST everything to
    the edge function in a single HTTP request.
    """
    import requests as req_lib

    # Drain packet queue
    packets = []
    while not packet_queue.empty():
        try:
            pkt = packet_queue.get_nowait()
            packets.append(pkt)
        except queue.Empty:
            break

    # Harvest alerts from all detectors
    all_alerts = []
    all_alerts.extend(port_scan_detector.check())
    all_alerts.extend(dos_detector.check())
    all_alerts.extend(flow_aggregator.detect_anomalies())

    # Malware behavior detection (uses flow summaries)
    current_flows = flow_aggregator.get_flows()
    all_alerts.extend(malware_detector.check(current_flows))

    # Evaluate regex rules against packets with payloads
    for pkt in packets:
        all_alerts.extend(evaluate_regex_rules(pkt))

    # Deduplicate and send alerts
    sent_count = 0
    if all_alerts:
        sent_count = alert_manager.process(all_alerts)

    metrics = get_system_metrics()

    # Prepare packets for sending (strip internal fields)
    send_packets = []
    for pkt in packets:
        send_pkt = {k: v for k, v in pkt.items() if k != "timestamp"}
        send_packets.append(send_pkt)

    # Get flow summaries for persistence
    flow_summaries = flow_aggregator.get_flow_summaries()

    payload = {
        "api_key": AGENT_API_KEY,
        "packets": send_packets,
        "system_metrics": metrics,
        "flow_summaries": flow_summaries,
    }

    try:
        resp = req_lib.post(
            EDGE_FUNCTION_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        pkt_count = len(send_packets)
        flows = flow_aggregator.get_flows()
        print(
            f"[+] Packets: {pkt_count} | Alerts: {sent_count} | "
            f"Flows: {len(flows)} | Flow Summaries: {len(flow_summaries)} | "
            f"CPU: {metrics['cpu_usage']}% | Status: {resp.status_code}"
        )
    except req_lib.exceptions.RequestException as e:
        print(f"[!] Send failed: {e}")


def main():
    """Entry point — validate config, start sniffer thread, loop forever."""
    global last_rule_refresh

    if AGENT_API_KEY == "REPLACE_WITH_YOUR_SECRET_KEY":
        print("ERROR: Set AGENT_API_KEY before running.")
        print("       Either set the env var or edit ids_agent.py.")
        print("       It must match the AGENT_API_KEY secret in your Supabase project.")
        exit(1)

    print("=" * 60)
    print("  IDS Real-Time Agent v2")
    print("  Port Scan + DoS (burst/sustained) + Flow Anomaly")
    print("  + Dynamic Rule Sync + Regex Engine")
    print("=" * 60)
    print(f"  Endpoint      : {EDGE_FUNCTION_URL}")
    print(f"  Send interval : {SEND_INTERVAL}s")
    print(f"  Rule refresh  : {RULE_REFRESH_INTERVAL}s")
    print(f"  Port scan     : >{port_scan_detector.threshold} ports in {port_scan_detector.window_seconds}s")
    print(f"  DoS flood     : >{dos_detector.pps_threshold} pps")
    print(f"  Flow fanout   : >{flow_aggregator.fanout_threshold} destinations")
    print(f"  Malware C2    : >{malware_detector.beacon_min_connections} conns, std<{malware_detector.beacon_max_interval_std}s")
    print(f"  Lateral move  : >{malware_detector.lateral_min_targets} internal targets")
    print(f"  Exfiltration  : >{malware_detector.exfil_byte_threshold / 1024:.0f} KB")
    print("=" * 60)

    # Initial rule fetch
    print("[*] Fetching detection rules from Supabase...")
    refresh_rules()

    # Start packet capture
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    print("[*] Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(SEND_INTERVAL)
            send_batch()

            # Periodic rule refresh
            if time.time() - last_rule_refresh >= RULE_REFRESH_INTERVAL:
                refresh_rules()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
