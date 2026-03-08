"""
IDS Real-Time Agent — Full Pipeline
=====================================
Main entry point for the local IDS agent.

Architecture:
    1. A daemon thread runs scapy's ``sniff()`` to capture IP packets.
    2. Each packet is immediately fed to all detection modules:
       - PortScanDetector  (15+ unique ports in 10 s)
       - DoSDetector       (100+ pps or 3x traffic spike, burst/sustained)
       - FlowAggregator    (per-flow statistics + anomaly detection)
       - MalwareBehaviorDetector (C2 beaconing, lateral movement, exfil)
    3. Every SEND_INTERVAL seconds the main loop:
       a) Drains the packet queue
       b) Calls ``check()`` on each detector to harvest alerts
       c) Calls ``detect_anomalies()`` on FlowAggregator
       d) Evaluates regex rules against payload previews
       e) Enriches alerts with threat intelligence (IP reputation)
       f) Passes alerts through AlertManager for 60-s deduplication
       g) Updates asset discovery from observed packets
       h) POSTs packets, alerts, flow summaries, and system metrics
          to the ``ingest-traffic`` Supabase edge function
    4. Every RULE_REFRESH_INTERVAL seconds, detection rules are
       fetched from the Supabase ``detection_rules`` table.
    5. Every RISK_SCORING_INTERVAL seconds, host risk scores are
       recomputed and pushed to the database.
    6. High-severity alerts trigger automated response actions and
       multi-channel notifications.

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
import logging
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
from threat_intel_enricher import ThreatIntelEnricher
from asset_discovery import AssetDiscovery
from response_manager import ResponseManager
from notification_dispatcher import NotificationDispatcher, NotificationPayload
from risk_scoring_engine import compute_host_risk_scores, compute_network_risk, push_risk_scores
from alert_suppression_engine import AlertSuppressionEngine

logger = logging.getLogger("ids_agent")

# ============================================================
# CONFIGURATION — Update these values or set env vars
# ============================================================
SUPABASE_URL = os.environ.get(
    "SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co"
)
SUPABASE_KEY = os.environ.get(
    "SUPABASE_ANON_KEY", "YOUR_SUPABASE_ANON_KEY"
)
EDGE_FUNCTION_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = os.environ.get(
    "AGENT_API_KEY", "REPLACE_WITH_YOUR_SECRET_KEY"
)
SEND_INTERVAL = 2            # seconds between batch sends
RULE_REFRESH_INTERVAL = 30   # seconds between rule refreshes
RISK_SCORING_INTERVAL = 300  # seconds between risk score recalculations
# ============================================================

# Thread-safe queue holding parsed packet dicts until the next send cycle.
packet_queue = queue.Queue(maxsize=500)

# ---------------------------------------------------------------------------
# Detection modules
# ---------------------------------------------------------------------------
port_scan_detector = PortScanDetector(threshold=15, window_seconds=10)
dos_detector = DoSDetector(pps_threshold=100, window_seconds=10)
flow_aggregator = FlowAggregator(window_seconds=10)
malware_detector = MalwareBehaviorDetector(window_seconds=60)

# ---------------------------------------------------------------------------
# Pipeline modules (instantiated in main() with real credentials)
# ---------------------------------------------------------------------------
alert_manager = None
rule_fetcher = None
threat_enricher = None
asset_discovery = None
response_manager = None
notification_dispatcher = None
suppression_engine = None

# State
last_rule_refresh = 0.0
last_risk_scoring = 0.0
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
                    "destination_ip": packet_data.get("destination_ip", ""),
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
            pass

    return alerts


def packet_callback(packet):
    """
    Scapy callback — invoked for every captured IP packet.
    Extracts fields, feeds to detectors, enqueues for batch sending.
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


def run_risk_scoring():
    """Compute and push host risk scores (periodic task)."""
    global last_risk_scoring
    try:
        scores = compute_host_risk_scores()
        network_risk = compute_network_risk(scores)
        push_risk_scores(scores)
        print(f"[RISK] Scored {len(scores)} hosts | Network risk: {network_risk}")
        last_risk_scoring = time.time()
    except Exception as e:
        print(f"[!] Risk scoring failed: {e}")


def handle_high_severity_alerts(alerts):
    """
    For high/critical alerts, trigger automated response and notifications.
    """
    for alert in alerts:
        severity = alert.get("severity", "low")
        if severity not in ("high", "critical"):
            continue

        source_ip = alert.get("source_ip", "unknown")
        alert_type = alert.get("alert_type", "Unknown")
        description = alert.get("description", "")

        # --- Automated Response ---
        if response_manager:
            incident_data = {
                "source_ip": source_ip,
                "total_score": 100 if severity == "critical" else 50,
                "attack_types": [alert_type],
            }
            try:
                actions = response_manager.auto_respond(incident_data)
                if actions:
                    print(f"[RESPONSE] {source_ip}: {', '.join(actions)}")
            except Exception as e:
                logger.error(f"Auto-response failed: {e}")

        # --- Notification Dispatch ---
        if notification_dispatcher:
            try:
                payload = NotificationPayload(
                    alert_type=alert_type,
                    severity=severity,
                    source_ip=source_ip,
                    description=description,
                    timestamp=time.time(),
                    score=100 if severity == "critical" else 50,
                )
                result = notification_dispatcher.dispatch(payload)
                if result and "skipped" not in result:
                    print(f"[NOTIFY] Dispatched for {source_ip}: {list(result.keys())}")
            except Exception as e:
                logger.error(f"Notification dispatch failed: {e}")


def send_batch():
    """
    Drain the packet queue, run full pipeline:
    detect → enrich → dedup → respond → notify → send to DB.
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

    # ---------------------------------------------------------------
    # 1. Harvest alerts from all detectors
    # ---------------------------------------------------------------
    all_alerts = []
    all_alerts.extend(port_scan_detector.check())
    all_alerts.extend(dos_detector.check())
    all_alerts.extend(flow_aggregator.detect_anomalies())

    # Malware behavior detection
    current_flows = flow_aggregator.get_flows()
    all_alerts.extend(malware_detector.check(current_flows))

    # Regex rules against packets with payloads
    for pkt in packets:
        all_alerts.extend(evaluate_regex_rules(pkt))

    # ---------------------------------------------------------------
    # 2. Enrich alerts with threat intelligence
    # ---------------------------------------------------------------
    if threat_enricher and all_alerts:
        try:
            all_alerts = threat_enricher.enrich(all_alerts)
        except Exception as e:
            logger.error(f"Threat enrichment failed: {e}")

    # ---------------------------------------------------------------
    # 2b. Suppress noise (trusted IPs, severity filter, rate limit)
    # ---------------------------------------------------------------
    if suppression_engine and all_alerts:
        try:
            all_alerts = suppression_engine.evaluate(all_alerts)
        except Exception as e:
            logger.error(f"Alert suppression failed: {e}")

    # ---------------------------------------------------------------
    # 3. Deduplicate and send alerts to DB
    # ---------------------------------------------------------------
    sent_count = 0
    if all_alerts:
        sent_count = alert_manager.process(all_alerts)

    # ---------------------------------------------------------------
    # 4. Trigger automated response + notifications for severe alerts
    # ---------------------------------------------------------------
    if all_alerts:
        handle_high_severity_alerts(all_alerts)

    # ---------------------------------------------------------------
    # 5. Asset discovery — track IPs from packets
    # ---------------------------------------------------------------
    if asset_discovery and packets:
        try:
            new_assets = asset_discovery.update(packets)
            if new_assets > 0:
                print(f"[ASSET] Discovered {new_assets} new host(s)")
        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")

    # ---------------------------------------------------------------
    # 6. Periodic risk scoring
    # ---------------------------------------------------------------
    if time.time() - last_risk_scoring >= RISK_SCORING_INTERVAL:
        run_risk_scoring()

    # ---------------------------------------------------------------
    # 7. Send packets + metrics to edge function
    # ---------------------------------------------------------------
    metrics = get_system_metrics()

    send_packets = []
    for pkt in packets:
        send_pkt = {k: v for k, v in pkt.items() if k != "timestamp"}
        send_packets.append(send_pkt)

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
    """Entry point — validate config, initialise all modules, start sniffer, loop."""
    global alert_manager, rule_fetcher, threat_enricher, asset_discovery
    global response_manager, notification_dispatcher, suppression_engine
    global last_rule_refresh, last_risk_scoring

    if AGENT_API_KEY == "REPLACE_WITH_YOUR_SECRET_KEY":
        print("ERROR: Set AGENT_API_KEY before running.")
        print("       Either set the env var or edit ids_agent.py.")
        print("       It must match the AGENT_API_KEY secret in your Supabase project.")
        exit(1)

    # --- Initialise pipeline modules ---
    alert_manager = AlertManager(
        edge_function_url=EDGE_FUNCTION_URL,
        api_key=AGENT_API_KEY,
        dedup_window=60,
    )

    rule_fetcher = RuleFetcher(SUPABASE_URL)

    threat_enricher = ThreatIntelEnricher(
        supabase_url=SUPABASE_URL,
        supabase_key=SUPABASE_KEY,
        cache_ttl=300,
    )

    asset_discovery = AssetDiscovery(
        supabase_url=SUPABASE_URL,
        supabase_key=SUPABASE_KEY,
        sync_interval=60,
    )

    response_manager = ResponseManager(
        supabase_url=SUPABASE_URL,
        api_key=AGENT_API_KEY,
        dry_run=True,  # Set to False in production
        auto_block_threshold=80,
        auto_isolate_threshold=120,
    )

    notification_dispatcher = NotificationDispatcher(
        supabase_url=SUPABASE_URL,
        supabase_key=SUPABASE_KEY,
        rate_limit=30,
        dedupe_window=60,
    )

    suppression_engine = AlertSuppressionEngine(
        supabase_url=SUPABASE_URL,
        supabase_key=SUPABASE_KEY,
        rule_refresh_interval=60,
    )

    print("=" * 60)
    print("  IDS Real-Time Agent v3 — Full Pipeline")
    print("  Detection → Enrichment → Response → Notification")
    print("=" * 60)
    print(f"  Endpoint      : {EDGE_FUNCTION_URL}")
    print(f"  Send interval : {SEND_INTERVAL}s")
    print(f"  Rule refresh  : {RULE_REFRESH_INTERVAL}s")
    print(f"  Risk scoring  : {RISK_SCORING_INTERVAL}s")
    print(f"  Port scan     : >{port_scan_detector.threshold} ports in {port_scan_detector.window_seconds}s")
    print(f"  DoS flood     : >{dos_detector.pps_threshold} pps")
    print(f"  Flow fanout   : >{flow_aggregator.fanout_threshold} destinations")
    print(f"  Malware C2    : >{malware_detector.beacon_min_connections} conns")
    print(f"  Response      : dry_run={response_manager.dry_run}")
    print("  Modules       : Enricher ✓ | Assets ✓ | Risk ✓ | Response ✓ | Notify ✓")
    print("=" * 60)

    # Initial rule fetch
    print("[*] Fetching detection rules from Supabase...")
    refresh_rules()

    # Initial risk scoring
    print("[*] Running initial risk scoring...")
    run_risk_scoring()

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
        # Print final stats
        print("\n" + "=" * 60)
        print("  Agent Stopped — Final Statistics")
        print("=" * 60)
        if threat_enricher:
            print(f"  Enricher : {threat_enricher.get_stats()}")
        if asset_discovery:
            print(f"  Assets   : {asset_discovery.get_stats()}")
        if notification_dispatcher:
            print(f"  Notify   : {notification_dispatcher.get_stats()}")
        print("=" * 60)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
