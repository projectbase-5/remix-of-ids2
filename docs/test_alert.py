#!/usr/bin/env python3
"""
Test Alert Script (v3 — Multi-Profile incl. Malware Behavior)
==============================================================
Sends test alerts and sample packets to the ingest-traffic edge function
to verify the full pipeline without running scapy.

Test profiles:
    1. port_scan     — 20 unique ports from a single attacker
    2. dos           — 100 packets from a single source (burst)
    3. flow_anomaly  — fan-out pattern hitting many destinations
    4. c2_beacon     — periodic small packets to same external IP
    5. lateral_movement — probing 6+ internal IPs on SMB port
    6. exfiltration  — large outbound transfer to external IP
    7. malware_all   — runs all three malware profiles
    8. all           — runs every profile

Usage:
    1. Set AGENT_API_KEY below (must match Supabase secret)
    2. Run:  python docs/test_alert.py [profile]
    3. Open dashboard in live mode — you should see the alerts
"""

import json
import sys
import time
import random

try:
    import requests
except ImportError:
    print("ERROR: requests is not installed. Run: pip install requests")
    exit(1)

# ============================================================
# CONFIGURATION — Update before running
# ============================================================
SUPABASE_URL = "https://saeofugyscjfgqqnqowk.supabase.co"
EDGE_FUNCTION_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = "REPLACE_WITH_YOUR_SECRET_KEY"
# ============================================================


def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"


def random_internal_ip():
    return f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"


# ──────────────────────────────────────────────
# Original profiles
# ──────────────────────────────────────────────

def generate_port_scan_payload(attacker_ip):
    num_ports = 20
    ports = random.sample(range(1, 65535), num_ports)
    packets = [
        {
            "source_ip": attacker_ip,
            "destination_ip": "10.0.1.50",
            "protocol": "TCP",
            "packet_size": random.randint(40, 120),
            "flags": ["SYN"],
            "port": port,
        }
        for port in ports
    ]
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "Port Scan",
                "severity": "high",
                "source_ip": attacker_ip,
                "description": f"[TEST] Port scan from {attacker_ip}: {num_ports} unique ports probed in 10s",
                "detection_module": "test_script",
                "dedupe_key": f"test_portscan_{int(time.time())}",
                "metadata": {
                    "unique_ports": num_ports,
                    "sample_ports": sorted(ports)[:10],
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 15.0,
            "memory_usage": 42.0,
            "disk_usage": 55.0,
            "network_health": 98.5,
            "active_connections": 12,
        },
    }


def generate_dos_payload(attacker_ip):
    target_ip = "10.0.1.50"
    packets = [
        {
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "protocol": "TCP",
            "packet_size": random.randint(800, 1400),
            "flags": ["SYN"],
            "port": 80,
        }
        for _ in range(100)
    ]
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "DoS",
                "severity": "high",
                "source_ip": attacker_ip,
                "description": (
                    f"[TEST] DoS flooding from {attacker_ip}: 100 packets "
                    f"targeting {target_ip}:80 (burst mode)"
                ),
                "detection_module": "test_script",
                "dedupe_key": f"test_dos_{int(time.time())}",
                "metadata": {
                    "packets_per_second": 100,
                    "threshold": 50,
                    "threshold_multiplier": 2.0,
                    "attack_mode": "burst",
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 65.0,
            "memory_usage": 72.0,
            "disk_usage": 55.0,
            "network_health": 45.0,
            "active_connections": 250,
        },
    }


def generate_flow_anomaly_payload(attacker_ip):
    packets = []
    destinations = [f"10.0.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(25)]
    for dst in destinations:
        packets.append({
            "source_ip": attacker_ip,
            "destination_ip": dst,
            "protocol": "TCP",
            "packet_size": random.randint(64, 256),
            "flags": ["SYN"],
            "port": random.choice([22, 80, 443, 3389, 8080]),
        })
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "Flow Anomaly",
                "severity": "medium",
                "source_ip": attacker_ip,
                "description": (
                    f"[TEST] Fan-out anomaly from {attacker_ip}: contacting "
                    f"{len(set(destinations))} unique destinations"
                ),
                "detection_module": "test_script",
                "dedupe_key": f"test_flow_{int(time.time())}",
                "metadata": {
                    "anomaly_type": "fan_out",
                    "unique_destinations": len(set(destinations)),
                    "threshold": 20,
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 35.0,
            "memory_usage": 50.0,
            "disk_usage": 55.0,
            "network_health": 82.0,
            "active_connections": 45,
        },
    }


# ──────────────────────────────────────────────
# Malware behavior profiles
# ──────────────────────────────────────────────

def generate_c2_beacon_payload(attacker_ip):
    """Simulate C2 beaconing: 10 small packets at regular intervals to same external C2 server."""
    c2_server = random_ip()
    packets = [
        {
            "source_ip": attacker_ip,
            "destination_ip": c2_server,
            "protocol": "TCP",
            "packet_size": random.randint(60, 120),
            "flags": ["PSH", "ACK"],
            "port": 443,
        }
        for _ in range(10)
    ]
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "Malware C2 Communication",
                "severity": "high",
                "source_ip": attacker_ip,
                "description": (
                    f"[TEST] C2 beaconing from {attacker_ip} → {c2_server}:443 — "
                    f"10 periodic connections (≈60s interval, low jitter)"
                ),
                "detection_module": "malware_behavior_detector",
                "dedupe_key": f"test_c2_{int(time.time())}",
                "metadata": {
                    "destination_ip": c2_server,
                    "interval_seconds": 60,
                    "interval_std": 2.3,
                    "connection_count": 10,
                    "pattern": "periodic_beaconing",
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 22.0,
            "memory_usage": 48.0,
            "disk_usage": 55.0,
            "network_health": 90.0,
            "active_connections": 18,
        },
    }


def generate_lateral_movement_payload(attacker_ip):
    """Simulate lateral movement: infected host probing 6+ internal IPs on SMB (445)."""
    internal_targets = [random_internal_ip() for _ in range(8)]
    packets = [
        {
            "source_ip": attacker_ip,
            "destination_ip": dst,
            "protocol": "TCP",
            "packet_size": random.randint(60, 200),
            "flags": ["SYN"],
            "port": 445,
        }
        for dst in internal_targets
    ]
    unique_targets = len(set(internal_targets))
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "Lateral Movement",
                "severity": "high",
                "source_ip": attacker_ip,
                "description": (
                    f"[TEST] Lateral movement from {attacker_ip}: probing "
                    f"{unique_targets} internal hosts on port 445/SMB"
                ),
                "detection_module": "malware_behavior_detector",
                "dedupe_key": f"test_lateral_{int(time.time())}",
                "metadata": {
                    "unique_internal_targets": unique_targets,
                    "target_port": 445,
                    "sample_targets": internal_targets[:5],
                    "pattern": "lateral_movement",
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 30.0,
            "memory_usage": 55.0,
            "disk_usage": 55.0,
            "network_health": 75.0,
            "active_connections": 35,
        },
    }


def generate_exfiltration_payload(attacker_ip):
    """Simulate data exfiltration: large outbound transfer (>500KB) to external IP."""
    exfil_target = random_ip()
    num_packets = 50
    packets = [
        {
            "source_ip": attacker_ip,
            "destination_ip": exfil_target,
            "protocol": "TCP",
            "packet_size": random.randint(1200, 1460),
            "flags": ["PSH", "ACK"],
            "port": 443,
        }
        for _ in range(num_packets)
    ]
    total_bytes = sum(p["packet_size"] for p in packets)
    return {
        "api_key": AGENT_API_KEY,
        "packets": packets,
        "alerts": [
            {
                "alert_type": "Data Exfiltration",
                "severity": "critical",
                "source_ip": attacker_ip,
                "description": (
                    f"[TEST] Data exfiltration from {attacker_ip} → {exfil_target}: "
                    f"{total_bytes:,} bytes outbound ({total_bytes/1024:.0f} KB)"
                ),
                "detection_module": "malware_behavior_detector",
                "dedupe_key": f"test_exfil_{int(time.time())}",
                "metadata": {
                    "destination_ip": exfil_target,
                    "total_bytes": total_bytes,
                    "total_kb": round(total_bytes / 1024, 1),
                    "packet_count": num_packets,
                    "pattern": "data_exfiltration",
                    "test": True,
                },
            }
        ],
        "system_metrics": {
            "cpu_usage": 45.0,
            "memory_usage": 60.0,
            "disk_usage": 58.0,
            "network_health": 65.0,
            "active_connections": 42,
        },
    }


# ──────────────────────────────────────────────
# Send helper
# ──────────────────────────────────────────────

def send_payload(name, payload):
    print(f"\n{'='*50}")
    print(f"  Sending: {name}")
    print(f"  Endpoint: {EDGE_FUNCTION_URL}")
    print(f"  Packets:  {len(payload.get('packets', []))}")
    print(f"  Alerts:   {len(payload.get('alerts', []))}")
    print(f"{'='*50}")

    try:
        resp = requests.post(
            EDGE_FUNCTION_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        print(f"Response: {resp.status_code}")
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)

        if resp.status_code == 200:
            print(f"✅ {name} sent successfully!")
        else:
            print(f"❌ {name} failed with status {resp.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")


# ──────────────────────────────────────────────
# CLI dispatcher
# ──────────────────────────────────────────────

def main():
    if AGENT_API_KEY == "REPLACE_WITH_YOUR_SECRET_KEY":
        print("ERROR: Set AGENT_API_KEY in test_alert.py before running.")
        exit(1)

    profile = sys.argv[1] if len(sys.argv) > 1 else "all"
    valid = {
        "port_scan", "dos", "flow_anomaly",
        "c2_beacon", "lateral_movement", "exfiltration",
        "malware_all", "all",
    }
    if profile not in valid:
        print(f"Unknown profile '{profile}'. Valid: {', '.join(sorted(valid))}")
        exit(1)

    attacker_ip = random_ip()
    print(f"Attacker IP: {attacker_ip}")

    # Original profiles
    if profile in ("port_scan", "all"):
        send_payload("Port Scan", generate_port_scan_payload(attacker_ip))
        time.sleep(1)

    if profile in ("dos", "all"):
        send_payload("DoS Flood", generate_dos_payload(attacker_ip))
        time.sleep(1)

    if profile in ("flow_anomaly", "all"):
        send_payload("Flow Anomaly", generate_flow_anomaly_payload(attacker_ip))
        time.sleep(1)

    # Malware profiles
    if profile in ("c2_beacon", "malware_all", "all"):
        send_payload("C2 Beaconing", generate_c2_beacon_payload(attacker_ip))
        time.sleep(1)

    if profile in ("lateral_movement", "malware_all", "all"):
        send_payload("Lateral Movement", generate_lateral_movement_payload(attacker_ip))
        time.sleep(1)

    if profile in ("exfiltration", "malware_all", "all"):
        send_payload("Data Exfiltration", generate_exfiltration_payload(attacker_ip))

    print("\n" + "=" * 50)
    print("  Switch dashboard to LIVE mode to see the alerts.")
    print("=" * 50)


if __name__ == "__main__":
    main()
