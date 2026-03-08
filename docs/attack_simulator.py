"""
Attack Simulator
================
Generates synthetic attack traffic and sends it to the ingest-traffic
edge function or directly to Supabase tables for IDS testing.

Usage (standalone):
    python attack_simulator.py --type port_scan --target 10.0.0.5 --duration 30

Integration:
    from attack_simulator import AttackSimulator
    sim = AttackSimulator(supabase_url, supabase_key)
    sim.simulate_port_scan(target_ip="10.0.0.5", duration_sec=30)
"""

import os
import json
import time
import random
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

logger = logging.getLogger("attack_simulator")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
ATTACKER_IPS = ["10.99.1.50", "10.99.2.100", "10.99.3.200", "10.99.4.77"]


class AttackSimulator:
    """Generates synthetic attack packets for IDS testing."""

    def __init__(self, supabase_url: str, supabase_key: str):
        self.base_url = supabase_url.rstrip("/")
        self.headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    # ── packet sender ────────────────────────────────────────────────
    def _send_packets(self, packets: list[dict]) -> int:
        """Insert packets into network_traffic via REST API. Returns count inserted."""
        url = f"{self.base_url}/rest/v1/network_traffic"
        try:
            resp = requests.post(url, headers=self.headers, json=packets, timeout=15)
            resp.raise_for_status()
            return len(packets)
        except Exception as exc:
            logger.error("Failed to send packets: %s", exc)
            return 0

    def _send_alert(self, alert: dict) -> bool:
        """Insert an alert into live_alerts."""
        url = f"{self.base_url}/rest/v1/live_alerts"
        try:
            resp = requests.post(url, headers=self.headers, json=[alert], timeout=10)
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Failed to send alert: %s", exc)
            return False

    # ── simulations ──────────────────────────────────────────────────

    def simulate_port_scan(
        self,
        target_ip: str = "192.168.1.100",
        source_ip: Optional[str] = None,
        duration_sec: int = 10,
        packets_per_sec: int = 5,
    ) -> dict:
        """
        Simulate a port scan: rapid SYN packets to many ports from one source.
        """
        src = source_ip or random.choice(ATTACKER_IPS)
        total_packets = duration_sec * packets_per_sec
        ports_to_scan = random.sample(range(1, 65536), min(total_packets, 200))
        packets = []

        for port in ports_to_scan[:total_packets]:
            packets.append({
                "source_ip": src,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "port": port,
                "packet_size": random.randint(40, 64),
                "flags": json.dumps(["SYN"]),
                "payload_preview": None,
                "is_suspicious": True,
            })

        sent = self._send_packets(packets)
        self._send_alert({
            "alert_type": "Port Scan",
            "severity": "high",
            "source_ip": src,
            "destination_ip": target_ip,
            "detection_module": "attack_simulator",
            "description": f"Simulated port scan: {sent} ports scanned on {target_ip}",
            "metadata": json.dumps({"simulation": True, "ports_scanned": sent}),
        })
        logger.info("Port scan simulation: %d packets sent", sent)
        return {"type": "port_scan", "packets_sent": sent, "source_ip": src, "target_ip": target_ip}

    def simulate_ddos(
        self,
        target_ip: str = "192.168.1.1",
        duration_sec: int = 10,
        packets_per_sec: int = 20,
    ) -> dict:
        """
        Simulate a DoS/DDoS flood: high-volume large packets from multiple sources.
        """
        total_packets = duration_sec * packets_per_sec
        packets = []

        for _ in range(total_packets):
            src = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            packets.append({
                "source_ip": src,
                "destination_ip": target_ip,
                "protocol": random.choice(["TCP", "UDP"]),
                "port": random.choice([80, 443, 53]),
                "packet_size": random.randint(1200, 1500),
                "flags": json.dumps(["SYN", "ACK"] if random.random() > 0.5 else ["SYN"]),
                "payload_preview": None,
                "is_suspicious": True,
            })

        sent = self._send_packets(packets)
        self._send_alert({
            "alert_type": "DDoS Flood",
            "severity": "critical",
            "source_ip": "multiple",
            "destination_ip": target_ip,
            "detection_module": "attack_simulator",
            "description": f"Simulated DDoS flood: {sent} packets targeting {target_ip}",
            "metadata": json.dumps({"simulation": True, "total_packets": sent}),
        })
        logger.info("DDoS simulation: %d packets sent", sent)
        return {"type": "ddos", "packets_sent": sent, "target_ip": target_ip}

    def simulate_beacon(
        self,
        target_ip: str = "203.0.113.50",
        source_ip: Optional[str] = None,
        duration_sec: int = 30,
        interval_sec: float = 5.0,
    ) -> dict:
        """
        Simulate a C2 beacon: periodic connections to a suspicious external IP.
        """
        src = source_ip or "192.168.1.42"
        num_beacons = int(duration_sec / interval_sec)
        packets = []

        for i in range(num_beacons):
            jitter = random.uniform(-0.5, 0.5)
            packets.append({
                "source_ip": src,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "port": random.choice([443, 8443, 4444]),
                "packet_size": random.randint(60, 200),
                "flags": json.dumps(["SYN", "ACK", "PSH"]),
                "payload_preview": f"beacon_{i:04d}",
                "is_suspicious": True,
            })

        sent = self._send_packets(packets)
        self._send_alert({
            "alert_type": "C2 Beacon",
            "severity": "high",
            "source_ip": src,
            "destination_ip": target_ip,
            "detection_module": "attack_simulator",
            "description": f"Simulated C2 beacon: {sent} callbacks to {target_ip} every ~{interval_sec}s",
            "metadata": json.dumps({"simulation": True, "beacon_count": sent, "interval": interval_sec}),
        })
        logger.info("Beacon simulation: %d callbacks sent", sent)
        return {"type": "beacon", "packets_sent": sent, "source_ip": src, "target_ip": target_ip}

    def simulate_exfiltration(
        self,
        target_ip: str = "198.51.100.25",
        source_ip: Optional[str] = None,
        duration_sec: int = 15,
    ) -> dict:
        """
        Simulate data exfiltration: large outbound transfers to an external IP.
        """
        src = source_ip or "192.168.1.88"
        packets = []

        for _ in range(duration_sec * 3):
            packets.append({
                "source_ip": src,
                "destination_ip": target_ip,
                "protocol": random.choice(["TCP", "UDP"]),
                "port": random.choice([443, 53, 8080]),
                "packet_size": random.randint(1300, 1500),
                "flags": json.dumps(["ACK", "PSH"]),
                "payload_preview": "base64_encoded_data...",
                "is_suspicious": True,
            })

        sent = self._send_packets(packets)
        self._send_alert({
            "alert_type": "Data Exfiltration",
            "severity": "critical",
            "source_ip": src,
            "destination_ip": target_ip,
            "detection_module": "attack_simulator",
            "description": f"Simulated data exfiltration: {sent} large packets from {src} to {target_ip}",
            "metadata": json.dumps({"simulation": True, "total_packets": sent}),
        })
        logger.info("Exfiltration simulation: %d packets sent", sent)
        return {"type": "exfiltration", "packets_sent": sent, "source_ip": src, "target_ip": target_ip}


# ── CLI ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Attack Simulator")
    parser.add_argument("--type", choices=["port_scan", "ddos", "beacon", "exfiltration"], required=True)
    parser.add_argument("--target", default="192.168.1.100", help="Target IP")
    parser.add_argument("--source", default=None, help="Source IP (optional)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    args = parser.parse_args()

    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY", ""))
    if not url or not key:
        print("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables")
        return

    sim = AttackSimulator(url, key)
    result = getattr(sim, f"simulate_{args.type}")(
        target_ip=args.target,
        **({"source_ip": args.source} if args.source else {}),
        duration_sec=args.duration,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
