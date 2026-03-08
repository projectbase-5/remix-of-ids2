"""
Incident Scoring Engine — Python Agent Module
===============================================
Aggregates alerts by source IP in a sliding window and calculates a composite
severity score, then pushes scored incidents to the ingest-traffic endpoint.

Scoring formula (consistent with edge function):
  base      = Σ SEVERITY_WEIGHTS[alert.severity]
  diversity = unique_attack_types × 10
  sequence  = has_kill_chain_sequence ? 30 : 0
  recency   = alerts_in_last_5_min × 1.5 + alerts_in_last_15_min × 1.0
  total     = base + diversity + sequence + recency

Usage:
  engine = IncidentScoringEngine(supabase_url, api_key)
  engine.ingest_alert(alert_dict)
  # Periodically:
  engine.flush_scored_incidents()
"""

import time
import json
import logging
import requests
from collections import defaultdict
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

KILL_CHAIN_ORDER = [
    "reconnaissance",
    "delivery",
    "exploitation",
    "installation",
    "command_control",
    "exfiltration",
]

ATTACK_TO_PHASE = {
    "Port Scan": "reconnaissance",
    "Network Scan": "reconnaissance",
    "Reconnaissance": "reconnaissance",
    "Brute Force": "exploitation",
    "SQL Injection": "exploitation",
    "XSS": "exploitation",
    "Exploit": "exploitation",
    "DoS": "delivery",
    "DDoS": "delivery",
    "Malware": "installation",
    "Trojan": "installation",
    "Ransomware": "installation",
    "C2 Communication": "command_control",
    "Beacon": "command_control",
    "DNS Anomaly": "command_control",
    "Data Exfiltration": "exfiltration",
    "Data Leak": "exfiltration",
}


def detect_kill_chain_sequence(attack_types: List[str]) -> tuple:
    """Detect if attack types form a kill chain sequence (3+ consecutive phases)."""
    phases = list(set(
        ATTACK_TO_PHASE[t] for t in attack_types if t in ATTACK_TO_PHASE
    ))
    indices = sorted(
        KILL_CHAIN_ORDER.index(p) for p in phases if p in KILL_CHAIN_ORDER
    )

    if len(indices) < 3:
        return False, None

    max_run = 1
    current_run = 1
    best_start = 0

    for i in range(1, len(indices)):
        if indices[i] - indices[i - 1] <= 1:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
                best_start = i - current_run + 1
        else:
            current_run = 1

    if max_run >= 3:
        seq = [KILL_CHAIN_ORDER[indices[best_start + j]] for j in range(max_run)]
        return True, " → ".join(seq)

    return False, None


def score_severity(total_score: int) -> str:
    if total_score >= 100:
        return "critical"
    elif total_score >= 60:
        return "high"
    elif total_score >= 30:
        return "medium"
    return "low"


class IncidentScoringEngine:
    """
    Sliding-window alert aggregator that scores incidents by source IP.

    Alerts are cached locally and scored every `flush_interval` seconds.
    Scored incidents are pushed to the ingest-traffic edge function.
    """

    def __init__(
        self,
        supabase_url: str,
        api_key: str,
        window_seconds: int = 900,       # 15-minute default window
        flush_interval: int = 30,         # Score every 30 seconds
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.api_key = api_key
        self.window_seconds = window_seconds
        self.flush_interval = flush_interval

        # alert_cache[source_ip] = [(timestamp, alert_dict), ...]
        self.alert_cache: Dict[str, List[tuple]] = defaultdict(list)
        self.last_flush = time.time()

    def ingest_alert(self, alert: Dict[str, Any]) -> None:
        """Add an alert to the local cache for scoring."""
        source_ip = alert.get("source_ip", "0.0.0.0")
        self.alert_cache[source_ip].append((time.time(), alert))
        logger.debug(f"Cached alert for {source_ip}: {alert.get('alert_type')}")

        # Auto-flush if interval elapsed
        if time.time() - self.last_flush >= self.flush_interval:
            self.flush_scored_incidents()

    def _prune_window(self) -> None:
        """Remove alerts older than the scoring window."""
        cutoff = time.time() - self.window_seconds
        for ip in list(self.alert_cache.keys()):
            self.alert_cache[ip] = [
                (ts, a) for ts, a in self.alert_cache[ip] if ts >= cutoff
            ]
            if not self.alert_cache[ip]:
                del self.alert_cache[ip]

    def _score_ip(self, ip: str, entries: List[tuple]) -> Optional[Dict[str, Any]]:
        """Score alerts for a single source IP."""
        if not entries:
            return None

        now = time.time()
        alerts = [a for _, a in entries]
        timestamps = [ts for ts, _ in entries]

        # Base severity score
        base = sum(SEVERITY_WEIGHTS.get(a.get("severity", "low"), 3) for a in alerts)

        # Attack diversity
        attack_types = list(set(a.get("alert_type", "Unknown") for a in alerts))
        diversity = len(attack_types) * 10

        # Sequence detection
        has_sequence, pattern = detect_kill_chain_sequence(attack_types)
        sequence_bonus = 0
        if has_sequence:
            sequence_bonus = 40 if len(attack_types) >= 4 else 30

        # Recency bonus
        recency = 0.0
        for ts in timestamps:
            age = now - ts
            if age < 300:        # < 5 min
                recency += 1.5
            elif age < 900:      # < 15 min
                recency += 1.0
            else:
                recency += 0.5

        total_score = round(base + diversity + sequence_bonus + recency)
        severity = score_severity(total_score)

        return {
            "source_ip": ip,
            "total_score": total_score,
            "alert_count": len(alerts),
            "attack_types": attack_types,
            "severity": severity,
            "first_alert_at": min(timestamps),
            "last_alert_at": max(timestamps),
            "sequence_pattern": pattern,
            "status": "open",
        }

    def flush_scored_incidents(self) -> List[Dict[str, Any]]:
        """Score all cached IPs and push incidents to the backend."""
        self._prune_window()
        self.last_flush = time.time()

        incidents = []
        for ip, entries in self.alert_cache.items():
            scored = self._score_ip(ip, entries)
            if scored and scored["total_score"] >= 10:
                incidents.append(scored)

        if not incidents:
            logger.info("No incidents above threshold to push")
            return []

        # Sort by score descending
        incidents.sort(key=lambda x: x["total_score"], reverse=True)

        # Push to ingest-traffic
        try:
            url = f"{self.supabase_url}/functions/v1/ingest-traffic"
            payload = {
                "api_key": self.api_key,
                "incidents": incidents,
            }
            resp = requests.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"Pushed {len(incidents)} scored incidents: "
                f"{result.get('incidents_inserted', 0)} inserted"
            )
        except Exception as e:
            logger.error(f"Failed to push scored incidents: {e}")

        return incidents

    def get_priority_queue(self) -> List[Dict[str, Any]]:
        """Return current scored incidents sorted by priority (local only)."""
        self._prune_window()
        incidents = []
        for ip, entries in self.alert_cache.items():
            scored = self._score_ip(ip, entries)
            if scored:
                incidents.append(scored)
        incidents.sort(key=lambda x: x["total_score"], reverse=True)
        return incidents


# ---------------------------------------------------------------------------
# Example integration with the IDS agent
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co")
    API_KEY = os.getenv("AGENT_API_KEY", "")

    engine = IncidentScoringEngine(SUPABASE_URL, API_KEY)

    # Simulate a multi-stage attack
    test_alerts = [
        {"alert_type": "Port Scan", "severity": "medium", "source_ip": "10.0.0.50",
         "description": "Port scan detected", "detection_module": "port_scan_detector"},
        {"alert_type": "Brute Force", "severity": "high", "source_ip": "10.0.0.50",
         "description": "SSH brute force", "detection_module": "auth_detector"},
        {"alert_type": "Malware", "severity": "critical", "source_ip": "10.0.0.50",
         "description": "Malware payload detected", "detection_module": "malware_detector"},
        {"alert_type": "C2 Communication", "severity": "critical", "source_ip": "10.0.0.50",
         "description": "Beacon activity detected", "detection_module": "beacon_detector"},
    ]

    for alert in test_alerts:
        engine.ingest_alert(alert)

    queue = engine.get_priority_queue()
    for incident in queue:
        print(
            f"[{incident['severity'].upper():>8}] "
            f"Score: {incident['total_score']:>4} | "
            f"IP: {incident['source_ip']} | "
            f"Types: {', '.join(incident['attack_types'])} | "
            f"Sequence: {incident.get('sequence_pattern', 'none')}"
        )

    if API_KEY:
        engine.flush_scored_incidents()
    else:
        print("\nSet AGENT_API_KEY to push incidents to backend")
