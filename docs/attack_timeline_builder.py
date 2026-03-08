"""
attack_timeline_builder.py — Attack Timeline Builder
=====================================================
Reconstructs attack sequences per source IP by correlating alerts,
incidents, and hunt results into a chronological kill-chain timeline.

Kill-chain phases (Lockheed Martin Cyber Kill Chain):
  1. Reconnaissance  — port scans, network mapping
  2. Weaponization    — malware preparation (rarely visible)
  3. Delivery         — phishing, exploit delivery
  4. Exploitation     — exploit execution
  5. Installation     — malware installation, persistence
  6. Command & Control — beaconing, C2 channels
  7. Exfiltration     — data theft

Usage:
    builder = AttackTimelineBuilder(supabase_url, supabase_key, agent_api_key)
    builder.build_all_timelines()          # build for all active source IPs
    builder.build_timeline("192.168.1.50") # build for specific IP
"""

import time
import math
import requests
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Any, Optional


# ── Kill-chain phase mapping ──────────────────────────────────────────────
ALERT_TYPE_TO_PHASE = {
    "Port Scan":          "reconnaissance",
    "port_scan":          "reconnaissance",
    "Network Mapping":    "reconnaissance",
    "DNS Query":          "reconnaissance",
    "Vulnerability Scan": "reconnaissance",

    "Exploit":            "exploitation",
    "exploit":            "exploitation",
    "SQL Injection":      "exploitation",
    "Buffer Overflow":    "exploitation",
    "RCE":                "exploitation",

    "Malware":            "installation",
    "malware":            "installation",
    "Trojan":             "installation",
    "Backdoor":           "installation",
    "Persistence":        "installation",

    "DoS":                "delivery",
    "dos":                "delivery",
    "DDoS":               "delivery",
    "Phishing":           "delivery",
    "Spam":               "delivery",

    "Beaconing":          "command_and_control",
    "beaconing":          "command_and_control",
    "C2":                 "command_and_control",
    "DNS Tunnel":         "command_and_control",

    "Data Exfiltration":  "exfiltration",
    "data_exfil":         "exfiltration",
    "Large Upload":       "exfiltration",
}

HUNT_TYPE_TO_PHASE = {
    "rare_destination":   "reconnaissance",
    "dns_entropy":        "command_and_control",
    "beaconing":          "command_and_control",
    "data_exfil":         "exfiltration",
}

PHASE_ORDER = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "exfiltration",
]

SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class AttackTimelineBuilder:
    """Builds attack timelines by correlating multiple data sources."""

    def __init__(self, supabase_url: str, supabase_key: str, agent_api_key: str):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key
        self.agent_api_key = agent_api_key
        self.headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
        }

    # ── Data fetching ─────────────────────────────────────────────────────

    def _fetch_alerts(self, source_ip: Optional[str] = None) -> List[Dict]:
        """Fetch live_alerts, optionally filtered by source IP."""
        url = f"{self.supabase_url}/rest/v1/live_alerts?select=*&order=created_at.asc"
        if source_ip:
            url += f"&source_ip=eq.{source_ip}"
        resp = requests.get(url, headers=self.headers)
        return resp.json() if resp.status_code == 200 else []

    def _fetch_incidents(self, source_ip: Optional[str] = None) -> List[Dict]:
        """Fetch scored_incidents."""
        url = f"{self.supabase_url}/rest/v1/scored_incidents?select=*&order=first_alert_at.asc"
        if source_ip:
            url += f"&source_ip=eq.{source_ip}"
        resp = requests.get(url, headers=self.headers)
        return resp.json() if resp.status_code == 200 else []

    def _fetch_hunt_results(self, source_ip: Optional[str] = None) -> List[Dict]:
        """Fetch hunt_results."""
        url = f"{self.supabase_url}/rest/v1/hunt_results?select=*&order=created_at.asc"
        if source_ip:
            url += f"&source_ip=eq.{source_ip}"
        resp = requests.get(url, headers=self.headers)
        return resp.json() if resp.status_code == 200 else []

    # ── Phase classification ──────────────────────────────────────────────

    @staticmethod
    def _classify_phase(event_type: str, mapping: Dict[str, str]) -> str:
        """Map an event type to a kill-chain phase."""
        return mapping.get(event_type, "unknown")

    # ── Timeline construction ─────────────────────────────────────────────

    def build_timeline(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """Build a single attack timeline for a given source IP."""
        alerts = self._fetch_alerts(source_ip)
        incidents = self._fetch_incidents(source_ip)
        hunts = self._fetch_hunt_results(source_ip)

        events: List[Dict[str, Any]] = []

        # Process alerts
        for a in alerts:
            phase = self._classify_phase(a.get("alert_type", ""), ALERT_TYPE_TO_PHASE)
            events.append({
                "timestamp": a.get("created_at"),
                "event_type": a.get("alert_type", "unknown"),
                "phase": phase,
                "description": a.get("description", ""),
                "severity": a.get("severity", "medium"),
                "ref_id": a.get("id"),
                "source": "alert",
            })

        # Process incidents
        for inc in incidents:
            attack_types = inc.get("attack_types", [])
            label = ", ".join(attack_types) if attack_types else "Incident"
            phase = "unknown"
            for at in attack_types:
                p = self._classify_phase(at, ALERT_TYPE_TO_PHASE)
                if p != "unknown":
                    phase = p
                    break
            events.append({
                "timestamp": inc.get("first_alert_at"),
                "event_type": label,
                "phase": phase,
                "description": f"Scored incident: {inc.get('severity', 'low')} severity, score {inc.get('total_score', 0)}, {inc.get('alert_count', 0)} alerts",
                "severity": inc.get("severity", "low"),
                "ref_id": inc.get("id"),
                "source": "incident",
            })

        # Process hunt results
        for h in hunts:
            phase = self._classify_phase(h.get("hunt_type", ""), HUNT_TYPE_TO_PHASE)
            events.append({
                "timestamp": h.get("created_at"),
                "event_type": h.get("hunt_type", "unknown"),
                "phase": phase,
                "description": f"Hunt finding: {h.get('target', '')} (score: {h.get('score', 0)})",
                "severity": "medium",
                "ref_id": h.get("id"),
                "source": "hunt",
            })

        if not events:
            return None

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp") or "")

        # Detect kill-chain phases present
        phases_detected = list(set(e["phase"] for e in events if e["phase"] != "unknown"))
        phases_detected.sort(key=lambda p: PHASE_ORDER.index(p) if p in PHASE_ORDER else 99)

        # Detect multi-stage patterns
        pattern = self._detect_pattern(events)

        first_ts = events[0].get("timestamp")
        last_ts = events[-1].get("timestamp")

        return {
            "source_ip": source_ip,
            "timeline_events": events,
            "kill_chain_phases": phases_detected,
            "total_events": len(events),
            "first_event_at": first_ts,
            "last_event_at": last_ts,
            "is_active": True,
            "pattern": pattern,
        }

    @staticmethod
    def _detect_pattern(events: List[Dict]) -> Optional[str]:
        """Detect multi-stage attack patterns from ordered events."""
        phases_seq = [e["phase"] for e in events if e["phase"] != "unknown"]
        if not phases_seq:
            return None

        # Deduplicate consecutive phases
        deduped = [phases_seq[0]]
        for p in phases_seq[1:]:
            if p != deduped[-1]:
                deduped.append(p)

        if len(deduped) >= 3:
            return " → ".join(deduped)
        elif len(deduped) == 2:
            return " → ".join(deduped)
        return deduped[0] if deduped else None

    # ── Bulk building ─────────────────────────────────────────────────────

    def build_all_timelines(self) -> List[Dict[str, Any]]:
        """Build timelines for all source IPs that have alerts."""
        alerts = self._fetch_alerts()
        source_ips = list(set(a.get("source_ip", "") for a in alerts if a.get("source_ip")))

        timelines = []
        for ip in source_ips:
            tl = self.build_timeline(ip)
            if tl:
                timelines.append(tl)

        if timelines:
            self._push_timelines(timelines)

        return timelines

    # ── Push to ingest-traffic ────────────────────────────────────────────

    def _push_timelines(self, timelines: List[Dict[str, Any]]):
        """Push assembled timelines to the ingest-traffic edge function."""
        payload = {
            "api_key": self.agent_api_key,
            "attack_timelines": timelines,
        }
        url = f"{self.supabase_url}/functions/v1/ingest-traffic"
        try:
            resp = requests.post(url, json=payload, headers={
                "Content-Type": "application/json",
            })
            print(f"[TimelineBuilder] Pushed {len(timelines)} timelines: {resp.status_code}")
        except Exception as e:
            print(f"[TimelineBuilder] Push error: {e}")


# ── Standalone execution ──────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "")

    builder = AttackTimelineBuilder(SUPABASE_URL, SUPABASE_KEY, AGENT_API_KEY)
    results = builder.build_all_timelines()
    print(f"Built {len(results)} attack timelines")
    for tl in results:
        phases = " → ".join(tl["kill_chain_phases"])
        print(f"  {tl['source_ip']}: {tl['total_events']} events, phases: {phases}")
