"""
Rule Fetcher (v3 — with Malware Behavior Thresholds)
=====================================================
Fetches enabled detection rules from the Supabase ``detection_rules``
table via the REST API and maps them to detector configurations.

Security: The anon key is read from the SUPABASE_ANON_KEY environment
variable first, falling back to the hardcoded default only if unset.

Usage from ids_agent.py:
    from rule_fetcher import RuleFetcher
    fetcher = RuleFetcher(SUPABASE_URL)
    config = fetcher.fetch()
    port_scan_detector.update_config(config["port_scan"]["threshold"], ...)
    malware_detector.update_config(**{k: v for k, v in config["malware"].items() if v is not None})

Rule mapping:
    Rules are matched by both ``rule_type`` and ``pattern`` fields:
    - PORT_SCAN, port_scan, "port scan" → port_scan config
    - DOS, DDOS, flooding → dos config
    - Malware-related patterns → malware config (see _MALWARE_FIELD_MAP)
    - Any rule with a ``regex_pattern`` → regex_patterns list
    - rate_limit_threshold/rate_limit_window_seconds are respected

Malware mapping (by pattern/name keyword → config field):
    beaconing, c2         → beacon_min_connections
    lateral_movement      → lateral_min_destinations
    exfiltration          → exfil_bytes_threshold
    dns_anomaly, dns      → dns_query_threshold
    rare_destination      → rare_dest_frequency
    (window_seconds from rate_limit_window_seconds)
"""

import os
import re
import requests


# Default anon key — prefer env var
_DEFAULT_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNhZW9mdWd5c2NqZmdxcW5xb3drIiwi"
    "cm9sZSI6ImFub24iLCJpYXQiOjE3NTY3OTA1ODYsImV4cCI6MjA3MjM2NjU4Nn0."
    "92yIPYoeF3zCMt6UbOTuBmVIWKMs9UI6Xd51Q4dORKE"
)

# Pattern constants for robust matching
_PORT_SCAN_PATTERNS = {"port_scan", "portscan", "port scan"}
_DOS_PATTERNS = {"dos", "ddos", "flooding", "flood", "dos_attack", "ddos_attack"}
_MALWARE_PATTERNS = {
    "malware", "malware_behavior", "c2", "beaconing",
    "lateral_movement", "exfiltration", "dns_anomaly", "rare_destination",
}

# Maps a keyword found in rule name/pattern to the malware config field
_MALWARE_FIELD_MAP = {
    "beaconing":         "beacon_min_connections",
    "c2":                "beacon_min_connections",
    "beacon":            "beacon_min_connections",
    "lateral_movement":  "lateral_min_destinations",
    "lateral":           "lateral_min_destinations",
    "exfiltration":      "exfil_bytes_threshold",
    "exfil":             "exfil_bytes_threshold",
    "dns_anomaly":       "dns_query_threshold",
    "dns":               "dns_query_threshold",
    "rare_destination":  "rare_dest_frequency",
    "rare_dest":         "rare_dest_frequency",
}


class RuleFetcher:
    """Fetch detection_rules from Supabase and parse into detector configs."""

    def __init__(self, supabase_url: str, anon_key: str = None):
        resolved_key = anon_key or os.environ.get("SUPABASE_ANON_KEY", _DEFAULT_ANON_KEY)
        self.rest_url = f"{supabase_url}/rest/v1/detection_rules"
        self.headers = {
            "apikey": resolved_key,
            "Authorization": f"Bearer {resolved_key}",
            "Accept": "application/json",
        }

    def fetch(self) -> dict:
        """
        Fetch enabled rules and return a config dict:
        {
            "port_scan": {"threshold": int, "window_seconds": int},
            "dos": {"pps_threshold": int, "spike_factor": float},
            "malware": {
                "beacon_min_connections": int|None,
                "beacon_max_interval_std": float|None,
                "lateral_min_destinations": int|None,
                "exfil_bytes_threshold": int|None,
                "dns_query_threshold": int|None,
                "rare_dest_frequency": int|None,
                "window_seconds": int|None,
            },
            "regex_patterns": [...],
            "raw_rules": [...],
        }
        """
        config = {
            "port_scan": {"threshold": None, "window_seconds": None},
            "dos": {"pps_threshold": None, "spike_factor": None},
            "malware": {
                "beacon_min_connections": None,
                "beacon_max_interval_std": None,
                "lateral_min_destinations": None,
                "exfil_bytes_threshold": None,
                "dns_query_threshold": None,
                "rare_dest_frequency": None,
                "window_seconds": None,
            },
            "regex_patterns": [],
            "raw_rules": [],
        }

        try:
            resp = requests.get(
                self.rest_url,
                headers=self.headers,
                params={"enabled": "eq.true", "select": "*"},
                timeout=10,
            )
            if resp.status_code != 200:
                print(f"[rule_fetcher] HTTP {resp.status_code}: {resp.text[:200]}")
                return config

            rules = resp.json()
            config["raw_rules"] = rules

            for rule in rules:
                rt = (rule.get("rule_type") or "").lower().strip()
                name = (rule.get("name") or "").lower().strip()
                pattern = (rule.get("pattern") or "").lower().strip()

                identifiers = {rt, name, pattern}

                # Port scan rules
                if identifiers & _PORT_SCAN_PATTERNS:
                    if rule.get("rate_limit_threshold"):
                        config["port_scan"]["threshold"] = rule["rate_limit_threshold"]
                    if rule.get("rate_limit_window_seconds"):
                        config["port_scan"]["window_seconds"] = rule["rate_limit_window_seconds"]

                # DoS / flooding rules
                elif identifiers & _DOS_PATTERNS:
                    if rule.get("rate_limit_threshold"):
                        config["dos"]["pps_threshold"] = rule["rate_limit_threshold"]
                    try:
                        pattern_val = float(rule.get("pattern", ""))
                        if 1.0 < pattern_val < 100.0:
                            config["dos"]["spike_factor"] = pattern_val
                    except (ValueError, TypeError):
                        pass

                # Malware behavior rules
                elif identifiers & _MALWARE_PATTERNS:
                    # Map rate_limit_threshold to the correct malware field
                    if rule.get("rate_limit_threshold"):
                        for keyword, field in _MALWARE_FIELD_MAP.items():
                            if keyword in name or keyword in pattern or keyword in rt:
                                config["malware"][field] = rule["rate_limit_threshold"]
                                break
                    # Window seconds
                    if rule.get("rate_limit_window_seconds"):
                        config["malware"]["window_seconds"] = rule["rate_limit_window_seconds"]
                    # beacon_max_interval_std can be encoded in pattern as a float
                    try:
                        pattern_val = float(rule.get("pattern", ""))
                        if 0.0 < pattern_val < 60.0:
                            for keyword in ("beaconing", "c2", "beacon"):
                                if keyword in name or keyword in rt:
                                    config["malware"]["beacon_max_interval_std"] = pattern_val
                                    break
                    except (ValueError, TypeError):
                        pass

                # Regex-based rules — always collect if present
                if rule.get("regex_pattern"):
                    try:
                        re.compile(rule["regex_pattern"])
                        config["regex_patterns"].append({
                            "name": rule.get("name", "unnamed"),
                            "pattern": rule["regex_pattern"],
                            "severity": rule.get("severity", "medium"),
                            "rule_id": rule.get("id", ""),
                        })
                    except re.error as e:
                        print(f"[rule_fetcher] Invalid regex in rule '{rule.get('name')}': {e}")

        except requests.exceptions.RequestException as e:
            print(f"[rule_fetcher] Failed to fetch rules: {e}")

        return config
