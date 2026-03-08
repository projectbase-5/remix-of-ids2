"""
Threat Intelligence Enricher — Module 6
=========================================
Enriches alerts with external threat intelligence data before they are
stored in the database.

For each alert's source_ip (and optionally destination_ip), the enricher
calls the ``enrich-alert`` Supabase edge function, which in turn queries
``check-ip-reputation`` for AbuseIPDB / VirusTotal / threat-feed data.

Results are cached locally with a configurable TTL to avoid redundant
lookups for the same IP within a short window.

Integration point:
    In ``ids_agent.py``, call ``enricher.enrich(alerts)`` *before*
    ``alert_manager.process(alerts)`` so that every alert written to
    ``live_alerts`` already carries enrichment metadata.

Usage:
    enricher = ThreatIntelEnricher(supabase_url, supabase_key)
    enriched_alerts = enricher.enrich(alerts)
"""

import time
import logging
import requests
from typing import Dict, List, Optional, Any

logger = logging.getLogger("threat_intel_enricher")


class ThreatIntelEnricher:
    """
    Enriches alert dicts with IP reputation and threat intelligence
    by calling the enrich-alert edge function.

    Features:
        - TTL-based in-memory cache (default 300 s) per IP
        - Batch-friendly: processes a list of alerts in one call
        - Graceful degradation: enrichment failure does not block alerts
    """

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        cache_ttl: int = 300,
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key
        self.cache_ttl = cache_ttl

        # {ip_address: {"data": {...}, "expires": timestamp}}
        self._cache: Dict[str, Dict[str, Any]] = {}

        # Statistics
        self.stats = {
            "total_lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, alerts: List[Dict]) -> List[Dict]:
        """
        Enrich a list of alert dicts in-place with threat intelligence.

        For each alert, the ``metadata`` field is augmented with:
            - source_reputation: {reputation_score, is_malicious, country_code, ...}
            - destination_reputation: (if destination_ip present)
            - threat_summary: {max_threat_score, enriched_at}

        Returns the same list (mutated) for convenience.
        """
        for alert in alerts:
            try:
                src_ip = alert.get("source_ip")
                dst_ip = alert.get("destination_ip") or alert.get("metadata", {}).get("destination_ip")

                metadata = alert.setdefault("metadata", {})

                if src_ip:
                    src_data = self._lookup(src_ip)
                    if src_data:
                        metadata["source_reputation"] = src_data

                if dst_ip:
                    dst_data = self._lookup(dst_ip)
                    if dst_data:
                        metadata["destination_reputation"] = dst_data

                # Build summary
                src_score = (metadata.get("source_reputation") or {}).get("reputation_score", 0)
                dst_score = (metadata.get("destination_reputation") or {}).get("reputation_score", 0)
                metadata["threat_summary"] = {
                    "max_threat_score": max(src_score, dst_score),
                    "source_malicious": (metadata.get("source_reputation") or {}).get("is_malicious", False),
                    "destination_malicious": (metadata.get("destination_reputation") or {}).get("is_malicious", False),
                    "enriched_at": time.time(),
                }

            except Exception as e:
                logger.debug(f"Enrichment failed for alert: {e}")
                self.stats["errors"] += 1

        return alerts

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _lookup(self, ip: str) -> Optional[Dict]:
        """Look up a single IP, using cache when possible."""
        self.stats["total_lookups"] += 1

        # Check cache
        cached = self._cache.get(ip)
        if cached and cached["expires"] > time.time():
            self.stats["cache_hits"] += 1
            return cached["data"]

        self.stats["cache_misses"] += 1

        # Call edge function
        data = self._call_enrich_alert(ip)
        if data:
            self._cache[ip] = {
                "data": data,
                "expires": time.time() + self.cache_ttl,
            }
        return data

    def _call_enrich_alert(self, ip: str) -> Optional[Dict]:
        """Call the enrich-alert edge function for a single IP."""
        url = f"{self.supabase_url}/functions/v1/enrich-alert"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.supabase_key}",
        }
        body = {"source_ip": ip}

        try:
            resp = requests.post(url, json=body, headers=headers, timeout=10)
            resp.raise_for_status()
            result = resp.json()

            # The edge function returns {source_reputation, summary, ...}
            # Extract the source reputation data
            return result.get("source_reputation", result)

        except Exception as e:
            logger.warning(f"Enrich-alert failed for {ip}: {e}")
            self.stats["errors"] += 1
            return None

    def cleanup_cache(self):
        """Remove expired cache entries."""
        now = time.time()
        expired = [k for k, v in self._cache.items() if v["expires"] < now]
        for k in expired:
            del self._cache[k]

    def get_stats(self) -> Dict:
        """Return enrichment statistics."""
        return {
            **self.stats,
            "cache_size": len(self._cache),
        }


# ---------------------------------------------------------------------------
# Standalone usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "YOUR_ANON_KEY")

    enricher = ThreatIntelEnricher(SUPABASE_URL, SUPABASE_KEY)

    test_alerts = [
        {
            "alert_type": "Port Scan",
            "severity": "high",
            "source_ip": "185.220.101.1",
            "description": "Test alert",
            "detection_module": "test",
        }
    ]

    enriched = enricher.enrich(test_alerts)
    for a in enriched:
        print(f"  {a['source_ip']}: {a.get('metadata', {}).get('threat_summary', {})}")
    print(f"Stats: {enricher.get_stats()}")
