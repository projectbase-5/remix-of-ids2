"""
Event Query Engine
==================
Queries Supabase tables (network_traffic, flow_metrics_log, incident_logs,
live_alerts, predictions) with unified filter parameters.

Usage (standalone):
    python event_query_engine.py --ip 192.168.1.10 --hours 24 --severity high

Integration:
    from event_query_engine import EventQueryEngine
    engine = EventQueryEngine(supabase_url, supabase_key)
    results = engine.search(source_ip="192.168.1.10", hours=24)
"""

import os
import json
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

logger = logging.getLogger("event_query_engine")

# ── helpers ──────────────────────────────────────────────────────────
TABLES = [
    "network_traffic",
    "flow_metrics_log",
    "incident_logs",
    "live_alerts",
    "predictions",
]


class EventQueryEngine:
    """Unified event search across all IDS-related Supabase tables."""

    def __init__(self, supabase_url: str, supabase_key: str):
        self.base_url = supabase_url.rstrip("/")
        self.headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    # ── core search ──────────────────────────────────────────────────
    def search(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        hours: int = 24,
        limit: int = 500,
        tables: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Search across tables and return unified results sorted by timestamp.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        target_tables = tables or TABLES
        all_results: list[dict] = []

        for table in target_tables:
            rows = self._query_table(
                table,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                severity=severity,
                attack_type=attack_type,
                cutoff=cutoff,
                limit=limit,
            )
            for row in rows:
                all_results.append(
                    {
                        "table": table,
                        "timestamp": row.get("created_at", ""),
                        **row,
                    }
                )

        # Sort newest first
        all_results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return all_results[:limit]

    # ── per-table query builder ──────────────────────────────────────
    def _query_table(
        self,
        table: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        protocol: Optional[str],
        severity: Optional[str],
        attack_type: Optional[str],
        cutoff: str,
        limit: int,
    ) -> list[dict]:
        params: list[str] = [
            "select=*",
            f"created_at=gte.{cutoff}",
            f"limit={limit}",
            "order=created_at.desc",
        ]

        # Apply filters based on which columns the table has
        if source_ip:
            if table in ("network_traffic", "incident_logs", "live_alerts", "flow_metrics_log"):
                params.append(f"source_ip=ilike.*{source_ip}*")

        if destination_ip:
            if table in ("network_traffic", "incident_logs", "live_alerts"):
                params.append(f"destination_ip=ilike.*{destination_ip}*")

        if protocol and table in ("network_traffic", "incident_logs"):
            params.append(f"protocol=eq.{protocol}")

        if severity and table in ("incident_logs", "live_alerts"):
            params.append(f"severity=eq.{severity}")

        if attack_type and table == "live_alerts":
            params.append(f"alert_type=ilike.*{attack_type}*")

        url = f"{self.base_url}/rest/v1/{table}?{'&'.join(params)}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("Query %s failed: %s", table, exc)
            return []

    # ── convenience shortcuts ────────────────────────────────────────
    def search_ip(self, ip: str, hours: int = 24) -> list[dict]:
        """Search all tables for a specific IP (source or destination)."""
        src = self.search(source_ip=ip, hours=hours)
        dst = self.search(destination_ip=ip, hours=hours)
        merged = {r.get("id", id(r)): r for r in src + dst}
        return sorted(merged.values(), key=lambda r: r.get("timestamp", ""), reverse=True)

    def search_alerts(self, severity: Optional[str] = None, hours: int = 24) -> list[dict]:
        """Search only live_alerts and incident_logs."""
        return self.search(
            severity=severity, hours=hours, tables=["live_alerts", "incident_logs"]
        )

    def search_traffic(
        self,
        source_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        hours: int = 24,
    ) -> list[dict]:
        """Search only network_traffic."""
        return self.search(
            source_ip=source_ip, protocol=protocol, hours=hours, tables=["network_traffic"]
        )


# ── CLI ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Event Query Engine")
    parser.add_argument("--ip", help="Source IP filter")
    parser.add_argument("--dest-ip", help="Destination IP filter")
    parser.add_argument("--protocol", help="Protocol filter")
    parser.add_argument("--severity", help="Severity filter")
    parser.add_argument("--attack-type", help="Attack type filter")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours")
    parser.add_argument("--limit", type=int, default=100, help="Max results")
    args = parser.parse_args()

    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY", ""))
    if not url or not key:
        print("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables")
        return

    engine = EventQueryEngine(url, key)
    results = engine.search(
        source_ip=args.ip,
        destination_ip=args.dest_ip,
        protocol=args.protocol,
        severity=args.severity,
        attack_type=args.attack_type,
        hours=args.hours,
        limit=args.limit,
    )

    print(f"Found {len(results)} results:")
    for r in results[:20]:
        print(f"  [{r['table']}] {r['timestamp']} | {json.dumps({k: v for k, v in r.items() if k not in ('table', 'timestamp')}, default=str)[:120]}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
