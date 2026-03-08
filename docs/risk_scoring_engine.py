"""
Risk Scoring Engine — Module 9
================================
Computes per-host composite risk scores:

  risk = (alert_score + anomaly_score + reputation_penalty) × asset_criticality_weight

Data sources:
  • scored_incidents  → alert_score (severity-weighted sum)
  • predictions       → anomaly_score (anomaly count × 5)
  • ip_reputation     → reputation_penalty (100 - reputation_score)
  • asset_inventory   → asset_criticality_weight

Results are pushed to `host_risk_scores` table via ingest-traffic.
"""

import time
import math
import logging
import requests
from collections import defaultdict
from typing import Dict, List, Any, Optional

logger = logging.getLogger("risk_scoring_engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SUPABASE_URL = "https://saeofugyscjfgqqnqowk.supabase.co"
SUPABASE_KEY = "YOUR_SUPABASE_ANON_KEY"
INGEST_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = "YOUR_AGENT_API_KEY"

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
}

CRITICALITY_MULTIPLIERS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
}


def _supabase_get(table: str, params: Optional[Dict] = None) -> List[Dict]:
    """Fetch rows from a Supabase table via REST API."""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.get(url, headers=headers, params=params or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch {table}: {e}")
        return []


# ---------------------------------------------------------------------------
# Score Calculation
# ---------------------------------------------------------------------------
def compute_alert_scores() -> Dict[str, int]:
    """
    Sum severity-weighted scores from scored_incidents per source IP.
    """
    incidents = _supabase_get("scored_incidents", {
        "select": "source_ip,severity,total_score",
        "status": "eq.open",
    })

    scores: Dict[str, int] = defaultdict(int)
    for inc in incidents:
        ip = inc.get("source_ip", "")
        severity = inc.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        scores[ip] += weight + inc.get("total_score", 0) // 10

    return dict(scores)


def compute_anomaly_scores() -> Dict[str, int]:
    """
    Count anomaly predictions per source IP (from features.source_ip).
    Each anomaly = 5 points.
    """
    predictions = _supabase_get("predictions", {
        "select": "features,is_anomaly",
        "is_anomaly": "eq.true",
        "order": "created_at.desc",
        "limit": "1000",
    })

    scores: Dict[str, int] = defaultdict(int)
    for pred in predictions:
        features = pred.get("features", {})
        if isinstance(features, dict):
            ip = features.get("source_ip", "unknown")
        else:
            ip = "unknown"
        scores[ip] += 5

    return dict(scores)


def get_reputation_scores() -> Dict[str, int]:
    """
    Fetch IP reputation scores. Penalty = 100 - reputation_score.
    """
    ips = _supabase_get("ip_reputation", {
        "select": "ip_address,reputation_score",
    })

    scores: Dict[str, int] = {}
    for ip in ips:
        addr = ip.get("ip_address", "")
        rep = ip.get("reputation_score", 50)
        scores[addr] = 100 - rep  # Higher penalty for lower reputation

    return scores


def get_asset_multipliers() -> Dict[str, float]:
    """
    Map IP addresses to criticality multipliers from asset inventory.
    """
    assets = _supabase_get("asset_inventory", {
        "select": "ip_address,criticality,hostname",
        "is_active": "eq.true",
    })

    multipliers: Dict[str, float] = {}
    for asset in assets:
        ip = asset.get("ip_address", "")
        crit = asset.get("criticality", "medium")
        multipliers[ip] = CRITICALITY_MULTIPLIERS.get(crit, 1.0)

    return multipliers


def get_hostnames() -> Dict[str, str]:
    """Map IP addresses to hostnames from asset inventory."""
    assets = _supabase_get("asset_inventory", {
        "select": "ip_address,hostname",
    })
    return {a["ip_address"]: a.get("hostname") or "" for a in assets}


def compute_host_risk_scores() -> List[Dict[str, Any]]:
    """
    Compute composite risk scores for all known hosts.

    Returns:
        List of host risk score dicts ready for upsert.
    """
    alert_scores = compute_alert_scores()
    anomaly_scores = compute_anomaly_scores()
    reputation_penalties = get_reputation_scores()
    asset_multipliers = get_asset_multipliers()
    hostnames = get_hostnames()

    # Collect all known IPs
    all_ips = set()
    all_ips.update(alert_scores.keys())
    all_ips.update(anomaly_scores.keys())
    all_ips.update(reputation_penalties.keys())
    all_ips.update(asset_multipliers.keys())
    all_ips.discard("unknown")

    results = []
    for ip in all_ips:
        a_score = alert_scores.get(ip, 0)
        an_score = anomaly_scores.get(ip, 0)
        rep_score = reputation_penalties.get(ip, 0)
        multiplier = asset_multipliers.get(ip, 1.0)

        raw_risk = a_score + an_score + rep_score
        total_risk = min(100, int(raw_risk * multiplier))

        # Determine risk level
        if total_risk >= 80:
            risk_level = "critical"
        elif total_risk >= 60:
            risk_level = "high"
        elif total_risk >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        results.append({
            "ip_address": ip,
            "hostname": hostnames.get(ip, ""),
            "alert_score": a_score,
            "anomaly_score": an_score,
            "reputation_score": rep_score,
            "asset_multiplier": multiplier,
            "total_risk": total_risk,
            "risk_level": risk_level,
        })

    # Sort by risk descending
    results.sort(key=lambda x: x["total_risk"], reverse=True)
    logger.info(f"Computed risk scores for {len(results)} hosts")
    return results


def compute_network_risk(host_scores: List[Dict[str, Any]]) -> float:
    """
    Compute network-wide risk as a weighted average of all host scores.
    Higher-risk hosts contribute more to the aggregate.
    """
    if not host_scores:
        return 0.0

    total_weighted = sum(
        s["total_risk"] * s.get("asset_multiplier", 1.0)
        for s in host_scores
    )
    total_weight = sum(s.get("asset_multiplier", 1.0) for s in host_scores)

    return round(total_weighted / max(total_weight, 1), 1)


# ---------------------------------------------------------------------------
# Push Results
# ---------------------------------------------------------------------------
def push_risk_scores(scores: List[Dict[str, Any]]) -> bool:
    """Push host risk scores to ingest-traffic edge function."""
    if not scores:
        return True

    payload = {
        "api_key": AGENT_API_KEY,
        "risk_scores": scores,
    }

    try:
        resp = requests.post(INGEST_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"Pushed {len(scores)} risk scores: {data}")
        return True
    except Exception as e:
        logger.error(f"Failed to push risk scores: {e}")
        return False


# ---------------------------------------------------------------------------
# Continuous Loop
# ---------------------------------------------------------------------------
def run_continuous(interval: int = 300):
    """Run risk scoring in a loop every `interval` seconds."""
    logger.info(f"Starting risk scoring engine (interval={interval}s)")
    while True:
        try:
            scores = compute_host_risk_scores()
            network_risk = compute_network_risk(scores)
            logger.info(f"Network risk score: {network_risk}")
            push_risk_scores(scores)
        except Exception as e:
            logger.error(f"Risk scoring error: {e}")

        time.sleep(interval)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    scores = compute_host_risk_scores()
    network_risk = compute_network_risk(scores)

    print(f"\nNetwork Risk Score: {network_risk}")
    print(f"Hosts scored: {len(scores)}\n")
    for s in scores[:10]:
        print(
            f"  {s['ip_address']:20s} | "
            f"alert={s['alert_score']:3d} anom={s['anomaly_score']:3d} "
            f"rep={s['reputation_score']:3d} × {s['asset_multiplier']:.1f} "
            f"= {s['total_risk']:3d} ({s['risk_level']})"
        )
