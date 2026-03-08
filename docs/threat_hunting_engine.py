"""
Threat Hunting Engine — Module 8
=================================
Pre-built hunt queries for proactive threat detection:
  • Rare destinations: hosts contacting IPs seen by < N other hosts
  • DNS entropy: flag hostnames with high Shannon entropy (DGA detection)
  • Beaconing: detect periodic connections with low jitter
  • Data exfiltration: hosts with abnormally high outbound bytes

Results are pushed to the `ingest-traffic` edge function as `hunt_results[]`.
"""

import math
import time
import logging
import requests
from collections import defaultdict
from typing import List, Dict, Any, Optional

logger = logging.getLogger("threat_hunting_engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SUPABASE_URL = "https://saeofugyscjfgqqnqowk.supabase.co"
INGEST_URL = f"{SUPABASE_URL}/functions/v1/ingest-traffic"
AGENT_API_KEY = "YOUR_AGENT_API_KEY"


# ---------------------------------------------------------------------------
# Shannon Entropy Calculator
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ---------------------------------------------------------------------------
# Hunt: Rare Destinations
# ---------------------------------------------------------------------------
def hunt_rare_destinations(
    traffic_data: List[Dict[str, Any]],
    threshold: int = 2
) -> List[Dict[str, Any]]:
    """
    Find hosts contacting destination IPs that fewer than `threshold`
    other source IPs have contacted.

    Args:
        traffic_data: List of packet dicts with source_ip, destination_ip
        threshold: Max number of unique sources contacting a dest to flag it

    Returns:
        List of hunt result dicts
    """
    # Build dest -> set of sources mapping
    dest_sources: Dict[str, set] = defaultdict(set)
    for pkt in traffic_data:
        src = pkt.get("source_ip", "")
        dst = pkt.get("destination_ip", "")
        if src and dst:
            dest_sources[dst].add(src)

    # Find rare destinations (contacted by fewer than threshold sources)
    rare_dests = {dst for dst, sources in dest_sources.items() if len(sources) < threshold}

    # Build results: which sources are contacting rare destinations
    src_rare_contacts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for pkt in traffic_data:
        src = pkt.get("source_ip", "")
        dst = pkt.get("destination_ip", "")
        if dst in rare_dests:
            src_rare_contacts[src][dst] += 1

    results = []
    for src, dests in src_rare_contacts.items():
        for dst, count in dests.items():
            uniqueness = 1.0 / max(len(dest_sources[dst]), 1)
            score = min(100, int(uniqueness * 100 * math.log2(count + 1)))
            results.append({
                "hunt_type": "rare_destination",
                "source_ip": src,
                "target": dst,
                "score": score,
                "details": {
                    "contact_count": count,
                    "total_sources_for_dest": len(dest_sources[dst]),
                    "threshold": threshold,
                },
            })

    logger.info(f"Rare destination hunt: {len(results)} findings")
    return results


# ---------------------------------------------------------------------------
# Hunt: DNS Entropy (DGA Detection)
# ---------------------------------------------------------------------------
def hunt_dns_entropy(
    dns_queries: List[Dict[str, Any]],
    entropy_threshold: float = 3.5
) -> List[Dict[str, Any]]:
    """
    Flag DNS queries with high Shannon entropy, indicative of
    Domain Generation Algorithm (DGA) usage.

    Args:
        dns_queries: List of dicts with source_ip, domain
        entropy_threshold: Minimum entropy to flag

    Returns:
        List of hunt result dicts
    """
    results = []
    for query in dns_queries:
        domain = query.get("domain", "")
        src = query.get("source_ip", "")

        # Strip TLD for entropy calculation
        parts = domain.split(".")
        if len(parts) >= 2:
            name_part = parts[0]  # Subdomain or main name
        else:
            name_part = domain

        entropy = shannon_entropy(name_part)
        if entropy >= entropy_threshold:
            score = min(100, int((entropy / 5.0) * 100))
            results.append({
                "hunt_type": "dns_entropy",
                "source_ip": src,
                "target": domain,
                "score": score,
                "details": {
                    "entropy": round(entropy, 3),
                    "name_part": name_part,
                    "length": len(name_part),
                    "threshold": entropy_threshold,
                },
            })

    logger.info(f"DNS entropy hunt: {len(results)} findings")
    return results


# ---------------------------------------------------------------------------
# Hunt: Beaconing Detection
# ---------------------------------------------------------------------------
def hunt_beaconing(
    connections: List[Dict[str, Any]],
    jitter_threshold: float = 0.15
) -> List[Dict[str, Any]]:
    """
    Detect periodic connections (beaconing) by analyzing inter-arrival
    times. Low jitter (coefficient of variation) indicates C2 beaconing.

    Args:
        connections: List of dicts with source_ip, destination_ip, timestamp
        jitter_threshold: Max CV to flag as beaconing (0-1)

    Returns:
        List of hunt result dicts
    """
    # Group connections by (source, dest) pair
    pairs: Dict[str, List[float]] = defaultdict(list)
    for conn in connections:
        src = conn.get("source_ip", "")
        dst = conn.get("destination_ip", "")
        ts = conn.get("timestamp", 0)
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                continue
        key = f"{src}->{dst}"
        pairs[key].append(float(ts))

    results = []
    for pair_key, timestamps in pairs.items():
        if len(timestamps) < 5:
            continue

        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue

        std_interval = math.sqrt(sum((x - mean_interval) ** 2 for x in intervals) / len(intervals))
        cv = std_interval / mean_interval  # Coefficient of variation

        if cv <= jitter_threshold:
            src, dst = pair_key.split("->")
            score = min(100, int((1.0 - cv) * 100))
            results.append({
                "hunt_type": "beaconing",
                "source_ip": src,
                "target": dst,
                "score": score,
                "details": {
                    "mean_interval_sec": round(mean_interval, 2),
                    "jitter_cv": round(cv, 4),
                    "connection_count": len(timestamps),
                    "threshold": jitter_threshold,
                },
            })

    logger.info(f"Beaconing hunt: {len(results)} findings")
    return results


# ---------------------------------------------------------------------------
# Hunt: Data Exfiltration
# ---------------------------------------------------------------------------
def hunt_data_exfil(
    flow_data: List[Dict[str, Any]],
    bytes_threshold: int = 10_000_000  # 10 MB
) -> List[Dict[str, Any]]:
    """
    Find hosts with abnormally high outbound byte counts,
    potentially indicating data exfiltration.

    Args:
        flow_data: List of dicts with source_ip, total_bytes
        bytes_threshold: Minimum bytes to flag

    Returns:
        List of hunt result dicts
    """
    # Aggregate bytes per source IP
    bytes_by_src: Dict[str, int] = defaultdict(int)
    dest_by_src: Dict[str, set] = defaultdict(set)

    for flow in flow_data:
        src = flow.get("source_ip", "")
        total_bytes = flow.get("total_bytes", 0)
        dst = flow.get("destination_ip", "")
        bytes_by_src[src] += total_bytes
        if dst:
            dest_by_src[src].add(dst)

    # Calculate mean and std for z-score
    all_bytes = list(bytes_by_src.values())
    if not all_bytes:
        return []

    mean_bytes = sum(all_bytes) / len(all_bytes)
    std_bytes = math.sqrt(sum((x - mean_bytes) ** 2 for x in all_bytes) / max(len(all_bytes), 1))

    results = []
    for src, total in bytes_by_src.items():
        if total >= bytes_threshold:
            z_score = (total - mean_bytes) / max(std_bytes, 1)
            score = min(100, max(0, int(z_score * 20)))
            results.append({
                "hunt_type": "data_exfil",
                "source_ip": src,
                "target": f"{len(dest_by_src[src])} destinations",
                "score": score,
                "details": {
                    "total_bytes": total,
                    "total_bytes_mb": round(total / 1_000_000, 2),
                    "z_score": round(z_score, 2),
                    "unique_destinations": len(dest_by_src[src]),
                    "threshold_bytes": bytes_threshold,
                },
            })

    logger.info(f"Data exfil hunt: {len(results)} findings")
    return results


# ---------------------------------------------------------------------------
# Unified Hunt Runner
# ---------------------------------------------------------------------------
def run_hunt(
    hunt_type: str,
    data: List[Dict[str, Any]],
    params: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Run a specific hunt query.

    Args:
        hunt_type: One of rare_destination, dns_entropy, beaconing, data_exfil
        data: Input data appropriate for the hunt type
        params: Optional parameters to override defaults

    Returns:
        List of hunt result dicts
    """
    params = params or {}

    hunters = {
        "rare_destination": lambda: hunt_rare_destinations(data, params.get("threshold", 2)),
        "dns_entropy": lambda: hunt_dns_entropy(data, params.get("entropy_threshold", 3.5)),
        "beaconing": lambda: hunt_beaconing(data, params.get("jitter_threshold", 0.15)),
        "data_exfil": lambda: hunt_data_exfil(data, params.get("bytes_threshold", 10_000_000)),
    }

    if hunt_type not in hunters:
        logger.error(f"Unknown hunt type: {hunt_type}")
        return []

    return hunters[hunt_type]()


# ---------------------------------------------------------------------------
# Push Results to Supabase
# ---------------------------------------------------------------------------
def push_hunt_results(results: List[Dict[str, Any]]) -> bool:
    """Push hunt results to the ingest-traffic edge function."""
    if not results:
        return True

    payload = {
        "api_key": AGENT_API_KEY,
        "hunt_results": results,
    }

    try:
        resp = requests.post(INGEST_URL, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"Pushed {len(results)} hunt results: {data}")
        return True
    except Exception as e:
        logger.error(f"Failed to push hunt results: {e}")
        return False


# ---------------------------------------------------------------------------
# Main — example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example: DNS entropy hunt with sample data
    sample_dns = [
        {"source_ip": "192.168.1.10", "domain": "xkcd7f9a2b.evil.com"},
        {"source_ip": "192.168.1.10", "domain": "a8f7d2e1c9.evil.com"},
        {"source_ip": "192.168.1.20", "domain": "google.com"},
        {"source_ip": "192.168.1.30", "domain": "qz8x7v6w5u.malware.net"},
    ]

    results = run_hunt("dns_entropy", sample_dns, {"entropy_threshold": 3.0})
    for r in results:
        print(f"  [{r['hunt_type']}] {r['source_ip']} -> {r['target']} (score: {r['score']})")

    # Push to Supabase
    # push_hunt_results(results)
