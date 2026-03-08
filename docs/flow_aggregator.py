"""
Flow Aggregator (v2 — Active Detection)
========================================
Groups packets into flows by the 4-tuple:
    (source_ip, destination_ip, destination_port, protocol)

Each flow maintains a sliding window of ``window_seconds`` (default 10 s).
Old entries are pruned on every ``get_flows()`` call.

Per-flow statistics returned by ``get_flows()``:
    - packet_count        — number of packets in the window
    - bytes_transferred   — sum of packet sizes
    - packets_per_second  — packet_count / flow duration
    - duration_seconds    — time span of packets in the window

Anomaly detection (new in v2):
    ``detect_anomalies()`` returns alerts for:
    - Per-source fan-out   — source contacting too many unique destinations
    - Byte-rate spikes     — single flow exceeding byte-rate threshold
    - Destination spread   — source contacting too many unique ports

``get_unique_dest_ports(source_ip)`` returns the set of distinct
destination ports contacted by a given source IP within the window,
useful for cross-checking port scan detection.

``get_flow_summaries()`` returns compact summaries suitable for
persistence in a flow_metrics_log table.
"""

import time
from collections import defaultdict


class FlowAggregator:
    """Aggregate raw packets into per-flow statistics with anomaly detection."""

    def __init__(
        self,
        window_seconds=10,
        fanout_threshold=20,
        byte_rate_threshold=100000,
        dest_spread_threshold=15,
    ):
        self.window_seconds = window_seconds
        self.fanout_threshold = fanout_threshold
        self.byte_rate_threshold = byte_rate_threshold
        self.dest_spread_threshold = dest_spread_threshold
        # key: (src, dst, port, proto) -> list of (timestamp, packet_size)
        self._flows = defaultdict(list)

    def ingest(self, packet):
        """
        Record a packet into its flow bucket.
        The flow key is (source_ip, destination_ip, port, protocol).
        """
        key = (
            packet.get("source_ip", "0.0.0.0"),
            packet.get("destination_ip", "0.0.0.0"),
            packet.get("port", 0),
            packet.get("protocol", "TCP"),
        )
        ts = packet.get("timestamp", time.time())
        size = packet.get("packet_size", 0)
        self._flows[key].append((ts, size))

    def _prune(self):
        """Remove entries older than the sliding window."""
        cutoff = time.time() - self.window_seconds
        for key in list(self._flows.keys()):
            entries = self._flows[key]
            entries[:] = [(t, s) for t, s in entries if t >= cutoff]
            if not entries:
                del self._flows[key]

    def get_flows(self):
        """
        Return a list of active flow summary dicts.
        Prunes entries older than ``window_seconds`` and removes empty flows.
        """
        self._prune()
        summaries = []

        for key, entries in self._flows.items():
            if not entries:
                continue

            src, dst, port, proto = key
            packet_count = len(entries)
            bytes_total = sum(s for _, s in entries)
            duration = max(entries[-1][0] - entries[0][0], 0.001)

            summaries.append({
                "source_ip": src,
                "destination_ip": dst,
                "port": port,
                "protocol": proto,
                "packet_count": packet_count,
                "bytes_transferred": bytes_total,
                "packets_per_second": round(packet_count / duration, 1) if duration > 0.01 else packet_count,
                "duration_seconds": round(duration, 2),
            })

        return summaries

    def get_unique_dest_ports(self, source_ip):
        """Return the set of unique destination ports for a given source IP."""
        ports = set()
        cutoff = time.time() - self.window_seconds
        for (src, _, port, _), entries in self._flows.items():
            if src == source_ip:
                if any(t >= cutoff for t, _ in entries):
                    ports.add(port)
        return ports

    def detect_anomalies(self):
        """
        Analyze current flows for anomalous patterns.
        Returns a list of alert dicts for detected anomalies.
        """
        import hashlib

        self._prune()
        alerts = []
        now = time.time()
        window_key = int(now / 60)

        # --- Per-source fan-out: too many unique destinations ---
        src_destinations = defaultdict(set)
        for (src, dst, _, _) in self._flows:
            src_destinations[src].add(dst)

        for src, dests in src_destinations.items():
            if len(dests) >= self.fanout_threshold:
                dedupe_key = hashlib.md5(
                    f"flow_fanout_{src}_{window_key}".encode()
                ).hexdigest()
                alerts.append({
                    "alert_type": "Flow Anomaly",
                    "severity": "high" if len(dests) >= self.fanout_threshold * 2 else "medium",
                    "source_ip": src,
                    "description": (
                        f"High fan-out: {src} contacting {len(dests)} unique "
                        f"destinations (threshold: {self.fanout_threshold})"
                    ),
                    "detection_module": "flow_aggregator",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "anomaly_type": "fan_out",
                        "unique_destinations": len(dests),
                        "threshold": self.fanout_threshold,
                    },
                })

        # --- Per-source destination port spread ---
        src_ports = defaultdict(set)
        for (src, _, port, _) in self._flows:
            src_ports[src].add(port)

        for src, ports in src_ports.items():
            if len(ports) >= self.dest_spread_threshold:
                dedupe_key = hashlib.md5(
                    f"flow_spread_{src}_{window_key}".encode()
                ).hexdigest()
                alerts.append({
                    "alert_type": "Flow Anomaly",
                    "severity": "high",
                    "source_ip": src,
                    "description": (
                        f"Port spread: {src} contacting {len(ports)} unique "
                        f"ports (threshold: {self.dest_spread_threshold})"
                    ),
                    "detection_module": "flow_aggregator",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "anomaly_type": "destination_spread",
                        "unique_ports": len(ports),
                        "threshold": self.dest_spread_threshold,
                    },
                })

        # --- Per-flow byte-rate spike ---
        for key, entries in self._flows.items():
            if len(entries) < 2:
                continue
            src, dst, port, proto = key
            duration = max(entries[-1][0] - entries[0][0], 0.001)
            bytes_total = sum(s for _, s in entries)
            byte_rate = bytes_total / duration

            if byte_rate >= self.byte_rate_threshold:
                dedupe_key = hashlib.md5(
                    f"flow_byterate_{src}_{dst}_{port}_{window_key}".encode()
                ).hexdigest()
                alerts.append({
                    "alert_type": "Flow Anomaly",
                    "severity": "high" if byte_rate >= self.byte_rate_threshold * 3 else "medium",
                    "source_ip": src,
                    "description": (
                        f"High byte-rate: {src} → {dst}:{port}/{proto} at "
                        f"{byte_rate:.0f} B/s (threshold: {self.byte_rate_threshold})"
                    ),
                    "detection_module": "flow_aggregator",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "anomaly_type": "byte_rate_spike",
                        "byte_rate": round(byte_rate, 1),
                        "threshold": self.byte_rate_threshold,
                        "destination_ip": dst,
                        "port": port,
                    },
                })

        return alerts

    def get_flow_summaries(self):
        """
        Return compact flow summaries suitable for persistence.
        Includes per-source aggregate metrics.
        """
        flows = self.get_flows()
        src_agg = defaultdict(lambda: {
            "total_packets": 0,
            "total_bytes": 0,
            "unique_dests": set(),
            "unique_ports": set(),
        })

        for f in flows:
            src = f["source_ip"]
            src_agg[src]["total_packets"] += f["packet_count"]
            src_agg[src]["total_bytes"] += f["bytes_transferred"]
            src_agg[src]["unique_dests"].add(f["destination_ip"])
            src_agg[src]["unique_ports"].add(f["port"])

        summaries = []
        for src, agg in src_agg.items():
            summaries.append({
                "source_ip": src,
                "total_packets": agg["total_packets"],
                "total_bytes": agg["total_bytes"],
                "unique_destinations": len(agg["unique_dests"]),
                "unique_ports": len(agg["unique_ports"]),
                "active_flows": sum(1 for f in flows if f["source_ip"] == src),
            })

        return summaries

    def update_config(
        self,
        fanout_threshold=None,
        byte_rate_threshold=None,
        dest_spread_threshold=None,
        window_seconds=None,
    ):
        """Dynamically update flow anomaly thresholds."""
        if fanout_threshold is not None:
            self.fanout_threshold = fanout_threshold
        if byte_rate_threshold is not None:
            self.byte_rate_threshold = byte_rate_threshold
        if dest_spread_threshold is not None:
            self.dest_spread_threshold = dest_spread_threshold
        if window_seconds is not None:
            self.window_seconds = window_seconds
