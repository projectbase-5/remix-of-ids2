"""
Port Scan Detector
==================
Tracks destination ports per source IP in a sliding time window.

Detection logic:
    Maintains a per-source-IP history of (timestamp, dest_port) tuples.
    On each ``check()`` call, entries older than ``window_seconds`` are
    pruned.  If the remaining entries contain ≥ ``threshold`` unique
    destination ports the source is flagged as performing a port scan.

Defaults:
    - window_seconds = 10   (sliding window width)
    - threshold      = 15   (unique ports to trigger alert)

Deduplication:
    The alert's ``dedupe_key`` is an MD5 of "Port Scan_{source_ip}_{minute}"
    so the same scan only fires once per calendar minute.
"""

import time
import hashlib
from collections import defaultdict


class PortScanDetector:
    """Detect port-scanning behaviour from per-source-IP port diversity."""

    def __init__(self, threshold=15, window_seconds=10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # {source_ip: [(timestamp, dest_port), ...]}
        self._history = defaultdict(list)

    def ingest(self, packet):
        """
        Feed a packet dict with at least ``source_ip``, ``port``, and
        ``timestamp`` keys.  Only non-zero ports are recorded.
        """
        src = packet.get("source_ip", "0.0.0.0")
        port = packet.get("port", 0)
        ts = packet.get("timestamp", time.time())
        if port > 0:
            self._history[src].append((ts, port))

    def check(self):
        """
        Scan all source IPs and return a list of alert dicts for any that
        have contacted ≥ threshold unique ports within the sliding window.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        alerts = []

        for src, entries in list(self._history.items()):
            # Prune entries outside the sliding window
            entries[:] = [(t, p) for t, p in entries if t >= cutoff]
            if not entries:
                del self._history[src]
                continue

            unique_ports = set(p for _, p in entries)
            if len(unique_ports) >= self.threshold:
                # Minute-granularity key to avoid repeat alerts
                window_key = int(now / 60)
                dedupe_key = hashlib.md5(
                    f"Port Scan_{src}_{window_key}".encode()
                ).hexdigest()

                alerts.append({
                    "alert_type": "Port Scan",
                    "severity": "high",
                    "source_ip": src,
                    "description": (
                        f"Port scan detected: {src} probed {len(unique_ports)} "
                        f"unique ports in {self.window_seconds}s"
                    ),
                    "detection_module": "port_scan_detector",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "unique_ports": len(unique_ports),
                        "sample_ports": sorted(list(unique_ports))[:20],
                        "window_seconds": self.window_seconds,
                    },
                })
                # Clear history for this IP to avoid repeat alerts within window
                del self._history[src]

        return alerts

    def update_config(self, threshold=None, window_seconds=None):
        """Dynamically update detection thresholds."""
        if threshold is not None:
            self.threshold = threshold
        if window_seconds is not None:
            self.window_seconds = window_seconds
