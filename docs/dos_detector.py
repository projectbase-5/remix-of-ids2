"""
DoS / Flooding Detector (v2 — Production-Grade)
=================================================
Monitors packets per second (pps) per source IP and overall.

Detection strategies:
    1. **Per-source flooding** — If a single source exceeds
       ``pps_threshold`` (default 100) within the sliding window,
       a DoS alert is raised for that IP.
    2. **Global traffic spike** — An Exponential Moving Average (EMA)
       baseline of global pps is maintained.  If current global pps
       exceeds ``spike_factor`` × baseline (default 3×), a DDoS alert
       is raised.
    3. **Burst vs sustained classification** — Per-source attacks are
       classified as ``burst`` (<5s) or ``sustained`` (≥5s) based on
       how long the flooding persists.

Severity tuning:
    Severity is computed dynamically based on the ratio of actual pps
    to the threshold:
        - 1×–2× threshold → medium
        - 2×–5× threshold → high
        - >5× threshold   → critical

Defaults:
    - pps_threshold   = 100   (per-source packets/sec to trigger)
    - spike_factor    = 3.0   (global traffic multiplier for DDoS)
    - window_seconds  = 10    (sliding window width)
    - burst_threshold = 5     (seconds; below = burst, above = sustained)
    - ema_alpha       = 0.1   (EMA smoothing factor for baseline)
    - warmup_samples  = 10    (minimum samples before spike detection)

Deduplication:
    Alert ``dedupe_key`` uses minute-granularity so the same source or
    spike is only reported once per calendar minute.
"""

import time
import hashlib
from collections import defaultdict, deque


class DoSDetector:
    """Detect per-source flooding and global traffic spikes."""

    def __init__(
        self,
        pps_threshold=100,
        spike_factor=3.0,
        window_seconds=10,
        burst_threshold=5,
        ema_alpha=0.1,
        warmup_samples=10,
    ):
        self.pps_threshold = pps_threshold
        self.spike_factor = spike_factor
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.ema_alpha = ema_alpha
        self.warmup_samples = warmup_samples

        # Per-source timestamp deques for pps calculation
        self._per_source = defaultdict(deque)
        # Per-source first-seen timestamps (for burst vs sustained)
        self._source_first_seen = {}
        # Global timestamp deque
        self._global = deque()
        # EMA baseline for global pps
        self._ema_baseline = 0.0
        self._sample_count = 0

    def _compute_severity(self, pps, threshold):
        """Dynamic severity based on how far pps exceeds the threshold."""
        ratio = pps / max(threshold, 1)
        if ratio >= 5.0:
            return "critical"
        elif ratio >= 2.0:
            return "high"
        else:
            return "medium"

    def _classify_attack_mode(self, source_ip, now):
        """Classify as burst or sustained based on first-seen time."""
        first = self._source_first_seen.get(source_ip, now)
        duration = now - first
        return "sustained" if duration >= self.burst_threshold else "burst"

    def ingest(self, packet):
        """Record a packet's timestamp for rate tracking."""
        src = packet.get("source_ip", "0.0.0.0")
        ts = packet.get("timestamp", time.time())
        self._per_source[src].append(ts)
        self._global.append(ts)

        # Track first-seen for burst/sustained classification
        if src not in self._source_first_seen:
            self._source_first_seen[src] = ts

    def check(self):
        """
        Evaluate current traffic rates and return alert dicts for any
        detected flooding or spike conditions.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        alerts = []

        # Prune global deque and compute current global pps
        while self._global and self._global[0] < cutoff:
            self._global.popleft()

        global_pps = len(self._global) / max(self.window_seconds, 1)

        # Update EMA baseline
        self._sample_count += 1
        if self._sample_count == 1:
            self._ema_baseline = global_pps
        else:
            self._ema_baseline = (
                self.ema_alpha * global_pps
                + (1 - self.ema_alpha) * self._ema_baseline
            )

        # --- Per-source flooding check ---
        for src, timestamps in list(self._per_source.items()):
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            if not timestamps:
                del self._per_source[src]
                # Clean up first-seen
                self._source_first_seen.pop(src, None)
                continue

            pps = len(timestamps) / max(self.window_seconds, 1)
            if pps >= self.pps_threshold:
                attack_mode = self._classify_attack_mode(src, now)
                severity = self._compute_severity(pps, self.pps_threshold)
                window_key = int(now / 60)
                dedupe_key = hashlib.md5(
                    f"DoS_{src}_{window_key}".encode()
                ).hexdigest()

                duration = now - self._source_first_seen.get(src, now)
                alerts.append({
                    "alert_type": "DoS",
                    "severity": severity,
                    "source_ip": src,
                    "description": (
                        f"DoS flooding detected ({attack_mode}): {src} sending "
                        f"{pps:.0f} pps (threshold: {self.pps_threshold}, "
                        f"{pps / self.pps_threshold:.1f}x over limit, "
                        f"duration: {duration:.0f}s)"
                    ),
                    "detection_module": "dos_detector",
                    "dedupe_key": dedupe_key,
                    "metadata": {
                        "packets_per_second": round(pps, 1),
                        "threshold": self.pps_threshold,
                        "threshold_multiplier": round(pps / self.pps_threshold, 2),
                        "attack_mode": attack_mode,
                        "duration_seconds": round(duration, 1),
                    },
                })
                # Clear this source's history to reset tracking
                timestamps.clear()
                self._source_first_seen.pop(src, None)

        # --- Global traffic spike check (DDoS indicator) ---
        if (
            self._sample_count >= self.warmup_samples
            and self._ema_baseline > 0
            and global_pps > self._ema_baseline * self.spike_factor
        ):
            spike_ratio = global_pps / self._ema_baseline
            severity = self._compute_severity(global_pps, self._ema_baseline * self.spike_factor)
            window_key = int(now / 60)
            dedupe_key = hashlib.md5(
                f"DDoS_global_{window_key}".encode()
            ).hexdigest()
            alerts.append({
                "alert_type": "DDoS",
                "severity": severity,
                "source_ip": "multiple",
                "description": (
                    f"Traffic spike detected: {global_pps:.0f} pps vs "
                    f"EMA baseline {self._ema_baseline:.0f} pps "
                    f"({spike_ratio:.1f}x, spike_factor: {self.spike_factor}x)"
                ),
                "detection_module": "dos_detector",
                "dedupe_key": dedupe_key,
                "metadata": {
                    "current_pps": round(global_pps, 1),
                    "baseline_pps": round(self._ema_baseline, 1),
                    "spike_ratio": round(spike_ratio, 2),
                    "spike_factor": self.spike_factor,
                    "baseline_type": "ema",
                    "sample_count": self._sample_count,
                },
            })

        return alerts

    def update_config(
        self,
        pps_threshold=None,
        spike_factor=None,
        window_seconds=None,
        burst_threshold=None,
    ):
        """Dynamically update detection thresholds."""
        if pps_threshold is not None:
            self.pps_threshold = pps_threshold
        if spike_factor is not None:
            self.spike_factor = spike_factor
        if window_seconds is not None:
            self.window_seconds = window_seconds
        if burst_threshold is not None:
            self.burst_threshold = burst_threshold
