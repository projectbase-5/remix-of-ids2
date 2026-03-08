"""
Alert Manager
=============
Handles deduplication and HTTP dispatch of detection alerts.

Deduplication logic:
    Each alert is assigned a ``dedupe_key`` (MD5 hash of
    alert_type + source_ip + time_window).  If the same key has been
    seen within the last ``dedup_window`` seconds (default 60), the
    alert is silently dropped.  Expired keys are cleaned up on every
    ``process()`` call.

Dispatch:
    New (non-duplicate) alerts are immediately POSTed to the Supabase
    ``ingest-traffic`` edge function as ``{"api_key": …, "alerts": […]}``.
    The edge function then inserts them into the ``live_alerts`` table
    (with its own server-side deduplication by ``dedupe_key``).
"""

import time
import hashlib
import requests


class AlertManager:
    """Deduplicate and dispatch alerts to the Supabase edge function."""

    def __init__(self, edge_function_url, api_key, dedup_window=60):
        self.edge_function_url = edge_function_url
        self.api_key = api_key
        self.dedup_window = dedup_window
        # {dedupe_key: expiry_timestamp} — keys expire after dedup_window
        self._seen = {}

    def _cleanup(self):
        """Remove expired dedupe keys so memory doesn't grow unbounded."""
        now = time.time()
        expired = [k for k, v in self._seen.items() if v < now]
        for k in expired:
            del self._seen[k]

    def _make_dedupe_key(self, alert):
        """
        Generate a dedupe key for an alert.
        If the alert already has one (e.g. from a detector), use it.
        Otherwise hash (alert_type + source_ip + time_window).
        """
        if alert.get("dedupe_key"):
            return alert["dedupe_key"]
        window = int(time.time() / self.dedup_window)
        raw = f"{alert.get('alert_type', '')}_{alert.get('source_ip', '')}_{window}"
        return hashlib.md5(raw.encode()).hexdigest()

    def process(self, alerts):
        """
        Deduplicate and send alerts.
        Returns the count of alerts actually inserted server-side.
        """
        self._cleanup()
        to_send = []

        for alert in alerts:
            key = self._make_dedupe_key(alert)
            alert["dedupe_key"] = key

            # Skip if we've already dispatched this key recently
            if key in self._seen:
                continue

            # Mark as seen with an expiry timestamp
            self._seen[key] = time.time() + self.dedup_window
            to_send.append(alert)

        if not to_send:
            return 0

        return self._post_alerts(to_send)

    def _post_alerts(self, alerts):
        """POST alerts to the edge function and return insert count."""
        payload = {
            "api_key": self.api_key,
            "alerts": alerts,
        }
        try:
            resp = requests.post(
                self.edge_function_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                inserted = data.get("agent_alerts_inserted", 0)
                print(f"[ALERT] Sent {len(alerts)} alerts, {inserted} inserted")
                return inserted
            else:
                print(f"[ALERT] POST failed: {resp.status_code} {resp.text[:200]}")
                return 0
        except requests.exceptions.RequestException as e:
            print(f"[ALERT] Send failed: {e}")
            return 0
