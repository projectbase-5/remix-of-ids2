"""
Module 7 — Notification Dispatcher
====================================
Multi-channel alert dispatcher supporting Email, Slack, Webhook, and SMS.

Usage:
    from notification_dispatcher import NotificationDispatcher

    dispatcher = NotificationDispatcher(supabase_url, supabase_key)
    dispatcher.dispatch(alert)

Integration points:
    - incident_scoring_engine.py calls dispatcher when score >= 100
    - response_manager.py calls dispatcher for executed actions

Reads notification_configs from Supabase to determine active channels
and severity thresholds.
"""

import time
import logging
import requests
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("notification_dispatcher")

# Severity ordering for threshold comparison
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class NotificationPayload:
    """Standard notification payload."""
    alert_type: str
    severity: str
    source_ip: str
    description: str
    timestamp: float = 0.0
    incident_id: Optional[str] = None
    score: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "description": self.description,
            "timestamp": self.timestamp or time.time(),
            "incident_id": self.incident_id,
            "score": self.score,
        }


class NotificationDispatcher:
    """
    Dispatches alerts to multiple channels based on notification_configs
    stored in Supabase.

    Channels:
        - email:   Calls send-alert-notification edge function
        - webhook: Direct HTTP POST to configured URL
        - slack:   Posts to Slack webhook URL
        - sms:     Placeholder for Twilio integration

    Features:
        - Deduplication via dedupe_key (60-second window)
        - Severity threshold filtering per channel
        - Rate limiting (max N notifications per minute)
        - Batch support
    """

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        rate_limit: int = 30,       # Max notifications per minute
        dedupe_window: int = 60,    # Dedup window in seconds
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key
        self.rate_limit = rate_limit
        self.dedupe_window = dedupe_window

        # Deduplication cache: dedupe_key -> last_sent_timestamp
        self._dedupe_cache: Dict[str, float] = {}

        # Rate limiting
        self._sent_timestamps: List[float] = []

        # Statistics
        self.stats = {
            "total_sent": 0,
            "total_skipped_dedup": 0,
            "total_skipped_threshold": 0,
            "total_skipped_rate_limit": 0,
            "by_channel": {"email": 0, "webhook": 0, "slack": 0, "sms": 0},
        }

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def fetch_configs(self) -> list:
        """Fetch active notification configs from Supabase."""
        url = f"{self.supabase_url}/rest/v1/notification_configs"
        params = {"is_active": "eq.true", "select": "*"}
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
        }

        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Failed to fetch notification configs: %s", e)
            return []

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(self, payload: NotificationPayload) -> dict:
        """
        Dispatch a notification to all configured channels.

        Args:
            payload: NotificationPayload with alert details

        Returns:
            dict with dispatch results per channel
        """
        # Check rate limit
        if self._is_rate_limited():
            self.stats["total_skipped_rate_limit"] += 1
            logger.warning("Rate limited, skipping notification")
            return {"skipped": "rate_limited"}

        # Check deduplication
        dedupe_key = self._make_dedupe_key(payload)
        if self._is_duplicate(dedupe_key):
            self.stats["total_skipped_dedup"] += 1
            logger.debug("Duplicate notification skipped: %s", dedupe_key)
            return {"skipped": "duplicate"}

        # Fetch active configs
        configs = self.fetch_configs()
        results = {}

        for config in configs:
            channel = config.get("config_type", "")
            target = config.get("target", "")
            threshold = config.get("severity_threshold", "critical")

            # Check severity threshold
            if not self._meets_threshold(payload.severity, threshold):
                self.stats["total_skipped_threshold"] += 1
                continue

            # Dispatch to channel
            try:
                if channel == "email":
                    results["email"] = self._send_email(target, payload)
                elif channel == "webhook":
                    results["webhook"] = self._send_webhook(target, payload)
                elif channel == "slack":
                    results["slack"] = self._send_slack(target, payload)
                elif channel == "sms":
                    results["sms"] = self._send_sms(target, payload)
                else:
                    logger.warning("Unknown channel: %s", channel)

                self.stats["by_channel"][channel] = (
                    self.stats["by_channel"].get(channel, 0) + 1
                )
            except Exception as e:
                logger.error("Failed to dispatch to %s: %s", channel, e)
                results[channel] = {"error": str(e)}

        # Record sent
        self._dedupe_cache[dedupe_key] = time.time()
        self._sent_timestamps.append(time.time())
        self.stats["total_sent"] += 1

        return results

    def dispatch_batch(self, payloads: List[NotificationPayload]) -> List[dict]:
        """Dispatch multiple notifications."""
        return [self.dispatch(p) for p in payloads]

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------

    def _send_email(self, target: str, payload: NotificationPayload) -> dict:
        """Send email via send-alert-notification edge function."""
        url = f"{self.supabase_url}/functions/v1/send-alert-notification"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.supabase_key}",
        }
        body = {
            "config_type": "email",
            "target": target,
            "alert": payload.to_dict(),
        }

        resp = requests.post(url, json=body, headers=headers, timeout=15)
        resp.raise_for_status()
        logger.info("Email sent to %s", target)
        return {"status": "sent", "target": target}

    def _send_webhook(self, target: str, payload: NotificationPayload) -> dict:
        """Send alert to a webhook URL via HTTP POST."""
        resp = requests.post(
            target,
            json=payload.to_dict(),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Webhook delivered to %s", target)
        return {"status": "sent", "target": target, "status_code": resp.status_code}

    def _send_slack(self, target: str, payload: NotificationPayload) -> dict:
        """Send alert to Slack via incoming webhook."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }
        emoji = severity_emoji.get(payload.severity, "⚪")

        slack_body = {
            "text": (
                f"{emoji} *IDS Alert — {payload.alert_type}*\n"
                f"*Severity:* {payload.severity.upper()}\n"
                f"*Source:* {payload.source_ip}\n"
                f"*Description:* {payload.description}"
            ),
        }

        if payload.score is not None:
            slack_body["text"] += f"\n*Score:* {payload.score}"

        resp = requests.post(
            target,
            json=slack_body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Slack notification sent")
        return {"status": "sent", "channel": "slack"}

    def _send_sms(self, target: str, payload: NotificationPayload) -> dict:
        """
        Placeholder for SMS via Twilio.

        To enable, set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and
        TWILIO_FROM_NUMBER environment variables.
        """
        logger.warning(
            "SMS dispatch not configured. Would send to %s: %s",
            target,
            payload.description,
        )
        return {"status": "placeholder", "target": target}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _meets_threshold(self, severity: str, threshold: str) -> bool:
        """Check if alert severity meets or exceeds the threshold."""
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)

    def _make_dedupe_key(self, payload: NotificationPayload) -> str:
        """Create a deduplication key from alert attributes."""
        raw = f"{payload.alert_type}:{payload.source_ip}:{payload.severity}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _is_duplicate(self, dedupe_key: str) -> bool:
        """Check if this notification was sent within the dedup window."""
        last_sent = self._dedupe_cache.get(dedupe_key)
        if last_sent is None:
            return False
        return (time.time() - last_sent) < self.dedupe_window

    def _is_rate_limited(self) -> bool:
        """Check if we've exceeded the rate limit."""
        now = time.time()
        cutoff = now - 60
        self._sent_timestamps = [t for t in self._sent_timestamps if t > cutoff]
        return len(self._sent_timestamps) >= self.rate_limit

    def get_stats(self) -> dict:
        """Return dispatch statistics."""
        return {**self.stats}
