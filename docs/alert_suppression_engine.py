"""
Alert Suppression Engine
=========================
Filters repetitive or low-risk alerts before they reach the AlertManager.

Rule types:
    - ``trusted_ip``    : Always suppress alerts from this source IP.
    - ``severity_filter``: Suppress alerts below a severity threshold.
    - ``rate_limit``     : Max N alerts per source IP per window (seconds).
    - ``pattern_ignore`` : Suppress alerts whose alert_type matches a regex.

Rules are fetched from the ``suppression_rules`` table in Supabase.

Usage in the IDS pipeline::

    suppression = AlertSuppressionEngine(SUPABASE_URL, SUPABASE_KEY)
    filtered = suppression.evaluate(raw_alerts)
    alert_manager.process(filtered)
"""

import re
import time
import requests


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AlertSuppressionEngine:
    """Evaluate alerts against suppression rules and filter noise."""

    def __init__(self, supabase_url, supabase_key, rule_refresh_interval=60):
        self.base_url = f"{supabase_url}/rest/v1"
        self.headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        self.rule_refresh_interval = rule_refresh_interval
        self._rules = []
        self._last_refresh = 0.0

        # Rate limit state: {source_ip: [(timestamp, count)]}
        self._rate_counts = {}

        # Stats
        self.stats = {
            "total_evaluated": 0,
            "total_suppressed": 0,
            "by_rule_type": {
                "trusted_ip": 0,
                "severity_filter": 0,
                "rate_limit": 0,
                "pattern_ignore": 0,
            },
        }

    def _refresh_rules(self):
        """Fetch active suppression rules from the database."""
        now = time.time()
        if now - self._last_refresh < self.rule_refresh_interval:
            return

        try:
            resp = requests.get(
                f"{self.base_url}/suppression_rules?is_active=eq.true&select=*",
                headers=self.headers,
                timeout=10,
            )
            if resp.status_code == 200:
                self._rules = resp.json()
                print(f"[SUPPRESS] Loaded {len(self._rules)} active suppression rules")
            else:
                print(f"[SUPPRESS] Rule fetch failed: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[SUPPRESS] Rule fetch error: {e}")

        self._last_refresh = now

    def _is_trusted_ip(self, alert, trusted_ips):
        """Check if alert source IP is in trusted list."""
        return alert.get("source_ip", "") in trusted_ips

    def _is_below_severity(self, alert, threshold):
        """Check if alert severity is below the threshold."""
        alert_sev = SEVERITY_ORDER.get(alert.get("severity", "low"), 1)
        threshold_sev = SEVERITY_ORDER.get(threshold, 2)
        return alert_sev < threshold_sev

    def _is_rate_limited(self, alert, max_count, window_seconds):
        """Check if source IP has exceeded the rate limit."""
        ip = alert.get("source_ip", "")
        now = time.time()

        if ip not in self._rate_counts:
            self._rate_counts[ip] = []

        # Clean old entries
        self._rate_counts[ip] = [
            t for t in self._rate_counts[ip] if now - t < window_seconds
        ]

        if len(self._rate_counts[ip]) >= max_count:
            return True

        self._rate_counts[ip].append(now)
        return False

    def _matches_pattern(self, alert, pattern):
        """Check if alert_type matches the suppression regex."""
        try:
            return bool(re.search(pattern, alert.get("alert_type", ""), re.IGNORECASE))
        except re.error:
            return False

    def _increment_rule_count(self, rule_id):
        """Increment the suppressed_count for a rule in the DB (fire-and-forget)."""
        try:
            requests.patch(
                f"{self.base_url}/suppression_rules?id=eq.{rule_id}",
                json={"suppressed_count": "suppressed_count + 1"},
                headers={**self.headers, "Prefer": "return=minimal"},
                timeout=5,
            )
        except Exception:
            pass

    def evaluate(self, alerts):
        """
        Apply suppression rules and return only non-suppressed alerts.

        Parameters
        ----------
        alerts : list[dict]
            Raw alerts from detectors.

        Returns
        -------
        list[dict]
            Alerts that passed all suppression rules.
        """
        self._refresh_rules()

        if not self._rules:
            return alerts

        # Pre-process rules by type
        trusted_ips = set()
        severity_threshold = None
        rate_limits = []
        patterns = []

        for rule in self._rules:
            rt = rule.get("rule_type", "")
            val = rule.get("value", "")

            if rt == "trusted_ip":
                trusted_ips.add(val)
            elif rt == "severity_filter":
                severity_threshold = val
            elif rt == "rate_limit":
                # value format: "count:window_seconds" e.g. "10:60"
                parts = val.split(":")
                if len(parts) == 2:
                    try:
                        rate_limits.append({
                            "max_count": int(parts[0]),
                            "window": int(parts[1]),
                            "rule_id": rule["id"],
                        })
                    except ValueError:
                        pass
            elif rt == "pattern_ignore":
                patterns.append({"pattern": val, "rule_id": rule["id"]})

        filtered = []
        for alert in alerts:
            self.stats["total_evaluated"] += 1
            suppressed = False

            # Check trusted IPs
            if trusted_ips and self._is_trusted_ip(alert, trusted_ips):
                self.stats["total_suppressed"] += 1
                self.stats["by_rule_type"]["trusted_ip"] += 1
                suppressed = True

            # Check severity threshold
            if not suppressed and severity_threshold and self._is_below_severity(alert, severity_threshold):
                self.stats["total_suppressed"] += 1
                self.stats["by_rule_type"]["severity_filter"] += 1
                suppressed = True

            # Check rate limits
            if not suppressed:
                for rl in rate_limits:
                    if self._is_rate_limited(alert, rl["max_count"], rl["window"]):
                        self.stats["total_suppressed"] += 1
                        self.stats["by_rule_type"]["rate_limit"] += 1
                        suppressed = True
                        break

            # Check pattern ignore
            if not suppressed:
                for pi in patterns:
                    if self._matches_pattern(alert, pi["pattern"]):
                        self.stats["total_suppressed"] += 1
                        self.stats["by_rule_type"]["pattern_ignore"] += 1
                        suppressed = True
                        break

            if not suppressed:
                filtered.append(alert)

        suppressed_count = len(alerts) - len(filtered)
        if suppressed_count > 0:
            print(f"[SUPPRESS] {suppressed_count}/{len(alerts)} alerts suppressed")

        return filtered

    def get_stats(self):
        """Return suppression statistics."""
        return dict(self.stats)
