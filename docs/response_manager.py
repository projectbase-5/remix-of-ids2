"""
Response Manager — Python Agent Module
========================================
Automated incident response actions triggered by the IDS agent.

Actions are logged to the backend via the execute-response edge function.
In production, each action handler would integrate with real infrastructure
(iptables, AWS WAF, Cloudflare API, EDR agents, SIEM webhooks, etc.).

Supported actions:
  - block_ip       : Block source IP at firewall
  - unblock_ip     : Remove IP block
  - isolate_host   : Quarantine a host from the network
  - send_notification : Alert SOC team via configured channels
  - rate_limit     : Apply rate limiting to a source IP
  - capture_forensics : Initiate forensic data capture

Usage:
  manager = ResponseManager(supabase_url, api_key)
  manager.block_ip("10.0.0.50", incident_id="abc-123")
  manager.isolate_host("10.0.0.50", reason="Multi-stage attack detected")

  # Or use automatic response based on severity:
  manager.auto_respond(incident)
"""

import time
import json
import logging
import subprocess
import requests
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ResponseManager:
    """
    Automated response manager for the IDS agent.

    Executes response actions locally and logs them to the Supabase backend.
    Actions can be triggered manually, by the scoring engine, or automatically
    based on incident severity thresholds.
    """

    def __init__(
        self,
        supabase_url: str,
        api_key: str,
        dry_run: bool = True,
        auto_block_threshold: int = 80,
        auto_isolate_threshold: int = 120,
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.api_key = api_key
        self.dry_run = dry_run
        self.auto_block_threshold = auto_block_threshold
        self.auto_isolate_threshold = auto_isolate_threshold

        # Track recent actions to prevent duplicates
        self._recent_actions: Dict[str, float] = {}
        self._cooldown_seconds = 300  # 5 min cooldown per IP+action

    def _is_on_cooldown(self, action_type: str, target: str) -> bool:
        key = f"{action_type}:{target}"
        last = self._recent_actions.get(key, 0)
        if time.time() - last < self._cooldown_seconds:
            logger.info(f"Action {key} on cooldown, skipping")
            return True
        return False

    def _record_action(self, action_type: str, target: str):
        self._recent_actions[f"{action_type}:{target}"] = time.time()

    def _log_to_backend(
        self,
        action_type: str,
        target_ip: str = None,
        target_host: str = None,
        parameters: Dict = None,
        incident_id: str = None,
        scored_incident_id: str = None,
    ) -> Optional[Dict]:
        """Send action to the execute-response edge function for logging."""
        try:
            url = f"{self.supabase_url}/functions/v1/execute-response"
            payload = {
                "action_type": action_type,
                "target_ip": target_ip,
                "target_host": target_host,
                "parameters": parameters or {},
                "incident_id": incident_id,
                "scored_incident_id": scored_incident_id,
                "triggered_by": "python_agent",
            }
            resp = requests.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(f"Action logged: {action_type} → {result.get('status')}")
            return result
        except Exception as e:
            logger.error(f"Failed to log action to backend: {e}")
            return None

    # -----------------------------------------------------------------------
    # Action: Block IP
    # -----------------------------------------------------------------------
    def block_ip(
        self,
        ip: str,
        incident_id: str = None,
        scored_incident_id: str = None,
        reason: str = "",
    ) -> bool:
        if self._is_on_cooldown("block_ip", ip):
            return False

        logger.warning(f"🚫 BLOCKING IP: {ip} | Reason: {reason}")

        if not self.dry_run:
            try:
                # Linux iptables example — adapt for your environment
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                )
                logger.info(f"iptables rule added for {ip}")
            except Exception as e:
                logger.error(f"Failed to add iptables rule: {e}")
        else:
            logger.info(f"[DRY RUN] Would block {ip} via iptables")

        self._record_action("block_ip", ip)
        self._log_to_backend(
            "block_ip",
            target_ip=ip,
            parameters={"reason": reason, "dry_run": self.dry_run},
            incident_id=incident_id,
            scored_incident_id=scored_incident_id,
        )
        return True

    # -----------------------------------------------------------------------
    # Action: Unblock IP
    # -----------------------------------------------------------------------
    def unblock_ip(self, ip: str, reason: str = "") -> bool:
        logger.info(f"✅ UNBLOCKING IP: {ip} | Reason: {reason}")

        if not self.dry_run:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                )
            except Exception as e:
                logger.error(f"Failed to remove iptables rule: {e}")
        else:
            logger.info(f"[DRY RUN] Would unblock {ip}")

        self._log_to_backend("unblock_ip", target_ip=ip, parameters={"reason": reason})
        return True

    # -----------------------------------------------------------------------
    # Action: Isolate Host
    # -----------------------------------------------------------------------
    def isolate_host(
        self,
        ip_or_host: str,
        incident_id: str = None,
        scored_incident_id: str = None,
        reason: str = "",
    ) -> bool:
        if self._is_on_cooldown("isolate_host", ip_or_host):
            return False

        logger.warning(f"🔒 ISOLATING HOST: {ip_or_host} | Reason: {reason}")

        if not self.dry_run:
            # In production: call EDR API, VLAN switch, or network segmentation tool
            logger.info(f"[PRODUCTION] Would isolate {ip_or_host} via EDR/NAC")
        else:
            logger.info(f"[DRY RUN] Would isolate {ip_or_host}")

        self._record_action("isolate_host", ip_or_host)
        self._log_to_backend(
            "isolate_host",
            target_ip=ip_or_host,
            target_host=ip_or_host,
            parameters={"reason": reason, "dry_run": self.dry_run},
            incident_id=incident_id,
            scored_incident_id=scored_incident_id,
        )
        return True

    # -----------------------------------------------------------------------
    # Action: Send Notification
    # -----------------------------------------------------------------------
    def send_notification(
        self,
        message: str,
        channel: str = "soc_team",
        severity: str = "high",
        incident_id: str = None,
    ) -> bool:
        logger.info(f"📢 NOTIFICATION [{severity}] → {channel}: {message}")

        # In production: integrate with Slack, PagerDuty, email, SMS, etc.
        if not self.dry_run:
            logger.info(f"[PRODUCTION] Would send to {channel}")
        else:
            logger.info(f"[DRY RUN] Would notify {channel}")

        self._log_to_backend(
            "send_notification",
            parameters={"message": message, "channel": channel, "severity": severity},
            incident_id=incident_id,
        )
        return True

    # -----------------------------------------------------------------------
    # Action: Rate Limit
    # -----------------------------------------------------------------------
    def rate_limit(
        self,
        ip: str,
        requests_per_minute: int = 10,
        incident_id: str = None,
    ) -> bool:
        if self._is_on_cooldown("rate_limit", ip):
            return False

        logger.info(f"⏱ RATE LIMITING: {ip} → {requests_per_minute} req/min")

        self._record_action("rate_limit", ip)
        self._log_to_backend(
            "rate_limit",
            target_ip=ip,
            parameters={"requests_per_minute": requests_per_minute},
            incident_id=incident_id,
        )
        return True

    # -----------------------------------------------------------------------
    # Action: Capture Forensics
    # -----------------------------------------------------------------------
    def capture_forensics(
        self,
        ip_or_host: str,
        incident_id: str = None,
    ) -> bool:
        logger.info(f"🔍 CAPTURING FORENSICS: {ip_or_host}")

        # In production: trigger tcpdump, memory dump, or EDR artifact collection
        if not self.dry_run:
            logger.info(f"[PRODUCTION] Would capture forensics for {ip_or_host}")
        else:
            logger.info(f"[DRY RUN] Would capture forensics for {ip_or_host}")

        self._log_to_backend(
            "capture_forensics",
            target_ip=ip_or_host,
            target_host=ip_or_host,
            incident_id=incident_id,
        )
        return True

    # -----------------------------------------------------------------------
    # Automatic Response Based on Incident Score
    # -----------------------------------------------------------------------
    def auto_respond(self, incident: Dict[str, Any]) -> List[str]:
        """
        Automatically execute response actions based on incident severity score.

        Thresholds:
          score >= auto_isolate_threshold → isolate + block + notify
          score >= auto_block_threshold   → block + notify
          score >= 30                     → rate limit + notify
          score < 30                      → notify only
        """
        score = incident.get("total_score", 0)
        source_ip = incident.get("source_ip", "unknown")
        incident_id = incident.get("id")
        scored_incident_id = incident.get("scored_incident_id")
        attack_types = incident.get("attack_types", [])
        actions_taken = []

        reason = f"Auto-response: score={score}, types={', '.join(attack_types)}"

        if score >= self.auto_isolate_threshold:
            self.isolate_host(source_ip, incident_id=incident_id,
                            scored_incident_id=scored_incident_id, reason=reason)
            actions_taken.append("isolate_host")

            self.block_ip(source_ip, incident_id=incident_id,
                        scored_incident_id=scored_incident_id, reason=reason)
            actions_taken.append("block_ip")

            self.capture_forensics(source_ip, incident_id=incident_id)
            actions_taken.append("capture_forensics")

            self.send_notification(
                f"🚨 CRITICAL: Host {source_ip} isolated — score {score} "
                f"({', '.join(attack_types)})",
                channel="soc_critical",
                severity="critical",
                incident_id=incident_id,
            )
            actions_taken.append("send_notification")

        elif score >= self.auto_block_threshold:
            self.block_ip(source_ip, incident_id=incident_id,
                        scored_incident_id=scored_incident_id, reason=reason)
            actions_taken.append("block_ip")

            self.send_notification(
                f"⚠️ HIGH: IP {source_ip} blocked — score {score} "
                f"({', '.join(attack_types)})",
                channel="soc_team",
                severity="high",
                incident_id=incident_id,
            )
            actions_taken.append("send_notification")

        elif score >= 30:
            self.rate_limit(source_ip, requests_per_minute=5, incident_id=incident_id)
            actions_taken.append("rate_limit")

            self.send_notification(
                f"⚡ MEDIUM: Rate limiting {source_ip} — score {score}",
                channel="soc_team",
                severity="medium",
                incident_id=incident_id,
            )
            actions_taken.append("send_notification")

        else:
            self.send_notification(
                f"ℹ️ LOW: Monitoring {source_ip} — score {score}",
                channel="soc_info",
                severity="low",
                incident_id=incident_id,
            )
            actions_taken.append("send_notification")

        logger.info(f"Auto-response for {source_ip}: {', '.join(actions_taken)}")
        return actions_taken


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co")
    API_KEY = os.getenv("AGENT_API_KEY", "")

    manager = ResponseManager(
        SUPABASE_URL,
        API_KEY,
        dry_run=True,
        auto_block_threshold=80,
        auto_isolate_threshold=120,
    )

    # Manual action
    manager.block_ip("10.0.0.50", reason="Port scan + exploit detected")
    manager.send_notification("Test notification from IDS agent", channel="soc_team")

    # Automatic response based on incident score
    test_incident = {
        "source_ip": "192.168.1.100",
        "total_score": 95,
        "attack_types": ["Port Scan", "Brute Force", "C2 Communication"],
    }
    actions = manager.auto_respond(test_incident)
    print(f"Actions taken: {actions}")

    # Critical incident example
    critical_incident = {
        "source_ip": "10.0.0.77",
        "total_score": 150,
        "attack_types": ["Port Scan", "Exploit", "Malware", "C2 Communication", "Data Exfiltration"],
    }
    actions = manager.auto_respond(critical_incident)
    print(f"Critical actions: {actions}")
