"""
Module 6 — Data Retention Manager
====================================
Automates data lifecycle management: archives old events, compresses logs,
and cleans up the database to prevent unbounded growth.

Usage:
    from data_retention_manager import DataRetentionManager

    manager = DataRetentionManager(supabase_url, agent_api_key)
    manager.run_cleanup()

The manager reads retention policies from Supabase and calls the
`cleanup-data` edge function to execute deletions.
"""

import time
import logging
import requests
import threading
from typing import Optional

logger = logging.getLogger("data_retention_manager")

# Default retention periods (days) per table
DEFAULT_POLICIES = {
    "network_traffic": 7,
    "system_metrics_log": 14,
    "flow_metrics_log": 14,
    "live_alerts": 30,
    "incident_logs": 90,
    "predictions": 30,
    "network_topology": 30,
}


class DataRetentionManager:
    """
    Manages data retention for the IDS system.

    Periodically calls the cleanup-data edge function to delete old rows
    based on configurable retention policies stored in Supabase.
    """

    def __init__(
        self,
        supabase_url: str,
        agent_api_key: str,
        check_interval: int = 3600,  # Default: check every hour
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.agent_api_key = agent_api_key
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Statistics
        self.total_cleanups = 0
        self.total_rows_deleted = 0
        self.last_cleanup_time: Optional[float] = None
        self.cleanup_history: list = []

    # ------------------------------------------------------------------
    # Cleanup execution
    # ------------------------------------------------------------------

    def run_cleanup(self) -> dict:
        """
        Trigger a cleanup by calling the cleanup-data edge function.

        Returns:
            dict with cleanup results from the edge function
        """
        url = f"{self.supabase_url}/functions/v1/cleanup-data"
        payload = {"api_key": self.agent_api_key}

        try:
            resp = requests.post(url, json=payload, timeout=60)
            resp.raise_for_status()
            result = resp.json()

            self.total_cleanups += 1
            self.last_cleanup_time = time.time()

            total_deleted = result.get("total_deleted", 0)
            self.total_rows_deleted += total_deleted

            self.cleanup_history.append(
                {
                    "timestamp": time.time(),
                    "total_deleted": total_deleted,
                    "details": result.get("details", []),
                }
            )

            # Keep history bounded
            if len(self.cleanup_history) > 100:
                self.cleanup_history = self.cleanup_history[-100:]

            logger.info(
                "Cleanup completed: %d rows deleted across %d tables",
                total_deleted,
                len(result.get("details", [])),
            )
            return result

        except Exception as e:
            logger.error("Cleanup failed: %s", e)
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Background scheduler
    # ------------------------------------------------------------------

    def start(self):
        """Start the retention manager in a background thread."""
        if self._running:
            logger.warning("Retention manager already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info(
            "Retention manager started (interval: %ds)", self.check_interval
        )

    def stop(self):
        """Stop the background thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Retention manager stopped")

    def _loop(self):
        """Background loop that periodically runs cleanup."""
        while self._running:
            try:
                self.run_cleanup()
            except Exception as e:
                logger.error("Retention loop error: %s", e)

            # Sleep in small increments to allow quick shutdown
            for _ in range(self.check_interval):
                if not self._running:
                    break
                time.sleep(1)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return cleanup statistics."""
        return {
            "total_cleanups": self.total_cleanups,
            "total_rows_deleted": self.total_rows_deleted,
            "last_cleanup_time": self.last_cleanup_time,
            "is_running": self._running,
            "check_interval": self.check_interval,
            "recent_history": self.cleanup_history[-10:],
        }
