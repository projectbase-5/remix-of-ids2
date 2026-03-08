"""
Asset Discovery Engine — Module 10
====================================
Automatically discovers and tracks network assets from observed traffic.

For every packet processed by the IDS agent, the discovery engine:
  1. Extracts source and destination IPs
  2. Checks if each IP is already known (local cache)
  3. If new: upserts into ``asset_inventory`` via the Supabase REST API
  4. If known: periodically updates ``last_seen`` and ``connection_count``

Integration point:
    In ``ids_agent.py``, call ``discovery.update(packets)`` after each
    batch cycle to keep the asset inventory populated automatically.

Usage:
    discovery = AssetDiscovery(supabase_url, supabase_key)
    discovery.update(packets)   # list of packet dicts
"""

import time
import logging
import requests
from typing import Dict, List, Set, Optional
from collections import defaultdict

logger = logging.getLogger("asset_discovery")


class AssetDiscovery:
    """
    Tracks unique IPs observed in network traffic and upserts them
    into the ``asset_inventory`` Supabase table.

    Features:
        - Local cache of known IPs to minimise DB writes
        - Periodic ``last_seen`` sync (every sync_interval seconds)
        - Tracks open ports and protocols per host
        - Classifies device type heuristically from port usage
    """

    # Common port → service/device-type hints
    PORT_HINTS = {
        22: ("ssh", "server"),
        53: ("dns", "server"),
        80: ("http", "server"),
        443: ("https", "server"),
        3306: ("mysql", "server"),
        5432: ("postgres", "server"),
        8080: ("http-alt", "server"),
        3389: ("rdp", "workstation"),
        445: ("smb", "workstation"),
        137: ("netbios", "workstation"),
        161: ("snmp", "network_device"),
        179: ("bgp", "router"),
        1883: ("mqtt", "iot"),
        5683: ("coap", "iot"),
        8883: ("mqtt-tls", "iot"),
    }

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        sync_interval: int = 60,
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key
        self.sync_interval = sync_interval

        # {ip: {"first_seen": ts, "last_seen": ts, "ports": set, "protocols": set, "connections": int}}
        self._known: Dict[str, Dict] = {}
        self._last_sync = 0.0

        # Statistics
        self.stats = {
            "new_assets": 0,
            "updates": 0,
            "errors": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, packets: List[Dict]) -> int:
        """
        Process a batch of packet dicts and discover/update assets.

        Returns the number of new assets discovered in this batch.
        """
        new_count = 0
        now = time.time()

        for pkt in packets:
            src = pkt.get("source_ip", "")
            dst = pkt.get("destination_ip", "")
            port = pkt.get("port", 0)
            protocol = pkt.get("protocol", "TCP")

            for ip in (src, dst):
                if not ip or ip.startswith("0.") or ip == "255.255.255.255":
                    continue

                if ip not in self._known:
                    # New asset
                    self._known[ip] = {
                        "first_seen": now,
                        "last_seen": now,
                        "ports": set(),
                        "protocols": set(),
                        "connections": 0,
                    }
                    new_count += 1
                    self.stats["new_assets"] += 1

                entry = self._known[ip]
                entry["last_seen"] = now
                entry["connections"] += 1
                entry["protocols"].add(protocol)

                # Track destination ports for the destination IP
                if ip == dst and port > 0:
                    entry["ports"].add(port)

        # Upsert new assets immediately
        if new_count > 0:
            self._upsert_new_assets()

        # Periodic sync for last_seen updates
        if now - self._last_sync >= self.sync_interval:
            self._sync_existing()
            self._last_sync = now

        return new_count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _classify_device(self, ports: Set[int]) -> str:
        """Heuristically classify device type from observed ports."""
        device_votes = defaultdict(int)
        for port in ports:
            if port in self.PORT_HINTS:
                _, dtype = self.PORT_HINTS[port]
                device_votes[dtype] += 1

        if not device_votes:
            return "unknown"
        return max(device_votes, key=device_votes.get)

    def _get_services(self, ports: Set[int]) -> List[str]:
        """Map ports to known service names."""
        services = []
        for port in sorted(ports):
            if port in self.PORT_HINTS:
                services.append(self.PORT_HINTS[port][0])
        return services

    def _is_private(self, ip: str) -> bool:
        """Check if IP is in a private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
        except ValueError:
            return False
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    def _upsert_new_assets(self):
        """Upsert newly discovered assets to asset_inventory."""
        url = f"{self.supabase_url}/rest/v1/asset_inventory"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }

        for ip, info in self._known.items():
            # Only upsert assets seen recently (within last 10 seconds)
            if time.time() - info["first_seen"] > 10:
                continue

            ports = sorted(info["ports"])
            device_type = self._classify_device(info["ports"])
            services = self._get_services(info["ports"])

            row = {
                "ip_address": ip,
                "device_type": device_type,
                "open_ports": ports,
                "services": services,
                "is_active": True,
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info["last_seen"])),
            }

            try:
                # Use upsert (on conflict ip_address)
                resp = requests.post(url, json=row, headers=headers, timeout=10)
                if resp.status_code in (200, 201):
                    logger.info(f"Asset discovered: {ip} ({device_type})")
                elif resp.status_code == 409:
                    # Already exists — update instead
                    self._update_asset(ip, info)
                else:
                    logger.warning(f"Asset upsert {ip}: {resp.status_code}")
            except Exception as e:
                logger.error(f"Failed to upsert asset {ip}: {e}")
                self.stats["errors"] += 1

    def _update_asset(self, ip: str, info: Dict):
        """Update last_seen and connection data for an existing asset."""
        url = f"{self.supabase_url}/rest/v1/asset_inventory"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        params = {"ip_address": f"eq.{ip}"}

        ports = sorted(info["ports"])
        services = self._get_services(info["ports"])

        patch = {
            "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info["last_seen"])),
            "is_active": True,
            "open_ports": ports,
            "services": services,
        }

        try:
            resp = requests.patch(url, json=patch, headers=headers, params=params, timeout=10)
            if resp.status_code in (200, 204):
                self.stats["updates"] += 1
            else:
                logger.warning(f"Asset update {ip}: {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to update asset {ip}: {e}")
            self.stats["errors"] += 1

    def _sync_existing(self):
        """Periodically sync last_seen for all tracked assets."""
        url = f"{self.supabase_url}/rest/v1/asset_inventory"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }

        for ip, info in self._known.items():
            params = {"ip_address": f"eq.{ip}"}
            patch = {
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info["last_seen"])),
                "is_active": True,
            }
            try:
                requests.patch(url, json=patch, headers=headers, params=params, timeout=5)
            except Exception:
                pass

        logger.info(f"Asset sync complete: {len(self._known)} hosts tracked")

    def get_stats(self) -> Dict:
        """Return discovery statistics."""
        return {
            **self.stats,
            "tracked_hosts": len(self._known),
        }


# ---------------------------------------------------------------------------
# Standalone usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "YOUR_ANON_KEY")

    discovery = AssetDiscovery(SUPABASE_URL, SUPABASE_KEY)

    test_packets = [
        {"source_ip": "192.168.1.10", "destination_ip": "10.0.0.5", "port": 443, "protocol": "TCP"},
        {"source_ip": "192.168.1.10", "destination_ip": "10.0.0.5", "port": 80, "protocol": "TCP"},
        {"source_ip": "192.168.1.20", "destination_ip": "10.0.0.1", "port": 22, "protocol": "TCP"},
        {"source_ip": "172.16.0.100", "destination_ip": "8.8.8.8", "port": 53, "protocol": "UDP"},
    ]

    new = discovery.update(test_packets)
    print(f"New assets: {new}")
    print(f"Stats: {discovery.get_stats()}")
