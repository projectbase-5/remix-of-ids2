"""
asset_inventory.py — Asset Inventory Agent Module
===================================================
Passive host discovery and device classification.

Extracts unique IPs from captured network traffic and upserts them
into the `asset_inventory` table via the ingest-traffic edge function.

Device classification heuristics:
  - port 22 + 80 + 443        → server
  - port 3389                  → windows_workstation
  - port 5432 / 3306 / 27017  → database_server
  - port 53                    → dns_server
  - port 25 / 587 / 993       → mail_server
  - DHCP (port 67/68)         → endpoint
  - otherwise                  → unknown

Usage:
    from asset_inventory import AssetInventory
    inventory = AssetInventory(api_url, api_key)
    inventory.process_packets(packets)
    inventory.flush()          # sends batch to ingest-traffic
"""

import time
import requests
import logging

logger = logging.getLogger("asset_inventory")

# ---------- Classification heuristics ----------

DB_PORTS = {5432, 3306, 27017, 6379, 9200}
SERVER_PORTS = {80, 443, 8080, 8443}
MAIL_PORTS = {25, 587, 993, 995, 143}


def classify_device(ip: str, open_ports: list[int], services: list[str] | None = None) -> dict:
    """
    Return {"device_type": ..., "os": ... (guess)} based on open ports.
    """
    port_set = set(open_ports)

    if port_set & DB_PORTS:
        return {"device_type": "database_server", "os": None}
    if 53 in port_set:
        return {"device_type": "dns_server", "os": None}
    if port_set & MAIL_PORTS:
        return {"device_type": "mail_server", "os": None}
    if port_set & SERVER_PORTS and 22 in port_set:
        return {"device_type": "linux_server", "os": "Linux"}
    if port_set & SERVER_PORTS:
        return {"device_type": "server", "os": None}
    if 3389 in port_set:
        return {"device_type": "windows_workstation", "os": "Windows"}
    if 22 in port_set:
        return {"device_type": "linux_endpoint", "os": "Linux"}
    if 67 in port_set or 68 in port_set:
        return {"device_type": "endpoint", "os": None}

    return {"device_type": "unknown", "os": None}


class AssetInventory:
    """Track hosts seen on the network and classify them."""

    def __init__(self, api_url: str, api_key: str, flush_interval: int = 30):
        self.api_url = api_url
        self.api_key = api_key
        self.flush_interval = flush_interval

        # ip -> {"open_ports": set(), "last_seen": float, "services": set()}
        self._hosts: dict[str, dict] = {}
        self._last_flush = time.time()

    # ---- ingestion ----

    def observe_packet(self, packet: dict):
        """Record a packet sighting.  Call for every captured packet."""
        for ip_field in ("source_ip", "destination_ip"):
            ip = packet.get(ip_field)
            if not ip or ip == "0.0.0.0":
                continue
            if ip not in self._hosts:
                self._hosts[ip] = {
                    "open_ports": set(),
                    "services": set(),
                    "last_seen": time.time(),
                }
            host = self._hosts[ip]
            host["last_seen"] = time.time()
            port = packet.get("port")
            if port:
                host["open_ports"].add(int(port))
            protocol = packet.get("protocol")
            if protocol:
                host["services"].add(protocol)

    def process_packets(self, packets: list[dict]):
        """Convenience: observe many packets at once."""
        for p in packets:
            self.observe_packet(p)
        if time.time() - self._last_flush >= self.flush_interval:
            self.flush()

    # ---- flush to backend ----

    def flush(self):
        """Send accumulated asset sightings to the ingest-traffic edge function."""
        if not self._hosts:
            return

        assets = []
        for ip, info in self._hosts.items():
            classification = classify_device(ip, list(info["open_ports"]))
            assets.append({
                "ip_address": ip,
                "device_type": classification["device_type"],
                "os": classification["os"],
                "open_ports": sorted(info["open_ports"]),
                "services": sorted(info["services"]),
                "last_seen": time.time(),
            })

        payload = {
            "api_key": self.api_key,
            "assets": assets,
        }

        try:
            resp = requests.post(
                f"{self.api_url}/functions/v1/ingest-traffic",
                json=payload,
                timeout=10,
            )
            if resp.ok:
                logger.info("Flushed %d assets to backend", len(assets))
            else:
                logger.error("Asset flush failed: %s %s", resp.status_code, resp.text)
        except Exception as e:
            logger.error("Asset flush error: %s", e)

        self._hosts.clear()
        self._last_flush = time.time()

    # ---- query helpers ----

    def get_known_hosts(self) -> dict[str, dict]:
        """Return current in-memory host map."""
        return {
            ip: {
                "open_ports": sorted(info["open_ports"]),
                "services": sorted(info["services"]),
                "last_seen": info["last_seen"],
                **classify_device(ip, list(info["open_ports"])),
            }
            for ip, info in self._hosts.items()
        }


# ---------- Standalone usage ----------

if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)

    SUPABASE_URL = os.getenv("SUPABASE_URL", "http://localhost:54321")
    AGENT_API_KEY = os.getenv("AGENT_API_KEY", "changeme")

    inv = AssetInventory(SUPABASE_URL, AGENT_API_KEY)

    # Example: simulate some packets
    sample_packets = [
        {"source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "port": 22, "protocol": "TCP"},
        {"source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "port": 80, "protocol": "TCP"},
        {"source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "port": 443, "protocol": "TCP"},
        {"source_ip": "192.168.1.20", "destination_ip": "10.0.0.2", "port": 5432, "protocol": "TCP"},
        {"source_ip": "192.168.1.30", "destination_ip": "10.0.0.3", "port": 3389, "protocol": "TCP"},
    ]

    inv.process_packets(sample_packets)
    inv.flush()

    for ip, info in inv.get_known_hosts().items():
        print(f"  {ip} → {info['device_type']} (OS: {info['os']})")
