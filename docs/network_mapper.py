"""
Module 5 — Network Topology Mapper
====================================
Discovers network devices from captured traffic and builds a topology graph
showing device-to-device connections.

Usage:
    from network_mapper import NetworkMapper

    mapper = NetworkMapper(supabase_url, agent_api_key)
    mapper.process_packet(source_ip, destination_ip, protocol, packet_size)
    mapper.flush()   # Push topology to ingest-traffic

The mapper maintains an in-memory adjacency graph and periodically flushes
discovered connections to Supabase via the ingest-traffic edge function.
"""

import time
import logging
import requests
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional

logger = logging.getLogger("network_mapper")


@dataclass
class Connection:
    """Represents a connection between two network hosts."""
    source_ip: str
    destination_ip: str
    connection_count: int = 0
    protocols: Set[str] = field(default_factory=set)
    bytes_transferred: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


class NetworkMapper:
    """
    Builds and maintains a network topology graph from observed traffic.

    The mapper tracks:
    - Node-to-node connections (edges)
    - Connection frequency (weight)
    - Protocols used per edge
    - Total bytes transferred per edge
    - Gateway detection (nodes with high connection counts)
    """

    def __init__(
        self,
        supabase_url: str,
        agent_api_key: str,
        flush_interval: int = 60,
        gateway_threshold: int = 10,
    ):
        self.supabase_url = supabase_url.rstrip("/")
        self.agent_api_key = agent_api_key
        self.flush_interval = flush_interval
        self.gateway_threshold = gateway_threshold

        # Adjacency map: (src, dst) -> Connection
        self.connections: Dict[tuple, Connection] = {}

        # Track per-node connection counts for gateway detection
        self.node_connections: Dict[str, Set[str]] = defaultdict(set)

        self.last_flush = time.time()

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def process_packet(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str = "TCP",
        packet_size: int = 0,
    ):
        """
        Record a connection between two hosts.

        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            protocol: Protocol (TCP, UDP, ICMP, etc.)
            packet_size: Size of the packet in bytes
        """
        if source_ip == destination_ip:
            return  # Skip loopback

        key = self._edge_key(source_ip, destination_ip)
        now = time.time()

        if key not in self.connections:
            self.connections[key] = Connection(
                source_ip=key[0],
                destination_ip=key[1],
                first_seen=now,
            )

        conn = self.connections[key]
        conn.connection_count += 1
        conn.protocols.add(protocol.upper())
        conn.bytes_transferred += packet_size
        conn.last_seen = now

        # Track node neighbors
        self.node_connections[source_ip].add(destination_ip)
        self.node_connections[destination_ip].add(source_ip)

        # Auto-flush if interval elapsed
        if time.time() - self.last_flush >= self.flush_interval:
            self.flush()

    def process_batch(self, packets: list):
        """Process a batch of packet dicts from the sniffer."""
        for pkt in packets:
            self.process_packet(
                source_ip=pkt.get("source_ip", "0.0.0.0"),
                destination_ip=pkt.get("destination_ip", "0.0.0.0"),
                protocol=pkt.get("protocol", "TCP"),
                packet_size=pkt.get("packet_size", 0),
            )

    # ------------------------------------------------------------------
    # Gateway detection
    # ------------------------------------------------------------------

    def get_gateways(self) -> List[str]:
        """
        Identify gateway nodes — hosts connected to many other hosts.

        Returns:
            List of IP addresses that exceed the gateway threshold.
        """
        return [
            ip
            for ip, neighbors in self.node_connections.items()
            if len(neighbors) >= self.gateway_threshold
        ]

    # ------------------------------------------------------------------
    # Topology export
    # ------------------------------------------------------------------

    def get_topology(self) -> dict:
        """
        Export the current topology as nodes + edges.

        Returns:
            {
                "nodes": [{"ip": "...", "connection_count": N, "is_gateway": bool}],
                "edges": [{"source_ip": "...", "destination_ip": "...", ...}]
            }
        """
        gateways = set(self.get_gateways())

        # Collect all unique IPs
        all_ips: Set[str] = set()
        for conn in self.connections.values():
            all_ips.add(conn.source_ip)
            all_ips.add(conn.destination_ip)

        nodes = [
            {
                "ip": ip,
                "connection_count": len(self.node_connections.get(ip, set())),
                "is_gateway": ip in gateways,
            }
            for ip in sorted(all_ips)
        ]

        edges = [
            {
                "source_ip": conn.source_ip,
                "destination_ip": conn.destination_ip,
                "connection_count": conn.connection_count,
                "protocols": sorted(conn.protocols),
                "bytes_transferred": conn.bytes_transferred,
                "first_seen": conn.first_seen,
                "last_seen": conn.last_seen,
            }
            for conn in self.connections.values()
        ]

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Flush to Supabase
    # ------------------------------------------------------------------

    def flush(self):
        """Push topology data to the ingest-traffic edge function."""
        if not self.connections:
            return

        topology_edges = []
        for conn in self.connections.values():
            topology_edges.append(
                {
                    "source_ip": conn.source_ip,
                    "destination_ip": conn.destination_ip,
                    "connection_count": conn.connection_count,
                    "protocols": sorted(conn.protocols),
                    "bytes_transferred": conn.bytes_transferred,
                }
            )

        payload = {
            "api_key": self.agent_api_key,
            "topology": topology_edges,
        }

        try:
            url = f"{self.supabase_url}/functions/v1/ingest-traffic"
            resp = requests.post(url, json=payload, timeout=15)
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                "Topology flush: %d edges sent, server inserted %s",
                len(topology_edges),
                result.get("topology_upserted", "?"),
            )
        except Exception as e:
            logger.error("Failed to flush topology: %s", e)

        self.last_flush = time.time()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _edge_key(ip_a: str, ip_b: str) -> tuple:
        """Normalize edge direction so (A,B) == (B,A)."""
        return tuple(sorted([ip_a, ip_b]))

    def reset(self):
        """Clear all tracked state."""
        self.connections.clear()
        self.node_connections.clear()

    def summary(self) -> dict:
        """Quick stats about the current topology."""
        all_ips: Set[str] = set()
        for conn in self.connections.values():
            all_ips.add(conn.source_ip)
            all_ips.add(conn.destination_ip)

        return {
            "total_nodes": len(all_ips),
            "total_edges": len(self.connections),
            "gateways": self.get_gateways(),
            "total_bytes": sum(c.bytes_transferred for c in self.connections.values()),
        }
