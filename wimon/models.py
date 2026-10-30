"""Shared data types. Nothing in here is platform-specific."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0  # logged only
    WARNING = 1  # notification, menu bar turns amber
    CRITICAL = 2  # full-screen alert, Wi-Fi disconnected


@dataclass
class Snapshot:
    """What the network looks like from this laptop at one moment."""

    interface: str
    wifi_on: bool
    ip: str | None = None
    router_ip: str | None = None
    router_mac: str | None = None
    dhcp_server: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    lease_start: str | None = None
    arp: dict[str, str] = field(default_factory=dict)  # ip -> mac
    # Only filled in when macOS grants Location access (needed to read SSID/BSSID).
    ssid: str | None = None
    bssid: str | None = None
    security: str | None = None
    taken_at: float = field(default_factory=time.time)

    @property
    def connected(self) -> bool:
        return self.wifi_on and bool(self.ip and self.router_ip)


@dataclass
class Baseline:
    """The network as it looked when we joined it. Detectors compare against this."""

    router_ip: str
    router_mac: str | None
    dhcp_server: str | None
    lease_start: str | None
    ip: str | None
    # IPs that already shared the router's MAC when we joined (proxy-ARP networks do this).
    shared_router_mac_ips: set[str] = field(default_factory=set)
    ssid: str | None = None
    security: str | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        """Identifies this network for the trust list."""
        return self.router_mac or f"ip:{self.router_ip}"


@dataclass
class Event:
    severity: Severity
    kind: str  # arp_spoof, dns_hijack, port_scan, evil_twin, tls_intercept, ...
    title: str  # short headline for the alert
    explanation: str  # plain-language "what this means"
    source_ip: str | None = None
    source_mac: str | None = None
    details: dict = field(default_factory=dict)
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
