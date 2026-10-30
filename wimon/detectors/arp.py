"""ARP spoofing: someone on the Wi-Fi pretends to be the router to sit between you and the internet."""

from __future__ import annotations

from ..models import Baseline, Event, Severity, Snapshot

EXPLANATION = (
    "Another device on this Wi-Fi is pretending to be the router. Your internet traffic was "
    "flowing through that device first, so it could read or change what you send and receive. "
    "This is called a man-in-the-middle attack."
)


class ArpSpoofDetector:
    name = "arp"

    def __init__(self):
        self._warned_lease_change: str | None = None

    def check(self, snap: Snapshot, base: Baseline, lease_changed: bool) -> list[Event]:
        if not snap.router_mac or not base.router_mac:
            return []
        events = []

        if snap.router_mac != base.router_mac:
            attacker_ip = next(
                (ip for ip, mac in snap.arp.items() if mac == snap.router_mac and ip != snap.router_ip),
                None,
            )
            details = {
                "router_ip": snap.router_ip,
                "expected_router_mac": base.router_mac,
                "current_router_mac": snap.router_mac,
            }
            if lease_changed and attacker_ip is None:
                # A DHCP lease and the router changed together: most likely a different
                # router that reuses the same address. Say so once, then let the engine re-baseline.
                if self._warned_lease_change != snap.router_mac:
                    self._warned_lease_change = snap.router_mac
                    events.append(Event(
                        Severity.WARNING, "router_changed", "The router's identity changed",
                        "The device answering as your router is not the one you joined. If you "
                        "just moved to a different Wi-Fi, this is normal. If you did not, treat "
                        "this network as unsafe.",
                        source_mac=snap.router_mac, details=details,
                    ))
                return events
            events.append(Event(
                Severity.CRITICAL, "arp_spoof", "Man-in-the-middle attack (ARP spoofing)",
                EXPLANATION, source_ip=attacker_ip, source_mac=snap.router_mac, details=details,
            ))
            return events

        # The router's MAC is right, but a new device has started claiming it as well.
        sharers = {
            ip for ip, mac in snap.arp.items()
            if mac == base.router_mac and ip != snap.router_ip
        } - base.shared_router_mac_ips
        if sharers:
            ip = sorted(sharers)[0]
            events.append(Event(
                Severity.WARNING, "mac_conflict", "A device is copying the router's identity",
                "A device on this Wi-Fi is answering with the router's hardware address. This is "
                "often the first step of a man-in-the-middle attack.",
                source_ip=ip, source_mac=base.router_mac,
                details={"router_ip": snap.router_ip, "ips_sharing_router_mac": sorted(sharers)},
            ))
        return events
