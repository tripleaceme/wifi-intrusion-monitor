"""Evil twin: a fake hotspot with the same name as one you trust, usually with weaker security.

Needs the Wi-Fi name, which macOS only reveals to apps holding Location permission. Without
it this detector stays quiet.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Baseline, Event, Severity, Snapshot


# Rough strength ranking of the security names each platform reports, to spot a downgrade.
SECURITY_RANK = {
    "None": 0, "OWE Transition": 1, "OWE": 1, "WEP": 1, "Dynamic WEP": 1,
    "WPA Personal": 2, "WPA/WPA2 Personal": 2, "Personal": 2, "WPA2 Personal": 3,
    "WPA3 Transition": 3, "WPA3 Personal": 4, "WPA Enterprise": 4, "WPA/WPA2 Enterprise": 4,
    "Enterprise": 4, "WPA2 Enterprise": 5, "WPA3 Enterprise": 6,
}


class EvilTwinDetector:
    name = "evil_twin"

    def __init__(self, memory_path: Path):
        self.path = memory_path
        try:
            self.known: dict[str, dict] = json.loads(memory_path.read_text())
        except (OSError, json.JSONDecodeError):
            self.known = {}
        self._reported: set[tuple[str, str]] = set()

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.known, indent=2))

    def check(self, snap: Snapshot, base: Baseline, lease_changed: bool) -> list[Event]:
        if not snap.ssid or not snap.security:
            return []
        seen = self.known.get(snap.ssid)
        if seen is None:
            self.known[snap.ssid] = {"security": snap.security, "router_macs": [snap.router_mac]}
            self._save()
            return []

        events, changed = [], False
        was, now = SECURITY_RANK.get(seen["security"], 0), SECURITY_RANK.get(snap.security, 0)
        if now < was and (snap.ssid, snap.security) not in self._reported:
            self._reported.add((snap.ssid, snap.security))
            events.append(Event(
                Severity.CRITICAL, "evil_twin", "Fake hotspot detected (evil twin)",
                f'"{snap.ssid}" used to be protected with {seen["security"]}, but the network you '
                f"just joined under that name uses {snap.security}. Attackers set up copies of "
                "trusted Wi-Fi names with weaker security to capture everything you send.",
                source_mac=snap.bssid,
                details={"ssid": snap.ssid, "remembered_security": seen["security"], "current_security": snap.security},
            ))
        elif now > was:
            seen["security"] = snap.security  # the owner upgraded their router
            changed = True
        if snap.router_mac and snap.router_mac not in seen["router_macs"]:
            seen["router_macs"].append(snap.router_mac)
            changed = True
        if changed:
            self._save()
        return events
