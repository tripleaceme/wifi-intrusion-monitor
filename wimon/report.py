"""What the full-screen alert says. Shared by the macOS and Windows windows that show alert.html."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from .models import Event, Severity

HTML = Path(__file__).with_name("alert.html")

_SHARING_OFF = (
    "Make sure Remote Desktop and file and printer sharing are off in Settings."
    if sys.platform == "win32"
    else "Make sure File Sharing, Screen Sharing and Remote Login are off in System Settings."
)

STEPS = {
    "default": [
        "Stay off this Wi-Fi. Use mobile data or a hotspot you control.",
        "If you logged in to anything on this network, change that password from a safe connection.",
        "If this is your own home Wi-Fi, restart the router and change its Wi-Fi password.",
    ],
    "port_scan": [
        "Stay off this Wi-Fi until you know who the device is.",
        "On your own network, find the device in your router's connected-devices list and block it.",
        _SHARING_OFF,
    ],
    "tls_intercept": [
        "Do not log in to anything on this Wi-Fi, even sites that show a padlock.",
        "If this is a work network that inspects traffic on purpose, ask IT before trusting it.",
        "Change any password you typed on this network, from a safe connection.",
    ],
}

# Short labels for the threat report. Details not listed here stay in the log only.
DETAIL_LABELS = {
    "expected_router_mac": "REAL ROUTER",
    "ips_sharing_router_mac": "IMPOSTERS",
    "domain": "WEBSITE",
    "expected": "REAL ADDRESS",
    "real_answer": "REAL ADDRESS",
    "wifi_answered": "WI-FI SAID",
    "services": "PROBED",
    "ssid": "WI-FI NAME",
    "remembered_security": "WAS",
    "current_security": "NOW",
    "error": "TLS ERROR",
}


def alert_payload(event: Event, network: str, disconnected: bool) -> dict:
    rows = [
        ["THREAT", event.kind.upper(), "hot"],
        ["SEVERITY", event.severity.name, "hot"],
    ]
    if event.source_ip:
        rows.append(["SOURCE IP", event.source_ip, "hot"])
    if event.source_mac:
        rows.append(["SOURCE MAC", event.source_mac])
    rows.append(["NETWORK", network])
    for key, value in event.details.items():
        label = DETAIL_LABELS.get(key)
        if label is None:
            continue
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        rows.append([label, str(value)])
    rows += [
        ["TARGET", "THIS DEVICE"],
        ["DETECTED", time.strftime("%H:%M:%S", time.localtime(event.at))],
        ["ACTION", "WI-FI DISCONNECTED" if disconnected else "STILL CONNECTED", "ok" if disconnected else "hot"],
    ]
    return {
        "title": event.title,
        "explanation": event.explanation,
        "rows": rows[:12],  # keep the panel inside the screen
        "steps": STEPS.get(event.kind, STEPS["default"]),
        "disconnected": disconnected,
    }


def event_from_log(entry: dict) -> Event:
    return Event(
        Severity[entry["severity"]], entry["kind"], entry["title"], entry["explanation"],
        entry.get("source_ip"), entry.get("source_mac"), entry.get("details", {}), entry["at"],
    )


def demo_event() -> Event:
    return Event(
        Severity.CRITICAL, "arp_spoof", "Man-in-the-middle attack (ARP spoofing) — TEST",
        "This is a test. Nothing is wrong with your network. In a real attack, another device "
        "on the Wi-Fi pretends to be the router so it can read or change your traffic.",
        source_ip="192.168.0.66", source_mac="de:ad:be:ef:00:66",
        details={"expected_router_mac": "50:91:e3:f6:0a:de"},
    )
