"""macOS system queries. Everything here works without admin rights.

Since macOS 14.4 Apple has removed the `airport` tool, and macOS 15+ redacts the SSID and
BSSID from `ipconfig` and `networksetup` unless the app holds Location permission. So we
identify the network by its router and DHCP lease, and read the SSID through CoreWLAN only
when the bundled app has been granted Location access.
"""

from __future__ import annotations

import re
import subprocess

from .models import Snapshot


def _run(args: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def normalise_mac(mac: str) -> str | None:
    """`arp` prints 50:91:e3:f6:a:de. Pad each octet so MACs compare reliably."""
    parts = mac.strip().lower().split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None


def parse_arp(output: str, interface: str) -> dict[str, str]:
    table = {}
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) on (\S+)", output):
        ip, mac, iface = m.groups()
        mac = normalise_mac(mac)
        if iface != interface or not mac:
            continue
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):  # broadcast / multicast
            continue
        table[ip] = mac
    return table


def parse_dhcp_packet(output: str) -> dict:
    info: dict = {}
    if m := re.search(r"^yiaddr = (\S+)", output, re.M):
        info["ip"] = m.group(1)
    if m := re.search(r"server_identifier \(ip\): (\S+)", output):
        info["dhcp_server"] = m.group(1)
    if m := re.search(r"router \(ip_mult\): \{([^}]*)\}", output):
        info["router_ip"] = m.group(1).split(",")[0].strip()
    if m := re.search(r"domain_name_server \(ip_mult\): \{([^}]*)\}", output):
        info["dns_servers"] = [s.strip() for s in m.group(1).split(",") if s.strip()]
    return info


class MacOSPlatform:
    name = "macOS"

    def __init__(self, interface: str | None = None):
        self.interface = interface or self._find_wifi_interface()

    @staticmethod
    def _find_wifi_interface() -> str:
        out = _run(["networksetup", "-listallhardwareports"])
        m = re.search(r"Hardware Port: Wi-Fi\nDevice: (\S+)", out)
        return m.group(1) if m else "en0"

    def wifi_on(self) -> bool:
        return "On" in _run(["networksetup", "-getairportpower", self.interface])

    def snapshot(self) -> Snapshot:
        snap = Snapshot(interface=self.interface, wifi_on=self.wifi_on())
        if not snap.wifi_on:
            return snap
        packet = parse_dhcp_packet(_run(["ipconfig", "getpacket", self.interface]))
        snap.ip = _run(["ipconfig", "getifaddr", self.interface]).strip() or packet.get("ip")
        snap.router_ip = packet.get("router_ip")
        snap.dhcp_server = packet.get("dhcp_server")
        snap.dns_servers = packet.get("dns_servers", [])
        if m := re.search(r"LeaseStartTime : (.+)", _run(["ipconfig", "getsummary", self.interface])):
            snap.lease_start = m.group(1).strip()
        if snap.router_ip:
            # One ping keeps the router's ARP entry fresh, so a poisoned entry shows up quickly.
            _run(["ping", "-c", "1", "-t", "1", snap.router_ip], timeout=2)
        snap.arp = parse_arp(_run(["arp", "-an"]), self.interface)
        snap.router_mac = snap.arp.get(snap.router_ip) if snap.router_ip else None
        snap.ssid, snap.bssid, snap.security = self._corewlan_details()
        return snap

    def _corewlan_details(self):
        """SSID, BSSID and security mode. Returns Nones without Location permission."""
        try:
            from CoreWLAN import CWWiFiClient
        except ImportError:
            return None, None, None
        iface = CWWiFiClient.sharedWiFiClient().interfaceWithName_(self.interface)
        if iface is None:
            return None, None, None
        ssid, bssid = iface.ssid(), iface.bssid()
        security = _SECURITY_NAMES.get(int(iface.security())) if ssid else None
        return ssid, bssid, security

    def is_connected(self) -> bool:
        # Turning the Wi-Fi radio off sticks on macOS, so "radio on" is enough here.
        return self.wifi_on()

    def disconnect_wifi(self) -> bool:
        _run(["networksetup", "-setairportpower", self.interface, "off"])
        return not self.wifi_on()

    def reconnect_wifi(self) -> bool:
        _run(["networksetup", "-setairportpower", self.interface, "on"])
        return self.wifi_on()


# CWSecurity enum values from CoreWLAN.h
_SECURITY_NAMES = {
    0: "None",
    1: "WEP",
    2: "WPA Personal",
    3: "WPA/WPA2 Personal",
    4: "WPA2 Personal",
    5: "Personal",
    6: "Dynamic WEP",
    7: "WPA Enterprise",
    8: "WPA/WPA2 Enterprise",
    9: "WPA2 Enterprise",
    10: "Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA3 Transition",
    14: "OWE",
    15: "OWE Transition",
}

