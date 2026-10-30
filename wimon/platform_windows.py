"""Windows system queries. Everything here works without admin rights.

`ipconfig` and `netsh` print their labels in the user's language, so the parts that matter
avoid them: adapter details come from PowerShell as JSON, and the ARP table and routes come
from `arp -a` and `route print`, whose columns are plain numbers. Only the Wi-Fi name and
security type come from `netsh wlan`, which is English-only here and, since Windows 11 24H2,
needs Location permission. Without it the evil-twin check stays quiet and nothing else changes.
"""

from __future__ import annotations

import json
import re
import subprocess
import time

from .models import Snapshot

CREATE_NO_WINDOW = 0x08000000  # stops a console window flashing up on every check
ADAPTER_REFRESH_SECONDS = 15

ADAPTER_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$a = Get-NetAdapter | Where-Object { $_.PhysicalMediaType -match '802\.11' } |
     Sort-Object { $_.Status -ne 'Up' } | Select-Object -First 1
if (-not $a) { '{}'; exit }
$c = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($a.ifIndex)"
[pscustomobject]@{
  alias  = $a.Name
  status = [string]$a.Status
  ip     = @($c.IPAddress)
  gw     = @($c.DefaultIPGateway)
  dhcp   = $c.DHCPServer
  lease  = [string]$c.DHCPLeaseObtained
  dns    = @($c.DNSServerSearchOrder)
} | ConvertTo-Json -Compress
"""


def _run(args: list[str], timeout: float = 8) -> str:
    try:
        out = subprocess.run(
            args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return out.decode("utf-8", errors="replace")


def normalise_mac(mac: str) -> str | None:
    parts = re.split(r"[-:]", mac.strip().lower())
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None


def _ipv4(values) -> list[str]:
    return [v for v in (values or []) if v and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", v)]


def parse_adapter(output: str) -> dict:
    try:
        data = json.loads(output.strip() or "{}")
    except json.JSONDecodeError:
        return {}
    if not data:
        return {}
    ips, gws = _ipv4(data.get("ip")), _ipv4(data.get("gw"))
    return {
        "alias": data.get("alias"),
        "up": data.get("status") == "Up",
        "ip": ips[0] if ips else None,
        "router_ip": gws[0] if gws else None,
        "dhcp_server": data.get("dhcp") or None,
        "lease_start": data.get("lease") or None,
        "dns_servers": _ipv4(data.get("dns")),
    }


def parse_arp(output: str) -> dict[str, str]:
    """`arp -a -N <ip>` rows look like: 192.168.0.1   50-91-e3-f6-0a-de   dynamic"""
    table = {}
    for m in re.finditer(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s", output, re.M):
        ip, mac = m.group(1), normalise_mac(m.group(2))
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
            continue
        table[ip] = mac
    return table


def parse_default_routes(output: str) -> set[tuple[str, str]]:
    """(gateway, interface ip) pairs from `route print -4 0.0.0.0`."""
    return set(re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", output, re.M))


def parse_netsh(output: str) -> dict:
    """SSID, BSSID and security from `netsh wlan show interfaces` (English Windows)."""
    def field(label):
        m = re.search(rf"^\s*{label}\s*:\s*(.+?)\s*$", output, re.M)
        return m.group(1) if m else None

    auth = field("Authentication")
    return {
        "ssid": field("SSID"),
        "bssid": normalise_mac(field(r"(?:AP )?BSSID") or ""),
        "security": _SECURITY.get(auth, auth),
    }


# netsh's names mapped onto the names the evil-twin detector ranks.
_SECURITY = {
    "Open": "None",
    "WEP": "WEP",
    "WPA-Personal": "WPA Personal",
    "WPA2-Personal": "WPA2 Personal",
    "WPA3-Personal": "WPA3 Personal",
    "WPA3-Personal Transition": "WPA3 Transition",
    "WPA-Enterprise": "WPA Enterprise",
    "WPA2-Enterprise": "WPA2 Enterprise",
    "WPA3-Enterprise": "WPA3 Enterprise",
    "OWE": "OWE",
}


class WindowsPlatform:
    name = "Windows"

    def __init__(self):
        self._adapter: dict = {}
        self._adapter_at = 0.0
        self._routes: set = set()
        self.interface = self._refresh_adapter().get("alias") or "Wi-Fi"
        self._last_ssid: str | None = None

    def _refresh_adapter(self) -> dict:
        self._adapter = parse_adapter(
            _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ADAPTER_SCRIPT], timeout=20)
        )
        self._adapter_at = time.time()
        return self._adapter

    def _adapter_info(self) -> dict:
        # PowerShell takes about a second, so only ask again when the routes change or the
        # cached answer is old. Routes are cheap to read on every check.
        routes = parse_default_routes(_run(["route", "print", "-4", "0.0.0.0"]))
        if routes != self._routes or time.time() - self._adapter_at > ADAPTER_REFRESH_SECONDS:
            self._routes = routes
            self._refresh_adapter()
        if self._adapter.get("alias"):
            self.interface = self._adapter["alias"]
        return self._adapter

    def wifi_on(self) -> bool:
        return bool(self._adapter_info().get("up"))

    def is_connected(self) -> bool:
        """Fast check: is there a default route through the Wi-Fi adapter's address?"""
        routes = parse_default_routes(_run(["route", "print", "-4", "0.0.0.0"]))
        if routes != self._routes:
            self._routes = routes
            self._refresh_adapter()
        ip = self._adapter.get("ip")
        return bool(self._adapter.get("up") and ip and any(ip == via for _, via in routes))

    def snapshot(self) -> Snapshot:
        info = self._adapter_info()
        snap = Snapshot(interface=self.interface, wifi_on=bool(info.get("up")))
        if not snap.wifi_on:
            return snap
        snap.ip = info.get("ip")
        snap.router_ip = info.get("router_ip")
        snap.dhcp_server = info.get("dhcp_server")
        snap.dns_servers = info.get("dns_servers", [])
        snap.lease_start = info.get("lease_start")
        if snap.router_ip:
            # One ping keeps the router's ARP entry fresh, so a poisoned entry shows up quickly.
            _run(["ping", "-n", "1", "-w", "1000", snap.router_ip], timeout=3)
        if snap.ip:
            snap.arp = parse_arp(_run(["arp", "-a", "-N", snap.ip]))
        snap.router_mac = snap.arp.get(snap.router_ip) if snap.router_ip else None
        wlan = parse_netsh(_run(["netsh", "wlan", "show", "interfaces"]))
        snap.ssid, snap.bssid, snap.security = wlan["ssid"], wlan["bssid"], wlan["security"]
        if snap.ssid:
            self._last_ssid = snap.ssid
        return snap

    def disconnect_wifi(self) -> bool:
        _run(["netsh", "wlan", "disconnect", f"interface={self.interface}"])
        for _ in range(10):
            if not self.is_connected():
                return True
            time.sleep(0.5)
        return False

    def reconnect_wifi(self) -> bool:
        if self._last_ssid:
            _run(["netsh", "wlan", "connect", f"name={self._last_ssid}", f"interface={self.interface}"])
        else:
            # Without the Wi-Fi name we cannot pick the profile; open the Wi-Fi list instead.
            subprocess.Popen(["explorer", "ms-availablenetworks:"], creationflags=CREATE_NO_WINDOW)
        return True
