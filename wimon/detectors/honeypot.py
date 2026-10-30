"""Port scanning: another device on the Wi-Fi is probing this laptop for a way in.

Packet capture needs root, so instead we open decoy ports that nothing on a Mac uses
(Telnet, RDP, SMB, database ports). No honest device has a reason to connect to them, so
any connection from the local network is someone looking for a weakness. Ports that are
already in use (for example SMB when File Sharing is on) are skipped.
"""

from __future__ import annotations

import selectors
import socket
import threading
import time

from ..models import Baseline, Event, Severity, Snapshot

DECOY_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "Windows RPC",
    445: "SMB file sharing",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop",
    5985: "Windows remote management",
    8291: "MikroTik router admin",
}
SCAN_WINDOW_SECONDS = 120
SCAN_PORT_THRESHOLD = 2  # distinct decoy ports touched by one device inside the window


class PortScanDetector:
    name = "portscan"

    def __init__(self, ports: dict[int, str] | None = None, ignore_ips: set[str] | None = None):
        self.ports = ports if ports is not None else DECOY_PORTS
        self.ignore_ips = ignore_ips if ignore_ips is not None else {"127.0.0.1"}
        self.listening: list[int] = []
        self._hits: list[tuple[float, str, int]] = []  # (time, ip, port)
        self._lock = threading.Lock()
        self._sel = selectors.DefaultSelector()
        self._stop = threading.Event()
        self._reported: dict[str, Severity] = {}

    def start(self) -> None:
        for port in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # survive a quick app restart
            try:
                s.bind(("0.0.0.0", port))
                s.listen(16)
            except OSError:
                s.close()
                continue
            s.setblocking(False)
            self._sel.register(s, selectors.EVENT_READ, port)
            self.listening.append(port)
        threading.Thread(target=self._serve, name="wimon-decoys", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _serve(self) -> None:
        while not self._stop.is_set():
            for key, _ in self._sel.select(timeout=1):
                try:
                    conn, (ip, _) = key.fileobj.accept()
                except OSError:
                    continue
                conn.close()  # we only need to know someone knocked
                self.record(ip, key.data)
        for key in list(self._sel.get_map().values()):
            key.fileobj.close()

    def record(self, ip: str, port: int, at: float | None = None) -> None:
        if ip in self.ignore_ips:
            return
        with self._lock:
            self._hits.append((at or time.time(), ip, port))

    def check(self, snap: Snapshot, base: Baseline, lease_changed: bool) -> list[Event]:
        if snap.ip:
            self.ignore_ips.add(snap.ip)
        cutoff = time.time() - SCAN_WINDOW_SECONDS
        with self._lock:
            self._hits = [h for h in self._hits if h[0] >= cutoff and h[1] not in self.ignore_ips]
            by_ip: dict[str, set[int]] = {}
            for _, ip, port in self._hits:
                by_ip.setdefault(ip, set()).add(port)

        events = []
        for ip, ports in by_ip.items():
            is_router = ip == snap.router_ip
            # Some home routers scan devices for their "connected devices" page, so the
            # router alone never triggers a disconnect.
            if len(ports) >= SCAN_PORT_THRESHOLD and not is_router:
                severity = Severity.CRITICAL
            else:
                severity = Severity.WARNING
            if self._reported.get(ip, Severity.INFO - 1) >= severity:
                continue
            self._reported[ip] = severity
            services = ", ".join(self.ports.get(p, str(p)) for p in sorted(ports))
            events.append(Event(
                severity, "port_scan",
                "Someone is probing this laptop" if severity == Severity.CRITICAL
                else "A device knocked on a closed door",
                f"The device at {ip} on this Wi-Fi tried to connect to services that attackers "
                f"use to break into computers ({services}). Normal phones, laptops and TVs never "
                "do this.",
                source_ip=ip, source_mac=snap.arp.get(ip),
                details={"ports": sorted(ports), "services": services, "is_router": is_router},
            ))
        return events

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
        self._reported.clear()
