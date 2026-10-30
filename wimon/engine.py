"""The monitoring loop. Platform-independent: it only talks to a platform object and detectors."""

from __future__ import annotations

import logging
import queue
import threading
import time

from .detectors import ArpSpoofDetector, DnsTamperDetector, EvilTwinDetector, PortScanDetector
from .models import Baseline, Event, Severity, Snapshot
from .store import Store

log = logging.getLogger("wimon")
REPEAT_SUPPRESS_SECONDS = 600


class Monitor:
    """Runs in a background thread and puts Events (and status updates) on `self.events`.

    The UI drains that queue on its own main thread, because AppKit windows can only be
    created there.
    """

    def __init__(self, platform, store: Store):
        self.platform = platform
        self.store = store
        self.events: queue.Queue[Event] = queue.Queue()
        self.baseline: Baseline | None = None
        self.last_snapshot: Snapshot | None = None
        self.paused = threading.Event()
        self._stop = threading.Event()
        self._last_emitted: dict[tuple, float] = {}
        self.attacker_macs: set[str] = set()
        self.portscan = PortScanDetector()
        self.detectors = [
            (ArpSpoofDetector(), 0),
            (self.portscan, 0),
            (EvilTwinDetector(store.root / "known_networks.json"), 0),
            (DnsTamperDetector(), store.get("dns_check_interval_seconds")),
        ]
        self._last_run = {d.name: 0.0 for d, _ in self.detectors}

    # ---- lifecycle -------------------------------------------------------------------
    def start(self) -> None:
        if self.store.get("honeypot_enabled"):
            self.portscan.start()
            log.info("decoy ports listening: %s", self.portscan.listening)
        threading.Thread(target=self._loop, name="wimon-monitor", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self.portscan.stop()

    def pause(self) -> None:
        self.paused.set()

    def resume(self) -> None:
        """Called after a reconnect: start fresh on whatever network we land on."""
        self.baseline = None
        self.portscan.reset()
        self.paused.clear()

    # ---- the loop --------------------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            if not self.paused.is_set():
                try:
                    self.tick()
                except Exception:  # one bad check must never stop monitoring
                    log.exception("check failed")
            self._stop.wait(self.store.get("check_interval_seconds"))

    def tick(self) -> list[Event]:
        snap = self.platform.snapshot()
        prev, self.last_snapshot = self.last_snapshot, snap
        if not snap.connected:
            self.baseline = None  # disconnected: the next network gets a fresh baseline
            return []
        if not snap.router_mac:
            return []  # router's ARP entry briefly missing; keep the baseline, check next time

        if self._joined_new_network(snap, prev):
            self.baseline = self._make_baseline(snap)
            log.info("new network baseline: router %s at %s", snap.router_ip, snap.router_mac)
            if snap.router_mac in self.attacker_macs:
                # Rejoined a network where we caught an attacker, and the "router" is that attacker.
                e = Event(
                    Severity.CRITICAL, "arp_spoof", "The attacker is still on this network",
                    "You reconnected to a Wi-Fi where an attack was caught, and the same device "
                    "is still pretending to be the router.",
                    source_mac=snap.router_mac, details={"router_ip": snap.router_ip},
                )
                self.store.log(e)
                self.events.put(e)
                return [e]
            return []

        lease_changed = snap.lease_start != self.baseline.lease_start
        now = time.time()
        found: list[Event] = []
        for detector, interval in self.detectors:
            if now - self._last_run[detector.name] < interval:
                continue
            self._last_run[detector.name] = now
            found.extend(detector.check(snap, self.baseline, lease_changed))

        emitted = [e for e in found if self._should_emit(e)]
        for e in emitted:
            if e.kind == "arp_spoof" and e.source_mac:
                self.attacker_macs.add(e.source_mac)
            self.store.log(e)
            self.events.put(e)

        if lease_changed:
            # Renewals are routine. Carry the lease forward, and accept a new router only
            # when the detector judged it a network change rather than an attack.
            self.baseline.lease_start = snap.lease_start
            if not any(e.severity == Severity.CRITICAL for e in found):
                self.baseline.router_mac = snap.router_mac
        return emitted

    def _joined_new_network(self, snap: Snapshot, prev: Snapshot | None) -> bool:
        b = self.baseline
        if b is None:
            return True
        if (snap.router_ip, snap.dhcp_server) != (b.router_ip, b.dhcp_server):
            return True
        return bool(snap.ssid and b.ssid and snap.ssid != b.ssid)

    @staticmethod
    def _make_baseline(snap: Snapshot) -> Baseline:
        return Baseline(
            router_ip=snap.router_ip,
            router_mac=snap.router_mac,
            dhcp_server=snap.dhcp_server,
            lease_start=snap.lease_start,
            ip=snap.ip,
            shared_router_mac_ips={
                ip for ip, mac in snap.arp.items() if mac == snap.router_mac and ip != snap.router_ip
            },
            ssid=snap.ssid,
            security=snap.security,
        )

    def _should_emit(self, e: Event) -> bool:
        # Severity is part of the key so an escalation (one knock -> full scan) always gets through.
        key = (e.kind, e.severity, e.source_ip, e.source_mac)
        last = self._last_emitted.get(key, 0)
        if time.time() - last < REPEAT_SUPPRESS_SECONDS:
            return False
        self._last_emitted[key] = time.time()
        return True

    # ---- helpers for the UI ----------------------------------------------------------
    @property
    def network_key(self) -> str | None:
        return self.baseline.key if self.baseline else None

    def network_label(self) -> str:
        s = self.last_snapshot
        if s is None:
            return "Starting…"
        if not s.wifi_on:
            return "Wi-Fi is off"
        if not s.connected:
            return "Not connected"
        name = s.ssid or f"router {s.router_ip}"
        return f"Watching {name}"
