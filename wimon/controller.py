"""Decides what happens when the monitor finds something. Shared by the macOS and Windows apps.

The UI object it drives needs: show_alert(payload), alert_showing (bool), notify(title, message).
poll() must be called regularly from the UI's main thread.
"""

from __future__ import annotations

import logging
import os
import queue
import time

from .engine import Monitor
from .models import Event, Severity
from .report import alert_payload, demo_event, event_from_log
from .store import Store

log = logging.getLogger("wimon")

WARNING_HOLD_SECONDS = 600
RECONNECT_GRACE_SECONDS = 900
WATCHDOG_SECONDS = 3


class Controller:
    def __init__(self, platform, store: Store, ui, monitor: Monitor | None = None):
        self.platform = platform
        self.store = store
        self.ui = ui
        self.monitor = monitor or Monitor(platform, store)
        # Set WIMON_DRY_RUN=1 to see alerts without actually dropping Wi-Fi (useful when testing).
        self.dry_run = os.environ.get("WIMON_DRY_RUN") == "1"
        self.critical = False
        self.blocked = False  # we cut the Wi-Fi and the user has not dismissed the alert yet
        self.warning_until = 0.0
        self.reconnect_grace_until = 0.0
        self.alert_network_key: str | None = None
        self._last_watchdog = 0.0

    # ---- called by the UI ------------------------------------------------------------
    def poll(self) -> list[Event]:
        handled = []
        try:
            while True:
                event = self.monitor.events.get_nowait()
                self.handle(event)
                handled.append(event)
        except queue.Empty:
            pass
        self._watchdog()
        return handled

    @property
    def state(self) -> str:
        if self.critical and self.ui.alert_showing:
            return "critical"
        if self.monitor.paused.is_set():
            return "paused"
        if time.time() < self.warning_until:
            return "warning"
        return "ok"

    def handle(self, event: Event) -> None:
        log.warning("%s %s from %s", event.severity.name, event.kind, event.source_ip or event.source_mac)
        if event.severity == Severity.WARNING:
            self.warning_until = time.time() + WARNING_HOLD_SECONDS
            self.ui.notify(event.title, event.explanation)
            return
        if event.severity != Severity.CRITICAL:
            return

        key = self.monitor.network_key
        trusted = bool(key and self.store.is_trusted(key))
        in_grace = time.time() < self.reconnect_grace_until
        network = self.monitor.network_label().replace("Watching ", "")
        disconnected = False
        if self.store.get("auto_disconnect") and not trusted and not in_grace:
            disconnected = self._disconnect()
        self.critical = True
        self.alert_network_key = key
        self.ui.show_alert(alert_payload(event, network, disconnected))

    def on_alert_action(self, action: str) -> None:
        if action == "disconnect":
            disconnected = self._disconnect()
            latest = self.store.recent_events(1)
            if latest:
                self.ui.show_alert(alert_payload(event_from_log(latest[0]), "logged event", disconnected))
            return
        if action == "trust" and self.alert_network_key:
            self.store.set_trusted(self.alert_network_key, True)
        if action in {"reconnect", "trust"}:
            self.reconnect_grace_until = time.time() + RECONNECT_GRACE_SECONDS
            if not self.dry_run:
                self.platform.reconnect_wifi()
        self.critical = False
        self.blocked = False
        self.monitor.resume()

    def test_alert(self) -> None:
        self.alert_network_key = None
        self.ui.show_alert(alert_payload(demo_event(), "test network", disconnected=False))

    def show_logged(self, entry: dict) -> None:
        self.alert_network_key = self.monitor.network_key
        self.ui.show_alert(alert_payload(event_from_log(entry), "logged event", disconnected=False))

    # ---- internals --------------------------------------------------------------------
    def _disconnect(self) -> bool:
        self.monitor.pause()
        if self.dry_run:
            return True
        ok = self.platform.disconnect_wifi()
        self.blocked = ok
        if not ok:
            log.error("could not disconnect Wi-Fi")
        return ok

    def _watchdog(self) -> None:
        """Windows rejoins known networks on its own. Keep the Wi-Fi off until the user decides."""
        if not self.blocked or time.time() - self._last_watchdog < WATCHDOG_SECONDS:
            return
        self._last_watchdog = time.time()
        if self.platform.is_connected():
            log.warning("Wi-Fi reconnected by itself while the alert is up; disconnecting again")
            self.platform.disconnect_wifi()
