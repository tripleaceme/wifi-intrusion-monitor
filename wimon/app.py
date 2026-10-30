"""Menu-bar app for macOS. Run with: python -m wimon"""

from __future__ import annotations

import logging
import plistlib
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import rumps

from . import APP_NAME, WEBSITE, __version__, single_instance
from .alert import AlertPresenter
from .controller import Controller
from .platform_macos import MacOSPlatform
from .store import Store

log = logging.getLogger("wimon")

ICON = {"ok": "🟢", "warning": "🟠", "critical": "🔴", "paused": "⚪️"}
LAUNCH_AGENT = Path.home() / "Library" / "LaunchAgents" / "tech.ayoadeabel.wifi-intrusion-monitor.plist"


def bundle_path() -> Path | None:
    """The .app folder when running as a packaged app, else None."""
    exe = Path(sys.executable).resolve()
    for parent in exe.parents:
        if parent.suffix == ".app":
            return parent
    return None


class WimonApp(rumps.App):
    def __init__(self, store: Store):
        super().__init__(APP_NAME, title=ICON["ok"], quit_button=None)
        self.store = store
        self.presenter = AlertPresenter(self.on_alert_action)
        self.controller = Controller(MacOSPlatform(), store, ui=self)
        self.monitor = self.controller.monitor
        self._location = None

        self.status_item = rumps.MenuItem("Starting…")
        self.check_item = rumps.MenuItem("")
        self.pause_item = rumps.MenuItem("Pause monitoring", callback=self.toggle_pause)
        self.auto_item = rumps.MenuItem("Disconnect automatically when attacked", callback=self.toggle_auto)
        self.auto_item.state = self.store.get("auto_disconnect")
        self.trust_item = rumps.MenuItem("Trust this network", callback=self.toggle_trust)
        self.login_item = rumps.MenuItem("Start at login", callback=self.toggle_login)
        self.login_item.state = LAUNCH_AGENT.exists()
        self.recent_menu = rumps.MenuItem("Recent alerts")
        self.location_item = rumps.MenuItem("Show Wi-Fi names (needs Location access)…",
                                            callback=self.request_location)
        self.menu = [
            self.status_item,
            self.check_item,
            None,
            self.pause_item,
            self.auto_item,
            self.trust_item,
            self.login_item,
            None,
            self.recent_menu,
            rumps.MenuItem("Open alert log", callback=self.open_log),
            rumps.MenuItem("Show a test alert", callback=lambda _: self.controller.test_alert()),
            self.location_item,
            None,
            rumps.MenuItem(f"About {APP_NAME} {__version__}", callback=lambda _: webbrowser.open(WEBSITE)),
            rumps.MenuItem("Quit", callback=self.quit),
        ]
        self.refresh_recent()
        self.monitor.start()
        self.timer = rumps.Timer(self.on_timer, 0.5)
        self.timer.start()

    # ---- what the controller needs from the UI ----------------------------------------
    @property
    def alert_showing(self) -> bool:
        return self.presenter.showing

    def show_alert(self, payload: dict) -> None:
        self.presenter.show(payload)

    def notify(self, title: str, message: str) -> None:
        try:
            rumps.notification(APP_NAME, title, message)
        except RuntimeError:
            # Running from source has no bundle identifier, which macOS notifications require.
            script = f"display notification {_osa(message)} with title {_osa(APP_NAME)} subtitle {_osa(title)}"
            subprocess.Popen(["osascript", "-e", script])

    def on_alert_action(self, action: str) -> None:
        self.controller.on_alert_action(action)

    # ---- menu ---------------------------------------------------------------------------
    def on_timer(self, _):
        if self.controller.poll():
            self.refresh_recent()
        self.title = ICON[self.controller.state]
        self.status_item.title = self.monitor.network_label()
        snap = self.monitor.last_snapshot
        if snap:
            ago = int(time.time() - snap.taken_at)
            self.check_item.title = f"Last check {ago}s ago · {len(self.monitor.portscan.listening)} decoy ports"
        key = self.monitor.network_key
        self.trust_item.state = bool(key and self.store.is_trusted(key))
        self.pause_item.title = "Resume monitoring" if self.monitor.paused.is_set() else "Pause monitoring"
        if snap and snap.ssid:
            self.location_item._menuitem.setHidden_(True)  # Wi-Fi names already readable

    def refresh_recent(self):
        if self.recent_menu._menu is not None:
            self.recent_menu.clear()
        events = self.store.recent_events(10)
        if not events:
            self.recent_menu.add(rumps.MenuItem("No alerts yet"))
            return
        for e in events:
            when = time.strftime("%d %b %H:%M", time.localtime(e["at"]))
            label = f"{when} · {e['severity'].title()} · {e['title']}"
            self.recent_menu.add(rumps.MenuItem(label, callback=lambda _, ev=e: self.controller.show_logged(ev)))

    def toggle_pause(self, _):
        if self.monitor.paused.is_set():
            self.monitor.resume()
        else:
            self.monitor.pause()

    def toggle_auto(self, item):
        item.state = not item.state
        self.store.set("auto_disconnect", bool(item.state))

    def toggle_trust(self, item):
        key = self.monitor.network_key
        if key:
            self.store.set_trusted(key, not self.store.is_trusted(key))

    def toggle_login(self, item):
        app = bundle_path()
        if app is None:
            rumps.alert(APP_NAME, "Start at login works from the installed app, not from source.")
            return
        if LAUNCH_AGENT.exists():
            LAUNCH_AGENT.unlink()
        else:
            LAUNCH_AGENT.parent.mkdir(parents=True, exist_ok=True)
            LAUNCH_AGENT.write_bytes(plistlib.dumps({
                "Label": LAUNCH_AGENT.stem,
                "ProgramArguments": ["/usr/bin/open", "-a", str(app)],
                "RunAtLoad": True,
            }))
        item.state = LAUNCH_AGENT.exists()

    def open_log(self, _):
        self.store.log_path.touch()
        subprocess.run(["open", "-R", str(self.store.log_path)])

    def request_location(self, _):
        try:
            from CoreLocation import CLLocationManager
        except ImportError:
            return
        if bundle_path() is None:
            rumps.alert(APP_NAME, "macOS only grants Location access to the installed app.")
            return
        self._location = CLLocationManager.alloc().init()
        self._location.requestWhenInUseAuthorization()
        # macOS shows no prompt if the user already declined once; send them to Settings.
        subprocess.run(["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"])

    def quit(self, _):
        self.monitor.stop()
        rumps.quit_application()


def _osa(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    store = Store()
    lock = single_instance.acquire(store.root / "wimon.lock")
    if lock is None:
        sys.exit(0)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(store.root / "wimon.log"), logging.StreamHandler()],
    )
    app = WimonApp(store)
    if "--demo-alert" in sys.argv:
        def once(timer):
            timer.stop()
            app.controller.test_alert()
        rumps.Timer(once, 1.5).start()
    app.run()


if __name__ == "__main__":
    main()
