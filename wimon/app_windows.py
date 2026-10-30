"""System-tray app for Windows. Run with: python -m wimon

Threads: pywebview owns the main thread (it needs it for windows), pystray runs detached,
and one worker loop below owns the Controller. Tray clicks and alert buttons are queued to
that loop, so the Controller is only ever touched from one thread.
"""

from __future__ import annotations

import logging
import queue
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import pystray
import webview
from PIL import Image, ImageDraw

from . import APP_NAME, WEBSITE, __version__, single_instance
from .alert_windows import AlertPresenter
from .controller import Controller
from .platform_windows import WindowsPlatform
from .store import Store

log = logging.getLogger("wimon")

DOT = {"ok": "#22c55e", "warning": "#f59e0b", "critical": "#ef4444", "paused": "#9ca3af"}
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "WiFiIntrusionMonitor"


def resource(name: str) -> Path:
    """Files bundled by PyInstaller live under sys._MEIPASS."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / name


def tray_image(state: str) -> Image.Image:
    # Crop the icon's outer padding: the tray draws it at 16 px, so every pixel counts.
    icon = Image.open(resource("assets/icon-1024.png")).convert("RGBA").crop((100, 100, 924, 924))
    base = icon.resize((64, 64), Image.LANCZOS)
    draw = ImageDraw.Draw(base)
    draw.ellipse((38, 38, 63, 63), fill=DOT[state], outline="#000000", width=3)
    return base


class WindowsApp:
    def __init__(self, store: Store):
        self.store = store
        self.commands: queue.Queue = queue.Queue()
        self.presenter = AlertPresenter(lambda action: self.commands.put(("alert", action)))
        self.controller = Controller(WindowsPlatform(), store, ui=self)
        self.monitor = self.controller.monitor
        self.images = {s: tray_image(s) for s in DOT}
        self.state = "ok"
        self.icon = pystray.Icon(RUN_NAME, self.images["ok"], APP_NAME, menu=self._menu())
        self.anchor = None
        self._running = True

    # ---- what the controller needs from the UI ----------------------------------------
    @property
    def alert_showing(self) -> bool:
        return self.presenter.showing

    def show_alert(self, payload: dict) -> None:
        self.presenter.show(payload)

    def notify(self, title: str, message: str) -> None:
        try:
            self.icon.notify(message, title)
        except Exception:
            log.exception("notification failed")

    # ---- tray menu ----------------------------------------------------------------------
    def _menu(self) -> pystray.Menu:
        cmd = lambda name: (lambda icon, item: self.commands.put((name, None)))  # noqa: E731
        return pystray.Menu(
            pystray.MenuItem(lambda _: self.monitor.network_label(), None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Pause monitoring", cmd("pause"), checked=lambda _: self.monitor.paused.is_set()),
            pystray.MenuItem("Disconnect automatically when attacked", cmd("auto"),
                             checked=lambda _: bool(self.store.get("auto_disconnect"))),
            pystray.MenuItem("Trust this network", cmd("trust"), checked=lambda _: self._trusted()),
            pystray.MenuItem("Start when Windows starts", cmd("login"), checked=lambda _: self._starts_at_login()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Recent alerts", pystray.Menu(self._recent_items)),
            pystray.MenuItem("Open alert log", cmd("log")),
            pystray.MenuItem("Show a test alert", cmd("test")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"About {APP_NAME} {__version__}", lambda: webbrowser.open(WEBSITE)),
            pystray.MenuItem("Quit", cmd("quit")),
        )

    def _recent_items(self):
        events = self.store.recent_events(10)
        if not events:
            yield pystray.MenuItem("No alerts yet", None, enabled=False)
            return
        for e in events:
            when = time.strftime("%d %b %H:%M", time.localtime(e["at"]))
            label = f"{when} · {e['severity'].title()} · {e['title']}"
            yield pystray.MenuItem(label, lambda icon, item, ev=e: self.commands.put(("logged", ev)))

    def _trusted(self) -> bool:
        key = self.monitor.network_key
        return bool(key and self.store.is_trusted(key))

    def _starts_at_login(self) -> bool:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
                winreg.QueryValueEx(k, RUN_NAME)
            return True
        except OSError:
            return False

    def _toggle_login(self) -> None:
        import winreg
        if not getattr(sys, "frozen", False):
            self.notify(APP_NAME, "Start when Windows starts works from the installed app, not from source.")
            return
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if self._starts_at_login():
                winreg.DeleteValue(k, RUN_NAME)
            else:
                winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{sys.executable}"')

    # ---- the worker loop -------------------------------------------------------------------
    def run_commands(self) -> None:
        name, arg = self.commands.get_nowait()
        if name == "alert":
            self.controller.on_alert_action(arg)
        elif name == "pause":
            self.monitor.resume() if self.monitor.paused.is_set() else self.monitor.pause()
        elif name == "auto":
            self.store.set("auto_disconnect", not self.store.get("auto_disconnect"))
        elif name == "trust":
            key = self.monitor.network_key
            if key:
                self.store.set_trusted(key, not self.store.is_trusted(key))
        elif name == "login":
            self._toggle_login()
        elif name == "log":
            self.store.log_path.touch()
            subprocess.Popen(["explorer", "/select,", str(self.store.log_path)])
        elif name == "test":
            self.controller.test_alert()
        elif name == "logged":
            self.controller.show_logged(arg)
        elif name == "quit":
            self._running = False
        self.icon.update_menu()

    def loop(self) -> None:
        self.monitor.start()
        if "--demo-alert" in sys.argv:
            self.commands.put(("test", None))
        while self._running:
            try:
                while True:
                    self.run_commands()
            except queue.Empty:
                pass
            if self.controller.poll():
                self.icon.update_menu()
            state = self.controller.state
            if state != self.state:
                self.state = state
                self.icon.icon = self.images[state]
            time.sleep(0.5)
        self.monitor.stop()
        self.presenter.close()
        self.icon.stop()
        self.anchor.destroy()  # last window gone: webview.start() returns and the app exits

    def run(self) -> None:
        self.icon.run_detached()
        # pywebview needs one window to keep running between alerts; this one is never shown.
        self.anchor = webview.create_window(APP_NAME, html="<html></html>", hidden=True, width=1, height=1)
        webview.start(self.loop, gui="edgechromium" if sys.platform == "win32" else None)


def main():
    store = Store()
    lock = single_instance.acquire(store.root / "wimon.lock")
    if lock is None:
        sys.exit(0)
    handlers = [logging.FileHandler(store.root / "wimon.log")]
    if sys.stdout is not None:  # a windowed .exe has no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)
    WindowsApp(store).run()


if __name__ == "__main__":
    main()
