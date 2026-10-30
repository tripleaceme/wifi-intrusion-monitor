"""The full-screen alert on Windows: alert.html in a frameless, always-on-top pywebview window
(Microsoft Edge WebView2, which ships with Windows 10 and 11).
"""

from __future__ import annotations

import json
import sys
import threading
from typing import Callable

import webview

from .report import HTML


def page_with_payload(payload: dict) -> str:
    # The payload can hold an attacker-chosen Wi-Fi name, so "</script>" inside it must not
    # end the script block early.
    data = json.dumps(payload).replace("</", "<\\/")
    return HTML.read_text(encoding="utf-8").replace(
        "<script>", f"<script>window.WIMON = {data};</script>\n<script>", 1
    )


class _Api:
    """Methods here are callable from the page as pywebview.api.<name>()."""

    def __init__(self, presenter: "AlertPresenter"):
        self._presenter = presenter

    def action(self, name):
        self._presenter._handle(str(name))


class AlertPresenter:
    """Shows one alert at a time, covering every connected screen.

    `on_action` is called on pywebview's thread; the app hands it to its own loop.
    """

    def __init__(self, on_action: Callable[[str], None]):
        self.on_action = on_action
        self.windows: list = []
        self._api = _Api(self)

    @property
    def showing(self) -> bool:
        return bool(self.windows)

    def show(self, payload: dict) -> None:
        self.close()
        html = page_with_payload(payload)
        for screen in webview.screens or [None]:
            self.windows.append(webview.create_window(
                "Intrusion detected", html=html, js_api=self._api,
                fullscreen=True, frameless=True, on_top=True, focus=True,
                screen=screen, background_color="#000000",
            ))
        self._alarm(3)

    def _alarm(self, times: int) -> None:
        if sys.platform != "win32":
            return
        import winsound
        winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
        if times > 1:
            threading.Timer(0.8, self._alarm, (times - 1,)).start()

    def close(self) -> None:
        windows, self.windows = self.windows, []
        for w in windows:
            try:
                w.destroy()
            except Exception:  # already closed by the user (Alt+F4)
                pass

    def _handle(self, action: str) -> None:
        if action in {"dismiss", "reconnect", "trust"}:
            self.close()
        self.on_action(action)
