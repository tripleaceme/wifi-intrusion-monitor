"""The full-screen alert: alert.html in a borderless WKWebView window above everything else.

Must be called on the main thread (AppKit rule).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import objc
from AppKit import (
    NSApp,
    NSBackingStoreBuffered,
    NSColor,
    NSScreen,
    NSScreenSaverWindowLevel,
    NSSound,
    NSWindow,
    NSWindowCollectionBehaviorCanJoinAllSpaces,
    NSWindowCollectionBehaviorFullScreenAuxiliary,
    NSWindowStyleMaskBorderless,
)
from Foundation import NSObject, NSURL
from WebKit import WKUserContentController, WKUserScript, WKWebView, WKWebViewConfiguration

from .report import HTML


class AlertWindow(NSWindow):
    # Borderless windows refuse keyboard focus unless told otherwise.
    def canBecomeKeyWindow(self):
        return True

    def canBecomeMainWindow(self):
        return True


class _Bridge(NSObject, protocols=[objc.protocolNamed("WKScriptMessageHandler")]):
    def initWithCallback_(self, callback):
        self = objc.super(_Bridge, self).init()
        self.callback = callback
        return self

    def userContentController_didReceiveScriptMessage_(self, controller, message):
        self.callback(str(message.body()))


class AlertPresenter:
    """Shows one alert at a time, covering every connected screen."""

    def __init__(self, on_action: Callable[[str], None]):
        self.on_action = on_action
        self.windows: list[AlertWindow] = []
        self._bridge = _Bridge.alloc().initWithCallback_(self._handle)

    @property
    def showing(self) -> bool:
        return bool(self.windows)

    def show(self, payload: dict) -> None:
        self.close()
        script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
            f"window.WIMON = {json.dumps(payload)};", 0, True  # 0 = at document start
        )
        for screen in NSScreen.screens():
            frame = screen.frame()
            win = AlertWindow.alloc().initWithContentRect_styleMask_backing_defer_(
                frame, NSWindowStyleMaskBorderless, NSBackingStoreBuffered, False
            )
            win.setLevel_(NSScreenSaverWindowLevel)
            win.setCollectionBehavior_(
                NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorFullScreenAuxiliary
            )
            win.setBackgroundColor_(NSColor.blackColor())
            win.setReleasedWhenClosed_(False)

            controller = WKUserContentController.alloc().init()
            controller.addUserScript_(script)
            controller.addScriptMessageHandler_name_(self._bridge, "wimon")
            config = WKWebViewConfiguration.alloc().init()
            config.setUserContentController_(controller)
            view = WKWebView.alloc().initWithFrame_configuration_(((0, 0), frame.size), config)
            url = NSURL.fileURLWithPath_(str(HTML))
            view.loadFileURL_allowingReadAccessToURL_(url, url.URLByDeletingLastPathComponent())
            win.setContentView_(view)
            win.setFrame_display_(frame, True)
            win.makeKeyAndOrderFront_(None)
            self.windows.append(win)

        NSApp.activateIgnoringOtherApps_(True)
        self._alarm(3)

    def _alarm(self, times: int) -> None:
        sound = NSSound.soundNamed_("Sosumi") or NSSound.soundNamed_("Basso")
        if sound is None:
            return
        sound.play()
        if times > 1:
            from PyObjCTools import AppHelper
            AppHelper.callLater(0.7, self._alarm, times - 1)

    def close(self) -> None:
        for win in self.windows:
            win.orderOut_(None)
            win.contentView().configuration().userContentController().removeScriptMessageHandlerForName_("wimon")
        self.windows = []

    def _handle(self, action: str) -> None:
        if action in {"dismiss", "reconnect", "trust"}:
            self.close()
        self.on_action(action)
