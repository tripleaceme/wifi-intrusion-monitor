"""Starts the right app for this operating system."""

import sys


def main():
    if sys.platform == "win32":
        from .app_windows import main as run
    else:
        from .app import main as run
    run()
