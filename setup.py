"""Builds the macOS app: .venv/bin/python setup.py py2app  (or ./build_mac.sh for the .dmg)"""

from setuptools import setup

from wimon import APP_NAME, __version__

OPTIONS = {
    "iconfile": "assets/AppIcon.icns",
    "packages": ["wimon", "dns", "certifi", "rumps"],
    # Windows-only libraries (used by app_windows / alert_windows) stay out of the Mac app.
    "excludes": ["webview", "pystray", "PIL", "bottle", "proxy_tools"],
    "plist": {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": "tech.ayoadeabel.wifi-intrusion-monitor",
        "CFBundleVersion": __version__,
        "CFBundleShortVersionString": __version__,
        "LSUIElement": True,  # menu-bar only, no Dock icon
        "LSMinimumSystemVersion": "11.0",
        "NSHumanReadableCopyright": "© 2026 Ayoade Adegbite. MIT licence.",
        "NSLocationUsageDescription": (
            "macOS hides Wi-Fi names from apps without Location access. "
            "Wi-Fi Intrusion Monitor uses the name only to spot fake hotspots that copy a network you trust. "
            "Your location is never read or stored."
        ),
        "NSLocationWhenInUseUsageDescription": (
            "macOS hides Wi-Fi names from apps without Location access. "
            "Wi-Fi Intrusion Monitor uses the name only to spot fake hotspots that copy a network you trust. "
            "Your location is never read or stored."
        ),
    },
}

setup(
    name="wifi-intrusion-monitor",
    version=__version__,
    app=["run_app.py"],
    options={"py2app": OPTIONS},
)
