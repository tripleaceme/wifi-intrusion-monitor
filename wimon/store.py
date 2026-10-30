"""Settings, trusted networks and the event log, kept in the user's Application Support folder."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .models import Event

DEFAULTS = {
    "auto_disconnect": True,
    "check_interval_seconds": 3,
    "dns_check_interval_seconds": 30,
    "honeypot_enabled": True,
    "trusted_networks": [],
}


def data_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path.home() / ".local" / "share"
    path = Path(os.environ.get("WIMON_DATA_DIR", base / "Wi-Fi Intrusion Monitor"))
    path.mkdir(parents=True, exist_ok=True)
    return path


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()
        self.config_path = self.root / "config.json"
        self.log_path = self.root / "events.jsonl"
        self.config = dict(DEFAULTS)
        if self.config_path.exists():
            try:
                self.config.update(json.loads(self.config_path.read_text()))
            except (json.JSONDecodeError, OSError):
                pass  # a broken config file falls back to defaults

    def save(self) -> None:
        self.config_path.write_text(json.dumps(self.config, indent=2))

    def get(self, key):
        return self.config.get(key, DEFAULTS.get(key))

    def set(self, key, value) -> None:
        self.config[key] = value
        self.save()

    def is_trusted(self, network_key: str) -> bool:
        return network_key in self.config["trusted_networks"]

    def set_trusted(self, network_key: str, trusted: bool) -> None:
        nets = set(self.config["trusted_networks"])
        nets.add(network_key) if trusted else nets.discard(network_key)
        self.set("trusted_networks", sorted(nets))

    def log(self, event: Event) -> None:
        with self.log_path.open("a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def recent_events(self, limit: int = 10) -> list[dict]:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text().splitlines()[-limit:]
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
