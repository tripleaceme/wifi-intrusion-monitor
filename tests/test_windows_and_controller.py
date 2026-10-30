"""Windows command parsing, the shared Controller, and alert-page escaping. Runs on any OS."""

import time

import pytest

from wimon.alert_windows import page_with_payload
from wimon.controller import Controller
from wimon.models import Event, Severity
from wimon.platform_windows import parse_adapter, parse_arp, parse_default_routes, parse_netsh
from wimon.report import alert_payload
from wimon.store import Store

# ---- Windows command output (formats as printed by Windows 10/11) ---------------------
ARP = """
Interface: 192.168.0.137 --- 0xb
  Internet Address      Physical Address      Type
  192.168.0.1           50-91-e3-f6-0a-de     dynamic
  192.168.0.66          de-ad-be-ef-00-66     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

ROUTE = """
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.137     35
===========================================================================
"""

NETSH = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Kigali Airport Free
    AP BSSID               : 66:77:88:99:aa:bb
    Network type           : Infrastructure
    Authentication         : Open
    Cipher                 : None
"""

NETSH_NO_LOCATION = """
Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings.
"""

ADAPTER_JSON = (
    '{"alias":"Wi-Fi","status":"Up","ip":["192.168.0.137","fe80::1c2d:3e4f:5a6b:7c8d"],'
    '"gw":["192.168.0.1"],"dhcp":"192.168.0.1","lease":"30/10/2026 01:12:44","dns":["192.168.0.1"]}'
)


def test_arp_table_skips_broadcast_and_multicast():
    assert parse_arp(ARP) == {"192.168.0.1": "50:91:e3:f6:0a:de", "192.168.0.66": "de:ad:be:ef:00:66"}


def test_default_route_through_wifi():
    assert parse_default_routes(ROUTE) == {("192.168.0.1", "192.168.0.137")}


def test_adapter_json_keeps_ipv4_only():
    info = parse_adapter(ADAPTER_JSON)
    assert info["up"] and info["alias"] == "Wi-Fi"
    assert (info["ip"], info["router_ip"], info["dns_servers"]) == ("192.168.0.137", "192.168.0.1", ["192.168.0.1"])


def test_no_wifi_adapter():
    assert parse_adapter("{}") == {} and parse_adapter("") == {}


def test_netsh_reads_name_and_maps_open_to_none():
    assert parse_netsh(NETSH) == {"ssid": "Kigali Airport Free", "bssid": "66:77:88:99:aa:bb", "security": "None"}


def test_netsh_without_location_permission_returns_nothing():
    assert parse_netsh(NETSH_NO_LOCATION) == {"ssid": None, "bssid": None, "security": None}


# ---- the alert page ---------------------------------------------------------------------
def test_hostile_wifi_name_cannot_break_out_of_the_script():
    evil = Event(Severity.CRITICAL, "evil_twin", "Fake hotspot", "x",
                 details={"ssid": "</script><script>alert(1)</script>"})
    page = page_with_payload(alert_payload(evil, "net", True))
    injected = page.split("window.WIMON = ", 1)[1].split("</script>", 1)[0]
    assert "<\\/script>" in injected  # the name is still there, but harmless


# ---- the Controller ---------------------------------------------------------------------
class FakePlatform:
    def __init__(self):
        self.connected = True
        self.disconnects = self.reconnects = 0

    def snapshot(self):
        raise AssertionError("monitor is not started in these tests")

    def is_connected(self):
        return self.connected

    def disconnect_wifi(self):
        self.disconnects += 1
        self.connected = False
        return True

    def reconnect_wifi(self):
        self.reconnects += 1
        self.connected = True
        return True


class FakeUI:
    def __init__(self):
        self.alerts, self.notes = [], []

    @property
    def alert_showing(self):
        return bool(self.alerts)

    def show_alert(self, payload):
        self.alerts.append(payload)

    def notify(self, title, message):
        self.notes.append(title)


@pytest.fixture
def ctl(tmp_path, monkeypatch):
    monkeypatch.delenv("WIMON_DRY_RUN", raising=False)
    c = Controller(FakePlatform(), Store(tmp_path), FakeUI())
    c.monitor.baseline = None
    return c


def attack(kind="arp_spoof"):
    return Event(Severity.CRITICAL, kind, "Attack", "x", source_ip="192.168.0.66")


def test_critical_disconnects_and_shows_alert(ctl):
    ctl.monitor.events.put(attack())
    ctl.poll()
    assert ctl.platform.disconnects == 1
    assert ctl.ui.alerts[-1]["disconnected"] is True
    assert ctl.state == "critical"


def test_warning_only_notifies(ctl):
    ctl.monitor.events.put(Event(Severity.WARNING, "port_scan", "Knock", "x"))
    ctl.poll()
    assert ctl.platform.disconnects == 0 and ctl.ui.notes == ["Knock"]
    assert ctl.state == "warning"


def test_auto_disconnect_off_keeps_wifi(ctl):
    ctl.store.set("auto_disconnect", False)
    ctl.monitor.events.put(attack())
    ctl.poll()
    assert ctl.platform.disconnects == 0
    assert ctl.ui.alerts[-1]["disconnected"] is False


def test_watchdog_disconnects_again_if_windows_rejoins(ctl, monkeypatch):
    monkeypatch.setattr("wimon.controller.WATCHDOG_SECONDS", 0)
    ctl.monitor.events.put(attack())
    ctl.poll()
    ctl.platform.connected = True  # Windows rejoined the network by itself
    ctl.poll()
    assert ctl.platform.disconnects == 2


def test_reconnect_anyway_gives_a_grace_period(ctl):
    ctl.monitor.events.put(attack())
    ctl.poll()
    ctl.on_alert_action("reconnect")
    assert ctl.platform.reconnects == 1 and not ctl.blocked
    assert not ctl.monitor.paused.is_set()
    ctl.monitor.events.put(attack("port_scan"))
    ctl.poll()
    assert ctl.platform.disconnects == 1  # alert shown, but Wi-Fi left alone during the grace period


def test_trust_is_remembered_for_the_network(ctl):
    ctl.alert_network_key = "50:91:e3:f6:0a:de"  # set by handle() from the monitor's baseline
    ctl.on_alert_action("trust")
    assert ctl.store.is_trusted("50:91:e3:f6:0a:de")
    assert ctl.platform.reconnects == 1


def test_dry_run_never_touches_wifi(tmp_path, monkeypatch):
    monkeypatch.setenv("WIMON_DRY_RUN", "1")
    c = Controller(FakePlatform(), Store(tmp_path), FakeUI())
    c.monitor.events.put(attack())
    c.poll()
    c.on_alert_action("reconnect")
    assert c.platform.disconnects == 0 and c.platform.reconnects == 0
