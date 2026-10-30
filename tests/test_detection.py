"""Simulated attacks against the engine. Run with: .venv/bin/python -m pytest"""

import copy
import ssl
import time

import pytest

from wimon.detectors import DnsTamperDetector, EvilTwinDetector, PortScanDetector
from wimon.engine import Monitor
from wimon.models import Severity, Snapshot
from wimon.store import Store

ROUTER, ROUTER_MAC = "192.168.0.1", "50:91:e3:f6:0a:de"
ATTACKER, ATTACKER_MAC = "192.168.0.66", "de:ad:be:ef:00:66"


def home(**changes) -> Snapshot:
    snap = Snapshot(
        interface="en0", wifi_on=True, ip="192.168.0.137", router_ip=ROUTER,
        router_mac=ROUTER_MAC, dhcp_server=ROUTER, dns_servers=[ROUTER],
        lease_start="10/29/2026 16:01:51",
        arp={ROUTER: ROUTER_MAC, "192.168.0.111": "50:3e:aa:3e:52:cd", ATTACKER: ATTACKER_MAC},
    )
    for k, v in changes.items():
        setattr(snap, k, v)
    return snap


class FakePlatform:
    def __init__(self):
        self.next = home()

    def snapshot(self):
        return copy.deepcopy(self.next)


@pytest.fixture
def monitor(tmp_path):
    m = Monitor(FakePlatform(), Store(tmp_path))
    # Keep the tests offline: only the ARP and port-scan detectors run here.
    m.detectors = [(d, i) for d, i in m.detectors if d.name in {"arp", "portscan"}]
    m.tick()  # first tick records the baseline
    return m


def kinds(events):
    return [(e.kind, e.severity) for e in events]


# ---- ARP spoofing -------------------------------------------------------------------
def test_quiet_network_raises_nothing(monitor):
    assert monitor.tick() == []
    assert monitor.tick() == []


def test_router_mac_swapped_mid_session_is_critical(monitor):
    poisoned = dict(monitor.platform.next.arp, **{ROUTER: ATTACKER_MAC})
    monitor.platform.next = home(arp=poisoned, router_mac=ATTACKER_MAC)
    events = monitor.tick()
    assert kinds(events) == [("arp_spoof", Severity.CRITICAL)]
    assert events[0].source_ip == ATTACKER  # the attacker's own IP still maps to its MAC


def test_dhcp_renewal_alone_is_silent(monitor):
    monitor.platform.next = home(lease_start="10/29/2026 17:01:50")
    assert monitor.tick() == []
    assert monitor.baseline.lease_start == "10/29/2026 17:01:50"


def test_new_router_with_new_lease_is_only_a_warning(monitor):
    other = "aa:bb:cc:00:11:22"
    monitor.platform.next = home(
        lease_start="10/29/2026 18:00:00", router_mac=other, arp={ROUTER: other}
    )
    assert kinds(monitor.tick()) == [("router_changed", Severity.WARNING)]
    assert monitor.baseline.router_mac == other  # accepted as the new normal
    assert monitor.tick() == []


def test_poisoning_during_renewal_is_still_critical(monitor):
    poisoned = dict(monitor.platform.next.arp, **{ROUTER: ATTACKER_MAC})
    monitor.platform.next = home(lease_start="later", arp=poisoned, router_mac=ATTACKER_MAC)
    assert kinds(monitor.tick()) == [("arp_spoof", Severity.CRITICAL)]
    assert monitor.baseline.router_mac == ROUTER_MAC  # never baseline the attacker


def test_rejoining_with_attacker_as_router_is_critical(monitor):
    poisoned = dict(monitor.platform.next.arp, **{ROUTER: ATTACKER_MAC})
    monitor.platform.next = home(arp=poisoned, router_mac=ATTACKER_MAC)
    monitor.tick()
    monitor.platform.next = home(wifi_on=False)  # we disconnected
    monitor.tick()
    monitor.platform.next = home(arp={ROUTER: ATTACKER_MAC}, router_mac=ATTACKER_MAC)
    assert kinds(monitor.tick()) == [("arp_spoof", Severity.CRITICAL)]


def test_different_subnet_is_a_new_network(monitor):
    monitor.platform.next = home(router_ip="10.0.0.1", dhcp_server="10.0.0.1",
                                 router_mac="11:22:33:44:55:66", arp={"10.0.0.1": "11:22:33:44:55:66"})
    assert monitor.tick() == []
    assert monitor.baseline.router_ip == "10.0.0.1"


def test_device_copying_router_mac_warns_once(monitor):
    arp = dict(monitor.platform.next.arp, **{ATTACKER: ROUTER_MAC})
    monitor.platform.next = home(arp=arp)
    assert kinds(monitor.tick()) == [("mac_conflict", Severity.WARNING)]
    assert monitor.tick() == []  # suppressed repeat


def test_proxy_arp_network_is_not_flagged(tmp_path):
    platform = FakePlatform()
    platform.next = home(arp={ROUTER: ROUTER_MAC, "192.168.0.50": ROUTER_MAC})
    m = Monitor(platform, Store(tmp_path))
    m.detectors = [(d, i) for d, i in m.detectors if d.name == "arp"]
    m.tick()
    assert m.tick() == []


# ---- port scanning ------------------------------------------------------------------
def test_one_knock_warns_two_ports_is_critical(monitor):
    monitor.portscan.record(ATTACKER, 23)
    assert kinds(monitor.tick()) == [("port_scan", Severity.WARNING)]
    monitor.portscan.record(ATTACKER, 3389)
    events = monitor.tick()
    assert kinds(events) == [("port_scan", Severity.CRITICAL)]
    assert events[0].source_mac == ATTACKER_MAC


def test_router_scanning_never_disconnects(monitor):
    for port in (21, 23, 445):
        monitor.portscan.record(ROUTER, port)
    assert kinds(monitor.tick()) == [("port_scan", Severity.WARNING)]


def test_own_ip_is_ignored(monitor):
    monitor.portscan.record("192.168.0.137", 23)
    monitor.portscan.record("192.168.0.137", 21)
    assert monitor.tick() == []


def test_old_knocks_expire(monitor):
    monitor.portscan.record(ATTACKER, 23, at=time.time() - 3600)
    assert monitor.tick() == []


def test_decoy_ports_accept_real_connections():
    import socket
    d = PortScanDetector(ports={47023: "test"}, ignore_ips=set())
    d.start()
    assert d.listening == [47023]
    socket.create_connection(("127.0.0.1", 47023), timeout=2).close()
    for _ in range(30):
        if d._hits:
            break
        time.sleep(0.1)
    d.stop()
    assert [(ip, port) for _, ip, port in d._hits] == [("127.0.0.1", 47023)]


# ---- DNS ----------------------------------------------------------------------------
class FakeDns(DnsTamperDetector):
    def __init__(self, wifi, doh=None, portal=False, tls_error=False):
        super().__init__()
        self.wifi, self.doh, self.portal, self.tls_error = wifi, doh or {}, portal, tls_error

    def captive_portal_active(self):
        return self.portal

    def wifi_lookup(self, name, servers):
        return self.wifi.get(name)

    def doh_lookup(self, name):
        if self.tls_error:
            raise ssl.SSLCertVerificationError("certificate verify failed")
        return self.doh.get(name)


HONEST = {"one.one.one.one": {"1.1.1.1"}, "dns.google": {"8.8.8.8", "8.8.4.4"},
          "www.gtbank.com": {"104.18.1.1"}}


def run_dns(det):
    snap = home()
    return det.check(snap, Monitor._make_baseline(snap), False)


def test_honest_dns_is_quiet():
    assert run_dns(FakeDns(HONEST)) == []


def test_rewritten_canary_is_critical():
    events = run_dns(FakeDns(dict(HONEST, **{"dns.google": {"192.168.0.66"}})))
    assert kinds(events) == [("dns_hijack", Severity.CRITICAL)]


def test_bank_pointing_into_lan_is_critical():
    wifi = dict(HONEST, **{"www.gtbank.com": {"192.168.0.66"}})
    events = run_dns(FakeDns(wifi, doh={"www.gtbank.com": {"104.18.1.1"}}))
    assert kinds(events) == [("dns_hijack", Severity.CRITICAL)]
    assert events[0].source_ip == "192.168.0.66"


def test_captive_portal_suppresses_dns_checks():
    assert run_dns(FakeDns({"dns.google": {"10.0.0.1"}}, portal=True)) == []


def test_certificate_interception_is_critical():
    assert kinds(run_dns(FakeDns(HONEST, tls_error=True))) == [("tls_intercept", Severity.CRITICAL)]


# ---- evil twin ----------------------------------------------------------------------
def test_security_downgrade_on_known_name_is_critical(tmp_path):
    det = EvilTwinDetector(tmp_path / "known.json")
    snap = home(ssid="CafeWiFi", security="WPA2 Personal")
    base = Monitor._make_baseline(snap)
    assert det.check(snap, base, False) == []
    twin = home(ssid="CafeWiFi", security="None", bssid="66:66:66:66:66:66")
    assert kinds(det.check(twin, base, False)) == [("evil_twin", Severity.CRITICAL)]
