"""DNS tampering: the Wi-Fi sends you to a fake address when you type a real website.

We ask the Wi-Fi's own DNS server (the one DHCP handed us) and compare its answers with:
  * canaries whose addresses never change (one.one.one.one is always 1.1.1.1), and
  * Cloudflare's encrypted DNS-over-HTTPS, which the Wi-Fi cannot quietly rewrite.
CDNs give different addresses in different places, so a mismatch on a normal site only
counts when the Wi-Fi's answer points into the local network, which no real bank lives on.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request

import dns.exception
import dns.resolver

from ..models import Baseline, Event, Severity, Snapshot

CANARIES = {
    "one.one.one.one": {"1.1.1.1", "1.0.0.1"},
    "dns.google": {"8.8.8.8", "8.8.4.4"},
}
SENSITIVE = [
    "accounts.google.com",
    "appleid.apple.com",
    "login.microsoftonline.com",
    "www.paypal.com",
    "www.gtbank.com",
    "www.accessbankplc.com",
]
DOH_URL = "https://1.1.1.1/dns-query?name={}&type=A"
CAPTIVE_URL = "http://captive.apple.com/hotspot-detect.html"


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


class DnsTamperDetector:
    name = "dns"

    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
        self.ctx = _ssl_context()

    # Network calls are methods so tests can replace them.
    def captive_portal_active(self) -> bool | None:
        """True if a login page is intercepting traffic, None if we are offline."""
        try:
            with urllib.request.urlopen(CAPTIVE_URL, timeout=self.timeout) as r:
                return b"Success" not in r.read(2048)
        except (urllib.error.URLError, OSError):
            return None

    def wifi_lookup(self, name: str, servers: list[str]) -> set[str] | None:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = servers
        resolver.lifetime = self.timeout
        try:
            return {r.address for r in resolver.resolve(name, "A")}
        except (dns.exception.DNSException, OSError):
            return None

    def doh_lookup(self, name: str) -> set[str] | None:
        """Raises ssl.SSLCertVerificationError if someone is intercepting HTTPS."""
        req = urllib.request.Request(DOH_URL.format(name), headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                body = json.loads(r.read())
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise e.reason
            return None
        except (OSError, json.JSONDecodeError):
            return None
        return {a["data"] for a in body.get("Answer", []) if a.get("type") == 1}

    def check(self, snap: Snapshot, base: Baseline, lease_changed: bool) -> list[Event]:
        servers = [s for s in snap.dns_servers if s]
        if not servers:
            return []
        portal = self.captive_portal_active()
        if portal is None or portal:
            return []  # offline, or a hotel/café login page is rewriting everything on purpose

        server = servers[0]
        for name, expected in CANARIES.items():
            got = self.wifi_lookup(name, servers)
            if got and not got & expected:
                return [Event(
                    Severity.CRITICAL, "dns_hijack", "DNS hijacking detected",
                    "This Wi-Fi is giving out fake addresses for websites. When you type a real "
                    "website name, you can be sent to a copy built to steal your passwords.",
                    source_ip=server,
                    details={"domain": name, "expected": sorted(expected), "wifi_answered": sorted(got)},
                )]

        try:
            for name in SENSITIVE:
                wifi = self.wifi_lookup(name, servers)
                if not wifi:
                    continue
                local = sorted(ip for ip in wifi if _is_local(ip))
                if not local:
                    continue
                trusted = self.doh_lookup(name)
                if trusted is not None and not wifi & trusted:
                    return [Event(
                        Severity.CRITICAL, "dns_hijack", "Fake website redirect detected",
                        f"This Wi-Fi sends {name} to a device inside the local network instead of "
                        "the real website. That device is very likely a fake login page.",
                        source_ip=local[0],
                        details={"domain": name, "wifi_answered": sorted(wifi), "real_answer": sorted(trusted)},
                    )]
            self.doh_lookup("example.com")  # always make one HTTPS call, to catch interception
        except ssl.SSLCertVerificationError as e:
            return [Event(
                Severity.CRITICAL, "tls_intercept", "Encrypted traffic is being intercepted",
                "Something on this Wi-Fi is replacing the security certificates of websites so it "
                "can read encrypted traffic, including passwords and banking sessions.",
                source_ip=server, details={"error": getattr(e, "verify_message", None) or str(e)},
            )]
        return []
