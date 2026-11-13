"""Shodan collection: exposed ports, banners, product/version and OS fingerprints.

The ``shodan`` SDK is synchronous, so every call is pushed to a worker thread
with :func:`asyncio.to_thread`; that keeps the dashboard event loop responsive
while dozens of host lookups are in flight.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field

import shodan as shodan_sdk

log = logging.getLogger(__name__)

# Ports we care about for a recon view (Shodan returns many more).
INTERESTING_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521,
    2049, 2375, 2376, 3000, 3306, 3389, 4443, 5432, 5601, 5900, 5984, 6379,
    7001, 8000, 8006, 8008, 8080, 8081, 8443, 8888, 9000, 9042, 9090, 9200,
    9300, 10000, 11211, 27017, 50000,
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class ShodanUnavailable(RuntimeError):
    """Raised when no usable Shodan API key is configured."""


@dataclass
class RawAsset:
    """Normalised service record produced by any collector."""

    ip: str
    port: int
    protocol: str = "tcp"
    hostname: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    os: str = ""
    tls: bool = False
    http_status: int = 0
    title: str = ""
    sources: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}/{self.protocol}"


def _clean_banner(data: str | bytes | None, limit: int = 400) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = " ".join(text.split())
    return text[:limit]


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    return " ".join(m.group(1).split())[:180] if m else ""


def parse_host(payload: dict, hostname: str = "") -> list[RawAsset]:
    """Turn one ``shodan.host()`` document into normalised asset rows."""
    assets: list[RawAsset] = []
    ip = str(payload.get("ip_str") or "")
    os_name = str(payload.get("os") or "")
    hostnames = payload.get("hostnames") or []
    default_host = hostname or (hostnames[0] if hostnames else "")

    for item in payload.get("data", []) or []:
        port = int(item.get("port") or 0)
        if not port:
            continue
        transport = str(item.get("transport") or "tcp")
        product = str(item.get("product") or "")
        version = str(item.get("version") or "")
        module = str(item.get("_shodan", {}).get("module") or "")

        http = item.get("http") or {}
        title = _extract_title(http.get("html") or "")
        status = int(http.get("status") or 0)
        tls = bool(item.get("ssl") or http.get("ssl") or port in (443, 8443, 993, 995))

        service = module or (item.get("_shodan", {}).get("module") if item.get("_shodan") else "")
        if not service:
            if http:
                service = "https" if tls else "http"
            elif item.get("ssh"):
                service = "ssh"
            else:
                service = str(item.get("service") or "")

        assets.append(
            RawAsset(
                ip=ip,
                port=port,
                protocol=transport,
                hostname=default_host,
                service=service,
                product=product,
                version=version,
                banner=_clean_banner(item.get("data")),
                os=os_name,
                tls=tls,
                http_status=status,
                title=title,
                sources={"shodan"},
            )
        )
    return assets


class ShodanCollector:
    """Thin async wrapper over the Shodan SDK with graceful degradation."""

    def __init__(self, api_key: str) -> None:
        if not api_key:
            raise ShodanUnavailable("No Shodan API key configured")
        self._api = shodan_sdk.Shodan(api_key)
        self._sem = asyncio.Semaphore(4)

    async def host(self, ip: str, hostname: str = "") -> list[RawAsset]:
        async with self._sem:
            try:
                payload = await asyncio.to_thread(self._api.host, ip)
            except shodan_sdk.APIError as exc:
                log.info("shodan host %s: %s", ip, exc)
                return []
            except Exception as exc:  # noqa: BLE001
                log.warning("shodan host %s failed: %s", ip, exc)
                return []
            return parse_host(payload, hostname)

    async def search(self, query: str, limit: int = 100) -> list[RawAsset]:
        """Run a Shodan search query (``hostname:example.com`` / ``net:10.0.0.0/24``)."""
        async with self._sem:
            try:
                payload = await asyncio.to_thread(self._api.search, query, limit=limit)
            except Exception as exc:  # noqa: BLE001
                log.info("shodan search %r failed: %s", query, exc)
                return []
        out: list[RawAsset] = []
        for match in payload.get("matches", []) or []:
            out.extend(parse_host(match))
        return out

    async def resolve(self, hostname: str) -> list[str]:
        """DNS resolution through Shodan (falls back to the OS resolver)."""
        try:
            payload = await asyncio.to_thread(self._api.dns.resolve, hostname)
            return [str(a) for a in payload.get("data", []) if a.get("type") == "A"]
        except Exception:  # noqa: BLE001
            return await resolve_ips(hostname)


async def resolve_ips(hostname: str) -> list[str]:
    """Resolve A records with the stdlib (no extra dependency, thread-safe)."""
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, hostname, None, socket.AF_INET, socket.SOCK_STREAM
        )
    except Exception:  # noqa: BLE001
        return []
    ips = {info[4][0] for info in infos}
    return sorted(ip for ip in ips if _is_public(ip))


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def expand_cidr(cidr: str, max_hosts: int = 64) -> list[str]:
    """Expand a CIDR (or single IP) to a bounded list of host addresses."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        try:
            return [str(ipaddress.ip_address(cidr))]
        except ValueError:
            return []
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 2 else [str(net.network_address)]
    return hosts[:max_hosts]
