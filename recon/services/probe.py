"""Active-but-shallow HTTP fingerprinting.

For every hostname discovered passively we fetch the web root over the usual
web ports and read what the server volunteers: ``Server`` / ``X-Powered-By``
headers, the HTTP status and the page title. That is enough to pin a product
and version (``nginx/1.18.0``, ``Apache/2.4.49``) without any API key.

Only ports 80/443/8080/8443 are touched and only for hosts that already
resolved inside the target scope. No exploitation, no brute force.
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx

from recon.services.shodan_client import RawAsset, _extract_title

log = logging.getLogger(__name__)

WEB_PORTS: tuple[tuple[int, str], ...] = (
    (443, "https"),
    (80, "http"),
    (8443, "https"),
    (8080, "http"),
)

_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _\-\.]*?)[/ ]v?(\d[\w\.\-]*)")

# Header values that identify a stack rather than a product version.
_NOISE = {"cloudflare", "akamai", "gws", "envoy", "sucuri", "awselb", "nginx-plus"}


def parse_server_header(value: str) -> tuple[str, str]:
    """'Apache/2.4.49 (Ubuntu)' -> ('Apache', '2.4.49')."""
    if not value:
        return "", ""
    raw = value.split("(")[0].strip()
    m = _SERVER_RE.match(raw)
    if not m:
        return raw.split()[0][:60], ""
    product = m.group(1).strip()
    version = m.group(2).strip().rstrip(".")
    if product.lower() in _NOISE:
        return product, version
    return product, version


def _guess_service(port: int, tls: bool) -> str:
    if port in (443, 8443) or tls:
        return "https"
    return "http"


async def probe_host(
    client: httpx.AsyncClient,
    hostname: str,
    ip: str,
    *,
    ports: tuple[tuple[int, str], ...] = WEB_PORTS,
) -> list[RawAsset]:
    """Probe the web ports of a single hostname concurrently."""
    tasks = [_probe_one(client, hostname, ip, port, scheme) for port, scheme in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assets: list[RawAsset] = []
    for res in results:
        if isinstance(res, RawAsset):
            assets.append(res)
        elif isinstance(res, Exception):
            log.debug("probe error %s: %s", hostname, res)
    return assets


async def _probe_one(
    client: httpx.AsyncClient, hostname: str, ip: str, port: int, scheme: str
) -> RawAsset | None:
    url = f"{scheme}://{hostname}:{port}/"
    try:
        resp = await client.get(url, follow_redirects=True, timeout=8.0)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError):
        return None
    except httpx.HTTPError:
        return None
    except Exception as exc:  # noqa: BLE001
        log.debug("probe %s failed: %s", url, exc)
        return None

    headers = resp.headers
    product, version = parse_server_header(headers.get("server", ""))
    powered = headers.get("x-powered-by", "")
    if powered and not product:
        product, version = parse_server_header(powered)

    body = ""
    try:
        body = resp.text[:60_000]
    except Exception:  # noqa: BLE001
        body = ""

    final_host = urlparse(str(resp.url)).hostname or hostname
    return RawAsset(
        ip=ip,
        port=port,
        protocol="tcp",
        hostname=final_host,
        service=_guess_service(port, scheme == "https"),
        product=product,
        version=version,
        banner=f"HTTP/{resp.http_version} {resp.status_code} server={headers.get('server','')} "
               f"powered-by={powered}".strip(),
        os="",
        tls=scheme == "https",
        http_status=resp.status_code,
        title=_extract_title(body),
        sources={"httpx"},
    )


def build_client(*, verify: bool = False, concurrency: int = 24) -> httpx.AsyncClient:
    """Shared async client: pooled connections, bounded concurrency, no TLS verify.

    TLS verification is disabled because recon targets routinely present
    self-signed or expired certificates and we only need the fingerprint.
    """
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    return httpx.AsyncClient(
        verify=verify,
        limits=limits,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ReconDashboard/1.0)"},
        timeout=httpx.Timeout(10.0, connect=6.0),
    )
