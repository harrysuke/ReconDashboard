"""Passive subdomain enumeration via Certificate Transparency (crt.sh).

crt.sh exposes a JSON endpoint that returns every certificate logged for a
domain, and each certificate carries all of its SAN entries. That is a free,
key-less way to discover hosts an organisation never meant to advertise.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Iterable

import httpx

log = logging.getLogger(__name__)

CRTSH_ENDPOINT = "https://crt.sh/"
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class CrtShError(RuntimeError):
    pass


def _clean_names(raw: Iterable[str], domain: str) -> list[str]:
    """Normalise SAN entries: drop wildcards, emails, bad syntax, off-domain names."""
    domain = domain.lower().strip(".")
    out: set[str] = set()
    for entry in raw:
        if not entry:
            continue
        for piece in str(entry).replace("\r", "\n").split("\n"):
            name = piece.strip().lower().rstrip(".")
            if not name or "*" in name or "@" in name or " " in name:
                continue
            if name == domain or name.endswith("." + domain):
                if _HOSTNAME_RE.match(name):
                    out.add(name)
    return sorted(out)


async def enumerate_subdomains(
    client: httpx.AsyncClient,
    domain: str,
    *,
    timeout: float = 45.0,
    retries: int = 2,
) -> list[str]:
    """Return unique in-scope hostnames from CT logs. Raises :class:`CrtShError`."""
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            resp = await client.get(
                CRTSH_ENDPOINT,
                params=params,
                timeout=timeout,
                headers={"User-Agent": "ReconDashboard/1.0 (+osint)"},
            )
            if resp.status_code in (502, 503, 504) or resp.status_code == 429:
                raise CrtShError(f"crt.sh busy (HTTP {resp.status_code})")
            resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, list):
                raise CrtShError("unexpected crt.sh payload")
            names: list[str] = []
            for row in payload:
                names.append(row.get("common_name") or "")
                names.append(row.get("name_value") or "")
            return _clean_names(names, domain)
        except Exception as exc:  # noqa: BLE001 - network layer is noisy
            last_error = exc
            log.warning("crt.sh attempt %s/%s failed: %s", attempt + 1, retries + 1, exc)
            await asyncio.sleep(1.5 * (attempt + 1))

    raise CrtShError(f"crt.sh lookup failed for {domain}: {last_error}")
