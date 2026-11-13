"""Map detected service banners to known CVEs.

Three sources, in order of availability:

1. **Bundled catalog** (:mod:`recon.services.cve_catalog`) - always available,
   deterministic, no rate limits. Covers the services seen most in the wild.
2. **CIRCL CVE Search** - free, no key, returns CPE configurations we can
   version-match against.
3. **NVD API 2.0** - only used when an API key is configured (the keyless rate
   limit of 5 requests / 30s is too slow for a scan).

Every hit carries a ``confidence`` value so the UI can distinguish an exact
version match from a wildcard product match.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx

from recon.services.cve_catalog import (
    CATALOG,
    compare_versions,
    severity_for,
    version_in_range,
)

log = logging.getLogger(__name__)

CIRCL_SEARCH = "https://cve.circl.lu/api/search/{vendor}/{product}"
CIRCL_KEYWORD = "https://cve.circl.lu/api/search/{keyword}"
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_CPE_RE = re.compile(r"^cpe:2\.3:[aho\*\-]:([^:]*):([^:]*):([^:]*):([^:]*):")


@dataclass
class CveHit:
    cve_id: str
    title: str = ""
    description: str = ""
    cvss: float = 0.0
    severity: str = "unknown"
    vector: str = ""
    published: str = ""
    url: str = ""
    exploited: bool = False
    confidence: str = "medium"
    matched_on: str = ""
    source: str = "local"

    def __post_init__(self) -> None:
        if self.severity == "unknown" and self.cvss:
            self.severity = severity_for(self.cvss)
        if not self.url:
            self.url = f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").lower()).strip()


def product_matches(detected: str, token: str) -> bool:
    """Loose product matching: 'apache httpd' should hit token 'httpd'."""
    d, t = _norm(detected), _norm(token)
    if not d or not t:
        return False
    if d == t or t in d or d in t:
        return True
    # token-by-token, so 'openssh 8.2p1' matches token 'openssh'
    dtokens = set(re.split(r"[^a-z0-9]+", d))
    ttokens = set(re.split(r"[^a-z0-9]+", t))
    return bool(ttokens and ttokens.issubset(dtokens))


def match_catalog(product: str, version: str, service: str = "") -> list[CveHit]:
    """Version-aware match against the bundled catalog."""
    if not product and not service:
        return []
    hits: list[CveHit] = []
    for entry in CATALOG:
        if not any(product_matches(product or service, token) for token in entry["products"]):
            continue
        constraint = entry.get("affected", "")
        if version:
            if not version_in_range(version, constraint):
                continue
            confidence = "high"
        else:
            # Product matched but version unknown: report it, flagged as unverified.
            confidence = "low"
        hits.append(
            CveHit(
                cve_id=entry["cve_id"],
                title=entry["title"],
                description=entry["description"],
                cvss=float(entry["cvss"]),
                vector=entry.get("vector", ""),
                published=entry.get("published", ""),
                exploited=bool(entry.get("exploited")),
                confidence=confidence,
                matched_on=f"{product} {version}".strip(),
                source="catalog",
            )
        )
    return hits


def _cpe_version_matches(cpe: str, version: str) -> bool:
    m = _CPE_RE.match(cpe or "")
    if not m:
        return False
    cpe_version = m.group(4)
    if cpe_version in ("*", "-"):
        return True
    if not version:
        return cpe_version in ("*", "-")
    return compare_versions(cpe_version, version) == 0


def parse_circl(rows: list[dict], version: str, label: str) -> list[CveHit]:
    hits: list[CveHit] = []
    for row in rows or []:
        cve_id = row.get("id") or row.get("cve_id") or ""
        if not cve_id.startswith("CVE-"):
            continue
        configs = row.get("vulnerable_configuration") or []
        if isinstance(configs, str):
            configs = [configs]
        exact = any(_cpe_version_matches(c, version) for c in configs)
        if not exact and version:
            continue
        cvss = row.get("cvss3") or row.get("cvss") or 0.0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0
        hits.append(
            CveHit(
                cve_id=cve_id,
                title=(row.get("summary") or "")[:180],
                description=row.get("summary") or "",
                cvss=cvss,
                vector=row.get("cvss3-vector") or row.get("cvss-vector") or "",
                published=(row.get("Published") or "")[:10],
                exploited=False,
                confidence="high" if exact else "medium",
                matched_on=label,
                source="circl",
            )
        )
    return hits


def parse_nvd(payload: dict, label: str) -> list[CveHit]:
    hits: list[CveHit] = []
    for item in (payload or {}).get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        metrics = cve.get("metrics", {})
        score, vector, severity = 0.0, "", "unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                score = float(data.get("baseScore") or 0.0)
                vector = data.get("vectorString", "")
                severity = (data.get("baseSeverity") or "").lower() or severity_for(score)
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        hits.append(
            CveHit(
                cve_id=cve_id,
                title=desc[:180],
                description=desc,
                cvss=score,
                severity=severity or severity_for(score),
                vector=vector,
                published=(cve.get("published") or "")[:10],
                confidence="medium",
                matched_on=label,
                source="nvd",
            )
        )
    return hits


def _vendor_product_tokens(product: str) -> list[tuple[str, str]]:
    """Best-effort (vendor, product) pairs for the CIRCL path-style API."""
    norm = _norm(product)
    if not norm:
        return []
    pairs: list[tuple[str, str]] = []
    tokens = re.split(r"[^a-z0-9]+", norm)
    tokens = [t for t in tokens if t]
    if not tokens:
        return []
    if len(tokens) >= 2:
        pairs.append((tokens[0], tokens[1]))
    pairs.append((tokens[0], tokens[0]))
    seen: set[tuple[str, str]] = set()
    return [p for p in pairs if not (p in seen or seen.add(p))]


class CveService:
    """Cached, concurrency-safe CVE resolver."""

    def __init__(self, *, nvd_api_key: str = "", network: bool = True, timeout: float = 12.0):
        self.nvd_api_key = nvd_api_key
        self.network = network
        self.timeout = timeout
        self._cache: dict[tuple[str, str], list[CveHit]] = {}
        self._lock = asyncio.Lock()

    async def lookup(self, client: httpx.AsyncClient, product: str, version: str,
                     service: str = "") -> list[CveHit]:
        label = f"{product} {version}".strip() or service
        cache_key = (_norm(product or service), _norm(version))
        async with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        hits = match_catalog(product, version, service)
        if self.network and product:
            hits.extend(await self._circl(client, product, version, label))
            if self.nvd_api_key and len(hits) < 3:
                hits.extend(await self._nvd(client, f"{product} {version}".strip(), label))

        merged = self._merge(hits)
        async with self._lock:
            self._cache[cache_key] = merged
        return merged

    @staticmethod
    def _merge(hits: list[CveHit]) -> list[CveHit]:
        best: dict[str, CveHit] = {}
        rank = {"high": 3, "medium": 2, "low": 1}
        for hit in hits:
            current = best.get(hit.cve_id)
            if current is None:
                best[hit.cve_id] = hit
                continue
            # keep the richer record, prefer higher confidence and a real CVSS
            keep_new = (
                (hit.cvss > 0 and current.cvss == 0)
                or rank.get(hit.confidence, 0) > rank.get(current.confidence, 0)
                or (len(hit.description) > len(current.description) and hit.cvss >= current.cvss)
            )
            if keep_new:
                hit.exploited = hit.exploited or current.exploited
                best[hit.cve_id] = hit
            else:
                current.exploited = current.exploited or hit.exploited
        return sorted(best.values(), key=lambda h: (-h.cvss, h.cve_id))

    async def _circl(self, client: httpx.AsyncClient, product: str, version: str,
                     label: str) -> list[CveHit]:
        for vendor, prod in _vendor_product_tokens(product)[:2]:
            try:
                resp = await client.get(
                    CIRCL_SEARCH.format(vendor=vendor, product=prod),
                    timeout=self.timeout,
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    rows = resp.json()
                    if isinstance(rows, list) and rows:
                        return parse_circl(rows, version, label)
            except Exception as exc:  # noqa: BLE001
                log.debug("circl lookup %s/%s failed: %s", vendor, prod, exc)
        # keyword fallback
        try:
            resp = await client.get(
                CIRCL_KEYWORD.format(keyword=_norm(product).replace(" ", "%20")),
                timeout=self.timeout,
            )
            if resp.status_code == 200 and isinstance(resp.json(), list):
                return parse_circl(resp.json(), version, label)
        except Exception as exc:  # noqa: BLE001
            log.debug("circl keyword lookup failed: %s", exc)
        return []

    async def _nvd(self, client: httpx.AsyncClient, keyword: str, label: str) -> list[CveHit]:
        if not keyword:
            return []
        try:
            resp = await client.get(
                NVD_ENDPOINT,
                params={"keywordSearch": keyword, "resultsPerPage": 40},
                headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
                timeout=self.timeout + 8,
            )
            if resp.status_code == 200:
                return parse_nvd(resp.json(), label)
            log.info("NVD returned HTTP %s", resp.status_code)
        except Exception as exc:  # noqa: BLE001
            log.debug("nvd lookup failed: %s", exc)
        return []
