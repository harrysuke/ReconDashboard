"""Scan orchestration: collect -> diff -> enrich with CVEs -> persist.

The pipeline is split into short stages so the UI can show real progress.
Progress lives in the ``scan_runs`` row rather than in process memory, because
the Reflex background handler that animates the progress bar runs in a
different task from the scan itself - the database is the channel between them.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from recon.db import get_setting, session_scope
from recon.models import (
    Asset,
    AssetVulnerability,
    ChangeEvent,
    ScanRun,
    Target,
    Vulnerability,
    utcnow,
)
from recon.services import crtsh, demo, probe
from recon.services.cve_catalog import severity_for
from recon.services.cve_lookup import CveService
from recon.services.shodan_client import (
    RawAsset,
    ShodanCollector,
    ShodanUnavailable,
    expand_cidr,
    resolve_ips,
)

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0, "info": 0}

STAGES: dict[str, int] = {
    "queued": 2,
    "subdomains": 10,
    "shodan": 32,
    "probe": 52,
    "diff": 68,
    "cve": 82,
    "report": 94,
    "done": 100,
}

STAGE_LABELS = {
    "queued": "Queued",
    "subdomains": "Certificate transparency",
    "shodan": "Shodan inventory",
    "probe": "HTTP fingerprinting",
    "diff": "Diffing assets",
    "cve": "CVE correlation",
    "report": "Writing change log",
    "done": "Complete",
    "error": "Failed",
}


# --------------------------------------------------------------------------- #
# progress plumbing
# --------------------------------------------------------------------------- #
def _set_progress(scan_id: int, stage: str, message: str = "", progress: int | None = None) -> None:
    pct = STAGES.get(stage, 0) if progress is None else progress
    with session_scope():
        (ScanRun.update(
            stage=stage,
            progress=max(0, min(100, pct)),
            message=(message or "")[:255],
            status="running",
        ).where(ScanRun.id == scan_id).execute())


def _finish(scan_id: int, *, status: str, error: str = "") -> None:
    scan = ScanRun.get_or_none(ScanRun.id == scan_id)
    if scan is None:
        return
    finished = utcnow()
    duration = int((finished - scan.started_at).total_seconds() * 1000) if scan.started_at else 0
    with session_scope():
        (ScanRun.update(
            status=status,
            stage="done" if status == "success" else "error",
            progress=100 if status == "success" else scan.progress,
            error=(error or "")[:4000],
            finished_at=finished,
            duration_ms=max(0, duration),
        ).where(ScanRun.id == scan_id).execute())
        if status == "success":
            (Target.update(last_scan_at=finished).where(Target.id == scan.target_id).execute())


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #
async def _collect(
    target: Target,
    mode: str,
    scan_id: int,
    *,
    probe_enabled: bool,
    max_hosts: int,
) -> tuple[list[RawAsset], list[str], list[str]]:
    """Return ``(assets, subdomains, warnings)``."""
    warnings: list[str] = []
    subdomains: list[str] = []
    assets: list[RawAsset] = []

    if mode == "demo":
        _set_progress(scan_id, "subdomains", "Synthesising demo estate")
        subdomains = demo.demo_subdomains(target.value)
        await asyncio.sleep(0.1)
        _set_progress(scan_id, "shodan", "Building demo service inventory")
        # Continue the timeline where the recorded history stopped, so repeated
        # demo scans keep revealing new services instead of replaying a snapshot.
        done = (ScanRun
                .select()
                .where(ScanRun.target_id == target.id, ScanRun.status == "success")
                .count())
        assets = demo.build_demo_assets(target.value, scan_index=max(0, done))
        await asyncio.sleep(0.1)
        return assets, subdomains, warnings

    shodan_key = get_setting("shodan_api_key", "")
    collector: ShodanCollector | None = None
    if shodan_key:
        try:
            collector = ShodanCollector(shodan_key)
        except ShodanUnavailable as exc:
            warnings.append(str(exc))

    async with probe.build_client() as client:
        # --- stage 1: passive subdomain enumeration -------------------------
        _set_progress(scan_id, "subdomains", "Querying certificate transparency logs")
        hosts: list[str] = []
        if target.kind == "domain":
            try:
                subdomains = await crtsh.enumerate_subdomains(client, target.value)
            except crtsh.CrtShError as exc:
                warnings.append(str(exc))
                subdomains = [target.value]
            hosts = subdomains or [target.value]
            _set_progress(scan_id, "subdomains",
                          f"{len(subdomains)} hostnames found in CT logs",
                          STAGES["subdomains"] + 8)

        # --- stage 2: Shodan -------------------------------------------------
        _set_progress(scan_id, "shodan", "Querying Shodan for exposed services")
        if collector is not None:
            if target.kind == "domain":
                assets.extend(await collector.search(f"hostname:{target.value}", limit=100))
            else:
                hosts_list = expand_cidr(target.value, max_hosts=max_hosts)
                sem = asyncio.Semaphore(5)

                async def _lookup(ip: str) -> list[RawAsset]:
                    async with sem:
                        return await collector.host(ip)

                for batch in await asyncio.gather(*[_lookup(ip) for ip in hosts_list]):
                    assets.extend(batch)
        else:
            warnings.append("Shodan API key not configured - passive sources only")

        # --- stage 3: shallow HTTP fingerprinting ---------------------------
        if probe_enabled and target.kind == "domain":
            _set_progress(scan_id, "probe", f"Fingerprinting {len(hosts)} hosts over HTTP(S)")
            resolution: dict[str, str] = {}
            for host in hosts[:max_hosts]:
                ips = await resolve_ips(host)
                if ips:
                    resolution[host] = ips[0]
            if resolution:
                tasks = [probe.probe_host(client, host, ip) for host, ip in resolution.items()]
                for batch in await asyncio.gather(*tasks, return_exceptions=True):
                    if isinstance(batch, list):
                        assets.extend(batch)

        _set_progress(scan_id, "diff", "Normalising and de-duplicating assets")

    return assets, subdomains, warnings


def _dedupe(raws: Iterable[RawAsset]) -> list[RawAsset]:
    """Collapse duplicate ip:port records, merging provenance and metadata."""
    merged: dict[str, RawAsset] = {}
    for raw in raws:
        if not raw.port:
            continue
        existing = merged.get(raw.key)
        if existing is None:
            merged[raw.key] = raw
            continue
        existing.sources |= raw.sources
        existing.hostname = existing.hostname or raw.hostname
        if not existing.product and raw.product:
            existing.product, existing.version = raw.product, raw.version
        existing.title = existing.title or raw.title
        existing.banner = existing.banner or raw.banner
        existing.os = existing.os or raw.os
        existing.tls = existing.tls or raw.tls
        existing.http_status = existing.http_status or raw.http_status
    return sorted(merged.values(), key=lambda a: (a.ip, a.port))


# --------------------------------------------------------------------------- #
# persistence + diff
# --------------------------------------------------------------------------- #
def _persist_assets(
    target_id: int, scan_id: int, raws: list[RawAsset], *, close_missing: bool = True
) -> tuple[list[Asset], list[str], list[str]]:
    """Upsert assets; return (new_assets, closed_keys, changed_keys).

    ``close_missing=False`` keeps the previous inventory active. A scan that
    collected nothing is far more likely to have been blocked (missing Shodan
    key, CT rate limit, DNS outage) than to mean the whole estate vanished, so
    the caller disables closure in that case instead of destroying history.
    """
    new_assets: list[Asset] = []
    closed_keys: list[str] = []
    changed_keys: list[str] = []
    now = utcnow()

    with session_scope():
        existing = {a.asset_key: a for a in Asset.select().where(Asset.target_id == target_id)}
        seen: set[str] = set()

        for raw in raws:
            seen.add(raw.key)
            asset = existing.get(raw.key)
            if asset is None:
                asset = Asset.create(
                    target_id=target_id,
                    asset_key=raw.key,
                    ip=raw.ip,
                    hostname=raw.hostname,
                    port=raw.port,
                    protocol=raw.protocol,
                    service=raw.service,
                    product=raw.product,
                    version=raw.version,
                    banner=raw.banner,
                    os=raw.os,
                    tls=raw.tls,
                    http_status=raw.http_status,
                    title=raw.title,
                    sources=",".join(sorted(raw.sources)),
                    first_seen=now,
                    last_seen=now,
                    is_active=True,
                    is_new=True,
                    last_scan_id=scan_id,
                )
                new_assets.append(asset)
                continue

            if (asset.version and raw.version and asset.version != raw.version) or (
                asset.product and raw.product and asset.product != raw.product
            ):
                changed_keys.append(raw.key)

            sources = set(filter(None, (asset.sources or "").split(","))) | raw.sources
            (Asset.update(
                hostname=raw.hostname or asset.hostname,
                product=raw.product or asset.product,
                version=raw.version or asset.version,
                service=raw.service or asset.service,
                banner=raw.banner or asset.banner,
                os=raw.os or asset.os,
                tls=asset.tls or raw.tls,
                http_status=raw.http_status or asset.http_status,
                title=raw.title or asset.title,
                sources=",".join(sorted(sources)),
                last_seen=now,
                is_active=True,
                is_new=False,
                last_scan_id=scan_id,
            ).where(Asset.id == asset.id).execute())

        for key, asset in existing.items():
            if key not in seen and asset.is_active and close_missing:
                (Asset.update(is_active=False).where(Asset.id == asset.id).execute())
                closed_keys.append(key)

    for asset in new_assets:
        asset.is_active = True
    return new_assets, closed_keys, changed_keys


def _active_assets(target_id: int) -> list[Asset]:
    return list(Asset.select().where(Asset.target_id == target_id, Asset.is_active == True))  # noqa: E712


def _persist_findings(
    scan_id: int, assets: list[Asset], hits_by_asset: dict[int, list]
) -> tuple[int, int, dict[str, int]]:
    """Store CVEs + link rows.

    Returns ``(distinct_cves, distinct_new_cves, severity_counts)`` - counts are
    per unique CVE so KPI cards answer "how many distinct issues exist", while
    the link table still records every affected asset.
    """
    severity_of: dict[str, str] = {}
    new_ids: set[str] = set()
    now = utcnow()
    asset_ids = [a.id for a in assets]

    with session_scope():
        if asset_ids:
            (AssetVulnerability.update(is_new=False)
             .where(AssetVulnerability.asset.in_(asset_ids))
             .execute())

        for asset in assets:
            for hit in hits_by_asset.get(asset.id, []):
                vuln = Vulnerability.get_or_none(Vulnerability.cve_id == hit.cve_id)
                if vuln is None:
                    vuln = Vulnerability.create(
                        cve_id=hit.cve_id,
                        title=hit.title[:255],
                        description=hit.description,
                        cvss_score=hit.cvss,
                        severity=hit.severity or severity_for(hit.cvss),
                        vector=hit.vector,
                        published=hit.published,
                        url=hit.url,
                        source=hit.source,
                        exploited=hit.exploited,
                    )
                elif hit.cvss > (vuln.cvss_score or 0):
                    severity = hit.severity or severity_for(hit.cvss)
                    (Vulnerability.update(cvss_score=hit.cvss, severity=severity)
                     .where(Vulnerability.id == vuln.id).execute())
                    vuln.cvss_score, vuln.severity = hit.cvss, severity

                link = AssetVulnerability.get_or_none(
                    (AssetVulnerability.asset == asset.id) & (AssetVulnerability.vuln == vuln.id)
                )
                if link is None:
                    AssetVulnerability.create(
                        asset=asset.id,
                        vuln=vuln.id,
                        confidence=hit.confidence,
                        matched_on=hit.matched_on[:120],
                        first_seen=now,
                        last_seen=now,
                        is_new=True,
                        scan_id=scan_id,
                    )
                    new_ids.add(vuln.cve_id)
                else:
                    (AssetVulnerability.update(last_seen=now, is_new=False,
                                               confidence=hit.confidence or link.confidence)
                     .where(AssetVulnerability.id == link.id).execute())
                severity_of[vuln.cve_id] = vuln.severity

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for sev in severity_of.values():
        counts[sev] = counts.get(sev, 0) + 1
    return len(severity_of), len(new_ids), counts


def _add_change(target_id: int, scan_id: int, kind: str, severity: str,
                title: str, detail: str, asset_key: str = "") -> None:
    ChangeEvent.create(
        target=target_id,
        scan=scan_id,
        kind=kind,
        severity=severity,
        title=title[:255],
        detail=detail,
        asset_key=asset_key,
    )


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
async def run_scan(
    target_id: int,
    *,
    mode: str | None = None,
    trigger: str = "manual",
    scan_id: int | None = None,
    probe_enabled: bool | None = None,
    started_at: datetime | None = None,
) -> int:
    """Execute a full recon pass and return the scan id."""
    target = Target.get_or_none(Target.id == target_id)
    if target is None:
        raise ValueError(f"target {target_id} not found")

    if mode is None:
        # The target decides: a demo scope must never be probed live, otherwise
        # the pass collects nothing and closes the whole synthetic estate.
        mode = (target.mode or "").strip() or get_setting("default_mode", "live")
    if probe_enabled is None:
        probe_enabled = get_setting("probe_enabled", "1") == "1"
    max_hosts = int(get_setting("max_hosts", "64") or 64)

    if scan_id is None:
        with session_scope():
            scan = ScanRun.create(
                target=target_id,
                mode=mode,
                trigger=trigger,
                status="running",
                stage="queued",
                progress=STAGES["queued"],
                message="Scan started",
                started_at=started_at or utcnow(),
            )
            scan_id = scan.id

    log.info("scan %s started for %s (%s)", scan_id, target.value, mode)

    try:
        raws, subdomains, warnings = await _collect(
            target, mode, scan_id, probe_enabled=probe_enabled, max_hosts=max_hosts
        )
        raws = _dedupe(raws)
        _set_progress(scan_id, "diff", f"{len(raws)} unique services discovered")

        # Guard: an empty result set must not be read as "everything was
        # decommissioned". Keep the inventory and flag the pass instead.
        collected = bool(raws)
        if not collected and _active_assets(target_id):
            warnings.append(
                "Scan collected no services - previous inventory retained "
                "(check API keys, DNS and rate limits)"
            )

        new_assets, closed_keys, changed_keys = _persist_assets(
            target_id, scan_id, raws, close_missing=collected
        )

        # --- CVE enrichment ------------------------------------------------
        _set_progress(scan_id, "cve", "Correlating service versions with known CVEs")
        service = CveService(nvd_api_key=get_setting("nvd_api_key", ""), network=mode != "demo")
        sem = asyncio.Semaphore(6)
        active = _active_assets(target_id)

        async with probe.build_client() as client:
            async def enrich(asset: Asset):
                async with sem:
                    return asset.id, await service.lookup(
                        client, asset.product, asset.version, asset.service
                    )

            pairs = await asyncio.gather(*[enrich(a) for a in active])

        hits_by_asset = {asset_id: hits for asset_id, hits in pairs if hits}
        total_cves, new_cves, counts = _persist_findings(scan_id, active, hits_by_asset)

        # --- change log ----------------------------------------------------
        _set_progress(scan_id, "report", "Writing change log")
        with session_scope():
            for asset in new_assets:
                hits = hits_by_asset.get(asset.id, [])
                worst = max((h.severity for h in hits),
                            key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
                _add_change(
                    target_id, scan_id, "new_asset",
                    worst if worst in SEVERITY_ORDER else "info",
                    f"New exposed service {asset.label}",
                    f"{asset.product_label} on {asset.hostname or asset.ip}"
                    + (f" - {len(hits)} known CVE(s)" if hits else ""),
                    asset.asset_key,
                )
            for key in closed_keys:
                _add_change(target_id, scan_id, "closed_asset", "info",
                            f"Service no longer exposed {key}",
                            "Disappeared since the previous scan", key)
            for key in changed_keys:
                _add_change(target_id, scan_id, "service_change", "medium",
                            f"Service version changed {key}",
                            "Banner/version drift detected", key)
            if new_cves:
                fresh = (AssetVulnerability
                         .select(AssetVulnerability, Vulnerability, Asset)
                         .join(Vulnerability)
                         .switch(AssetVulnerability)
                         .join(Asset)
                         .where(AssetVulnerability.scan_id == scan_id,
                                AssetVulnerability.is_new == True))  # noqa: E712
                for link in fresh:
                    _add_change(
                        target_id, scan_id, "new_cve", link.vuln.severity,
                        f"{link.vuln.cve_id} affects {link.asset.label}",
                        f"{(link.vuln.title or link.vuln.description)[:140]} "
                        f"(CVSS {link.vuln.cvss_score})",
                        link.asset.asset_key,
                    )

            (ScanRun.update(
                subdomains_found=len(subdomains),
                assets_total=len(active),
                assets_new=len(new_assets),
                assets_closed=len(closed_keys),
                cves_total=total_cves,
                cves_new=new_cves,
                crit=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                message=("; ".join(warnings) if warnings else "")[:250],
            ).where(ScanRun.id == scan_id).execute())

        _finish(scan_id, status="success")
        log.info("scan %s finished: %s assets, %s CVEs", scan_id, len(active), total_cves)
        return scan_id

    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        log.exception("scan %s failed", scan_id)
        _finish(scan_id, status="error", error=f"{type(exc).__name__}: {exc}")
        return scan_id


# --------------------------------------------------------------------------- #
# demo history seeding
# --------------------------------------------------------------------------- #
async def seed_demo_history(target_id: int, scans: int = 6, interval_days: int = 7) -> None:
    """Create a backdated scan history so growth charts have something to show."""
    target = Target.get_or_none(Target.id == target_id)
    if target is None:
        return
    value = target.value

    # Regenerating the demo must not stack a second timeline on top of the
    # first, so clear this target's derived rows before replaying it.
    with session_scope():
        asset_ids = [a.id for a in Asset.select(Asset.id).where(Asset.target_id == target_id)]
        if asset_ids:
            (AssetVulnerability.delete()
             .where(AssetVulnerability.asset.in_(asset_ids)).execute())
        ChangeEvent.delete().where(ChangeEvent.target == target_id).execute()
        Asset.delete().where(Asset.target_id == target_id).execute()
        ScanRun.delete().where(ScanRun.target_id == target_id).execute()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    service = CveService(network=False)

    for i in range(scans - 1, -1, -1):
        started = now - timedelta(days=i * interval_days)
        with session_scope():
            scan = ScanRun.create(
                target=target_id, mode="demo", trigger="seed", status="running",
                stage="queued", progress=2, message="Historical demo scan", started_at=started,
            )
            scan_id = scan.id

        raws = _dedupe(demo.build_demo_assets(value, scan_index=scans - 1 - i))
        new_assets, closed_keys, _changed = _persist_assets(target_id, scan_id, raws)

        active = _active_assets(target_id)
        hits_by_asset: dict[int, list] = {}
        async with probe.build_client() as client:
            for asset in active:
                hits = await service.lookup(client, asset.product, asset.version, asset.service)
                if hits:
                    hits_by_asset[asset.id] = hits

        total_cves, new_cves, counts = _persist_findings(scan_id, active, hits_by_asset)

        with session_scope():
            for asset in new_assets:
                hits = hits_by_asset.get(asset.id, [])
                worst = max((h.severity for h in hits),
                            key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
                _add_change(target_id, scan_id, "new_asset",
                            worst if worst in SEVERITY_ORDER else "info",
                            f"New exposed service {asset.label}",
                            f"{asset.product_label} on {asset.hostname or asset.ip}",
                            asset.asset_key)
            for key in closed_keys:
                _add_change(target_id, scan_id, "closed_asset", "info",
                            f"Service no longer exposed {key}",
                            "Disappeared since the previous scan", key)

            finished = started + timedelta(seconds=42)
            (ScanRun.update(
                status="success", stage="done", progress=100,
                message=f"Historical demo scan ({len(raws)} services)",
                subdomains_found=len(demo.demo_subdomains(value)),
                assets_total=len(active), assets_new=len(new_assets),
                assets_closed=len(closed_keys), cves_total=total_cves, cves_new=new_cves,
                crit=counts.get("critical", 0), high=counts.get("high", 0),
                medium=counts.get("medium", 0), low=counts.get("low", 0),
                finished_at=finished, duration_ms=42000,
            ).where(ScanRun.id == scan_id).execute())
            (Target.update(last_scan_at=finished).where(Target.id == target_id).execute())
