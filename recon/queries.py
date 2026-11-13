"""Read-model queries for the dashboard.

Every function returns plain, JSON-serialisable dicts with pre-formatted display
fields. Keeping formatting here (instead of in components) means the Reflex
state stays thin and the UI never has to know about ORM objects.
"""

from __future__ import annotations

from datetime import timedelta

from peewee import JOIN, fn

from recon.db import init_db
from recon.models import (
    Asset,
    AssetVulnerability,
    ChangeEvent,
    ScanRun,
    Target,
    Vulnerability,
    utcnow,
)

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0891b2",
    "unknown": "#64748b",
    "info": "#64748b",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
RISK_COLORS = {"high": "#dc2626", "medium": "#ea580c", "low": "#059669"}
INK_STRONG = "#0f172a"


def _sev(value: str) -> str:
    return value if value in SEVERITY_COLORS else "unknown"


def fmt_dt(value) -> str:
    if not value:
        return "-"
    return value.strftime("%d %b %H:%M")


def fmt_date(value) -> str:
    if not value:
        return "-"
    return value.strftime("%d %b")


def relative(value) -> str:
    if not value:
        return "never"
    delta = utcnow() - value
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


# --------------------------------------------------------------------------- #
# estate-wide
# --------------------------------------------------------------------------- #
def _active_asset_ids() -> list[int]:
    return [a.id for a in Asset.select(Asset.id).where(Asset.is_active == True)]  # noqa: E712


def severity_distribution() -> dict[str, int]:
    """Distinct CVEs per severity across all currently exposed assets."""
    ids = _active_asset_ids()
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    if not ids:
        return counts
    rows = (Vulnerability
            .select(Vulnerability.id, Vulnerability.severity)
            .join(AssetVulnerability, on=(AssetVulnerability.vuln == Vulnerability.id))
            .where(AssetVulnerability.asset.in_(ids))
            .distinct())
    seen: dict[int, str] = {}
    for row in rows:
        seen[row.id] = _sev(row.severity)
    for sev in seen.values():
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def dashboard_kpis() -> dict:
    init_db()
    active_ids = _active_asset_ids()
    assets = len(active_ids)
    new_assets = Asset.select().where(Asset.is_active == True, Asset.is_new == True).count()  # noqa: E712
    targets = Target.select().count()
    dist = severity_distribution()
    distinct_cves = sum(dist.values())
    crit, high = dist.get("critical", 0), dist.get("high", 0)
    weighted = (crit * 10 + high * 5 + dist.get("medium", 0) * 2 + dist.get("low", 0) * 0.5)
    score = round(min(100.0, weighted / max(1, assets) * 12), 1)

    last_scan = (ScanRun.select()
                 .where(ScanRun.status == "success")
                 .order_by(ScanRun.finished_at.desc())
                 .first())
    open_changes = (ChangeEvent.select()
                    .where(ChangeEvent.created_at >= utcnow() - timedelta(days=7))
                    .count())

    return {
        "assets": assets,
        "new_assets": new_assets,
        "targets": targets,
        "cves": distinct_cves,
        "critical": crit,
        "high": high,
        "medium": dist.get("medium", 0),
        "low": dist.get("low", 0),
        "score": score,
        "last_scan": relative(last_scan.finished_at) if last_scan else "never",
        "changes_7d": open_changes,
        "services": Asset.select().where(Asset.is_active == True).count(),  # noqa: E712
    }


def asset_growth(limit_scans: int = 12) -> list[dict]:
    """One series per target: assets_total per successful scan, oldest first."""
    series: list[dict] = []
    for target in Target.select().order_by(Target.id):
        scans = list(
            ScanRun.select()
            .where(ScanRun.target_id == target.id, ScanRun.status == "success")
            .order_by(ScanRun.started_at.asc())
        )[-limit_scans:]
        if not scans:
            continue
        series.append({
            "name": target.display,
            "points": [
                {"date": s.started_at.strftime("%Y-%m-%d"), "assets": s.assets_total,
                 "cves": s.cves_total}
                for s in scans if s.started_at
            ],
        })
    return series


def recent_changes(limit: int = 14) -> list[dict]:
    rows = (ChangeEvent
            .select(ChangeEvent, Target)
            .join(Target)
            .order_by(ChangeEvent.created_at.desc(), ChangeEvent.id.desc())
            .limit(limit))
    out = []
    for row in rows:
        out.append({
            "kind": row.kind.replace("_", " "),
            "kind_raw": row.kind,
            "severity": _sev(row.severity),
            "color": SEVERITY_COLORS[_sev(row.severity)],
            "title": row.title,
            "detail": row.detail,
            "target": row.target.display,
            "when": relative(row.created_at),
            "asset_key": row.asset_key,
        })
    return out


def top_exposed_assets(limit: int = 7) -> list[dict]:
    ids = _active_asset_ids()
    if not ids:
        return []
    rows = (Asset
            .select(Asset, Target,
                    fn.COUNT(AssetVulnerability.id).alias("finding_count"),
                    fn.MAX(Vulnerability.cvss_score).alias("max_cvss"))
            .join(Target)
            .switch(Asset)
            .join(AssetVulnerability, JOIN.LEFT_OUTER)
            .switch(AssetVulnerability)
            .join(Vulnerability, JOIN.LEFT_OUTER)
            .where(Asset.is_active == True)  # noqa: E712
            .group_by(Asset.id)
            .order_by(fn.MAX(Vulnerability.cvss_score).desc(), Asset.port.asc())
            .limit(limit))
    out = []
    for row in rows:
        out.append({
            "endpoint": f"{row.ip}:{row.port}",
            "host": row.hostname or row.ip,
            "service": row.service or "-",
            "product": row.product_label,
            "target": row.target.display,
            "findings": int(row.finding_count or 0),
            "max_cvss": float(row.max_cvss or 0.0),
            "title": row.title or "-",
        })
    return out


# --------------------------------------------------------------------------- #
# targets
# --------------------------------------------------------------------------- #
def list_targets() -> list[dict]:
    out = []
    for target in Target.select().order_by(Target.created_at.desc()):
        assets = Asset.select().where(Asset.target_id == target.id,
                                      Asset.is_active == True).count()  # noqa: E712
        cves = (Vulnerability
                .select(Vulnerability.id)
                .join(AssetVulnerability, on=(AssetVulnerability.vuln == Vulnerability.id))
                .join(Asset, on=(AssetVulnerability.asset == Asset.id))
                .where(Asset.target_id == target.id, Asset.is_active == True)  # noqa: E712
                .distinct()
                .count())
        latest = target.latest_scan
        risk = latest.risk_score if latest else 0.0
        band = "high" if risk >= 70 else ("medium" if risk >= 40 else "low")
        out.append({
            "id": target.id,
            "label": target.display,
            "value": target.value,
            "kind": target.kind,
            "schedule": target.schedule,
            "enabled": target.enabled,
            "assets": assets,
            "cves": cves,
            "cves_color": "#dc2626" if cves else "#64748b",
            "risk": risk,
            "risk_color": RISK_COLORS[band],
            "risk_band": band,
            "status": latest.status if latest else "never",
            "last_scan": relative(target.last_scan_at),
            "notes": target.notes,
        })
    return out


def target_options() -> list[dict]:
    return [{"value": str(t.id), "label": t.display} for t in Target.select().order_by(Target.id)]


# --------------------------------------------------------------------------- #
# assets / findings
# --------------------------------------------------------------------------- #
def list_assets(target_id: int | None = None, search: str = "",
                only_new: bool = False, limit: int = 300) -> list[dict]:
    query = Asset.select(Asset, Target).join(Target).where(Asset.is_active == True)  # noqa: E712
    if target_id:
        query = query.where(Asset.target_id == target_id)
    if only_new:
        query = query.where(Asset.is_new == True)  # noqa: E712
    query = query.order_by(Asset.port.asc(), Asset.ip.asc()).limit(limit)

    search = (search or "").strip().lower()
    out = []
    for row in query:
        haystack = " ".join([row.ip, row.hostname, row.product, row.version,
                             row.service, row.title, row.banner]).lower()
        if search and search not in haystack:
            continue
        findings = list(row.findings)
        worst = max((f.vuln.severity for f in findings),
                    key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 9,
                    default="unknown")
        out.append({
            "id": row.id,
            "endpoint": f"{row.ip}:{row.port}",
            "host": row.hostname or "-",
            "port": row.port,
            "protocol": row.protocol,
            "service": row.service or "-",
            "product": row.product or "-",
            "version": row.version or "",
            "title": row.title or "-",
            "os": row.os or "-",
            "tls": row.tls,
            "target": row.target.display,
            "findings": len(findings),
            "has_findings": len(findings) > 0,
            "findings_color": INK_STRONG if findings else "#94a3b8",
            "severity": _sev(worst),
            "color": SEVERITY_COLORS[_sev(worst)],
            "is_new": row.is_new,
            "first_seen": fmt_date(row.first_seen),
            "last_seen": relative(row.last_seen),
            "sources": ", ".join(filter(None, (row.sources or "").split(","))) or "-",
        })
    return out


def list_findings(severity: str = "all", search: str = "",
                  target_id: int | None = None, limit: int = 400) -> list[dict]:
    query = (AssetVulnerability
             .select(AssetVulnerability, Vulnerability, Asset, Target)
             .join(Vulnerability)
             .switch(AssetVulnerability)
             .join(Asset)
             .switch(Asset)
             .join(Target)
             .where(Asset.is_active == True)  # noqa: E712
             .order_by(Vulnerability.cvss_score.desc(), Vulnerability.cve_id.asc())
             .limit(limit))
    if target_id:
        query = query.where(Asset.target_id == target_id)

    search = (search or "").strip().lower()
    out = []
    for link in query:
        vuln, asset = link.vuln, link.asset
        if severity != "all" and _sev(vuln.severity) != severity:
            continue
        haystack = " ".join([vuln.cve_id, vuln.title, vuln.description[:200],
                             asset.product, asset.ip, asset.hostname]).lower()
        if search and search not in haystack:
            continue
        out.append({
            "cve": vuln.cve_id,
            "severity": _sev(vuln.severity),
            "color": SEVERITY_COLORS[_sev(vuln.severity)],
            "cvss": f"{vuln.cvss_score:.1f}",
            "title": (vuln.title or vuln.description or "")[:160],
            "endpoint": f"{asset.ip}:{asset.port}",
            "host": asset.hostname or asset.ip,
            "product": asset.product_label,
            "target": asset.target.display,
            "confidence": link.confidence,
            "is_new": link.is_new,
            "exploited": vuln.exploited,
            "published": vuln.published or "-",
            "url": vuln.url,
            "matched_on": link.matched_on or "-",
        })
    return out


# --------------------------------------------------------------------------- #
# scans
# --------------------------------------------------------------------------- #
def list_scans(limit: int = 40) -> list[dict]:
    rows = (ScanRun.select(ScanRun, Target).join(Target)
            .order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).limit(limit))
    out = []
    for s in rows:
        out.append({
            "id": s.id,
            "target": s.target.display,
            "target_id": s.target_id,
            "mode": s.mode,
            "trigger": s.trigger,
            "status": s.status,
            "stage": s.stage.replace("_", " "),
            "progress": s.progress,
            "started": fmt_dt(s.started_at),
            "duration": s.duration_label,
            "assets": s.assets_total,
            "new": s.assets_new,
            "closed": s.assets_closed,
            "cves": s.cves_total,
            "crit": s.crit,
            "high": s.high,
            "message": s.message or s.error or "",
            "has_crit": s.crit > 0,
            "has_high": s.high > 0,
            "has_new": s.assets_new > 0,
            "ok": s.status == "success",
            "running": s.status in ("queued", "running"),
        })
    return out


def scan_status(scan_id: int) -> dict:
    scan = ScanRun.get_or_none(ScanRun.id == scan_id)
    if scan is None:
        return {"progress": 0, "stage": "unknown", "status": "error", "message": ""}
    return {
        "progress": scan.progress,
        "stage": scan.stage.replace("_", " "),
        "status": scan.status,
        "message": scan.message or scan.error or "",
    }


def latest_scan_for_target(target_id: int) -> dict | None:
    scan = (ScanRun.select()
            .where(ScanRun.target_id == target_id)
            .order_by(ScanRun.started_at.desc()).first())
    if scan is None:
        return None
    return {"id": scan.id, "status": scan.status}


def any_running_scan() -> dict | None:
    scan = (ScanRun.select()
            .where(ScanRun.status.in_(("queued", "running")))
            .order_by(ScanRun.started_at.desc()).first())
    if scan is None:
        return None
    return {"id": scan.id, "target_id": scan.target_id, "progress": scan.progress,
            "stage": scan.stage.replace("_", " ")}
