"""Peewee models backing the recon dashboard.

Why Peewee and not SQLAlchemy? This host enforces an application-control policy
that blocks SQLAlchemy's compiled C extensions, so the project standardises on a
pure-Python ORM over the stdlib ``sqlite3`` driver. Same expressiveness, no
native code, works on locked-down Windows endpoints.

Schema overview
---------------
``Target``       a monitored scope (domain / IP / CIDR)
``ScanRun``      one execution of the pipeline, with progress + KPI counters
``Asset``        a reachable service (ip:port/proto), stable across scans
``Vulnerability``a CVE record, cached locally so reports work offline
``AssetVulnerability`` which CVE hits which asset, plus match provenance
``ChangeEvent``  append-only diff log: new assets, closures, new CVEs
``Setting``      runtime configuration (API keys, defaults)
"""

from __future__ import annotations

from datetime import datetime, timezone

import peewee as pw

# Deferred database: the path is bound in recon.db.init_db().
PRAGMAS = {
    "journal_mode": "wal",
    "synchronous": "normal",
    "foreign_keys": 1,
    "busy_timeout": 30000,
    "cache_size": -32_000,
}

db = pw.SqliteDatabase(None, pragmas=PRAGMAS)


def utcnow() -> datetime:
    """Naive UTC timestamp - SQLite stores datetimes without offsets."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class BaseModel(pw.Model):
    class Meta:
        database = db


class Target(BaseModel):
    label = pw.CharField(max_length=120, default="")
    kind = pw.CharField(max_length=16, default="domain")  # domain|ip|cidr
    value = pw.CharField(max_length=255, unique=True, index=True)
    enabled = pw.BooleanField(default=True)
    schedule = pw.CharField(max_length=16, default="manual")  # manual|daily|weekly
    notes = pw.TextField(default="")

    created_at = pw.DateTimeField(default=utcnow)
    last_scan_at = pw.DateTimeField(null=True)

    class Meta:
        table_name = "targets"

    @property
    def display(self) -> str:
        return self.label or self.value

    @property
    def latest_scan(self) -> "ScanRun | None":
        return (
            ScanRun.select()
            .where(ScanRun.target_id == self.id)
            .order_by(ScanRun.started_at.desc(), ScanRun.id.desc())
            .first()
        )


class ScanRun(BaseModel):
    target = pw.ForeignKeyField(Target, backref="scans", on_delete="CASCADE", index=True)
    mode = pw.CharField(max_length=16, default="live")  # live|demo
    trigger = pw.CharField(max_length=16, default="manual")  # manual|schedule|seed

    status = pw.CharField(max_length=16, default="queued")
    stage = pw.CharField(max_length=48, default="queued")
    progress = pw.IntegerField(default=0)
    message = pw.CharField(max_length=255, default="")
    error = pw.TextField(default="")

    started_at = pw.DateTimeField(default=utcnow, index=True)
    finished_at = pw.DateTimeField(null=True)
    duration_ms = pw.IntegerField(default=0)

    subdomains_found = pw.IntegerField(default=0)
    assets_total = pw.IntegerField(default=0)
    assets_new = pw.IntegerField(default=0)
    assets_closed = pw.IntegerField(default=0)
    cves_total = pw.IntegerField(default=0)
    cves_new = pw.IntegerField(default=0)
    crit = pw.IntegerField(default=0)
    high = pw.IntegerField(default=0)
    medium = pw.IntegerField(default=0)
    low = pw.IntegerField(default=0)

    class Meta:
        table_name = "scan_runs"

    @property
    def risk_score(self) -> float:
        """Weighted exposure score 0-100; criticals dominate the score."""
        weighted = self.crit * 10 + self.high * 5 + self.medium * 2 + self.low * 0.5
        return round(min(100.0, weighted / max(1, self.assets_total) * 12), 1)

    @property
    def duration_label(self) -> str:
        if self.duration_ms <= 0:
            return "-"
        return f"{self.duration_ms / 1000:.1f}s"


class Asset(BaseModel):
    target = pw.ForeignKeyField(Target, backref="assets", on_delete="CASCADE", index=True)
    asset_key = pw.CharField(max_length=160, index=True)  # ip:port/proto

    ip = pw.CharField(max_length=64, default="")
    hostname = pw.CharField(max_length=255, default="", index=True)
    port = pw.IntegerField(default=0)
    protocol = pw.CharField(max_length=8, default="tcp")

    service = pw.CharField(max_length=64, default="")
    product = pw.CharField(max_length=120, default="")
    version = pw.CharField(max_length=64, default="")
    banner = pw.TextField(default="")
    os = pw.CharField(max_length=120, default="")
    tls = pw.BooleanField(default=False)
    http_status = pw.IntegerField(default=0)
    title = pw.CharField(max_length=255, default="")
    sources = pw.CharField(max_length=120, default="")

    first_seen = pw.DateTimeField(default=utcnow)
    last_seen = pw.DateTimeField(default=utcnow)
    is_active = pw.BooleanField(default=True, index=True)
    is_new = pw.BooleanField(default=True)
    last_scan_id = pw.IntegerField(null=True)

    class Meta:
        table_name = "assets"
        indexes = (
            (("target", "asset_key"), True),
            (("target", "is_active"), False),
        )

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}/{self.protocol}"

    @property
    def product_label(self) -> str:
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product or self.service or "unknown"


class Vulnerability(BaseModel):
    cve_id = pw.CharField(max_length=32, unique=True, index=True)
    title = pw.CharField(max_length=255, default="")
    description = pw.TextField(default="")
    cvss_score = pw.FloatField(default=0.0)
    severity = pw.CharField(max_length=16, default="unknown", index=True)
    vector = pw.CharField(max_length=120, default="")
    published = pw.CharField(max_length=32, default="")
    url = pw.CharField(max_length=255, default="")
    source = pw.CharField(max_length=32, default="local")
    exploited = pw.BooleanField(default=False)

    class Meta:
        table_name = "vulnerabilities"

    @property
    def severity_rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(self.severity, 0)


class AssetVulnerability(BaseModel):
    asset = pw.ForeignKeyField(Asset, backref="findings", on_delete="CASCADE", index=True)
    vuln = pw.ForeignKeyField(Vulnerability, backref="findings", on_delete="CASCADE", index=True)
    confidence = pw.CharField(max_length=16, default="medium")
    matched_on = pw.CharField(max_length=120, default="")
    first_seen = pw.DateTimeField(default=utcnow)
    last_seen = pw.DateTimeField(default=utcnow)
    is_new = pw.BooleanField(default=True)
    scan_id = pw.IntegerField(null=True)

    class Meta:
        table_name = "asset_vulnerabilities"
        indexes = ((("asset", "vuln"), True),)


class ChangeEvent(BaseModel):
    target = pw.ForeignKeyField(Target, backref="changes", on_delete="CASCADE", index=True)
    scan = pw.ForeignKeyField(ScanRun, backref="changes", null=True, on_delete="CASCADE", index=True)
    kind = pw.CharField(max_length=32, default="new_asset")
    severity = pw.CharField(max_length=16, default="info")
    title = pw.CharField(max_length=255, default="")
    detail = pw.TextField(default="")
    asset_key = pw.CharField(max_length=160, default="")
    created_at = pw.DateTimeField(default=utcnow, index=True)

    class Meta:
        table_name = "change_events"
        indexes = ((("target", "created_at"), False),)


class Setting(BaseModel):
    key = pw.CharField(max_length=64, primary_key=True)
    value = pw.TextField(default="")

    class Meta:
        table_name = "settings"


ALL_MODELS = [Target, ScanRun, Asset, Vulnerability, AssetVulnerability, ChangeEvent, Setting]
