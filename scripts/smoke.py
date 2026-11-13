"""Backend smoke test: seed a demo target, run scans, verify diff + CVE output.

Usage:  python -m scripts.smoke
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.db import init_db, session_scope  # noqa: E402
from recon.models import (  # noqa: E402
    Asset,
    AssetVulnerability,
    ChangeEvent,
    ScanRun,
    Target,
    Vulnerability,
)
from recon.services import scanner  # noqa: E402


async def main() -> None:
    init_db()
    target = Target.get_or_none(Target.value == "demo.example.com")
    if target is None:
        with session_scope():
            target = Target.create(label="Demo Corp", kind="domain", value="demo.example.com",
                                   schedule="weekly", mode="demo", notes="smoke test")
    target_id = target.id

    with session_scope():
        ChangeEvent.delete().where(ChangeEvent.target == target_id).execute()
        AssetVulnerability.delete().where(
            AssetVulnerability.asset.in_(
                Asset.select(Asset.id).where(Asset.target_id == target_id)
            )
        ).execute()
        ScanRun.delete().where(ScanRun.target_id == target_id).execute()
        Asset.delete().where(Asset.target_id == target_id).execute()

    print(f"target_id={target_id}")
    await scanner.seed_demo_history(target_id, scans=5, interval_days=7)

    scan_id = await scanner.run_scan(target_id, mode="demo", trigger="manual")
    scan = ScanRun.get(ScanRun.id == scan_id)
    print(f"scan_id={scan_id} status={scan.status} progress={scan.progress} "
          f"assets={scan.assets_total} new={scan.assets_new} closed={scan.assets_closed} "
          f"cves={scan.cves_total} crit={scan.crit} high={scan.high} "
          f"med={scan.medium} low={scan.low} risk={scan.risk_score}")
    assert scan.status == "success", scan.error

    changes = list(ChangeEvent.select().where(ChangeEvent.scan == scan_id))
    print(f"change events: {len(changes)}")
    for c in changes[:8]:
        print(f"  [{c.severity}] {c.kind}: {c.title}")

    findings = (AssetVulnerability
                .select(AssetVulnerability, Vulnerability, Asset)
                .join(Vulnerability)
                .switch(AssetVulnerability)
                .join(Asset)
                .where(Asset.target_id == target_id)
                .order_by(Vulnerability.cvss_score.desc()))
    rows = [(f.vuln.cve_id, f.vuln.cvss_score, f.asset.port, f.asset.product) for f in findings]
    print(f"findings: {len(rows)}")
    for cve, cvss, port, product in rows[:10]:
        print(f"  {cve} {cvss} :{port} {product}")

    history = list(ScanRun.select().where(ScanRun.target_id == target_id)
                   .order_by(ScanRun.started_at))
    print("history:", [(s.started_at.strftime("%m-%d"), s.assets_total, s.cves_total) for s in history])

    from recon.services import report
    path = report.build_report(scan_id, target_id)
    print("pdf:", path.name, path.stat().st_size, "bytes")
    path2 = report.build_portfolio_report()
    print("portfolio pdf:", path2.name, path2.stat().st_size, "bytes")


if __name__ == "__main__":
    asyncio.run(main())
