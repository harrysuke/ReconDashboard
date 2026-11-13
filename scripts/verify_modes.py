"""Regression check for per-target scan modes and the empty-scan guard.

Run after ``init_db`` on a fresh database:

    ./.venv/Scripts/python.exe -m scripts.verify_modes

It asserts three behaviours:
1. ``init_db`` migrates an existing ``targets`` table (adds ``mode``).
2. A demo target scans in demo mode even when the global default is ``live``.
3. A live scan that collects nothing does not close the existing inventory.
"""

from __future__ import annotations

import asyncio
import sys

from recon.db import DB_PATH, db, init_db, session_scope, set_setting
from recon.models import Asset, ScanRun, Target, Vulnerability
from recon.services import scanner


def _columns(table: str) -> set[str]:
    return {col.name for col in db.get_columns(table)}


async def main() -> int:
    init_db()
    failures: list[str] = []

    # --- 1. migration -------------------------------------------------------
    cols = _columns("targets")
    print(f"targets columns: {sorted(cols)}")
    if "mode" not in cols:
        failures.append("targets.mode column missing after init_db")

    # --- 2. demo target runs in demo mode ----------------------------------
    set_setting("default_mode", "live")  # deliberately hostile default
    with session_scope():
        target = Target.create(label="Demo Corp", kind="domain",
                               value="demo.example.com", schedule="weekly", mode="demo")
    target_id = target.id

    await scanner.seed_demo_history(target_id, scans=6, interval_days=7)
    history = list(ScanRun.select().where(ScanRun.target_id == target_id)
                   .order_by(ScanRun.id.asc()))
    print("seeded scans:", [(s.id, s.mode, s.assets_total) for s in history])
    if any(s.mode != "demo" for s in history):
        failures.append("seed_demo_history produced a non-demo scan")

    scan_id = await scanner.run_scan(target_id, trigger="manual")
    scan = ScanRun.get_by_id(scan_id)
    active = Asset.select().where(Asset.target_id == target_id,
                                  Asset.is_active == True).count()  # noqa: E712
    cves = Vulnerability.select().count()
    print(f"manual scan: mode={scan.mode} assets={scan.assets_total} "
          f"new={scan.assets_new} closed={scan.assets_closed} cves={scan.cves_total}")
    print(f"active assets now: {active}, cached CVEs: {cves}")

    if scan.mode != "demo":
        failures.append(f"manual scan ran in {scan.mode!r} mode, expected 'demo'")
    if active == 0:
        failures.append("demo scan wiped the estate (0 active assets)")
    if scan.assets_closed > 0 and scan.assets_total < 10:
        failures.append("demo scan closed assets unexpectedly")

    # --- 3. empty live scan must not close the inventory -------------------
    before = active
    with session_scope():
        live = Target.create(label="Unreachable", kind="domain",
                             value="definitely-not-resolvable-test-domain-xyz.test",
                             schedule="manual", mode="live")
    live_scan_id = await scanner.run_scan(live.id, trigger="manual")
    live_scan = ScanRun.get_by_id(live_scan_id)
    live_active = Asset.select().where(Asset.target_id == live.id,
                                       Asset.is_active == True).count()  # noqa: E712
    print(f"empty live scan: status={live_scan.status} assets={live_scan.assets_total} "
          f"closed={live_scan.assets_closed} msg={live_scan.message!r}")

    # copy an asset under the live target, then re-scan: it must survive
    with session_scope():
        src = Asset.select().where(Asset.target_id == target_id,
                                   Asset.is_active == True).first()  # noqa: E712
        if src is not None:
            Asset.create(target_id=live.id, asset_key=src.asset_key, ip=src.ip,
                         hostname=src.hostname, port=src.port, protocol=src.protocol,
                         service=src.service, product=src.product, version=src.version,
                         banner=src.banner, sources="test", first_seen=src.first_seen,
                         last_seen=src.last_seen, is_active=True, is_new=False,
                         last_scan_id=live_scan_id)
    await scanner.run_scan(live.id, trigger="manual")
    live_active = Asset.select().where(Asset.target_id == live.id,
                                       Asset.is_active == True).count()  # noqa: E712
    print(f"active assets on empty-scan target after 2nd pass: {live_active}")
    if live_active != 1:
        failures.append("empty live scan closed the previous inventory "
                        f"(expected 1 active, got {live_active})")

    print()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("ALL CHECKS PASSED")
    print(f"db: {DB_PATH} ({before} demo assets)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
