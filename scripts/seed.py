"""CLI helper: create a target and optionally backfill demo history.

Examples
--------
    python -m scripts.seed demo                 # demo estate + 6 historical scans
    python -m scripts.seed add example.com      # add a real target
    python -m scripts.seed scan 1               # run one live scan for target 1
    python -m scripts.seed list                 # show targets
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.db import init_db, session_scope  # noqa: E402
from recon.models import Asset, ScanRun, Target  # noqa: E402
from recon.services import scanner  # noqa: E402


def _list() -> None:
    rows = list(Target.select().order_by(Target.id))
    if not rows:
        print("no targets")
        return
    for t in rows:
        scans = ScanRun.select().where(ScanRun.target_id == t.id).count()
        assets = Asset.select().where(Asset.target_id == t.id, Asset.is_active == True).count()  # noqa: E712
        print(f"#{t.id:<3} {t.value:<32} {t.kind:<7} scans={scans:<3} assets={assets:<3} "
              f"schedule={t.schedule}")


async def _demo() -> None:
    target = Target.get_or_none(Target.value == "demo.example.com")
    if target is None:
        with session_scope():
            target = Target.create(label="Demo Corp", kind="domain",
                                   value="demo.example.com", schedule="weekly",
                                   mode="demo",
                                   notes="Synthetic estate for demonstration.")
    await scanner.seed_demo_history(target.id, scans=6, interval_days=7)
    print(f"demo history ready for target #{target.id} (demo.example.com)")


def _add(value: str) -> None:
    value = value.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    existing = Target.get_or_none(Target.value == value)
    if existing:
        print(f"already monitored as #{existing.id}")
        return
    kind = "cidr" if "/" in value else ("ip" if value.replace(".", "").isdigit() else "domain")
    with session_scope():
        target = Target.create(label=value, kind=kind, value=value, schedule="manual")
    print(f"added #{target.id} {value} ({kind})")


async def _scan(target_id: int) -> None:
    scan_id = await scanner.run_scan(target_id, trigger="manual")
    scan = ScanRun.get(ScanRun.id == scan_id)
    print(f"scan #{scan_id} {scan.status}: assets={scan.assets_total} "
          f"new={scan.assets_new} cves={scan.cves_total} crit={scan.crit} high={scan.high}")
    if scan.error:
        print(scan.error)


def main() -> None:
    init_db()
    args = sys.argv[1:]
    if not args:
        _list()
        return
    cmd = args[0]
    if cmd == "demo":
        asyncio.run(_demo())
    elif cmd == "add" and len(args) > 1:
        _add(args[1])
    elif cmd == "scan" and len(args) > 1:
        asyncio.run(_scan(int(args[1])))
    elif cmd == "list":
        _list()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
