"""Recurring recon with APScheduler.

A background ``BackgroundScheduler`` thread wakes up periodically, finds targets
whose ``schedule`` (daily / weekly) is due, and runs the async pipeline with a
fresh event loop via :func:`asyncio.run`. Scans therefore keep happening even
when nobody has a browser tab open.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from recon.models import ScanRun, Target, utcnow
from recon.services.scanner import run_scan

log = logging.getLogger(__name__)

_INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}

_scheduler: BackgroundScheduler | None = None
_lock = threading.Lock()


def _due_targets() -> list[int]:
    now = utcnow()
    due: list[int] = []
    for target in Target.select().where(Target.enabled == True, Target.schedule != "manual"):  # noqa: E712
        interval = _INTERVALS.get(target.schedule)
        if interval is None:
            continue
        if target.last_scan_at is not None and now - target.last_scan_at < interval:
            continue
        running = (ScanRun.select()
                   .where(ScanRun.target_id == target.id,
                          ScanRun.status.in_(("queued", "running")))
                   .first())
        if running is not None:
            continue
        due.append(target.id)
    return due


def _tick() -> None:
    try:
        targets = _due_targets()
    except Exception as exc:  # noqa: BLE001
        log.warning("scheduler tick failed: %s", exc)
        return
    for target_id in targets:
        try:
            log.info("scheduled scan for target %s", target_id)
            asyncio.run(run_scan(target_id, trigger="schedule"))
        except Exception as exc:  # noqa: BLE001
            log.exception("scheduled scan for target %s failed: %s", target_id, exc)


def start(interval_minutes: int = 10) -> BackgroundScheduler:
    """Start the scheduler once per process (safe to call from app startup)."""
    global _scheduler
    with _lock:
        if _scheduler is not None and _scheduler.running:
            return _scheduler
        sched = BackgroundScheduler(timezone="UTC", daemon=True)
        sched.add_job(
            _tick,
            "interval",
            minutes=interval_minutes,
            id="recon-scan-dispatcher",
            max_instances=1,
            coalesce=True,
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        sched.start()
        _scheduler = sched
        log.info("scheduler started (tick every %s min)", interval_minutes)
        return sched


def shutdown() -> None:
    global _scheduler
    with _lock:
        if _scheduler is not None and _scheduler.running:
            _scheduler.shutdown(wait=False)
        _scheduler = None


def status() -> dict:
    if _scheduler is None or not _scheduler.running:
        return {"running": False, "jobs": []}
    jobs = [
        {
            "id": job.id,
            "next_run": job.next_run_time.strftime("%Y-%m-%d %H:%M") if job.next_run_time else "-",
        }
        for job in _scheduler.get_jobs()
    ]
    return {"running": True, "jobs": jobs}
