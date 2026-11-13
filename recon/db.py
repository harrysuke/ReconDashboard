"""Database plumbing.

The dashboard touches SQLite from three contexts: Reflex event handlers, the
APScheduler worker thread and the scanner's async tasks. Peewee keeps one
connection per thread, WAL allows concurrent readers, and ``session_scope``
wraps a unit of work in a transaction (nesting is handled with savepoints).
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from recon.models import ALL_MODELS, PRAGMAS, Setting, db, utcnow

DATA_DIR = Path(os.environ.get("RECON_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "recon.db"

_lock = threading.Lock()
_initialised = False


def init_db() -> None:
    """Bind the database file and create tables (idempotent)."""
    global _initialised
    with _lock:
        if _initialised:
            return
        db.init(DB_PATH.as_posix(), pragmas=PRAGMAS)
        db.connect(reuse_if_open=True)
        db.create_tables(ALL_MODELS, safe=True)
        _initialised = True

    defaults = {
        "default_mode": os.environ.get("RECON_DEFAULT_MODE", "live"),
        "shodan_api_key": os.environ.get("SHODAN_API_KEY", ""),
        "nvd_api_key": os.environ.get("NVD_API_KEY", ""),
        "max_hosts": "64",
        "probe_enabled": "1",
    }
    with session_scope():
        for key, value in defaults.items():
            Setting.insert(key=key, value=value).on_conflict_ignore().execute()


@contextmanager
def session_scope() -> Iterator[None]:
    """Transaction scope. Commits on success, rolls back on exception."""
    if not db.is_closed():
        pass
    with db.atomic():
        yield


def get_setting(key: str, default: str = "") -> str:
    init_db()
    row = Setting.get_or_none(Setting.key == key)
    return row.value if row and row.value else default


def set_setting(key: str, value: str) -> None:
    init_db()
    (Setting.insert(key=key, value=value)
     .on_conflict(conflict_target=[Setting.key], update={Setting.value: value})
     .execute())


def reset_database() -> None:
    """Drop and recreate every table (used by the Settings page)."""
    init_db()
    with session_scope():
        db.drop_tables(ALL_MODELS, safe=True)
    db.create_tables(ALL_MODELS, safe=True)
    defaults = {"default_mode": "live", "shodan_api_key": "", "nvd_api_key": "",
                "max_hosts": "64", "probe_enabled": "1"}
    with session_scope():
        for key, value in defaults.items():
            Setting.insert(key=key, value=value).on_conflict_ignore().execute()


def db_stats() -> dict:
    init_db()
    from recon.models import Asset, AssetVulnerability, ChangeEvent, ScanRun, Target, Vulnerability

    return {
        "targets": Target.select().count(),
        "scans": ScanRun.select().count(),
        "assets": Asset.select().where(Asset.is_active == True).count(),  # noqa: E712
        "cves": Vulnerability.select().count(),
        "findings": AssetVulnerability.select().count(),
        "events": ChangeEvent.select().count(),
        "size_kb": round(DB_PATH.stat().st_size / 1024, 1) if DB_PATH.exists() else 0,
        "path": str(DB_PATH),
    }


__all__ = [
    "DATA_DIR", "DB_PATH", "db", "db_stats", "get_setting", "init_db",
    "reset_database", "session_scope", "set_setting", "utcnow",
]
