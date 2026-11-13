"""Install the granian compatibility shim into the active virtualenv.

Reflex imports ``granian`` for log filtering, and its compiled extension is
blocked by the application-control policy on some Windows hosts. Installing
``sitecustomize.py`` into site-packages makes every interpreter start in this
virtualenv tolerate that, so the app can be served by uvicorn instead.

    python -m scripts.fix_granian_shim

Idempotent; safe to re-run after recreating the venv.
"""

from __future__ import annotations

import shutil
import sys
import sysconfig
from pathlib import Path

SOURCE = Path(__file__).with_name("sitecustomize_shim.py")


def main() -> None:
    target_dir = Path(sysconfig.get_paths()["purelib"])
    target = target_dir / "sitecustomize.py"
    if not SOURCE.exists():
        raise SystemExit(f"shim source missing: {SOURCE}")

    if target.exists() and "granian" not in target.read_text(encoding="utf-8", errors="ignore"):
        backup = target.with_suffix(".py.bak")
        shutil.copy2(target, backup)
        print(f"existing sitecustomize.py backed up to {backup.name}")

    shutil.copy2(SOURCE, target)
    print(f"installed shim -> {target}")
    print("start the app with:  REFLEX_USE_GRANIAN=0 python -m reflex run")


if __name__ == "__main__":
    main()
