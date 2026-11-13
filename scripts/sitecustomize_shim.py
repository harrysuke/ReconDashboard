"""Interpreter-startup shim for locked-down Windows hosts.

Reflex imports ``granian`` while building log frame filters, and Reflex's own
default ASGI server is granian. On this machine an application-control policy
blocks granian's compiled extension::

    ImportError: DLL load failed while importing _granian:
    An Application Control policy has blocked this file.

That is fatal for *any* import of ``granian``, even when the backend is served
by uvicorn instead (``REFLEX_USE_GRANIAN=0``).

This module is copied to ``<venv>/Lib/site-packages/sitecustomize.py`` so it is
imported automatically at interpreter start. It replaces an unimportable
``granian`` with a stub, which is only ever used for version/path introspection.

Run ``python -m scripts.fix_granian_shim`` to install it.
"""

from __future__ import annotations

import sys
import types


def install() -> bool:
    """Return True if a stub had to be installed."""
    try:
        import granian  # noqa: F401

        return False
    except Exception:  # noqa: BLE001 - any failure means the module is unusable
        stub = types.ModuleType("granian")
        stub.__version__ = "0.0.0+blocked"
        stub.__doc__ = "Stub: the real granian extension is blocked by host policy."
        # Reflex reads ``module.__file__`` when building log frame filters.
        stub.__file__ = __file__
        stub.__path__ = []  # behave like a package
        sys.modules["granian"] = stub
        return True


install()
