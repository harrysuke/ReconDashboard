"""Reflex app entry point: theme, routes, page titles."""

from __future__ import annotations

import threading

import reflex as rx

from recon.pages.assets import assets_page
from recon.pages.dashboard import dashboard_page
from recon.pages.scans import scans_page
from recon.pages.settings import settings_page
from recon.pages.targets import targets_page
from recon.pages.vulns import vulns_page
from recon.state import AppState


def _prewarm_plotly() -> None:
    """Parse plotly's 3 MB validator JSON off the event loop.

    plotly loads it lazily on the first ``Figure()``, which blocks whichever
    thread gets there first - normally the dashboard's load handler, stalling
    the first paint for ~0.4s. Doing it once in the background at import makes
    that cost invisible.
    """

    def run() -> None:
        try:
            import plotly.graph_objects as go

            go.Figure().to_json()
        except Exception:  # noqa: BLE001 - a cold cache is not worth failing over
            pass

    threading.Thread(target=run, name="plotly-prewarm", daemon=True).start()


_prewarm_plotly()

app = rx.App(
    style={
        "font_family": "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif",
        "color": "#0f172a",
        "background": "#f6f7f9",
    },
    # Plotly draws at its 700px default when the parent is still zero-width
    # during hydration; this re-fits every chart to its card.
    head_components=[rx.script(src="/plotly-fit.js")],
)

app.add_page(
    dashboard_page,
    route="/",
    title="Recon · Exposure overview",
    description="Automated OSINT and CVE reconnaissance dashboard.",
    on_load=AppState.load_dashboard,
)
app.add_page(
    targets_page,
    route="/targets",
    title="Recon · Targets",
    on_load=AppState.load_targets,
)
app.add_page(
    assets_page,
    route="/assets",
    title="Recon · Exposed assets",
    on_load=AppState.load_assets,
)
app.add_page(
    vulns_page,
    route="/vulnerabilities",
    title="Recon · Vulnerabilities",
    on_load=AppState.load_vulns,
)
app.add_page(
    scans_page,
    route="/scans",
    title="Recon · Scan history",
    on_load=AppState.load_scans,
)
app.add_page(
    settings_page,
    route="/settings",
    title="Recon · Settings",
    on_load=AppState.load_settings,
)
