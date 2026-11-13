"""Reflex app entry point: theme, routes, page titles."""

from __future__ import annotations

import reflex as rx

from recon.pages.assets import assets_page
from recon.pages.dashboard import dashboard_page
from recon.pages.scans import scans_page
from recon.pages.settings import settings_page
from recon.pages.targets import targets_page
from recon.pages.vulns import vulns_page
from recon.state import AppState

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
