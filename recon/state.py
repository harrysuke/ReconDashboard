"""Application state.

One state class keeps the whole dashboard coherent: page loaders write their
data into fields, filters re-run the relevant query, and the background scan
handler polls the ``scan_runs`` row to animate the progress bar.

Notes
-----
* Background event handlers must mutate state inside ``async with self`` to take
  the state lock; that is also what pushes updates to the browser.
* Plotly figures are stored as plain JSON dicts (``json.loads(fig.to_json())``)
  so they survive state serialisation without numpy types.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date, datetime, timedelta
from pathlib import Path

import plotly.graph_objects as go
import reflex as rx

from recon import queries
from recon.db import (
    db_stats,
    get_setting,
    init_db,
    reset_database,
    session_scope,
    set_setting,
)
from recon.models import Asset, ChangeEvent, ScanRun, Target, Vulnerability
from recon.services import scheduler, scanner
from recon.services.report import build_portfolio_report, build_report

SEV_COLORS = queries.SEVERITY_COLORS
INK = "#0f172a"
MUTED = "#64748b"
GRID = "#e2e8f0"
SERIES = ["#1d4ed8", "#0891b2", "#7c3aed", "#db2777", "#059669"]


def _fig(figure: go.Figure) -> dict:
    """Plotly figure -> plain JSON dict (state-safe)."""
    return json.loads(figure.to_json())


def _base_layout(height: int = 260, **kwargs) -> dict:
    layout = dict(
        height=height,
        margin=dict(l=8, r=8, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, ui-sans-serif, system-ui", size=11, color=MUTED),
        hoverlabel=dict(bgcolor="white", bordercolor=GRID, font=dict(color=INK, size=11)),
    )
    layout.update(kwargs)
    return layout


class AppState(rx.State):
    # ---------------------------------------------------------------- data
    kpis: dict = {}
    sev_counts: dict = {}
    growth: list[dict] = []
    changes: list[dict] = []
    top_assets: list[dict] = []
    targets: list[dict] = []
    target_options: list[dict] = []
    assets: list[dict] = []
    findings: list[dict] = []
    scans: list[dict] = []
    recent_cves: list[dict] = []

    # ------------------------------------------------------------- figures
    sev_fig: dict = {}
    growth_fig: dict = {}
    services_fig: dict = {}
    has_services: bool = False

    # ------------------------------------------------------------- filters
    asset_target: str = "all"
    asset_search: str = ""
    asset_only_new: bool = False
    vuln_severity: str = "all"
    vuln_search: str = ""
    vuln_target: str = "all"
    scan_filter: str = "all"

    # -------------------------------------------------------- target form
    new_target: str = ""
    new_label: str = ""
    new_schedule: str = "weekly"
    form_error: str = ""
    show_target_dialog: bool = False

    # ------------------------------------------------------ scan progress
    scanning: bool = False
    active_scan_id: int = 0
    scan_progress: int = 0
    scan_stage: str = ""
    scan_message: str = ""
    scan_target_label: str = ""
    scan_status: str = "idle"

    # ------------------------------------------------------------ settings
    shodan_key: str = ""
    nvd_key: str = ""
    default_mode: str = "live"
    probe_enabled: bool = True
    max_hosts: str = "64"
    settings_saved: bool = False
    scheduler_running: bool = False
    scheduler_jobs: list[dict] = []
    db_info: dict = {}

    # --------------------------------------------------------------- misc
    toast_message: str = ""
    toast_kind: str = "info"
    booted: bool = False
    booting: bool = False
    last_refresh: str = ""

    # ------------------------------------------------------------ computed
    @rx.var
    def asset_target_id(self) -> int:
        return 0 if self.asset_target == "all" else int(self.asset_target)

    @rx.var
    def vuln_target_id(self) -> int:
        return 0 if self.vuln_target == "all" else int(self.vuln_target)

    @rx.var
    def has_targets(self) -> bool:
        return len(self.target_options) > 0

    @rx.var
    def primary_target_id(self) -> int:
        return int(self.target_options[0]["value"]) if self.target_options else 0

    @rx.var
    def primary_target_label(self) -> str:
        return self.target_options[0]["label"] if self.target_options else "no target"

    @rx.var
    def scan_pct_label(self) -> str:
        return f"{self.scan_progress}%"

    @rx.var
    def score_color(self) -> str:
        score = float(self.kpis.get("score", 0) or 0)
        if score >= 70:
            return "#dc2626"
        if score >= 40:
            return "#ea580c"
        return "#059669"

    # ------------------------------------------------------------- helpers
    def _refresh_data(self) -> None:
        """Recompute every read model. Call inside the state lock."""
        self.kpis = queries.dashboard_kpis()
        self.sev_counts = queries.severity_distribution()
        self.growth = queries.asset_growth()
        self.changes = queries.recent_changes(limit=6)
        self.top_assets = queries.top_exposed_assets()
        self.targets = queries.list_targets()
        self.target_options = queries.target_options()
        self.assets = queries.list_assets(
            target_id=self._asset_pid(),
            search=self.asset_search,
            only_new=self.asset_only_new,
        )
        self.findings = queries.list_findings(
            severity=self.vuln_severity,
            search=self.vuln_search,
            target_id=self._vuln_pid(),
        )
        self.scans = queries.list_scans()
        self.recent_cves = queries.list_findings(limit=120)
        self.sev_fig = self._build_severity_figure()
        self.growth_fig = self._build_growth_figure()
        self.services_fig = self._build_services_figure()

    def _asset_pid(self) -> int | None:
        return None if self.asset_target == "all" else int(self.asset_target)

    def _vuln_pid(self) -> int | None:
        return None if self.vuln_target == "all" else int(self.vuln_target)

    def _toast(self, message: str, kind: str = "info") -> None:
        self.toast_message = message
        self.toast_kind = kind

    # -------------------------------------------------------------- charts
    def _build_severity_figure(self) -> dict:
        labels = ["Critical", "High", "Medium", "Low"]
        keys = ["critical", "high", "medium", "low"]
        values = [int(self.sev_counts.get(k, 0) or 0) for k in keys]
        colors = [SEV_COLORS["critical"], SEV_COLORS["high"], SEV_COLORS["medium"], SEV_COLORS["low"]]
        total = sum(values)
        if total == 0:
            fig = go.Figure(go.Pie(labels=["No findings"], values=[1], hole=0.68,
                                   marker_colors=["#e2e8f0"], textinfo="none", hoverinfo="skip"))
        else:
            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.68, sort=False,
                marker=dict(colors=colors, line=dict(color="white", width=2)),
                textinfo="none",
                hovertemplate="%{label}: %{value} CVEs<extra></extra>",
            ))
        fig.update_layout(**_base_layout(
            height=158,
            margin=dict(l=0, r=0, t=0, b=0),
            showlegend=False,
            annotations=[
                dict(text=f"<b>{total}</b>", x=0.5, y=0.56, showarrow=False,
                     font=dict(size=23, color=INK)),
                dict(text="distinct CVEs", x=0.5, y=0.36, showarrow=False,
                     font=dict(size=9.5, color=MUTED)),
            ],
        ))
        return _fig(fig)

    def _build_growth_figure(self) -> dict:
        fig = go.Figure()
        if not self.growth:
            fig.add_annotation(text="No scan history yet", showarrow=False,
                               font=dict(size=12, color=MUTED), x=0.5, y=0.5)
        for idx, series in enumerate(self.growth[:5]):
            points = series.get("points") or []
            if not points:
                continue
            color = SERIES[idx % len(SERIES)]
            fig.add_trace(go.Scatter(
                x=[p["date"] for p in points],
                y=[p["assets"] for p in points],
                name=series["name"],
                mode="lines+markers",
                line=dict(color=color, width=2.4, shape="spline", smoothing=0.6),
                marker=dict(size=6, color="white", line=dict(color=color, width=2)),
                fill="tozeroy" if idx == 0 else None,
                fillcolor="rgba(29,78,216,0.07)" if idx == 0 else None,
                hovertemplate="%{y} exposed services<extra></extra>",
                # The first and last points sit exactly on the axis edges; without
                # this their markers are sliced in half by the plot clip rect.
                cliponaxis=False,
            ))
        xaxis = dict(showgrid=False, zeroline=False, tickfont=dict(size=10),
                     linecolor=GRID, ticks="outside", tickcolor=GRID)
        # Pad the date axis so the outermost tick labels are not pinned to the
        # plot border (Plotly adds no padding of its own for date axes here).
        days = sorted({p["date"] for s in self.growth for p in (s.get("points") or [])})
        if len(days) > 1:
            try:
                first = date.fromisoformat(days[0])
                last = date.fromisoformat(days[-1])
                pad = max(1, int((last - first).days * 0.04))
                xaxis["range"] = [(first - timedelta(days=pad)).isoformat(),
                                  (last + timedelta(days=pad)).isoformat()]
            except ValueError:
                pass
        fig.update_layout(**_base_layout(
            height=260,
            showlegend=len(self.growth) > 1,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, font=dict(size=10)),
            xaxis=xaxis,
            yaxis=dict(showgrid=True, gridcolor="#f1f5f9", zeroline=False,
                       tickfont=dict(size=10), rangemode="tozero"),
            hovermode="x unified",
        ))
        return _fig(fig)

    def _build_services_figure(self) -> dict:
        rows = queries.top_exposed_assets(limit=6)
        rows = [r for r in rows if r["findings"] > 0]
        self.has_services = bool(rows)
        fig = go.Figure()
        if not rows:
            fig.add_annotation(text="No findings yet", showarrow=False,
                               font=dict(size=12, color=MUTED), x=0.5, y=0.5)
        else:
            rows = list(reversed(rows))
            fig.add_trace(go.Bar(
                x=[r["findings"] for r in rows],
                y=[_endpoint_label(r) for r in rows],
                orientation="h",
                marker=dict(color=[SEVERITY_COLORS_BY_SCORE(r["max_cvss"]) for r in rows],
                            line=dict(width=0)),
                hovertemplate="%{y}: %{x} CVE(s)<extra></extra>",
                text=[r["findings"] for r in rows],
                textposition="outside",
                textfont=dict(size=10, color=MUTED),
                width=0.55,
            ))
        max_findings = max((r["findings"] for r in rows), default=1)
        fig.update_layout(**_base_layout(
            height=262,
            margin=dict(l=6, r=28, t=8, b=4),
            showlegend=False,
            xaxis=dict(showgrid=True, gridcolor="#f1f5f9", zeroline=False,
                       tickfont=dict(size=9.5), title=None, showticklabels=False,
                       dtick=1, range=[0, max_findings + 0.7]),
            yaxis=dict(showgrid=False, zeroline=False, tickfont=dict(size=10.5),
                       automargin=True, ticks=""),
        ))
        return _fig(fig)

    # ------------------------------------------------------------- loaders
    @rx.event
    async def load_dashboard(self):
        init_db()
        scheduler.start()
        # Seed the sample estate on a database that has never held a target.
        # The flag (rather than an in-memory "booted" bool) means a database
        # reset re-seeds, while a user who deliberately deletes their last
        # target is left alone - their intent survives a page reload.
        if Target.select().count() == 0 and get_setting("demo_seeded", "") != "1":
            self.booting = True
            await self._bootstrap_demo()
            self.booting = False
            set_setting("demo_seeded", "1")
        self._refresh_data()
        self.last_refresh = datetime.now().strftime("%H:%M:%S")
        self.booted = True

    @rx.event
    def load_targets(self):
        init_db()
        self._refresh_data()

    @rx.event
    def load_assets(self):
        init_db()
        self.assets = queries.list_assets(
            target_id=self._asset_pid(),
            search=self.asset_search,
            only_new=self.asset_only_new,
        )
        self.target_options = queries.target_options()

    @rx.event
    def load_vulns(self):
        init_db()
        self.findings = queries.list_findings(
            severity=self.vuln_severity,
            search=self.vuln_search,
            target_id=self._vuln_pid(),
        )
        self.target_options = queries.target_options()
        self.sev_counts = queries.severity_distribution()
        self.sev_fig = self._build_severity_figure()

    @rx.event
    def load_scans(self):
        init_db()
        self.scans = queries.list_scans()

    @rx.event
    def load_settings(self):
        init_db()
        self.shodan_key = get_setting("shodan_api_key", "")
        self.nvd_key = get_setting("nvd_api_key", "")
        self.default_mode = get_setting("default_mode", "live")
        self.probe_enabled = get_setting("probe_enabled", "1") == "1"
        self.max_hosts = get_setting("max_hosts", "64")
        info = scheduler.status()
        self.scheduler_running = bool(info.get("running"))
        self.scheduler_jobs = info.get("jobs", [])
        self.db_info = db_stats()

    async def _bootstrap_demo(self) -> None:
        """First run: create a demo target with a backdated scan history."""
        with session_scope():
            target = Target.create(
                label="Demo Corp",
                kind="domain",
                value="demo.example.com",
                schedule="weekly",
                mode="demo",
                notes="Sample estate generated in demo mode - safe to delete.",
            )
            target_id = target.id
        await scanner.seed_demo_history(target_id, scans=6, interval_days=7)

    # ------------------------------------------------------------- filters
    @rx.event
    def set_asset_target(self, value: str):
        self.asset_target = value
        self.load_assets()

    @rx.event
    def set_asset_search(self, value: str):
        self.asset_search = value
        self.load_assets()

    @rx.event
    def toggle_asset_new(self):
        self.asset_only_new = not self.asset_only_new
        self.load_assets()

    @rx.event
    def set_vuln_severity(self, value: str):
        self.vuln_severity = value
        self.load_vulns()

    @rx.event
    def set_vuln_search(self, value: str):
        self.vuln_search = value
        self.load_vulns()

    @rx.event
    def set_vuln_target(self, value: str):
        self.vuln_target = value
        self.load_vulns()

    # ------------------------------------------------------------- targets
    @rx.event
    def set_new_target(self, value: str):
        self.new_target = value
        self.form_error = ""

    @rx.event
    def set_new_label(self, value: str):
        self.new_label = value

    @rx.event
    def set_new_schedule(self, value: str):
        self.new_schedule = value

    @rx.event
    def toggle_target_dialog(self):
        self.show_target_dialog = not self.show_target_dialog
        self.form_error = ""

    @rx.event
    def add_target(self):
        init_db()
        raw = (self.new_target or "").strip().lower()
        raw = re.sub(r"^https?://", "", raw).strip("/")
        if not raw:
            self.form_error = "Enter a domain, IP or CIDR range."
            return
        if _looks_like_cidr(raw):
            kind = "cidr"
        elif _looks_like_ip(raw):
            kind = "ip"
        elif _looks_like_domain(raw):
            kind = "domain"
        else:
            self.form_error = "That does not look like a domain, IP or CIDR range."
            return
        if Target.get_or_none(Target.value == raw) is not None:
            self.form_error = "This scope is already being monitored."
            return
        with session_scope():
            Target.create(
                label=(self.new_label or "").strip() or raw,
                kind=kind,
                value=raw,
                schedule=self.new_schedule or "manual",
                mode="demo" if _is_reserved(raw) else "live",
                notes="",
            )
        self.new_target = ""
        self.new_label = ""
        self.show_target_dialog = False
        self._refresh_data()
        self._toast(f"Now monitoring {raw}", "success")

    @rx.event
    def delete_target(self, target_id: int):
        with session_scope():
            ChangeEvent.delete().where(ChangeEvent.target == target_id).execute()
            Target.delete().where(Target.id == target_id).execute()
        self._refresh_data()
        self._toast("Target removed", "info")

    @rx.event
    def set_target_schedule(self, target_id: int, value: str):
        with session_scope():
            Target.update(schedule=value).where(Target.id == target_id).execute()
        self._refresh_data()

    @rx.event
    def toggle_target_enabled(self, target_id: int):
        target = Target.get_or_none(Target.id == target_id)
        if target is None:
            return
        with session_scope():
            Target.update(enabled=not target.enabled).where(Target.id == target_id).execute()
        self._refresh_data()

    # ---------------------------------------------------------------- scan
    @rx.event(background=True)
    async def start_scan(self, target_id: int):
        init_db()
        target = Target.get_or_none(Target.id == target_id)
        if target is None:
            return
        busy = (ScanRun.select()
                .where(ScanRun.target_id == target_id,
                       ScanRun.status.in_(("queued", "running")))
                .first())
        if busy is not None:
            async with self:
                self._toast("A scan is already running for this target", "warning")
            return

        # The target's own mode wins over the global default, so demo scopes are
        # always replayed from the synthetic generator instead of being probed.
        run_mode = (target.mode or "").strip() or get_setting("default_mode", "live")
        with session_scope():
            scan = ScanRun.create(
                target=target_id, mode=run_mode, trigger="manual",
                status="running", stage="queued", progress=2, message="Scan started",
            )
            scan_id = scan.id

        async with self:
            self.scanning = True
            self.active_scan_id = scan_id
            self.scan_target_label = target.display
            self.scan_progress = 2
            self.scan_stage = "queued"
            self.scan_message = "Scan started"
            self.scan_status = "running"

        task = asyncio.create_task(scanner.run_scan(target_id, mode=run_mode, scan_id=scan_id))
        while not task.done():
            await asyncio.sleep(0.35)
            state = queries.scan_status(scan_id)
            async with self:
                self.scan_progress = int(state["progress"] or 0)
                self.scan_stage = state["stage"]
                self.scan_message = state["message"]

        await task
        state = queries.scan_status(scan_id)
        async with self:
            self.scanning = False
            self.scan_progress = int(state["progress"] or 0)
            self.scan_stage = state["stage"]
            self.scan_message = state["message"]
            self.scan_status = state["status"]
            self._refresh_data()
            if state["status"] == "success":
                self._toast(f"Scan finished for {target.display}", "success")
            else:
                self._toast(f"Scan failed: {state['message']}", "error")

    @rx.event
    async def seed_demo(self):
        init_db()
        target = Target.get_or_none(Target.value == "demo.example.com")
        if target is None:
            with session_scope():
                target = Target.create(label="Demo Corp", kind="domain",
                                       value="demo.example.com", schedule="weekly",
                                       mode="demo",
                                       notes="Sample estate generated in demo mode.")
        await scanner.seed_demo_history(target.id, scans=6, interval_days=7)
        self._refresh_data()
        self._toast("Demo history generated", "success")

    @rx.event
    def clear_toast(self):
        self.toast_message = ""

    # ------------------------------------------------------------- reports
    @rx.event
    def export_scan_pdf(self, scan_id: int):
        init_db()
        try:
            path = build_report(scan_id)
        except Exception as exc:  # noqa: BLE001
            self._toast(f"Report failed: {exc}", "error")
            return
        self._toast(f"Report ready: {path.name}", "success")
        return rx.download(data=path.read_bytes(), filename=path.name,
                           mime_type="application/pdf")

    @rx.event
    def export_portfolio_pdf(self):
        init_db()
        try:
            path = build_portfolio_report()
        except Exception as exc:  # noqa: BLE001
            self._toast(f"Report failed: {exc}", "error")
            return
        return rx.download(data=path.read_bytes(), filename=path.name,
                           mime_type="application/pdf")

    # ------------------------------------------------------------ settings
    @rx.event
    def set_shodan_key(self, value: str):
        self.shodan_key = value
        self.settings_saved = False

    @rx.event
    def set_nvd_key(self, value: str):
        self.nvd_key = value
        self.settings_saved = False

    @rx.event
    def set_default_mode(self, value: str):
        self.default_mode = value
        self.settings_saved = False

    @rx.event
    def toggle_probe(self):
        self.probe_enabled = not self.probe_enabled
        self.settings_saved = False

    @rx.event
    def set_probe_enabled(self, value: bool):
        self.probe_enabled = bool(value)
        self.settings_saved = False

    @rx.event
    def set_max_hosts(self, value: str):
        self.max_hosts = value
        self.settings_saved = False

    @rx.event
    def save_settings(self):
        set_setting("shodan_api_key", (self.shodan_key or "").strip())
        set_setting("nvd_api_key", (self.nvd_key or "").strip())
        set_setting("default_mode", self.default_mode)
        set_setting("probe_enabled", "1" if self.probe_enabled else "0")
        try:
            hosts = max(1, min(1024, int(self.max_hosts or 64)))
        except ValueError:
            hosts = 64
        set_setting("max_hosts", str(hosts))
        self.max_hosts = str(hosts)
        self.settings_saved = True
        self.db_info = db_stats()
        self._toast("Settings saved", "success")

    @rx.event
    def reset_all(self):
        reset_database()
        self.booted = False
        self._refresh_data()
        self.db_info = db_stats()
        self._toast("Database reset", "warning")

    @rx.event
    def refresh_scheduler(self):
        info = scheduler.status()
        self.scheduler_running = bool(info.get("running"))
        self.scheduler_jobs = info.get("jobs", [])
        self.db_info = db_stats()


# --------------------------------------------------------------------------- #
# helpers used by the state
# --------------------------------------------------------------------------- #
def _endpoint_label(row: dict) -> str:
    """Compact axis label for an asset: host (or last octet) + port.

    ``service:port`` repeats itself when several hosts expose the same port, so
    the chart would show three identical ``http:8080`` rows. The hostname's
    first label identifies the endpoint far better and stays short enough for a
    narrow card.
    """
    ip, _, port = row["endpoint"].rpartition(":")
    host = (row.get("host") or "").strip()
    if not host or host == ip:
        host = ip.rsplit(".", 1)[-1] if "." in ip else ip
    else:
        host = host.split(".")[0]
    return f"{host}:{port}"


def SEVERITY_COLORS_BY_SCORE(cvss: float) -> str:  # noqa: N802 - used as a palette helper
    if cvss >= 9:
        return SEV_COLORS["critical"]
    if cvss >= 7:
        return SEV_COLORS["high"]
    if cvss >= 4:
        return SEV_COLORS["medium"]
    return SEV_COLORS["low"]


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _looks_like_ip(value: str) -> bool:
    return bool(_IP_RE.match(value)) and all(0 <= int(p) <= 255 for p in value.split("."))


def _looks_like_cidr(value: str) -> bool:
    if not _CIDR_RE.match(value):
        return False
    addr, bits = value.split("/")
    return all(0 <= int(p) <= 255 for p in addr.split(".")) and 0 <= int(bits) <= 32


def _looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


# RFC 2606 / RFC 6761 reserved names never resolve on the public internet, so a
# live pass against them can only ever return nothing. Treat them as demo scopes.
_RESERVED_SUFFIXES = (
    ".example", ".example.com", ".example.net", ".example.org",
    ".test", ".invalid", ".localhost", ".local",
)


def _is_reserved(value: str) -> bool:
    host = value.split(":")[0].strip(".")
    return any(host == s.lstrip(".") or host.endswith(s) for s in _RESERVED_SUFFIXES)
