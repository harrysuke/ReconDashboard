"""Overview page: estate KPIs, severity mix, growth trend, change feed."""

from __future__ import annotations

import plotly.graph_objects as go
import reflex as rx

from recon.components.layout import shell
from recon.components.theme import (
    ACCENT,
    BORDER,
    BORDER_SOFT,
    CRIT,
    FAINT,
    HIGH,
    INK,
    INK_SOFT,
    LOW,
    MED,
    MUTED,
    card,
    empty_state,
    ghost_button,
    kpi_card,
    mono,
    page_header,
    primary_button,
    sev_dot,
    severity_pill,
    table_shell,
    td,
    th,
)
from recon.state import AppState


def _kpis() -> rx.Component:
    return rx.grid(
        kpi_card("Active services", AppState.kpis["assets"].to_string(),
                 "reachable ip:port pairs", "server", ACCENT, "#eef2ff"),
        kpi_card("New this scan", AppState.kpis["new_assets"].to_string(),
                 "assets first seen in latest scan", "sparkles", HIGH, "#fff7ed"),
        kpi_card("Distinct CVEs", AppState.kpis["cves"].to_string(),
                 "correlated from NVD / CIRCL", "bug", INK_SOFT, "#f1f5f9"),
        kpi_card("Critical", AppState.kpis["critical"].to_string(),
                 "CVSS 9.0 and above", "shield-alert", CRIT, "#fef2f2"),
        kpi_card("Exposure score", AppState.kpis["score"].to_string(),
                 "weighted by severity per asset", "gauge", AppState.score_color, "#f8fafc"),
        columns="repeat(auto-fit, minmax(178px, 1fr))",
        spacing="3",
        width="100%",
    )


def _severity_card() -> rx.Component:
    legend = [
        ("critical", "Critical", CRIT),
        ("high", "High", HIGH),
        ("medium", "Medium", MED),
        ("low", "Low", LOW),
    ]
    return card(
        rx.text("Severity mix", font_size="13px", font_weight="600", color=INK),
        rx.text("distinct CVEs on live assets", font_size="11px", color=MUTED, margin_top="2px"),
        rx.box(
            rx.plotly(data=AppState.sev_fig.to(go.Figure),
                      config={"displayModeBar": False, "responsive": True}),
            width="100%",
            margin_top="2px",
        ),
        rx.vstack(
            *[
                rx.hstack(
                    rx.box(width="7px", height="7px", border_radius="2px", bg=color),
                    rx.text(label, font_size="11px", color=MUTED),
                    rx.spacer(),
                    rx.text(AppState.sev_counts[key].to_string(), font_size="11px",
                            color=INK, font_weight="600", font_family="ui-monospace"),
                    width="100%",
                    align="center",
                    spacing="2",
                )
                for key, label, color in legend
            ],
            spacing="1",
            width="100%",
            margin_top="6px",
        ),
        height="100%",
    )


def _growth_card() -> rx.Component:
    return card(
        rx.hstack(
            rx.vstack(
                rx.text("Asset growth", font_size="13px", font_weight="600", color=INK),
                rx.text("exposed services per scan, from stored history",
                        font_size="11px", color=MUTED),
                spacing="0",
                gap="2px",
                align="start",
            ),
            rx.spacer(),
            rx.hstack(
                rx.box(width="6px", height="6px", border_radius="50%", bg=ACCENT),
                rx.text("services", font_size="10.5px", color=MUTED),
                spacing="2",
                align="center",
            ),
            width="100%",
            align="start",
        ),
        rx.box(
            rx.plotly(data=AppState.growth_fig.to(go.Figure),
                      config={"displayModeBar": False, "responsive": True}),
            width="100%",
            margin_top="8px",
        ),
        height="100%",
    )


def _services_card() -> rx.Component:
    return card(
        rx.text("Most exposed services", font_size="13px", font_weight="600", color=INK),
        rx.text("CVE count per endpoint", font_size="11px", color=MUTED, margin_top="2px"),
        rx.box(
            rx.plotly(data=AppState.services_fig.to(go.Figure),
                      config={"displayModeBar": False, "responsive": True}),
            width="100%",
            margin_top="8px",
        ),
        height="100%",
    )


def _change_row(item: dict) -> rx.Component:
    return rx.hstack(
        rx.box(
            sev_dot(item["severity"]),
            bg="#fbfcfd",
            border=f"1px solid {BORDER_SOFT}",
            border_radius="7px",
            padding="7px",
            display="flex",
            align_items="center",
            justify_content="center",
            min_width="23px",
        ),
        rx.vstack(
            rx.text(item["title"], font_size="11.8px", color=INK, font_weight="500",
                    line_height="1.45"),
            rx.hstack(
                rx.text(item["target"], font_size="10.5px", color=MUTED),
                rx.text("·", font_size="10px", color=FAINT),
                rx.text(item["when"], font_size="10.5px", color=FAINT),
                rx.text("·", font_size="10px", color=FAINT),
                rx.text(item["kind"], font_size="10.5px", color=FAINT,
                        text_transform="capitalize"),
                spacing="1",
                align="center",
            ),
            spacing="0",
            gap="2px",
            align="start",
        ),
        width="100%",
        align="start",
        spacing="3",
        padding="8px 2px",
        border_bottom=f"1px solid {BORDER_SOFT}",
    )


def _changes_card() -> rx.Component:
    return card(
        rx.hstack(
            rx.vstack(
                rx.text("Change feed", font_size="13px", font_weight="600", color=INK),
                rx.text("new exposures, closures and fresh CVEs", font_size="11px", color=MUTED),
                spacing="0",
                gap="2px",
                align="start",
            ),
            rx.spacer(),
            rx.text(AppState.kpis["changes_7d"].to_string() + " events / 7d",
                    font_size="10.5px", color=MUTED, font_family="ui-monospace"),
            width="100%",
            align="start",
        ),
        rx.cond(
            AppState.changes.length() > 0,
            rx.vstack(
                rx.foreach(AppState.changes, _change_row),
                spacing="0",
                width="100%",
                max_height="330px",
                overflow_y="auto",
                margin_top="8px",
            ),
            empty_state("No changes yet", "Run a scan to populate the diff feed."),
        ),
        height="100%",
    )


def _asset_row(a: dict) -> rx.Component:
    return rx.table.row(
        td(
            rx.hstack(
                rx.text(a["endpoint"], font_family="ui-monospace", font_size="11.5px",
                        color=INK, font_weight="500"),
                rx.cond(
                    a["is_new"],
                    rx.box(rx.text("NEW", font_size="8.5px", font_weight="700", color=ACCENT),
                           bg="#eef2ff", border_radius="4px", padding="2px 4px"),
                    rx.fragment(),
                ),
                spacing="2",
                align="center",
            )
        ),
        td(rx.text(a["host"], font_size="11.5px", color=INK_SOFT)),
        td(rx.text(a["service"], font_size="11.5px", color=MUTED)),
        td(rx.text(a["product"], font_size="11.5px", color=INK_SOFT)),
        td(rx.text(a["findings"].to_string(), font_size="11.5px", font_family="ui-monospace",
                   color=INK)),
        td(severity_pill(a["severity"])),
        td(rx.text(a["max_cvss"].to_string(), font_size="11.5px", font_family="ui-monospace",
                   color=MUTED)),
    )


def _top_assets_card() -> rx.Component:
    return card(
        rx.hstack(
            rx.vstack(
                rx.text("Highest-risk endpoints", font_size="13px", font_weight="600", color=INK),
                rx.text("ranked by worst CVSS base score", font_size="11px", color=MUTED),
                spacing="0",
                gap="2px",
                align="start",
            ),
            rx.spacer(),
            rx.link(
                rx.hstack(
                    rx.text("All assets", font_size="11px", color=ACCENT, font_weight="500"),
                    rx.icon("arrow-right", size=12, color=ACCENT),
                    spacing="1",
                    align="center",
                ),
                href="/assets",
                underline="none",
            ),
            width="100%",
            align="center",
            margin_bottom="10px",
        ),
        rx.cond(
            AppState.top_assets.length() > 0,
            table_shell(
                rx.table.header(
                    rx.table.row(
                        th("Endpoint", width="170px"),
                        th("Host"),
                        th("Service", width="90px"),
                        th("Product"),
                        th("CVEs", width="60px"),
                        th("Worst", width="90px"),
                        th("Max CVSS", width="80px"),
                    )
                ),
                rx.table.body(rx.foreach(AppState.top_assets, _asset_row)),
            ),
            empty_state("Nothing exposed yet", "Add a target and run your first scan."),
        ),
    )


def dashboard_page() -> rx.Component:
    return shell(
        page_header(
            "Exposure overview",
            "Passive OSINT, service fingerprinting and CVE correlation across every monitored scope.",
            rx.hstack(
                ghost_button("Refresh", "refresh-cw", AppState.load_dashboard),
                ghost_button("Estate PDF", "file-down", AppState.export_portfolio_pdf),
                primary_button("Run scan", "radar", AppState.start_scan(AppState.primary_target_id)),
                spacing="2",
            ),
        ),
        _kpis(),
        rx.grid(
            rx.box(_severity_card(), grid_column="span 4"),
            rx.box(_growth_card(), grid_column="span 8"),
            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
        ),
        rx.grid(
            rx.box(_services_card(), grid_column="span 4"),
            rx.box(_changes_card(), grid_column="span 8"),
            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
        ),
        _top_assets_card(),
    )
