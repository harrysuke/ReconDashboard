"""Vulnerabilities page: CVE findings per asset, filterable by severity."""

from __future__ import annotations

import reflex as rx

from recon.components.layout import shell
from recon.components.theme import (
    ACCENT,
    BORDER,
    CRIT,
    FAINT,
    INK,
    INK_SOFT,
    MUTED,
    card,
    empty_state,
    ghost_button,
    input_field,
    page_header,
    sev_dot,
    severity_pill,
    table_shell,
    td,
    th,
)
from recon.state import AppState

SEVERITIES = [
    {"value": "all", "label": "All severities"},
    {"value": "critical", "label": "Critical"},
    {"value": "high", "label": "High"},
    {"value": "medium", "label": "Medium"},
    {"value": "low", "label": "Low"},
]


def _chip(value: str, label: str, count) -> rx.Component:
    active = AppState.vuln_severity == value
    return rx.hstack(
        rx.text(label, font_size="11.5px",
                color=rx.cond(active, ACCENT, INK_SOFT),
                font_weight=rx.cond(active, "600", "500")),
        rx.text(count.to_string(), font_size="10.5px", font_family="ui-monospace",
                color=rx.cond(active, ACCENT, FAINT)),
        on_click=AppState.set_vuln_severity(value),
        cursor="pointer",
        spacing="2",
        align="center",
        height="30px",
        padding="0 11px",
        border_radius="8px",
        bg=rx.cond(active, "#eef2ff", "white"),
        border=rx.cond(active, f"1px solid {ACCENT}", f"1px solid {BORDER}"),
    )


def _filters() -> rx.Component:
    return card(
        rx.vstack(
            rx.hstack(
                _chip("all", "All", AppState.kpis["cves"]),
                _chip("critical", "Critical", AppState.sev_counts["critical"]),
                _chip("high", "High", AppState.sev_counts["high"]),
                _chip("medium", "Medium", AppState.sev_counts["medium"]),
                _chip("low", "Low", AppState.sev_counts["low"]),
                rx.spacer(),
                rx.select.root(
                    rx.select.trigger(font_size="12.5px", height="32px", border_radius="8px",
                                      border=f"1px solid {BORDER}", bg="white", width="180px"),
                    rx.select.content(
                        rx.select.group(
                            rx.select.item("All targets", value="all"),
                            rx.foreach(
                                AppState.target_options,
                                lambda o: rx.select.item(o["label"], value=o["value"]),
                            ),
                        )
                    ),
                    value=AppState.vuln_target,
                    on_change=AppState.set_vuln_target,
                ),
                input_field("Search CVE, product, host…", AppState.vuln_search,
                            AppState.set_vuln_search, icon="search", width="290px"),
                width="100%",
                align="center",
                spacing="2",
                wrap="wrap",
            ),
            width="100%",
            align="start",
        ),
        padding="12px 14px",
    )


def _row(f: dict) -> rx.Component:
    return rx.table.row(
        td(
            rx.hstack(
                sev_dot(f["severity"]),
                rx.link(
                    rx.text(f["cve"], font_family="ui-monospace", font_size="11.5px",
                            color=INK, font_weight="600"),
                    href=f["url"],
                    is_external=True,
                    underline="none",
                    _hover={"color": ACCENT},
                ),
                rx.cond(
                    f["exploited"],
                    rx.tooltip(
                        rx.box(
                            rx.icon("flame", size=11, color=CRIT),
                            bg="#fef2f2", border_radius="4px", padding="2px",
                            display="flex",
                        ),
                        content="Known to be exploited in the wild",
                    ),
                    rx.fragment(),
                ),
                rx.cond(
                    f["is_new"],
                    rx.box(rx.text("NEW", font_size="8.5px", font_weight="700", color=ACCENT),
                           bg="#eef2ff", border_radius="4px", padding="2px 4px"),
                    rx.fragment(),
                ),
                spacing="2",
                align="center",
            ),
            width="200px",
        ),
        td(severity_pill(f["severity"])),
        td(rx.text(f["cvss"], font_family="ui-monospace", font_size="11.5px",
                   color=f["color"], font_weight="600")),
        td(
            rx.vstack(
                rx.text(f["endpoint"], font_family="ui-monospace", font_size="11px", color=INK),
                rx.text(f["target"], font_size="10px", color=FAINT),
                spacing="0",
                gap="1px",
                align="start",
            ),
            width="160px",
        ),
        td(
            rx.vstack(
                rx.text(f["product"], font_size="11.5px", color=INK_SOFT, font_weight="500"),
                rx.text(f["host"], font_size="10px", color=FAINT, max_width="160px",
                        overflow="hidden", text_overflow="ellipsis", white_space="nowrap"),
                spacing="0",
                gap="1px",
                align="start",
            )
        ),
        td(
            rx.text(f["title"], font_size="11.5px", color=MUTED, line_height="1.5",
                    max_width="380px")
        ),
        td(
            rx.box(
                rx.text(f["confidence"], font_size="9.5px", color=MUTED, font_weight="600",
                        text_transform="uppercase"),
                bg="#f8fafc", border=f"1px solid {BORDER}", border_radius="4px",
                padding="2px 5px", display="inline-flex",
            )
        ),
    )


def vulns_page() -> rx.Component:
    return shell(
        page_header(
            "Vulnerabilities",
            "Service versions correlated against the bundled catalogue, CIRCL CVE Search and NVD.",
            rx.hstack(
                ghost_button("Refresh", "refresh-cw", AppState.load_vulns),
                ghost_button("Estate PDF", "file-down", AppState.export_portfolio_pdf),
                spacing="2",
            ),
        ),
        _filters(),
        card(
            rx.hstack(
                rx.text(AppState.findings.length().to_string(), font_size="13px",
                        font_weight="700", color=INK, font_family="ui-monospace"),
                rx.text("findings shown", font_size="11.5px", color=MUTED),
                rx.spacer(),
                rx.hstack(
                    rx.icon("info", size=11, color=FAINT),
                    rx.text("version matches are indicators, not proof of exploitability",
                            font_size="10.5px", color=FAINT),
                    spacing="1",
                    align="center",
                ),
                width="100%",
                align="center",
                margin_bottom="10px",
            ),
            rx.cond(
                AppState.findings.length() > 0,
                table_shell(
                    rx.table.header(
                        rx.table.row(
                            th("CVE", width="200px"),
                            th("Severity", width="95px"),
                            th("CVSS", width="55px"),
                            th("Asset", width="160px"),
                            th("Product"),
                            th("Summary"),
                            th("Match", width="75px"),
                        )
                    ),
                    rx.table.body(rx.foreach(AppState.findings, _row)),
                ),
                empty_state("No matching findings",
                            "Either the estate is clean, or no service version matched the corpus.",
                            icon="shield-check"),
            ),
            padding="0",
        ),
    )
