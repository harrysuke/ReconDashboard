"""Scan history page: every run, its diff counters and PDF export."""

from __future__ import annotations

import reflex as rx

from recon.components.layout import shell
from recon.components.theme import (
    ACCENT,
    BORDER,
    CRIT,
    FAINT,
    HIGH,
    INK,
    INK_SOFT,
    MUTED,
    OK,
    card,
    empty_state,
    ghost_button,
    page_header,
    primary_button,
    table_shell,
    td,
    th,
)
from recon.state import AppState


def _status(ok, running, label) -> rx.Component:
    return rx.match(
        label,
        ("success", rx.hstack(
            rx.box(width="6px", height="6px", border_radius="50%", bg=OK),
            rx.text("success", font_size="11px", color=OK, font_weight="600"),
            spacing="2", align="center")),
        ("running", rx.hstack(
            rx.box(width="6px", height="6px", border_radius="50%", bg=ACCENT),
            rx.text("running", font_size="11px", color=ACCENT, font_weight="600"),
            spacing="2", align="center")),
        ("error", rx.hstack(
            rx.box(width="6px", height="6px", border_radius="50%", bg=CRIT),
            rx.text("failed", font_size="11px", color=CRIT, font_weight="600"),
            spacing="2", align="center")),
        rx.hstack(
            rx.box(width="6px", height="6px", border_radius="50%", bg=FAINT),
            rx.text(label, font_size="11px", color=MUTED),
            spacing="2", align="center"),
    )


def _row(s: dict) -> rx.Component:
    return rx.table.row(
        td(rx.text("#" + s["id"].to_string(), font_family="ui-monospace", font_size="11.5px",
                   color=MUTED)),
        td(
            rx.vstack(
                rx.text(s["target"], font_size="12px", color=INK, font_weight="600"),
                rx.hstack(
                    rx.text(s["mode"], font_size="9.5px", color=MUTED, text_transform="uppercase",
                            font_weight="600"),
                    rx.text("·", font_size="9px", color=FAINT),
                    rx.text(s["trigger"], font_size="9.5px", color=FAINT),
                    spacing="1",
                    align="center",
                ),
                spacing="0",
                gap="1px",
                align="start",
            )
        ),
        td(_status(s["ok"], s["running"], s["status"])),
        td(rx.text(s["started"], font_size="11px", color=MUTED)),
        td(rx.text(s["duration"], font_size="11px", font_family="ui-monospace", color=MUTED)),
        td(rx.text(s["assets"].to_string(), font_size="11.5px", font_family="ui-monospace",
                   color=INK, font_weight="600")),
        td(
            rx.hstack(
                rx.text("+" + s["new"].to_string(), font_size="11px", font_family="ui-monospace",
                        color=rx.cond(s["has_new"], HIGH, FAINT)),
                rx.text("-" + s["closed"].to_string(), font_size="11px",
                        font_family="ui-monospace", color=FAINT),
                spacing="2",
                align="center",
            )
        ),
        td(rx.text(s["cves"].to_string(), font_size="11.5px", font_family="ui-monospace",
                   color=INK)),
        td(
            rx.hstack(
                rx.cond(s["has_crit"], rx.text(s["crit"].to_string(), font_size="10.5px",
                                               color=CRIT, font_weight="700",
                                               font_family="ui-monospace"), rx.fragment()),
                rx.cond(s["has_high"], rx.text(s["high"].to_string(), font_size="10.5px",
                                               color=HIGH, font_weight="600",
                                               font_family="ui-monospace"), rx.fragment()),
                spacing="2",
                align="center",
            )
        ),
        td(
            rx.box(
                rx.icon("file-down", size=13, color=ACCENT),
                on_click=AppState.export_scan_pdf(s["id"]),
                cursor="pointer",
                padding="5px",
                border_radius="6px",
                border=f"1px solid {BORDER}",
                display="inline-flex",
                _hover={"bg": "#eef2ff"},
            ),
            text_align="right",
        ),
    )


def scans_page() -> rx.Component:
    return shell(
        page_header(
            "Scan history",
            "Every run is persisted, so exposure can be diffed scan over scan.",
            rx.hstack(
                ghost_button("Refresh", "refresh-cw", AppState.load_scans),
                primary_button("Run scan", "radar", AppState.start_scan(AppState.primary_target_id)),
                spacing="2",
            ),
        ),
        rx.cond(
            AppState.scanning,
            card(
                rx.hstack(
                    rx.icon("activity", size=14, color=ACCENT),
                    rx.text(AppState.scan_target_label, font_size="12px", font_weight="600",
                            color=INK),
                    rx.text("· " + AppState.scan_stage, font_size="11.5px", color=MUTED),
                    rx.spacer(),
                    rx.text(AppState.scan_pct_label, font_size="11.5px", color=ACCENT,
                            font_family="ui-monospace", font_weight="600"),
                    width="100%",
                    align="center",
                ),
                rx.progress(value=AppState.scan_progress, max=100, size="1",
                            color_scheme="blue", width="100%", margin_top="8px"),
                rx.text(AppState.scan_message, font_size="11px", color=FAINT, margin_top="6px"),
                padding="14px",
            ),
            rx.fragment(),
        ),
        card(
            rx.cond(
                AppState.scans.length() > 0,
                table_shell(
                    rx.table.header(
                        rx.table.row(
                            th("#", width="50px"),
                            th("Target"),
                            th("Status", width="100px"),
                            th("Started", width="105px"),
                            th("Took", width="65px"),
                            th("Assets", width="65px"),
                            th("Δ", width="80px"),
                            th("CVEs", width="60px"),
                            th("C/H", width="60px"),
                            th("", width="45px"),
                        )
                    ),
                    rx.table.body(rx.foreach(AppState.scans, _row)),
                ),
                empty_state("No scans recorded", "Run your first scan to build a baseline.",
                            icon="history"),
            ),
            padding="0",
        ),
    )
