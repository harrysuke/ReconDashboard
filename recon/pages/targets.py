"""Targets page: manage monitored scopes and trigger scans."""

from __future__ import annotations

import reflex as rx

from recon.components.layout import shell
from recon.components.theme import (
    ACCENT,
    BORDER,
    BORDER_SOFT,
    CRIT,
    FAINT,
    INK,
    INK_SOFT,
    MUTED,
    OK,
    card,
    empty_state,
    ghost_button,
    mono,
    page_header,
    primary_button,
    severity_pill,
    table_shell,
    td,
    th,
)
from recon.state import AppState

SCHEDULES = [
    {"value": "manual", "label": "Manual"},
    {"value": "daily", "label": "Daily"},
    {"value": "weekly", "label": "Weekly"},
]


def _add_form() -> rx.Component:
    return card(
        rx.hstack(
            rx.vstack(
                rx.text("Add a scope", font_size="13px", font_weight="600", color=INK),
                rx.text("Domain, single IP or CIDR range. Domains are enumerated through "
                        "certificate transparency first.",
                        font_size="11px", color=MUTED, max_width="520px"),
                spacing="0",
                gap="3px",
                align="start",
            ),
            rx.spacer(),
            width="100%",
            margin_bottom="12px",
        ),
        rx.hstack(
            rx.vstack(
                rx.text("Scope", font_size="10.5px", color=MUTED, font_weight="500"),
                rx.el.input(
                    placeholder="example.com  ·  10.0.0.0/24  ·  203.0.113.10",
                    # Controlled: the state var is the single source of truth.
                    # With default_value React only set this on mount, so a
                    # missed change event left the field showing text that
                    # add_target could not see - producing "Enter a domain..."
                    # for a visibly filled form.
                    value=AppState.new_target,
                    on_change=AppState.set_new_target,
                    width="100%",
                    height="34px",
                    padding="0 10px",
                    font_size="12.5px",
                    font_family="ui-monospace, Menlo, monospace",
                    color=INK,
                    bg="white",
                    border=f"1px solid {BORDER}",
                    border_radius="9px",
                    outline="none",
                    _focus={"border": f"1px solid {ACCENT}",
                            "box_shadow": "0 0 0 3px rgba(29,78,216,0.08)"},
                ),
                spacing="1",
                align="start",
                flex="2",
                min_width="220px",
            ),
            rx.vstack(
                rx.text("Label (optional)", font_size="10.5px", color=MUTED, font_weight="500"),
                rx.el.input(
                    placeholder="Production estate",
                    value=AppState.new_label,
                    on_change=AppState.set_new_label,
                    width="100%",
                    height="34px",
                    padding="0 10px",
                    font_size="12.5px",
                    color=INK,
                    bg="white",
                    border=f"1px solid {BORDER}",
                    border_radius="9px",
                    outline="none",
                    _focus={"border": f"1px solid {ACCENT}",
                            "box_shadow": "0 0 0 3px rgba(29,78,216,0.08)"},
                ),
                spacing="1",
                align="start",
                flex="1.4",
                min_width="160px",
            ),
            rx.vstack(
                rx.text("Schedule", font_size="10.5px", color=MUTED, font_weight="500"),
                rx.select.root(
                    rx.select.trigger(font_size="12.5px", height="34px", border_radius="9px",
                                      border=f"1px solid {BORDER}", bg="white", width="120px"),
                    rx.select.content(
                        rx.select.group(
                            *[rx.select.item(s["label"], value=s["value"]) for s in SCHEDULES]
                        )
                    ),
                    value=AppState.new_schedule,
                    on_change=AppState.set_new_schedule,
                ),
                spacing="1",
                align="start",
                width="120px",
            ),
            rx.box(
                primary_button("Add target", "plus", AppState.add_target),
                padding_top="19px",
            ),
            width="100%",
            align="start",
            spacing="3",
            wrap="wrap",
        ),
        rx.cond(
            AppState.form_error != "",
            rx.hstack(
                rx.icon("triangle-alert", size=12, color=CRIT),
                rx.text(AppState.form_error, font_size="11.5px", color=CRIT),
                spacing="2",
                align="center",
                margin_top="10px",
            ),
            rx.fragment(),
        ),
    )


def _target_row(t: dict) -> rx.Component:
    return rx.table.row(
        td(
            rx.vstack(
                rx.text(t["label"], font_size="12.5px", color=INK, font_weight="600"),
                rx.text(t["notes"], font_size="10.5px", color=FAINT,
                        max_width="260px", overflow="hidden",
                        text_overflow="ellipsis", white_space="nowrap"),
                spacing="0",
                gap="1px",
                align="start",
            )
        ),
        td(
            rx.hstack(
                rx.text(t["value"], font_family="ui-monospace", font_size="11.5px",
                        color=INK_SOFT),
                rx.box(
                    rx.text(t["kind"], font_size="9.5px", color=MUTED, font_weight="600",
                            text_transform="uppercase"),
                    bg="#f1f5f9", border_radius="4px", padding="2px 5px",
                ),
                spacing="2",
                align="center",
            )
        ),
        td(rx.text(t["assets"].to_string(), font_size="12px", font_family="ui-monospace",
                   color=INK, font_weight="600")),
        td(rx.text(t["cves"].to_string(), font_size="12px", font_family="ui-monospace",
                   color=t["cves_color"], font_weight="600")),
        td(
            rx.hstack(
                rx.box(width="5px", height="5px", border_radius="50%", bg=t["risk_color"]),
                rx.text(t["risk"].to_string(), font_size="11.5px", font_family="ui-monospace",
                        color=INK_SOFT),
                spacing="2",
                align="center",
            )
        ),
        td(
            rx.select.root(
                rx.select.trigger(font_size="11.5px", height="28px", border_radius="7px",
                                  border=f"1px solid {BORDER}", bg="white", width="104px"),
                rx.select.content(
                    rx.select.group(
                        *[rx.select.item(s["label"], value=s["value"]) for s in SCHEDULES]
                    )
                ),
                value=t["schedule"],
                on_change=lambda v: AppState.set_target_schedule(t["id"], v),
            )
        ),
        td(rx.text(t["last_scan"], font_size="11px", color=MUTED)),
        td(
            rx.hstack(
                rx.tooltip(
                    rx.box(
                        rx.icon("radar", size=13, color=ACCENT),
                        on_click=AppState.start_scan(t["id"]),
                        cursor="pointer",
                        padding="5px",
                        border_radius="6px",
                        border=f"1px solid {BORDER}",
                        _hover={"bg": "#eef2ff"},
                    ),
                    content="Run scan",
                ),
                rx.tooltip(
                    rx.box(
                        rx.icon("trash-2", size=13, color=FAINT),
                        on_click=AppState.delete_target(t["id"]),
                        cursor="pointer",
                        padding="5px",
                        border_radius="6px",
                        border=f"1px solid {BORDER}",
                        _hover={"bg": "#fef2f2", "color": CRIT},
                    ),
                    content="Remove target",
                ),
                spacing="2",
                align="center",
                justify="end",
            ),
            text_align="right",
        ),
    )


def targets_page() -> rx.Component:
    return shell(
        page_header(
            "Targets",
            "Scopes under continuous observation. Scheduled scans run even when nobody is watching.",
            rx.hstack(
                ghost_button("Refresh", "refresh-cw", AppState.load_targets),
                ghost_button("Estate PDF", "file-down", AppState.export_portfolio_pdf),
                spacing="2",
            ),
        ),
        _add_form(),
        card(
            rx.hstack(
                rx.text("Monitored scopes", font_size="13px", font_weight="600", color=INK),
                rx.box(
                    rx.text(AppState.targets.length().to_string(), font_size="10px",
                            color=MUTED, font_weight="600"),
                    bg="#f1f5f9", border_radius="10px", padding="2px 7px",
                ),
                spacing="2",
                align="center",
                margin_bottom="10px",
            ),
            rx.cond(
                AppState.targets.length() > 0,
                table_shell(
                    rx.table.header(
                        rx.table.row(
                            th("Target"),
                            th("Scope", width="260px"),
                            th("Assets", width="80px"),
                            th("CVEs", width="70px"),
                            th("Risk", width="80px"),
                            th("Schedule", width="120px"),
                            th("Last scan", width="100px"),
                            th("", width="90px"),
                        )
                    ),
                    rx.table.body(rx.foreach(AppState.targets, _target_row)),
                ),
                empty_state("No targets yet",
                            "Add a domain or CIDR range above to start collecting OSINT.",
                            icon="crosshair"),
            ),
        ),
    )
