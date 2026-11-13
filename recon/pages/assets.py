"""Exposed assets page: every live service, filterable."""

from __future__ import annotations

import reflex as rx

from recon.components.layout import shell
from recon.components.theme import (
    ACCENT,
    BORDER,
    FAINT,
    INK,
    INK_SOFT,
    MUTED,
    card,
    empty_state,
    ghost_button,
    input_field,
    page_header,
    primary_button,
    sev_dot,
    severity_pill,
    table_shell,
    td,
    th,
)
from recon.state import AppState


def _filters() -> rx.Component:
    return card(
        rx.hstack(
            rx.select.root(
                rx.select.trigger(font_size="12.5px", height="34px", border_radius="9px",
                                  border=f"1px solid {BORDER}", bg="white", width="190px"),
                rx.select.content(
                    rx.select.group(
                        rx.select.item("All targets", value="all"),
                        rx.foreach(
                            AppState.target_options,
                            lambda o: rx.select.item(o["label"], value=o["value"]),
                        ),
                    )
                ),
                value=AppState.asset_target,
                on_change=AppState.set_asset_target,
            ),
            input_field("Search host, product, banner…", AppState.asset_search,
                        AppState.set_asset_search, icon="search", width="320px"),
            rx.hstack(
                rx.icon("sparkles", size=13,
                        color=rx.cond(AppState.asset_only_new, ACCENT, FAINT)),
                rx.text("New only", font_size="12px",
                        color=rx.cond(AppState.asset_only_new, ACCENT, INK_SOFT),
                        font_weight=rx.cond(AppState.asset_only_new, "600", "500")),
                on_click=AppState.toggle_asset_new,
                cursor="pointer",
                spacing="2",
                align="center",
                height="34px",
                padding="0 12px",
                border_radius="9px",
                bg=rx.cond(AppState.asset_only_new, "#eef2ff", "white"),
                border=rx.cond(AppState.asset_only_new, f"1px solid {ACCENT}",
                               f"1px solid {BORDER}"),
            ),
            rx.spacer(),
            rx.text(AppState.assets.length().to_string() + " results",
                    font_size="11px", color=MUTED, font_family="ui-monospace"),
            width="100%",
            align="center",
            spacing="3",
            wrap="wrap",
        ),
    )


def _row(a: dict) -> rx.Component:
    return rx.table.row(
        td(
            rx.hstack(
                sev_dot(a["severity"]),
                rx.text(a["endpoint"], font_family="ui-monospace", font_size="11.5px",
                        color=INK, font_weight="500", white_space="nowrap"),
                rx.cond(
                    a["is_new"],
                    rx.box(rx.text("NEW", font_size="8.5px", font_weight="700", color=ACCENT),
                           bg="#eef2ff", border_radius="4px", padding="2px 4px",
                           flex_shrink="0"),
                    rx.fragment(),
                ),
                spacing="2",
                align="center",
                width="100%",
            ),
            width="220px",
        ),
        td(
            rx.vstack(
                rx.text(a["host"], font_size="11.5px", color=INK_SOFT),
                rx.text(a["target"], font_size="10px", color=FAINT),
                spacing="0",
                gap="1px",
                align="start",
            )
        ),
        td(
            rx.hstack(
                rx.box(
                    rx.text(a["service"], font_size="10px", color=MUTED, font_weight="600",
                            text_transform="lowercase"),
                    bg="#f8fafc", border=f"1px solid {BORDER}", border_radius="5px",
                    padding="2px 6px",
                ),
                rx.cond(
                    a["tls"],
                    rx.icon("lock", size=11, color="#059669"),
                    rx.fragment(),
                ),
                spacing="2",
                align="center",
            )
        ),
        td(
            rx.vstack(
                rx.text(a["product"], font_size="11.5px", color=INK_SOFT, font_weight="500"),
                rx.text(a["title"], font_size="10.5px", color=FAINT, max_width="240px",
                        overflow="hidden", text_overflow="ellipsis", white_space="nowrap"),
                spacing="0",
                gap="1px",
                align="start",
            )
        ),
        td(severity_pill(a["severity"])),
        td(rx.text(a["findings"].to_string(), font_size="11.5px", font_family="ui-monospace",
                   color=a["findings_color"], font_weight="600")),
        td(rx.text(a["first_seen"], font_size="11px", color=MUTED)),
        td(rx.text(a["sources"], font_size="10.5px", color=FAINT)),
    )


def assets_page() -> rx.Component:
    return shell(
        page_header(
            "Exposed assets",
            "Every reachable service discovered through certificate transparency, Shodan and HTTP fingerprinting.",
            rx.hstack(
                ghost_button("Refresh", "refresh-cw", AppState.load_assets),
                ghost_button("Estate PDF", "file-down", AppState.export_portfolio_pdf),
                spacing="2",
            ),
        ),
        _filters(),
        card(
            rx.cond(
                AppState.assets.length() > 0,
                table_shell(
                    rx.table.header(
                        rx.table.row(
                            th("Endpoint", width="220px"),
                            th("Host"),
                            th("Service", width="130px"),
                            th("Product"),
                            th("Severity", width="95px"),
                            th("CVEs", width="60px"),
                            th("First seen", width="95px"),
                            th("Sources", width="100px"),
                        )
                    ),
                    rx.table.body(rx.foreach(AppState.assets, _row)),
                ),
                empty_state("No assets match",
                            "Adjust the filters, or run a scan to discover services.",
                            icon="server"),
            ),
            padding="0",
        ),
    )
