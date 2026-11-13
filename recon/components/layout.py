"""Application shell: sidebar navigation, live scan strip, toast."""

from __future__ import annotations

import reflex as rx

from recon.components.theme import (
    ACCENT,
    ACCENT_SOFT,
    BORDER,
    BORDER_SOFT,
    CANVAS,
    FAINT,
    INK,
    INK_SOFT,
    MONO,
    MUTED,
    OK,
    CRIT,
    card,
)
from recon.state import AppState

NAV = [
    {"label": "Overview", "path": "/", "icon": "layout-dashboard"},
    {"label": "Targets", "path": "/targets", "icon": "crosshair"},
    {"label": "Exposed assets", "path": "/assets", "icon": "server"},
    {"label": "Vulnerabilities", "path": "/vulnerabilities", "icon": "bug"},
    {"label": "Scan history", "path": "/scans", "icon": "history"},
    {"label": "Settings", "path": "/settings", "icon": "settings"},
]


def _nav_item(item: dict) -> rx.Component:
    active = rx.State.router.page.path == item["path"]
    return rx.link(
        rx.hstack(
            rx.icon(item["icon"], size=15, color=rx.cond(active, ACCENT, MUTED)),
            rx.text(
                item["label"],
                font_size="12.5px",
                font_weight=rx.cond(active, "600", "500"),
                color=rx.cond(active, ACCENT, INK_SOFT),
            ),
            spacing="2",
            align="center",
            width="100%",
        ),
        href=item["path"],
        underline="none",
        width="100%",
        padding="8px 10px",
        border_radius="8px",
        bg=rx.cond(active, ACCENT_SOFT, "transparent"),
        _hover={"bg": rx.cond(active, ACCENT_SOFT, "#f6f7f9")},
    )


def _logo() -> rx.Component:
    return rx.hstack(
        rx.box(
            rx.icon("radar", size=17, color="white"),
            bg=INK,
            border_radius="9px",
            padding="8px",
            display="flex",
            align_items="center",
            justify_content="center",
        ),
        rx.vstack(
            rx.text("RECON", font_size="13px", font_weight="700", color=INK,
                    letter_spacing="0.08em", line_height="1.1"),
            rx.text("OSINT console", font_size="10px", color=MUTED, line_height="1.2"),
            spacing="0",
            gap="1px",
            align="start",
        ),
        spacing="3",
        align="center",
        padding="2px 6px 14px 6px",
    )


def _scan_widget() -> rx.Component:
    return rx.box(
        rx.cond(
            AppState.scanning,
            rx.vstack(
                rx.hstack(
                    rx.box(
                        width="6px", height="6px", border_radius="50%", bg=ACCENT,
                        animation="pulse 1.4s ease-in-out infinite",
                    ),
                    rx.text("Scanning", font_size="11px", font_weight="600", color=INK),
                    rx.spacer(),
                    rx.text(AppState.scan_pct_label, font_size="11px", color=MUTED,
                            font_family=MONO),
                    width="100%",
                    align="center",
                    spacing="2",
                ),
                rx.text(AppState.scan_target_label, font_size="10.5px", color=MUTED,
                        overflow="hidden", text_overflow="ellipsis", white_space="nowrap",
                        max_width="100%"),
                rx.progress(value=AppState.scan_progress, max=100, size="1",
                            color_scheme="blue", width="100%"),
                rx.text(AppState.scan_stage, font_size="10px", color=FAINT,
                        text_transform="capitalize"),
                spacing="1",
                align="start",
                width="100%",
            ),
            rx.vstack(
                rx.hstack(
                    rx.box(width="6px", height="6px", border_radius="50%", bg=OK),
                    rx.text("Idle", font_size="11px", font_weight="600", color=INK),
                    spacing="2",
                    align="center",
                ),
                rx.text("No scan running", font_size="10.5px", color=MUTED),
                spacing="1",
                align="start",
                width="100%",
            ),
        ),
        bg="#fbfcfd",
        border=f"1px solid {BORDER_SOFT}",
        border_radius="10px",
        padding="10px",
        width="100%",
    )


def sidebar() -> rx.Component:
    return rx.vstack(
        _logo(),
        rx.vstack(
            *[_nav_item(item) for item in NAV],
            spacing="1",
            width="100%",
            align="start",
        ),
        rx.spacer(),
        _scan_widget(),
        rx.hstack(
            rx.text("SQLite", font_size="10px", color=FAINT, font_family=MONO),
            rx.spacer(),
            rx.text(AppState.kpis["targets"].to_string(), font_size="10px", color=FAINT,
                    font_family=MONO),
            rx.text("targets", font_size="10px", color=FAINT),
            width="100%",
            align="center",
            padding="0 4px",
        ),
        width="248px",
        min_width="248px",
        height="100vh",
        position="sticky",
        top="0",
        bg="white",
        border_right=f"1px solid {BORDER}",
        padding="16px 12px 14px 12px",
        spacing="3",
        align="start",
    )


def scan_strip() -> rx.Component:
    """Slim progress strip pinned above page content while a scan runs."""
    return rx.cond(
        AppState.scanning,
        rx.box(
            rx.hstack(
                rx.icon("activity", size=13, color=ACCENT),
                rx.text(AppState.scan_target_label, font_size="11.5px", font_weight="600",
                        color=INK),
                rx.text("·", color=FAINT, font_size="11px"),
                rx.text(AppState.scan_stage, font_size="11.5px", color=MUTED,
                        text_transform="capitalize"),
                rx.text("·", color=FAINT, font_size="11px"),
                rx.text(AppState.scan_message, font_size="11.5px", color=MUTED,
                        overflow="hidden", text_overflow="ellipsis", white_space="nowrap"),
                rx.spacer(),
                rx.text(AppState.scan_pct_label, font_size="11.5px", color=ACCENT,
                        font_family=MONO, font_weight="600"),
                width="100%",
                align="center",
                spacing="2",
                padding="0 4px",
            ),
            rx.progress(value=AppState.scan_progress, max=100, size="1",
                        color_scheme="blue", width="100%", margin_top="6px"),
            bg="white",
            border=f"1px solid {BORDER}",
            border_radius="10px",
            padding="9px 12px",
            width="100%",
            box_shadow="0 1px 2px rgba(16,24,40,0.04)",
            margin_bottom="14px",
        ),
        rx.fragment(),
    )


def toast() -> rx.Component:
    return rx.cond(
        AppState.toast_message != "",
        rx.hstack(
            rx.icon(
                rx.match(
                    AppState.toast_kind,
                    ("success", "circle-check"),
                    ("error", "circle-x"),
                    ("warning", "triangle-alert"),
                    "info",
                ),
                size=14,
                color=rx.match(
                    AppState.toast_kind,
                    ("success", OK),
                    ("error", CRIT),
                    ("warning", "#b45309"),
                    ACCENT,
                ),
            ),
            rx.text(AppState.toast_message, font_size="12px", color=INK, font_weight="500"),
            rx.box(
                rx.icon("x", size=13, color=FAINT),
                on_click=AppState.clear_toast,
                cursor="pointer",
                padding="2px",
                border_radius="5px",
                _hover={"bg": "#f1f5f9"},
            ),
            spacing="2",
            align="center",
            position="fixed",
            bottom="20px",
            right="24px",
            bg="white",
            border=f"1px solid {BORDER}",
            border_radius="10px",
            padding="10px 12px",
            box_shadow="0 8px 24px rgba(15,23,42,0.10)",
            z_index="999",
            max_width="420px",
        ),
        rx.fragment(),
    )


def shell(*content: rx.Component) -> rx.Component:
    return rx.box(
        rx.el.style(
            f"""
            * {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; }}
            body {{ background: {CANVAS}; }}
            ::-webkit-scrollbar {{ width: 9px; height: 9px; }}
            ::-webkit-scrollbar-thumb {{ background: #d7dde7; border-radius: 6px; }}
            ::-webkit-scrollbar-track {{ background: transparent; }}
            @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: .35; }} }}
            table {{ border-collapse: separate; border-spacing: 0; }}
            """
        ),
        rx.hstack(
            sidebar(),
            rx.box(
                rx.vstack(
                    scan_strip(),
                    *content,
                    spacing="4",
                    align="start",
                    width="100%",
                    padding="22px 26px 40px 26px",
                    max_width="1500px",
                ),
                flex="1",
                min_width="0",
            ),
            width="100%",
            align="start",
            spacing="0",
        ),
        toast(),
        bg=CANVAS,
        min_height="100vh",
        width="100%",
    )
