"""Design tokens and shared UI primitives.

Light, dense, console-like: white cards on a soft grey canvas, slate text,
severity colours used sparingly as the only saturated accents.
"""

from __future__ import annotations

import reflex as rx

INK = "#0f172a"
INK_SOFT = "#334155"
MUTED = "#64748b"
FAINT = "#94a3b8"
BORDER = "#e5e9f0"
BORDER_SOFT = "#eef1f6"
CANVAS = "#f6f7f9"
ACCENT = "#1d4ed8"
ACCENT_SOFT = "#eef2ff"

CRIT = "#dc2626"
HIGH = "#ea580c"
MED = "#d97706"
LOW = "#0891b2"
OK = "#059669"

MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"
SANS = "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif"

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#ecfeff",
    "unknown": "#f1f5f9",
    "info": "#f1f5f9",
}
SEVERITY_FG = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#0e7490",
    "unknown": "#475569",
    "info": "#475569",
}


def card(*children, **props) -> rx.Component:
    """Standard surface."""
    return rx.box(
        *children,
        bg="white",
        border=f"1px solid {BORDER}",
        border_radius="14px",
        box_shadow="0 1px 2px rgba(16,24,40,0.04), 0 1px 3px rgba(16,24,40,0.04)",
        width="100%",
        padding=props.pop("padding", "18px"),
        **props,
    )


def section_title(title: str, subtitle: str = "", right: rx.Component | None = None) -> rx.Component:
    left = rx.vstack(
        rx.text(title, font_size="13.5px", font_weight="600", color=INK, letter_spacing="-0.01em"),
        rx.cond(
            subtitle != "",
            rx.text(subtitle, font_size="11.5px", color=MUTED, line_height="1.5"),
            rx.fragment(),
        ),
        spacing="0",
        align="start",
        gap="3px",
    )
    return rx.hstack(
        left,
        rx.spacer(),
        right if right is not None else rx.fragment(),
        width="100%",
        align="center",
        justify="between",
    )


def pill(text, bg: str, fg: str, *, mono: bool = False, size: str = "10.5px") -> rx.Component:
    return rx.box(
        rx.text(
            text,
            font_size=size,
            color=fg,
            font_weight="600",
            font_family=MONO if mono else SANS,
            line_height="1",
            white_space="nowrap",
        ),
        bg=bg,
        border_radius="6px",
        padding="4px 7px",
        display="inline-flex",
        align_items="center",
    )


def severity_pill(severity, *, size: str = "10.5px") -> rx.Component:
    """Severity badge driven by a Var string."""
    return rx.match(
        severity,
        ("critical", pill("CRITICAL", SEVERITY_BG["critical"], SEVERITY_FG["critical"], size=size)),
        ("high", pill("HIGH", SEVERITY_BG["high"], SEVERITY_FG["high"], size=size)),
        ("medium", pill("MEDIUM", SEVERITY_BG["medium"], SEVERITY_FG["medium"], size=size)),
        ("low", pill("LOW", SEVERITY_BG["low"], SEVERITY_FG["low"], size=size)),
        pill("INFO", SEVERITY_BG["info"], SEVERITY_FG["info"], size=size),
    )


def sev_dot(severity) -> rx.Component:
    return rx.match(
        severity,
        ("critical", rx.box(width="7px", height="7px", border_radius="50%", bg=CRIT, flex_shrink="0")),
        ("high", rx.box(width="7px", height="7px", border_radius="50%", bg=HIGH, flex_shrink="0")),
        ("medium", rx.box(width="7px", height="7px", border_radius="50%", bg=MED, flex_shrink="0")),
        ("low", rx.box(width="7px", height="7px", border_radius="50%", bg=LOW, flex_shrink="0")),
        rx.box(width="7px", height="7px", border_radius="50%", bg=FAINT, flex_shrink="0"),
    )


def mono(text, *, size: str = "12px", color: str = INK, weight: str = "500") -> rx.Component:
    return rx.text(text, font_family=MONO, font_size=size, color=color, font_weight=weight)


def page_header(title: str, subtitle: str, actions: rx.Component | None = None) -> rx.Component:
    return rx.hstack(
        rx.vstack(
            rx.text(title, font_size="21px", font_weight="700", color=INK, letter_spacing="-0.02em"),
            rx.text(subtitle, font_size="12.5px", color=MUTED),
            spacing="0",
            gap="4px",
            align="start",
        ),
        rx.spacer(),
        actions if actions is not None else rx.fragment(),
        width="100%",
        align="center",
        margin_bottom="4px",
    )


def kpi_card(label: str, value, hint: str, icon: str, accent: str = ACCENT,
             icon_bg: str = "#f1f5f9") -> rx.Component:
    return card(
        rx.hstack(
            rx.vstack(
                rx.text(label, font_size="11px", color=MUTED, font_weight="500",
                        letter_spacing="0.02em", text_transform="uppercase"),
                rx.text(value, font_size="26px", font_weight="700", color=INK,
                        letter_spacing="-0.03em", line_height="1.1"),
                spacing="0",
                gap="6px",
                align="start",
            ),
            rx.spacer(),
            rx.box(
                rx.icon(icon, size=16, color=accent),
                bg=icon_bg,
                border_radius="10px",
                padding="9px",
                display="flex",
                align_items="center",
                justify_content="center",
            ),
            width="100%",
            align="start",
        ),
        rx.text(hint, font_size="11px", color=MUTED, margin_top="8px"),
        padding="16px",
    )


def empty_state(title: str, hint: str, icon: str = "radar") -> rx.Component:
    return rx.vstack(
        rx.box(
            rx.icon(icon, size=20, color=FAINT),
            bg="#f8fafc",
            border=f"1px solid {BORDER_SOFT}",
            border_radius="12px",
            padding="12px",
        ),
        rx.text(title, font_size="13px", font_weight="600", color=INK_SOFT),
        rx.text(hint, font_size="11.5px", color=MUTED, text_align="center", max_width="320px"),
        spacing="2",
        align="center",
        justify="center",
        padding="28px 16px",
        width="100%",
    )


def table_shell(*children, **props) -> rx.Component:
    return rx.box(
        rx.table.root(
            *children,
            variant="surface",
            size="1",
            width="100%",
        ),
        width="100%",
        overflow_x="auto",
        **props,
    )


def th(text: str, *, width: str = "auto", align: str = "left") -> rx.Component:
    return rx.table.column_header_cell(
        rx.text(text, font_size="10.5px", color=MUTED, font_weight="600",
                text_transform="uppercase", letter_spacing="0.04em"),
        width=width,
        text_align=align,
        bg="#fbfcfd",
        padding="9px 12px",
        border_bottom=f"1px solid {BORDER}",
    )


def td(*children, **props) -> rx.Component:
    return rx.table.cell(*children, padding="10px 12px",
                         border_bottom=f"1px solid {BORDER_SOFT}", **props)


def input_field(placeholder: str, value, on_change, *, icon: str = "", width: str = "260px") -> rx.Component:
    inner = [
        rx.icon(icon, size=14, color=FAINT) if icon else rx.fragment(),
        rx.el.input(
            placeholder=placeholder,
            default_value=value,
            on_change=on_change,
            background="transparent",
            border="none",
            outline="none",
            font_size="12.5px",
            color=INK,
            width="100%",
            font_family=SANS,
        ),
    ]
    return rx.hstack(
        *inner,
        spacing="2",
        align="center",
        bg="white",
        border=f"1px solid {BORDER}",
        border_radius="9px",
        padding="0 10px",
        height="34px",
        width=width,
        _focus_within={"border": f"1px solid {ACCENT}", "box_shadow": "0 0 0 3px rgba(29,78,216,0.08)"},
    )


def select_field(items: list[dict], value, on_change, *, width: str = "170px",
                 placeholder: str = "Select") -> rx.Component:
    return rx.select.root(
        rx.select.trigger(
            font_size="12.5px",
            height="34px",
            border_radius="9px",
            border=f"1px solid {BORDER}",
            bg="white",
            color=INK,
            width=width,
        ),
        rx.select.content(
            rx.select.group(
                *[
                    rx.select.item(item["label"], value=item["value"])
                    for item in items
                ]
            )
        ),
        value=value,
        on_change=on_change,
    )


def ghost_button(label: str, icon: str, on_click, *, color: str = INK_SOFT,
                 border: str = BORDER, bg: str = "white") -> rx.Component:
    return rx.button(
        rx.icon(icon, size=13),
        rx.text(label, font_size="12px", font_weight="500"),
        on_click=on_click,
        bg=bg,
        color=color,
        border=f"1px solid {border}",
        border_radius="9px",
        height="34px",
        padding="0 12px",
        gap="6px",
        cursor="pointer",
        _hover={"bg": "#f8fafc"},
    )


def primary_button(label: str, icon: str, on_click, **props) -> rx.Component:
    return rx.button(
        rx.icon(icon, size=13),
        rx.text(label, font_size="12px", font_weight="600"),
        on_click=on_click,
        bg=ACCENT,
        color="white",
        border="none",
        border_radius="9px",
        height="34px",
        padding="0 13px",
        gap="6px",
        cursor="pointer",
        _hover={"bg": "#1e40af"},
        **props,
    )


def divider() -> rx.Component:
    return rx.box(height="1px", width="100%", bg=BORDER_SOFT, margin_y="2px")
