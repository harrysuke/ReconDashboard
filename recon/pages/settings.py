"""Settings page: API credentials, scan defaults, scheduler and data controls."""

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
    ghost_button,
    page_header,
    primary_button,
    section_title,
    td,
    th,
)
from recon.state import AppState


def _label(text: str, hint: str = "") -> rx.Component:
    return rx.vstack(
        rx.text(text, font_size="11px", color=INK_SOFT, font_weight="600"),
        rx.cond(hint != "", rx.text(hint, font_size="10.5px", color=FAINT), rx.fragment()),
        spacing="0",
        gap="2px",
        align="start",
    )


def _text_input(value, on_change, placeholder: str, *, password: bool = False,
                mono: bool = True, width: str = "100%") -> rx.Component:
    return rx.el.input(
        type=rx.cond(password, "password", "text"),
        placeholder=placeholder,
        default_value=value,
        on_change=on_change,
        width=width,
        height="34px",
        padding="0 10px",
        font_size="12px",
        font_family="ui-monospace, Menlo, monospace" if mono else "inherit",
        color=INK,
        bg="white",
        border=f"1px solid {BORDER}",
        border_radius="9px",
        outline="none",
        _focus={"border": f"1px solid {ACCENT}", "box_shadow": "0 0 0 3px rgba(29,78,216,0.08)"},
    )


def _credentials() -> rx.Component:
    return card(
        section_title("Collection sources",
                      "Keys are stored in the local SQLite database and only used server-side."),
        rx.grid(
            rx.vstack(
                _label("Shodan API key", "Enables port/banner/OS fingerprints via api.shodan.io"),
                _text_input(AppState.shodan_key, AppState.set_shodan_key,
                            "paste your Shodan API key", password=True),
                spacing="2",
                align="start",
                width="100%",
            ),
            rx.vstack(
                _label("NVD API key", "Optional - lifts the 5 requests / 30s rate limit"),
                _text_input(AppState.nvd_key, AppState.set_nvd_key,
                            "optional NVD 2.0 key", password=True),
                spacing="2",
                align="start",
                width="100%",
            ),
            columns="repeat(auto-fit, minmax(260px, 1fr))",
            spacing="4",
            width="100%",
            margin_top="12px",
        ),
        rx.hstack(
            _label("Default scan mode"),
            rx.select.root(
                rx.select.trigger(font_size="12.5px", height="34px", border_radius="9px",
                                  border=f"1px solid {BORDER}", bg="white", width="150px"),
                rx.select.content(
                    rx.select.group(
                        rx.select.item("Live collection", value="live"),
                        rx.select.item("Demo (synthetic)", value="demo"),
                    )
                ),
                value=AppState.default_mode,
                on_change=AppState.set_default_mode,
            ),
            rx.spacer(),
            primary_button("Save settings", "check", AppState.save_settings),
            width="100%",
            align="center",
            spacing="3",
            margin_top="16px",
            padding_top="14px",
            border_top=f"1px solid {BORDER_SOFT}",
            wrap="wrap",
        ),
        rx.cond(
            AppState.settings_saved,
            rx.hstack(
                rx.icon("circle-check", size=12, color=OK),
                rx.text("Saved. New scans pick these values up immediately.",
                        font_size="11px", color=OK),
                spacing="2",
                align="center",
                margin_top="8px",
            ),
            rx.fragment(),
        ),
    )


def _scan_options() -> rx.Component:
    return card(
        section_title("Scan behaviour",
                      "How aggressive the collection stage is allowed to be."),
        rx.hstack(
            rx.vstack(
                rx.text("HTTP fingerprinting", font_size="12px", color=INK, font_weight="500"),
                rx.text("Fetch port 80/443/8080/8443 of hosts found in CT logs and read the "
                        "Server header. No exploitation, no brute force.",
                        font_size="10.5px", color=MUTED, max_width="520px"),
                spacing="0",
                gap="3px",
                align="start",
            ),
            rx.spacer(),
            rx.switch(checked=AppState.probe_enabled, on_change=AppState.set_probe_enabled,
                      color_scheme="blue"),
            width="100%",
            align="center",
            spacing="4",
            padding="10px 0",
            border_bottom=f"1px solid {BORDER_SOFT}",
        ),
        rx.hstack(
            rx.vstack(
                rx.text("Max hosts per scan", font_size="12px", color=INK, font_weight="500"),
                rx.text("Upper bound when expanding CIDR ranges or probing hostnames.",
                        font_size="10.5px", color=MUTED),
                spacing="0",
                gap="3px",
                align="start",
            ),
            rx.spacer(),
            _text_input(AppState.max_hosts, AppState.set_max_hosts, "64", width="90px"),
            width="100%",
            align="center",
            spacing="4",
            padding="10px 0",
        ),
    )


def _scheduler_card() -> rx.Component:
    return card(
        section_title("Scheduler",
                      "APScheduler dispatches due targets every 10 minutes."),
        rx.hstack(
            rx.hstack(
                rx.box(
                    width="6px", height="6px", border_radius="50%",
                    bg=rx.cond(AppState.scheduler_running, OK, FAINT),
                ),
                rx.text(
                    rx.cond(AppState.scheduler_running, "running", "stopped"),
                    font_size="11.5px", color=INK, font_weight="600",
                ),
                spacing="2",
                align="center",
            ),
            rx.spacer(),
            ghost_button("Refresh", "refresh-cw", AppState.refresh_scheduler),
            width="100%",
            align="center",
            margin_top="10px",
        ),
        rx.foreach(
            AppState.scheduler_jobs,
            lambda job: rx.hstack(
                rx.icon("clock", size=12, color=FAINT),
                rx.text(job["id"], font_size="11px", font_family="ui-monospace", color=INK_SOFT),
                rx.spacer(),
                rx.hstack(
                    rx.text("next run", font_size="11px", color=FAINT),
                    rx.text(job["next_run"], font_size="11px", color=MUTED,
                            font_family="ui-monospace"),
                    spacing="1",
                    align="center",
                ),
                width="100%",
                align="center",
                padding="7px 0",
                border_bottom=f"1px solid {BORDER_SOFT}",
            ),
        ),
        rx.text("Targets set to Daily or Weekly are picked up automatically; a target with an "
                "in-flight scan is skipped until it finishes.",
                font_size="10.5px", color=FAINT, margin_top="8px"),
    )


def _data_card() -> rx.Component:
    return card(
        section_title("Local data", "Everything lives in one SQLite file - copy it to back up."),
        rx.hstack(
            rx.text(AppState.db_info["path"], font_size="10.5px", color=MUTED,
                    font_family="ui-monospace", overflow="hidden", text_overflow="ellipsis",
                    white_space="nowrap"),
            rx.spacer(),
            rx.text(AppState.db_info["size_kb"].to_string() + " KB", font_size="10.5px",
                    color=FAINT, font_family="ui-monospace"),
            width="100%",
            align="center",
            margin_top="8px",
            margin_bottom="10px",
        ),
        rx.grid(
            *[
                rx.vstack(
                    rx.text(label, font_size="10px", color=MUTED, text_transform="uppercase",
                            letter_spacing="0.03em"),
                    rx.text(AppState.db_info[key].to_string(), font_size="17px", color=INK,
                            font_weight="700", font_family="ui-monospace"),
                    spacing="0",
                    gap="2px",
                    align="start",
                    bg="#fbfcfd",
                    border=f"1px solid {BORDER_SOFT}",
                    border_radius="9px",
                    padding="9px 11px",
                )
                for key, label in [
                    ("targets", "targets"),
                    ("scans", "scans"),
                    ("assets", "assets"),
                    ("cves", "cves"),
                    ("findings", "findings"),
                    ("events", "events"),
                ]
            ],
            columns="repeat(auto-fit, minmax(96px, 1fr))",
            spacing="2",
            width="100%",
        ),
        rx.hstack(
            ghost_button("Generate demo history", "sparkles", AppState.seed_demo),
            ghost_button("Export estate PDF", "file-down", AppState.export_portfolio_pdf),
            rx.spacer(),
            ghost_button("Reset database", "trash-2", AppState.reset_all,
                         color=CRIT, border="#fecaca"),
            width="100%",
            align="center",
            spacing="2",
            margin_top="14px",
            wrap="wrap",
        ),
    )


def _method_card() -> rx.Component:
    steps = [
        ("Certificate transparency", "crt.sh returns every SAN entry logged for the domain - "
                                     "free, no key, catches forgotten hosts."),
        ("Shodan inventory", "Ports, banners, product/version and OS fingerprints for each IP."),
        ("HTTP fingerprint", "Server headers and page titles pin exact versions on web ports."),
        ("CVE correlation", "Banners are matched against a bundled catalogue, CIRCL and NVD, "
                            "with a confidence level per finding."),
        ("Diff + store", "New, changed and closed services are written as change events so "
                         "growth is trackable over time."),
    ]
    return card(
        section_title("How a scan works",
                      "Five stages, each one persisted so the UI can resume or report."),
        rx.vstack(
            *[
                rx.hstack(
                    rx.box(
                        rx.text(str(i + 1), font_size="10px", font_weight="700", color=ACCENT),
                        bg="#eef2ff", border_radius="6px", width="20px", height="20px",
                        display="flex", align_items="center", justify_content="center",
                        flex_shrink="0",
                    ),
                    rx.vstack(
                        rx.text(title, font_size="11.5px", color=INK, font_weight="600"),
                        rx.text(body, font_size="10.5px", color=MUTED, line_height="1.55"),
                        spacing="0",
                        gap="1px",
                        align="start",
                    ),
                    spacing="3",
                    align="start",
                    width="100%",
                    padding="8px 0",
                    border_bottom=f"1px solid {BORDER_SOFT}",
                )
                for i, (title, body) in enumerate(steps)
            ],
            spacing="0",
            width="100%",
            margin_top="6px",
        ),
        rx.hstack(
            rx.icon("shield-alert", size=12, color="#b45309"),
            rx.text("Only scan infrastructure you are authorised to assess. Passive sources and "
                    "banner grabs still touch third-party systems.",
                    font_size="10.5px", color="#b45309"),
            spacing="2",
            align="start",
            bg="#fffbeb",
            border="1px solid #fde68a",
            border_radius="8px",
            padding="9px 11px",
            margin_top="12px",
        ),
    )


def settings_page() -> rx.Component:
    return shell(
        page_header(
            "Settings",
            "Credentials, scan aggressiveness, scheduling and local storage.",
            ghost_button("Reload", "refresh-cw", AppState.load_settings),
        ),
        _credentials(),
        rx.grid(
            rx.box(_scan_options(), grid_column="span 6"),
            rx.box(_scheduler_card(), grid_column="span 6"),
            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
        ),
        rx.grid(
            rx.box(_data_card(), grid_column="span 7"),
            rx.box(_method_card(), grid_column="span 5"),
            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
        ),
    )
