"""Reflex project configuration.

Run the dashboard with::

    reflex init          # first run only, downloads the JS toolchain
    reflex run           # frontend on :3000, backend on :8000

Environment variables (all optional) are read from ``.env``:

    SHODAN_API_KEY        enables live Shodan collection
    NVD_API_KEY           enables NVD keyword enrichment
    RECON_DEFAULT_MODE    "live" (default) or "demo"
"""

import reflex as rx

config = rx.Config(
    app_name="recon",
    frontend_port=3000,
    backend_port=8000,
    telemetry_enabled=False,
    show_built_with_reflex=False,
    plugins=[
        rx.plugins.RadixThemesPlugin(
            theme=rx.theme(
                appearance="light",
                accent_color="blue",
                gray_color="slate",
                radius="large",
                scaling="100%",
            )
        ),
    ],
    disable_plugins=[rx.plugins.SitemapPlugin],
)
