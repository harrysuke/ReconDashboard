"""One-off layout tuning script (kept for reproducibility of the visual pass)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

p = ROOT / "recon/pages/dashboard.py"
s = p.read_text(encoding="utf-8")

# severity card: smaller donut, natural height
s = s.replace(
    """            spacing="1",
            width="100%",
            margin_top="2px",
        ),
        height="330px",
    )""",
    """            spacing="1",
            width="100%",
            margin_top="0px",
        ),
    )""",
)
# growth card: natural height
s = s.replace(
    """            width="100%",
            margin_top="8px",
        ),
        height="330px",
    )


def _services_card""",
    """            width="100%",
            margin_top="6px",
        ),
    )


def _services_card""",
)
# services card: natural height
s = s.replace(
    """            width="100%",
            margin_top="4px",
        ),
        height="352px",
    )""",
    """            width="100%",
            margin_top="4px",
        ),
    )""",
)
# changes card: natural height, no inner scroll
s = s.replace(
    """            rx.vstack(
                rx.foreach(AppState.changes, _change_row),
                spacing="0",
                width="100%",
                height="266px",
                overflow_y="auto",
                margin_top="6px",
                padding_right="6px",
            ),""",
    """            rx.vstack(
                rx.foreach(AppState.changes, _change_row),
                spacing="0",
                width="100%",
                margin_top="4px",
            ),""",
)
s = s.replace(
    """            empty_state("No changes yet", "Run a scan to populate the diff feed."),
        ),
        height="352px",
    )""",
    """            empty_state("No changes yet", "Run a scan to populate the diff feed."),
        ),
    )""",
)
# grids: let cards size naturally
s = s.replace(
    """            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
        ),""",
    """            columns="repeat(12, minmax(0, 1fr))",
            spacing="4",
            width="100%",
            align_items="start",
        ),""",
)
p.write_text(s, encoding="utf-8")

p = ROOT / "recon/state.py"
s = p.read_text(encoding="utf-8")
s = s.replace("        self.changes = queries.recent_changes()",
              "        self.changes = queries.recent_changes(limit=7)")
s = s.replace(
    """                y=[f'{r["service"]} :{r["endpoint"].split(":")[-1]}' for r in rows],""",
    """                y=[f':{r["endpoint"].split(":")[-1]}  {r["service"]}' for r in rows],""",
)
s = s.replace("            margin=dict(l=4, r=26, t=6, b=4),",
              "            margin=dict(l=8, r=30, t=6, b=6),")
s = s.replace("""            height=210,
            showlegend=False,""", """            height=186,
            showlegend=False,""")
p.write_text(s, encoding="utf-8")
print("layout fixes applied")
