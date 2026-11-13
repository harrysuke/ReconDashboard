# ReconDashboard

An automated OSINT & CVE reconnaissance dashboard. Give it a domain, an IP or a
CIDR range; it enumerates what the internet can already see, fingerprints the
services, maps them to known CVEs, and keeps every scan so you can watch
exposure change over time.

Built as a single Python codebase — Reflex for the UI, Peewee/SQLite for
storage, httpx/asyncio for collection, ReportLab for PDF reports. No separate
JavaScript build pipeline to maintain.

```
┌──────────────────────────── Reflex (pure Python) ────────────────────────────┐
│  Overview · Targets · Assets · Vulnerabilities · Scans · Settings            │
│  Plotly figures  ·  live progress bar  ·  PDF export                         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  state events (websocket)
┌───────────────────────────────────┴─────────────────────────────────────────┐
│  AppState (recon/state.py)                                                   │
│    background scan handler polls scan_runs.progress every 350ms              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴─────────────────────────────────────────┐
│  scanner.run_scan()  — 5 stages, progress persisted per stage                │
│                                                                              │
│  1 crt.sh ──► subdomains        4 CVE correlation ──► catalog / CIRCL / NVD  │
│  2 Shodan ──► ports, banners    5 diff + change log ──► change_events        │
│  3 httpx  ──► HTTP fingerprints                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                         SQLite (WAL)  data/recon.db
   targets · scan_runs · assets · vulnerabilities · asset_vulnerabilities ·
   change_events · settings
                                    │
                     APScheduler thread ── daily / weekly rescans
```

## Quick start

```bash
cd ReconDashboard
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on *nix)
pip install -r requirements.txt

copy .env.example .env          # optional: add SHODAN_API_KEY / NVD_API_KEY
python -m reflex run
```

Open <http://localhost:3000>. On first load the dashboard creates a demo target
(`demo.example.com`) with six weeks of backdated scan history so every chart has
something to show. Delete it whenever you like.

## How a scan works

| Stage | Source | What it yields |
|---|---|---|
| Subdomains | `crt.sh` JSON endpoint | every hostname that ever appeared in a certificate SAN |
| Inventory | Shodan `hostname:` / `net:` search | ports, banners, product + version, OS fingerprints |
| Fingerprint | `httpx` against 80/443/8080/8443 | `Server` / `X-Powered-By`, status, page title |
| CVE mapping | bundled catalogue → CIRCL → NVD | CVE id, CVSS, severity, match confidence |
| Diff | previous scan of the same target | new / closed / changed services, new CVEs |

Collection degrades gracefully:

* **No Shodan key** — still works: certificate transparency plus HTTP
  fingerprinting produces real assets and real versions.
* **No NVD key** — CIRCL and the bundled catalogue are used instead; NVD keyword
  search is skipped because its keyless rate limit would stall a scan.
* **No network at all** — demo mode synthesises a deterministic estate per
  target so the product can be evaluated offline.

Progress is written to the `scan_runs` row at each stage, which is why the
progress bar keeps working even if the browser reconnects mid-scan.

### Scan mode belongs to the target

Each target carries its own `mode` (`live` or `demo`). A demo scope replays the
synthetic estate generator instead of touching the network — otherwise a scan of
a reserved hostname such as `demo.example.com` would resolve to nothing and
close every asset. The Settings default only applies to live scopes, and any
hostname under an RFC 2606/6761 reserved suffix (`.example`, `.test`,
`.invalid`, `.localhost`, `.local`) is created as a demo scope automatically.

Demo scopes also advance: each scan continues the synthetic timeline from the
number of recorded scans, so a repeat run still reveals fresh services and
occasionally retires one.

### An empty result set never closes the estate

If a live pass collects zero services while the target already has inventory,
the previous assets are kept and the scan is flagged with a warning. A blocked
Shodan key, a CT rate limit or a DNS outage looks exactly like "everything was
decommissioned", and silently wiping the history is the wrong default for a
recon tool. Closures are only recorded when a scan actually collected something.

## CVE correlation

Service banners such as `Apache/2.4.49` or `OpenSSH_8.2p1` are parsed into
product + version, then matched three ways:

1. **Bundled catalogue** (`recon/services/cve_catalog.py`) — ~60 well-known CVEs
   for internet-facing software, each with an explicit version constraint
   (`>=2.0,<2.15.0`). Deterministic, offline, no rate limits.
2. **CIRCL CVE Search** — free and key-less; returns CPE configurations that are
   version-matched against the detected banner.
3. **NVD API 2.0** — used only when a key is configured.

Every finding carries a **confidence**: `high` for an exact version match,
`low` when only the product matched and the version could not be verified. The
UI shows it, and the PDF report prints it, because a version match is an
indicator — not proof of exploitability.

## Data model

* `targets` — monitored scopes, their schedule and last scan.
* `scan_runs` — one row per execution: stage, progress, KPI counters, error.
* `assets` — stable per `ip:port/proto` with `first_seen` / `last_seen`, so
  growth is a query rather than a diff of blobs.
* `vulnerabilities` — CVE records cached locally; reports work offline.
* `asset_vulnerabilities` — which CVE hits which asset, with provenance.
* `change_events` — append-only log of new/closed/changed assets and new CVEs.
  The dashboard feed and the PDF diff are both rendered from it.

## Scheduling

`APScheduler` runs a dispatcher every 10 minutes. Any target with
`schedule = daily | weekly` whose last scan is older than its interval is
scanned in a worker thread (fresh event loop via `asyncio.run`). Targets with an
in-flight scan are skipped. Set the schedule per target on the Targets page.

## Reports

* **Per scan** — `data/reports/recon_scan<id>.pdf`: KPIs, severity summary, new
  assets since the previous scan, disappeared assets, prioritised findings with
  confidence, full inventory, change log.
* **Estate** — `data/reports/estate_summary_<ts>.pdf`: one row per target.

Both are downloadable from the UI (Scans page / header buttons).

## CLI

```bash
python -m scripts.seed              # list targets
python -m scripts.seed demo         # demo estate + backdated history
python -m scripts.seed add example.com
python -m scripts.seed scan 1
python -m scripts.smoke             # end-to-end backend check incl. PDFs
python -m scripts.verify_modes      # regression: per-target modes + empty-scan guard
```

Browser-side checks (need a headless Edge/Chrome on port 9222):

```bash
node scripts/capture_pages.mjs      # screenshot every route into shots/
node scripts/measure_plots.mjs      # assert each chart matches its card width
node scripts/e2e_click.mjs http://localhost:3000/ shots   # click-through smoke test
```

## Project layout

```
ReconDashboard/
├── rxconfig.py               Reflex config (ports, app name)
├── recon/
│   ├── recon.py              app entry, routes
│   ├── models.py             Peewee models (SQLite)
│   ├── db.py                 engine, WAL pragmas, session_scope
│   ├── queries.py            read models -> plain dicts for the UI
│   ├── state.py              AppState: loaders, filters, background scan
│   ├── components/           theme tokens, sidebar shell, primitives
│   ├── pages/                dashboard, targets, assets, vulns, scans, settings
│   └── services/
│       ├── crtsh.py          certificate transparency enumeration
│       ├── shodan_client.py  Shodan SDK in threads + banner parsing
│       ├── probe.py          async HTTP fingerprinting
│       ├── cve_catalog.py    bundled CVE corpus + version range logic
│       ├── cve_lookup.py     CIRCL / NVD clients, confidence merge
│       ├── demo.py           deterministic synthetic estate
│       ├── scanner.py        the 5-stage pipeline + diff engine
│       ├── scheduler.py      APScheduler dispatcher
│       └── report.py         ReportLab PDFs
├── scripts/                  seed, smoke, verify_modes + CDP browser checks
├── assets/plotly-fit.js      re-fits Plotly charts to their cards
└── data/                     recon.db, reports/
```

## Design notes

* **Why Peewee, not SQLAlchemy** — this host enforces an application-control
  policy that blocks SQLAlchemy's compiled C extensions
  (`ImportError: DLL load failed ... blocked by policy`). Peewee is pure Python,
  so it runs anywhere, and the schema stays declarative.
* **Why progress lives in the database** — a Reflex background handler runs in a
  different task from the scan; polling the row keeps the two decoupled and
  survives reconnects.
* **Why figures are stored as JSON** — `json.loads(fig.to_json())` keeps numpy
  types out of the state payload, which Reflex would otherwise fail to
  serialise.
* **Why change events are append-only** — the diff is the product. Being able to
  answer "what appeared on Tuesday?" is the whole point of storing history.
* **Why charts need `assets/plotly-fit.js`** — react-plotly mounts its graph div
  as `display: inline-block` with no width, so Plotly measures 0 and falls back
  to its 700x450 default, overflowing every card. The script makes the div a
  block, then calls `Plotly.Plots.resize()` once the parent has a real width.
  `config.responsive` alone is not enough: it only listens for window resizes.

## Authorization

Only scan infrastructure you own or are explicitly authorised to assess.
Certificate transparency and Shodan are passive, but HTTP fingerprinting and any
port interaction still touch third-party systems. The tool performs no
exploitation, no authentication attempts and no brute forcing — it reads what
services volunteer.
