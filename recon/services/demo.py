"""Deterministic demo dataset.

The dashboard must be explorable without a Shodan key and without touching
third-party infrastructure, so demo mode synthesises a plausible estate for a
target: web front ends, VPN concentrators, mail, CI, databases and the odd
forgotten staging box.

Everything is derived from a hash of the target value, so the same target always
produces the same estate, and *later* scans see *more* assets - which is what
makes the asset-growth chart and the diff engine meaningful.
"""

from __future__ import annotations

import hashlib
import random

from recon.services.shodan_client import RawAsset

# (port, service, product, version, title, tls)
_SERVICE_POOL: list[tuple[int, str, str, str, str, bool]] = [
    (443, "https", "nginx", "1.18.0", "Welcome to nginx!", True),
    (443, "https", "Apache httpd", "2.4.49", "Apache2 Ubuntu Default Page", True),
    (80, "http", "Apache httpd", "2.4.49", "It works!", False),
    (443, "https", "nginx", "1.24.0", "Example CDN edge", True),
    (22, "ssh", "OpenSSH", "8.2p1", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", False),
    (22, "ssh", "OpenSSH", "9.2p1", "SSH-2.0-OpenSSH_9.2p1 Debian-2", False),
    (3389, "rdp", "Microsoft Terminal Services", "", "Remote Desktop", False),
    (445, "smb", "Microsoft Windows SMB", "", "SMBv1 enabled", False),
    (8080, "http", "Apache Tomcat", "9.0.30", "Apache Tomcat/9.0.30", False),
    (8080, "http", "Apache Log4j", "2.14.1", "Java Application Server", False),
    (8443, "https", "Citrix NetScaler", "13.0.47", "Citrix Gateway", True),
    (10443, "https", "FortiOS SSL-VPN", "6.0.4", "SSL VPN Service", True),
    (25, "smtp", "Exim", "4.91", "220 mail ESMTP Exim 4.91", False),
    (3306, "mysql", "MySQL", "5.5.20", "MySQL 5.5.20", False),
    (6379, "redis", "Redis", "6.0.9", "Redis key-value store", False),
    (9200, "http", "Elasticsearch", "7.10.2", "You Know, for Search", False),
    (8080, "http", "Jenkins", "2.303.1", "Dashboard [Jenkins]", False),
    (443, "https", "GitLab", "13.10.2", "GitLab Community Edition", True),
    (6443, "https", "Kubernetes", "1.19.3", "Kubernetes API", True),
    (443, "https", "Zimbra", "8.8.10", "Zimbra Web Client", True),
    (7001, "http", "Oracle WebLogic", "12.2.1.3", "Error 404--Not Found", False),
    (8090, "http", "Atlassian Confluence", "7.13.0", "Confluence", False),
    (80, "http", "PHP", "8.1.2", "phpinfo()", False),
    (8888, "https", "Spring Framework", "5.3.10", "Whitelabel Error Page", True),
    (9000, "http", "Portainer", "2.6.3", "Portainer", False),
    (8081, "http", "Sonatype Nexus", "3.29.2", "Nexus Repository Manager", False),
]

_HOST_PREFIXES = [
    "www", "api", "app", "vpn", "mail", "dev", "staging", "jenkins", "gitlab",
    "portal", "admin", "cdn", "db", "ftp", "remote", "old", "test", "sso",
    "intranet", "backup", "monitor", "gw", "edge", "legacy",
]

_TITLES_FALLBACK = "Service"


def _seed(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:12], 16)


def plan_estate(value: str) -> list[dict]:
    """Build a stable, ordered 'master plan' of assets for a target."""
    rng = random.Random(_seed(value))
    is_ip_scope = value.replace(".", "").replace("/", "").isdigit()

    count = rng.randint(9, 16)
    plan: list[dict] = []
    used: set[str] = set()

    for idx in range(count):
        port, service, product, version, title, tls = rng.choice(_SERVICE_POOL)
        if (port, product) in used:
            port, service, product, version, title, tls = rng.choice(_SERVICE_POOL)
        used.add((port, product))

        if is_ip_scope:
            octet = (idx * 17 + rng.randint(2, 90)) % 250 + 2
            host = value.split("/")[0].rsplit(".", 1)[0] + f".{octet}"
            ip = host
            hostname = ""
        else:
            prefix = _HOST_PREFIXES[idx % len(_HOST_PREFIXES)]
            hostname = f"{prefix}.{value}" if idx else value
            ip = f"203.0.113.{rng.randint(10, 240)}"

        plan.append(
            {
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "title": title or _TITLES_FALLBACK,
                "tls": tls,
                "ip": ip,
                "hostname": hostname,
                # Staggered introduction so growth is visible across the seeded
                # history; the final asset only shows up in the live demo scan,
                # which is what makes "new assets" non-empty on first click.
                "appears_at": 0 if idx < 6 else (5 if idx == count - 1 else 1 + (idx % 4)),
                "disappears_at": 5 if idx == count - 2 and count > 11 else None,
            }
        )
    return plan


def build_demo_assets(value: str, scan_index: int) -> list[RawAsset]:
    """Assets visible at ``scan_index`` (0 = first historical scan)."""
    out: list[RawAsset] = []
    for item in plan_estate(value):
        if item["appears_at"] > scan_index:
            continue
        if item["disappears_at"] is not None and scan_index >= item["disappears_at"]:
            continue
        banner = f"{item['product']}/{item['version']}".strip("/")
        out.append(
            RawAsset(
                ip=item["ip"],
                port=item["port"],
                protocol="tcp",
                hostname=item["hostname"],
                service=item["service"],
                product=item["product"],
                version=item["version"],
                banner=banner or item["service"],
                os="Linux 4.x" if "Windows" not in item["product"] else "Windows Server 2016",
                tls=item["tls"],
                http_status=200 if item["service"] in ("http", "https") else 0,
                title=item["title"],
                sources={"demo"},
            )
        )
    return out


def demo_subdomains(value: str) -> list[str]:
    if value.replace(".", "").replace("/", "").isdigit():
        return []
    names = {a["hostname"] for a in plan_estate(value) if a["hostname"]}
    names.add(value)
    return sorted(names)
