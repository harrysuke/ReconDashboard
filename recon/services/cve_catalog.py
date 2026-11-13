"""Bundled CVE catalog used for offline / fallback matching.

Live lookups (CIRCL, NVD) are authoritative, but recon must still work on an
air-gapped box or without API keys. This catalog contains well-known CVEs for
the services that show up most often in internet-wide scans, together with the
version range each one affects.

Each entry:
    cve_id, title, cvss, severity (derived), vector, published, exploited,
    products  -> lowercase tokens matched against the detected product/service
    affected  -> version constraint string understood by :func:`version_in_range`
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# version helpers
# --------------------------------------------------------------------------- #

_VER_RE = re.compile(r"\d+|[a-zA-Z]+")


def _vparts(version: str) -> list[int]:
    """'1.18.0-1ubuntu1' -> [1, 18, 0, 1] (letters dropped, digits kept in order)."""
    parts: list[int] = []
    for token in _VER_RE.findall(str(version).lower()):
        if token.isdigit():
            parts.append(int(token))
        else:
            # map common pre-release suffixes so '2.0.0-rc1' < '2.0.0'
            parts.append({"alpha": -3, "beta": -2, "rc": -1}.get(token, 0))
    return parts or [0]


def compare_versions(a: str, b: str) -> int:
    pa, pb = _vparts(a), _vparts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def version_in_range(version: str, constraint: str) -> bool:
    """Evaluate a constraint such as ``>=2.0,<2.15.0`` or ``==2.4.49``.

    An empty constraint means "all versions of this product are affected".
    """
    if not constraint or not version:
        return True
    for clause in constraint.split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"(>=|<=|==|>|<)?\s*(.+)$", clause)
        if not m:
            continue
        op, target = (m.group(1) or "=="), m.group(2).strip()
        cmp = compare_versions(version, target)
        ok = {
            ">=": cmp >= 0,
            "<=": cmp <= 0,
            "==": cmp == 0,
            ">": cmp > 0,
            "<": cmp < 0,
        }[op]
        if not ok:
            return False
    return True


def severity_for(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #

CATALOG: list[dict] = [
    # --- Java / middleware -------------------------------------------------
    dict(cve_id="CVE-2021-44228", title="Log4Shell: JNDI remote code execution in Log4j 2",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2021-12-10",
         exploited=True, products=["log4j", "log4j2", "apache log4j"], affected=">=2.0,<2.15.0",
         description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints, "
                     "allowing unauthenticated remote code execution via a crafted log message."),
    dict(cve_id="CVE-2021-45046", title="Log4j 2.15.0 incomplete fix for JNDI lookup",
         cvss=9.0, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2021-12-14",
         exploited=True, products=["log4j", "log4j2"], affected=">=2.15.0,<2.16.0",
         description="The fix for CVE-2021-44228 was incomplete in certain non-default configurations, "
                     "still permitting data exfiltration and RCE."),
    dict(cve_id="CVE-2021-44832", title="Log4j 2.17.0 JDBC appender RCE",
         cvss=6.6, vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", published="2021-12-28",
         exploited=False, products=["log4j", "log4j2"], affected=">=2.17.0,<2.17.1",
         description="An attacker with permission to modify the logging configuration can construct a "
                     "malicious configuration using a JDBC Appender, resulting in RCE."),
    dict(cve_id="CVE-2017-5638", title="Apache Struts 2 Jakarta Multipart parser RCE",
         cvss=10.0, vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2017-03-10",
         exploited=True, products=["struts", "struts2", "apache struts"], affected=">=2.3.5,<2.3.32",
         description="The Jakarta Multipart parser in Apache Struts 2 mishandles the Content-Type header, "
                     "allowing OGNL injection and remote code execution (Equifax breach)."),
    dict(cve_id="CVE-2022-22965", title="Spring4Shell: Spring Framework data binding RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2022-04-01",
         exploited=True, products=["spring", "spring framework", "spring boot"], affected=">=5.3.0,<5.3.18",
         description="Data binding in Spring MVC/WebFlux on JDK 9+ allows remote code execution through "
                     "manipulation of class loader properties."),
    dict(cve_id="CVE-2020-1938", title="Ghostcat: Apache Tomcat AJP file inclusion",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2020-02-24",
         exploited=True, products=["tomcat", "apache tomcat"], affected=">=7.0.0,<9.0.31",
         description="The AJP connector is enabled by default and allows reading files from the webapp and "
                     "potentially RCE if file upload is available."),
    dict(cve_id="CVE-2023-45648", title="Apache Tomcat request smuggling",
         cvss=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", published="2023-10-13",
         exploited=False, products=["tomcat"], affected=">=10.1.0,<10.1.14",
         description="Tomcat did not correctly parse HTTP trailer headers, enabling request smuggling "
                     "when behind a reverse proxy."),
    dict(cve_id="CVE-2020-14882", title="Oracle WebLogic Console unauthenticated RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2020-10-20",
         exploited=True, products=["weblogic", "oracle weblogic"], affected=">=12.2.1.3,<12.2.1.4",
         description="The WebLogic Console allows unauthenticated attackers to execute arbitrary code over "
                     "HTTP (used by DarkIRC / cve-2020-14882 botnets)."),
    dict(cve_id="CVE-2022-26134", title="Atlassian Confluence OGNL injection RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2022-06-02",
         exploited=True, products=["confluence", "atlassian confluence"], affected=">=7.4.0,<7.18.1",
         description="An unauthenticated OGNL injection vulnerability allows remote code execution on "
                     "Confluence Server and Data Center."),
    dict(cve_id="CVE-2023-22515", title="Confluence privilege escalation to administrator",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2023-10-04",
         exploited=True, products=["confluence"], affected=">=8.0.0,<8.5.2",
         description="Externally accessible Confluence instances allow unauthenticated attackers to create "
                     "unauthorised administrator accounts."),
    dict(cve_id="CVE-2021-26855", title="ProxyLogon: Exchange Server SSRF",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-03-02",
         exploited=True, products=["exchange", "microsoft exchange"], affected=">=15.0.0,<15.2.0",
         description="A server-side request forgery in Exchange allows an unauthenticated attacker to send "
                     "arbitrary HTTP requests and authenticate as the Exchange server."),
    dict(cve_id="CVE-2021-34473", title="ProxyShell: Exchange ACL bypass RCE chain",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-07-13",
         exploited=True, products=["exchange"], affected=">=15.0.0,<15.2.0",
         description="Pre-auth path confusion in Exchange leads to ACL bypass and, chained with other "
                     "flaws, unauthenticated remote code execution."),
    # --- web servers -------------------------------------------------------
    dict(cve_id="CVE-2021-41773", title="Apache httpd 2.4.49 path traversal / RCE",
         cvss=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", published="2021-10-05",
         exploited=True, products=["httpd", "apache httpd", "apache", "apache http server"],
         affected="==2.4.49",
         description="A flaw in path normalisation allows path traversal; with mod_cgi enabled it escalates "
                     "to remote code execution."),
    dict(cve_id="CVE-2021-42013", title="Apache httpd 2.4.50 path traversal / RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-10-07",
         exploited=True, products=["httpd", "apache httpd", "apache", "apache http server"],
         affected="==2.4.50",
         description="Incomplete fix for CVE-2021-41773 still allows path traversal and RCE when mod_cgi "
                     "or mod_cgid is enabled."),
    dict(cve_id="CVE-2019-0211", title="Apache httpd privilege escalation via scoreboard",
         cvss=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", published="2019-04-08",
         exploited=False, products=["httpd", "apache httpd", "apache"], affected=">=2.4.17,<2.4.39",
         description="A local user can escalate to root by manipulating the shared scoreboard through "
                     "MPM event/worker request handling."),
    dict(cve_id="CVE-2021-23017", title="nginx resolver off-by-one heap overflow",
         cvss=7.7, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2021-06-01",
         exploited=False, products=["nginx"], affected=">=0.6.18,<1.21.0",
         description="A DNS response with a crafted name can trigger a one-byte heap overwrite in the "
                     "nginx resolver, potentially allowing worker process takeover."),
    dict(cve_id="CVE-2019-20372", title="nginx HTTP request smuggling via error_page",
         cvss=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", published="2020-01-09",
         exploited=False, products=["nginx"], affected=">=1.0.0,<1.17.7",
         description="Error page handling can be abused to smuggle requests to upstream servers."),
    dict(cve_id="CVE-2019-11043", title="PHP-FPM underflow RCE (nginx + fastcgi)",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-10-28",
         exploited=True, products=["php", "php-fpm"], affected=">=7.1.0,<7.3.11",
         description="A bug in the FPM SAPI path handling allows remote code execution when nginx passes "
                     "certain crafted paths to PHP-FPM."),
    dict(cve_id="CVE-2024-4577", title="PHP CGI argument injection on Windows",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2024-06-07",
         exploited=True, products=["php", "php-cgi"], affected=">=8.1.0,<8.3.8",
         description="Best-fit encoding conversion on Windows allows argument injection into PHP-CGI, "
                     "leading to remote code execution."),
    # --- remote access -----------------------------------------------------
    dict(cve_id="CVE-2023-38408", title="OpenSSH PKCS#11 remote code execution",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2023-07-20",
         exploited=False, products=["openssh", "ssh", "openbsd openssh"], affected="<9.3p2",
         description="The PKCS#11 feature of ssh-agent lacks sufficient trust checks, allowing RCE via a "
                     "malicious PKCS#11 provider if agent forwarding is used."),
    dict(cve_id="CVE-2018-15473", title="OpenSSH username enumeration",
         cvss=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", published="2018-08-17",
         exploited=False, products=["openssh", "ssh"], affected="<7.8",
         description="OpenSSH does not delay invalid authentication requests until the authentication "
                     "cycle is complete, leaking valid usernames."),
    dict(cve_id="CVE-2024-6387", title="regreSSHion: OpenSSH unauthenticated RCE",
         cvss=8.1, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2024-07-01",
         exploited=True, products=["openssh", "ssh"], affected=">=8.5p1,<9.8p1",
         description="A signal handler race condition in sshd allows unauthenticated remote code execution "
                     "as root on glibc-based Linux."),
    dict(cve_id="CVE-2019-0708", title="BlueKeep: RDP pre-auth RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-05-14",
         exploited=True, products=["rdp", "remote desktop", "terminal services"], affected="<10.0",
         description="A use-after-free in Remote Desktop Services allows unauthenticated remote code "
                     "execution; wormable."),
    dict(cve_id="CVE-2017-0144", title="EternalBlue: SMBv1 remote code execution",
         cvss=8.1, vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2017-03-16",
         exploited=True, products=["smb", "smbv1", "microsoft-ds", "netbios-ssn"], affected="",
         description="The SMBv1 server mishandles specially crafted packets, enabling remote code execution "
                     "(WannaCry / NotPetya)."),
    dict(cve_id="CVE-2020-0796", title="SMBGhost: SMBv3 compression RCE",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2020-03-12",
         exploited=True, products=["smb", "smbv3"], affected="<10.0",
         description="A buffer overflow in SMBv3 compression handling allows unauthenticated remote code "
                     "execution on Windows 10 1903/1909 and Server 1903/1909."),
    dict(cve_id="CVE-2020-1472", title="Zerologon: Netlogon privilege escalation",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2020-08-17",
         exploited=True, products=["netlogon", "domain controller", "ldap"], affected="",
         description="An unauthenticated attacker with network access to a domain controller can gain "
                     "domain administrator privileges via AES-CFB8 with an all-zero IV."),
    dict(cve_id="CVE-2021-34527", title="PrintNightmare: Windows Print Spooler RCE",
         cvss=8.8, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", published="2021-07-01",
         exploited=True, products=["print spooler", "ipp", "microsoft-ds"], affected="",
         description="The Windows Print Spooler service allows remote code execution with SYSTEM privileges "
                     "when the attacker can load a driver."),
    # --- VPN / edge devices ------------------------------------------------
    dict(cve_id="CVE-2019-11510", title="Pulse Secure VPN arbitrary file read",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2019-05-08",
         exploited=True, products=["pulse secure", "pulse", "connect secure"], affected="<8.3",
         description="Unauthenticated arbitrary file read exposes session data and credentials, enabling "
                     "full VPN compromise."),
    dict(cve_id="CVE-2019-19781", title="Citrix ADC / NetScaler path traversal RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-12-17",
         exploited=True, products=["citrix", "netscaler", "adc"], affected=">=10.5,<13.0.47",
         description="Directory traversal in the Citrix ADC VPN endpoint allows unauthenticated code "
                     "execution."),
    dict(cve_id="CVE-2023-4966", title="Citrix Bleed: NetScaler session token leak",
         cvss=9.4, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", published="2023-10-10",
         exploited=True, products=["citrix", "netscaler", "adc"], affected=">=13.1.0,<13.1.49",
         description="Sensitive information disclosure in NetScaler ADC/Gateway allows session token "
                     "hijacking and MFA bypass."),
    dict(cve_id="CVE-2018-13379", title="Fortinet FortiOS SSL-VPN path traversal",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-05-28",
         exploited=True, products=["fortios", "fortigate", "fortinet", "ssl-vpn"], affected="<6.0.5",
         description="A path traversal in the SSL-VPN portal allows unauthenticated download of the "
                     "session file containing plaintext credentials."),
    dict(cve_id="CVE-2022-40684", title="Fortinet authentication bypass on admin interface",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2022-10-06",
         exploited=True, products=["fortios", "fortiproxy", "fortinet"], affected=">=7.0.0,<7.2.2",
         description="An authentication bypass using an alternate path or channel allows an attacker to "
                     "perform admin operations on the administrative interface."),
    dict(cve_id="CVE-2022-1388", title="F5 BIG-IP iControl REST authentication bypass",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2022-05-04",
         exploited=True, products=["big-ip", "f5", "bigip"], affected=">=16.1.0,<16.1.3",
         description="Undisclosed requests may bypass iControl REST authentication, allowing command "
                     "execution as root."),
    dict(cve_id="CVE-2023-46747", title="F5 BIG-IP configuration utility auth bypass",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2023-10-26",
         exploited=True, products=["big-ip", "f5"], affected=">=17.0.0,<17.1.0",
         description="Undisclosed requests to the configuration utility can bypass authentication and "
                     "execute arbitrary system commands."),
    dict(cve_id="CVE-2024-3400", title="PAN-OS GlobalProtect command injection",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2024-04-12",
         exploited=True, products=["pan-os", "globalprotect", "palo alto"], affected=">=10.2.0,<11.1.2",
         description="A command injection vulnerability in GlobalProtect allows an unauthenticated attacker "
                     "to execute arbitrary code with root privileges."),
    dict(cve_id="CVE-2024-21887", title="Ivanti Connect Secure command injection",
         cvss=9.1, vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", published="2024-01-10",
         exploited=True, products=["ivanti", "connect secure", "pulse secure"], affected=">=9.0,<22.6",
         description="Command injection in web components of Ivanti Connect Secure allows an authenticated "
                     "administrator to execute arbitrary commands; chained pre-auth with CVE-2023-46805."),
    dict(cve_id="CVE-2023-46805", title="Ivanti Connect Secure authentication bypass",
         cvss=8.2, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", published="2024-01-10",
         exploited=True, products=["ivanti", "connect secure"], affected=">=9.0,<22.6",
         description="An authentication bypass in the web component allows access to restricted resources."),
    # --- email / collaboration --------------------------------------------
    dict(cve_id="CVE-2023-34362", title="MOVEit Transfer SQL injection",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2023-06-02",
         exploited=True, products=["moveit", "moveit transfer", "ipswitch"], affected="<2023.0.1",
         description="SQL injection in MOVEit Transfer allows unauthenticated access to the database and "
                     "webshell deployment (Cl0p mass exploitation)."),
    dict(cve_id="CVE-2019-9670", title="Zimbra XXE in Autodiscover",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-03-25",
         exploited=True, products=["zimbra"], affected="<8.8.11",
         description="An XML external entity vulnerability in the Autodiscover service allows reading local "
                     "files and, chained with CVE-2019-9621, remote code execution."),
    # --- container / orchestration ----------------------------------------
    dict(cve_id="CVE-2018-1002105", title="Kubernetes API server privilege escalation",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2018-12-05",
         exploited=True, products=["kubernetes", "kube-apiserver", "k8s"], affected="<1.10.12",
         description="A flaw in the API server proxy allows an authenticated user to escalate privileges "
                     "and issue API calls with the server's credentials."),
    dict(cve_id="CVE-2021-25741", title="Kubernetes subPath symlink container escape",
         cvss=8.1, vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", published="2021-09-20",
         exploited=False, products=["kubernetes", "k8s"], affected=">=1.19.0,<1.22.4",
         description="A symlink exchange in subPath volume mounts can expose the host filesystem to a "
                     "container."),
    dict(cve_id="CVE-2019-5736", title="runc container escape",
         cvss=8.6, vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2019-02-11",
         exploited=True, products=["docker", "runc", "containerd"], affected="<1.0.0",
         description="runc can be tricked into overwriting the host runc binary, allowing container escape "
                     "to the host."),
    dict(cve_id="CVE-2024-21626", title="runc leaked file descriptor container escape",
         cvss=8.6, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", published="2024-01-31",
         exploited=False, products=["docker", "runc"], affected=">=1.0.0,<1.1.12",
         description="An internal file descriptor leak allows a container process to access the host "
                     "filesystem."),
    # --- databases ---------------------------------------------------------
    dict(cve_id="CVE-2012-2122", title="MySQL / MariaDB authentication bypass",
         cvss=7.5, vector="CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", published="2012-06-05",
         exploited=True, products=["mysql", "mariadb"], affected="<5.5.24",
         description="Repeated authentication attempts can succeed due to a flawed memcmp return value "
                     "check, bypassing the password."),
    dict(cve_id="CVE-2019-10149", title="Exim remote command execution",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-06-05",
         exploited=True, products=["exim", "exim4"], affected=">=4.87,<4.92",
         description="Improper validation of recipient addresses allows remote command execution in Exim "
                     "4.87-4.91 (The Return of the WIZard)."),
    dict(cve_id="CVE-2020-7247", title="OpenSMTPD command injection",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2020-01-29",
         exploited=True, products=["opensmtpd", "smtpd"], affected="==6.6",
         description="A shell metacharacter injection in the SMTP parser allows unauthenticated local "
                     "command execution as root."),
    dict(cve_id="CVE-2023-44487", title="HTTP/2 Rapid Reset denial of service",
         cvss=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", published="2023-10-10",
         exploited=True, products=["http2", "nginx", "envoy", "haproxy"], affected="",
         description="Rapid stream cancellation over HTTP/2 allows a modest botnet to exhaust server "
                     "resources, causing denial of service."),
    dict(cve_id="CVE-2021-22986", title="F5 BIG-IP iControl REST unauthenticated RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-03-31",
         exploited=True, products=["big-ip", "f5"], affected=">=16.0.0,<16.0.1",
         description="The iControl REST interface allows unauthenticated remote command execution."),
    dict(cve_id="CVE-2019-1663", title="Cisco RV router stack overflow",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2019-02-27",
         exploited=True, products=["cisco", "rv016", "rv042", "rv082"], affected="<1.0.3",
         description="A stack-based buffer overflow in the web interface allows unauthenticated remote code "
                     "execution."),
    dict(cve_id="CVE-2023-20198", title="Cisco IOS XE Web UI privilege escalation",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2023-10-16",
         exploited=True, products=["ios xe", "cisco ios", "cisco"], affected="",
         description="The IOS XE web UI allows an unauthenticated attacker to create a local account with "
                     "level 15 privileges."),
    dict(cve_id="CVE-2021-36260", title="Hikvision IP camera command injection",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-09-18",
         exploited=True, products=["hikvision", "ip camera"], affected="",
         description="A command injection in the web server allows unauthenticated remote code execution on "
                     "many camera and NVR models."),
    dict(cve_id="CVE-2023-1389", title="TP-Link Archer AX21 command injection",
         cvss=8.8, vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2023-03-15",
         exploited=True, products=["tp-link", "archer", "tplink"], affected="<1.1.4",
         description="Unauthenticated command injection in the locale endpoint allows remote code execution "
                     "on the LAN interface."),
    dict(cve_id="CVE-2020-8515", title="DrayTek Vigor router RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2020-03-04",
         exploited=True, products=["draytek", "vigor"], affected="<1.5.1",
         description="Multiple shell injection flaws in the web UI allow unauthenticated remote command "
                     "execution."),
    # --- libraries ---------------------------------------------------------
    dict(cve_id="CVE-2014-0160", title="Heartbleed: OpenSSL TLS heartbeat read overrun",
         cvss=7.5, vector="CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N", published="2014-04-07",
         exploited=True, products=["openssl"], affected=">=1.0.1,<1.0.1g",
         description="A missing bounds check in the TLS heartbeat extension leaks up to 64KB of process "
                     "memory per request, including private keys and session data."),
    dict(cve_id="CVE-2022-0778", title="OpenSSL BN_mod_sqrt infinite loop DoS",
         cvss=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", published="2022-03-15",
         exploited=False, products=["openssl"], affected=">=1.1.1,<1.1.1n",
         description="Parsing a crafted certificate with invalid explicit curve parameters triggers an "
                     "infinite loop, causing denial of service."),
    dict(cve_id="CVE-2021-3711", title="OpenSSL SM2 decryption buffer overflow",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-08-24",
         exploited=False, products=["openssl"], affected=">=1.1.1,<1.1.1l",
         description="A buffer overflow in SM2 decryption can crash the process or possibly change "
                     "application behaviour."),
    dict(cve_id="CVE-2019-11358", title="jQuery prototype pollution",
         cvss=6.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", published="2019-04-20",
         exploited=False, products=["jquery"], affected="<3.4.0",
         description="jQuery.extend performs a deep merge that can be abused for prototype pollution."),
    dict(cve_id="CVE-2022-21449", title="Java ECDSA 'Psychic Signatures'",
         cvss=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", published="2022-04-19",
         exploited=False, products=["java", "openjdk", "jdk"], affected=">=15.0,<18.0.1",
         description="ECDSA signature verification accepts blank signatures, allowing authentication "
                     "bypass in Java 15-18."),
    dict(cve_id="CVE-2021-3156", title="sudo Baron Samedit heap overflow",
         cvss=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", published="2021-01-26",
         exploited=True, products=["sudo"], affected=">=1.8.2,<1.9.5",
         description="A heap-based buffer overflow in sudoedit argument parsing allows any local user to "
                     "gain root."),
    dict(cve_id="CVE-2022-0847", title="Dirty Pipe: Linux kernel privilege escalation",
         cvss=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", published="2022-03-10",
         exploited=True, products=["linux", "kernel"], affected=">=5.8,<5.16.11",
         description="An uninitialised flag in pipe buffers allows overwriting read-only files, enabling "
                     "local privilege escalation."),
    dict(cve_id="CVE-2021-4034", title="PwnKit: polkit pkexec privilege escalation",
         cvss=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", published="2022-01-25",
         exploited=True, products=["polkit", "pkexec"], affected="<0.120",
         description="pkexec mishandles argv[0], allowing any local user to gain root on default "
                     "installations of most Linux distributions."),
    dict(cve_id="CVE-2023-3519", title="Citrix ADC unauthenticated RCE",
         cvss=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2023-07-19",
         exploited=True, products=["citrix", "netscaler"], affected=">=13.1.0,<13.1.49",
         description="A stack overflow in the NetScaler ADC/Gateway allows unauthenticated remote code "
                     "execution."),
    dict(cve_id="CVE-2024-1709", title="ConnectWise ScreenConnect auth bypass",
         cvss=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published="2024-02-19",
         exploited=True, products=["screenconnect", "connectwise"], affected="<23.9.8",
         description="An authentication bypass allows creation of administrator accounts, leading to "
                     "remote code execution."),
]


def as_records() -> list[dict]:
    """Normalise catalog entries for DB insertion."""
    out = []
    for entry in CATALOG:
        item = dict(entry)
        item["severity"] = severity_for(float(item["cvss"]))
        item["url"] = f"https://nvd.nist.gov/vuln/detail/{item['cve_id']}"
        item["source"] = "local"
        out.append(item)
    return out
