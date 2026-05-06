import json
import re
from pathlib import Path

CVE_DB_PATH = Path(__file__).parent.parent / "data" / "cve.json"
_db: dict | None = None


def _load() -> dict:
    global _db
    if _db is None:
        _db = json.loads(CVE_DB_PATH.read_text(encoding="utf-8"))
    return _db


def _parse_version(s: str) -> tuple[int, int, int]:
    m = re.search(r"(\d+)\.(\d+)(?:[._p-](\d+))?", s)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return (0, 0, 0)


def _check_range(version: tuple, range_str: str) -> bool:
    r = range_str.strip()
    if "," in r:
        return all(_check_range(version, part.strip()) for part in r.split(","))
    if r.startswith("<= "):
        return version <= _parse_version(r[3:])
    if r.startswith("< "):
        return version < _parse_version(r[2:])
    if r.startswith(">= "):
        return version >= _parse_version(r[3:])
    if r.startswith("> "):
        return version > _parse_version(r[2:])
    if r == "all":
        return True
    return True


def _version_in_range(detected: str, affected_ranges: list[str]) -> bool:
    if not detected or not affected_ranges:
        return True
    version = _parse_version(detected)
    if version == (0, 0, 0):
        return True
    return any(_check_range(version, r) for r in affected_ranges)


def _service_matches(service_key: str, service_name: str, version_str: str) -> bool:
    name_lower = service_name.lower()
    ver_lower = version_str.lower()
    combined = name_lower + " " + ver_lower
    return service_key in combined or any(
        alias in combined
        for alias in {
            "openssh": ["openssh", "ssh"],
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "tomcat": ["tomcat", "coyote"],
            "mysql": ["mysql", "mariadb"],
            "postgresql": ["postgresql", "postgres"],
            "redis": ["redis"],
            "mongodb": ["mongodb", "mongod"],
            "elasticsearch": ["elasticsearch"],
            "jenkins": ["jenkins"],
            "wordpress": ["wordpress"],
            "iis": ["iis", "microsoft-iis"],
            "php": ["php"],
            "spring": ["spring"],
            "log4j": ["log4j", "log4shell"],
            "openssl": ["openssl"],
            "smb": ["smb", "samba", "netbios"],
            "rdp": ["rdp", "ms-wbt-server", "terminal service"],
            "vnc": ["vnc", "rfb"],
            "winrm": ["winrm", "wsman"],
            "jboss": ["jboss", "wildfly"],
            "weblogic": ["weblogic"],
            "struts": ["struts"],
            "drupal": ["drupal"],
            "joomla": ["joomla"],
            "icecast": ["icecast"],
            "msrpc": ["msrpc", "microsoft windows rpc", "rpc"],
            "netbios": ["netbios", "netbios-ssn"],
            "winrm": ["winrm", "wsman", "httpapi"],
            "ftp": ["ftp", "vsftpd", "proftpd", "filezilla"],
            "smtp": ["smtp", "postfix", "exim", "sendmail", "opensmtpd"],
            "snmp": ["snmp"],
            "ldap": ["ldap", "active directory"],
            "kerberos": ["kerberos", "krb5"],
            "mssql": ["mssql", "ms-sql", "microsoft sql"],
            "docker": ["docker"],
            "kubernetes": ["kubernetes", "k8s", "kube"],
            "memcached": ["memcached"],
            "cassandra": ["cassandra"],
            "zookeeper": ["zookeeper"],
        }.get(service_key, [service_key])
    )


def match_service_version(service: str, version: str) -> list[dict]:
    db = _load()
    results = []
    for service_key, service_data in db["services"].items():
        if _service_matches(service_key, service, version):
            for cve in service_data.get("cves", []):
                if _version_in_range(version, cve.get("affected_versions", [])):
                    results.append({**cve, "service_key": service_key})
    results.sort(key=lambda x: x.get("cvss", 0), reverse=True)
    return results


def scan_ports_to_cves(ports) -> list[dict]:
    seen: set[str] = set()
    results = []
    for port in ports:
        cves = match_service_version(port.service, port.version)
        for cve in cves:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                results.append({**cve, "port": port.number, "port_service": port.service})
    return sorted(results, key=lambda x: x.get("cvss", 0), reverse=True)


def format_cves_for_llm(cves: list[dict]) -> str:
    if not cves:
        return ""
    lines = ["\nCVE INTELLIGENCE (version-matched, CVSS descending):"]
    for c in cves[:20]:
        msf = f"MSF: {c['metasploit']}" if c.get("metasploit") else "MSF: —"
        poc = "PoC: mevcut" if c.get("poc") else "PoC: —"
        patch = f"Patch: {c['patch']}" if c.get("patch") else "Patch: —"
        lines.append(
            f"  [CVSS {c.get('cvss','?')}] {c['id']} | Port {c.get('port','?')} ({c.get('port_service','')}) | "
            f"MITRE: {c.get('mitre','N/A')} | {msf} | {poc} | {patch}\n"
            f"    → {c.get('description','')}"
        )
    return "\n".join(lines)


def print_cve_table(cves: list[dict], console) -> None:
    if not cves:
        return
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.text import Text

    table = Table(
        "CVSS", "CVE ID", "Port", "Servis", "MITRE", "MSF", "Açıklama",
        box=box.SIMPLE_HEAD,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )
    for c in cves[:15]:
        cvss = c.get("cvss", 0)
        if cvss >= 9.0:
            cvss_style = "bold red"
        elif cvss >= 7.0:
            cvss_style = "bold orange3"
        elif cvss >= 4.0:
            cvss_style = "bold yellow"
        else:
            cvss_style = "green"

        table.add_row(
            Text(str(cvss), style=cvss_style),
            c["id"],
            str(c.get("port", "?")),
            c.get("port_service", c.get("service_key", "")),
            c.get("mitre", "—"),
            c.get("metasploit") or "—",
            c.get("description", "")[:60],
        )
    console.print(Panel(
        table,
        title=f"[bold]CVE İstihbaratı — {len(cves)} Eşleşme[/bold]",
        border_style="red",
    ))
