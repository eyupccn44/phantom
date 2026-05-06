import json
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, field

@dataclass
class Subdomain:
    name: str
    ip: str = ""
    alive: bool = False
    source: str = ""


def _crtsh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "phantom-scanner/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            names = set()
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name and domain in name and " " not in name:
                        names.add(name.lower())
            return sorted(names)
    except Exception:
        return []


def _resolve(name: str) -> str:
    try:
        return socket.gethostbyname(name)
    except Exception:
        return ""


def _common_subs() -> list[str]:
    return [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "stage",
        "staging", "test", "portal", "admin", "dashboard", "app", "cdn",
        "static", "media", "img", "images", "beta", "old", "new", "login",
        "auth", "sso", "git", "gitlab", "jira", "confluence", "jenkins",
        "grafana", "kibana", "elastic", "db", "mysql", "redis", "mongo",
        "backup", "internal", "intranet", "corp", "mx", "mx1", "mx2",
    ]


def enumerate_subdomains(domain: str, brute: bool = True) -> list[Subdomain]:
    results: dict[str, Subdomain] = {}

    for name in _crtsh(domain):
        results[name] = Subdomain(name=name, source="crt.sh")

    if brute:
        for prefix in _common_subs():
            fqdn = f"{prefix}.{domain}"
            if fqdn not in results:
                results[fqdn] = Subdomain(name=fqdn, source="bruteforce")

    for sub in results.values():
        ip = _resolve(sub.name)
        if ip:
            sub.ip = ip
            sub.alive = True

    alive = [s for s in results.values() if s.alive]
    alive.sort(key=lambda x: x.name)
    return alive


def format_for_llm(subdomains: list[Subdomain]) -> str:
    if not subdomains:
        return ""
    lines = [f"\nSUBDOMAIN ENUMERATION ({len(subdomains)} aktif):"]
    for s in subdomains:
        lines.append(f"  {s.name:<40} {s.ip:<16} [{s.source}]")
    return "\n".join(lines)


def print_subdomains(subdomains: list[Subdomain], console) -> None:
    if not subdomains:
        return
    from rich.table import Table
    from rich import box
    from rich.panel import Panel

    table = Table("Subdomain", "IP", "Kaynak", box=box.SIMPLE_HEAD,
                  border_style="red", header_style="bold red")
    for s in subdomains:
        table.add_row(s.name, s.ip, s.source)
    console.print(Panel(table, title=f"[bold]Subdomain Keşfi — {len(subdomains)} Aktif[/bold]",
                        border_style="red"))
