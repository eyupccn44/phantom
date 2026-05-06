import json
import socket
import ftplib
import urllib.request
import urllib.error
import base64
import subprocess
from pathlib import Path
from dataclasses import dataclass, field

CREDS_DB = Path(__file__).parent.parent / "data" / "default_creds.json"
_db: dict | None = None


def _load() -> dict:
    global _db
    if _db is None:
        _db = json.loads(CREDS_DB.read_text(encoding="utf-8"))
    return _db


@dataclass
class CredResult:
    service: str
    port: str
    host: str
    user: str
    password: str
    success: bool = False
    note: str = ""


def _try_redis(host: str, port: int) -> list[CredResult]:
    results = []
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.send(b"PING\r\n")
        resp = s.recv(64).decode("utf-8", errors="replace")
        s.close()
        if "+PONG" in resp:
            results.append(CredResult("redis", str(port), host, "", "", True, "no-auth"))
    except Exception:
        pass
    return results


def _try_mongodb(host: str, port: int) -> list[CredResult]:
    results = []
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        isMaster = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
        s.send(isMaster)
        resp = s.recv(256)
        s.close()
        if b"ismaster" in resp or b"isWritablePrimary" in resp:
            results.append(CredResult("mongodb", str(port), host, "", "", True, "no-auth"))
    except Exception:
        pass
    return results


def _try_ftp(host: str, port: int, creds: list[dict]) -> list[CredResult]:
    results = []
    for cred in creds:
        user = cred.get("user", "anonymous")
        passwd = cred.get("pass", "")
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user or "anonymous", passwd)
            ftp.quit()
            results.append(CredResult("ftp", str(port), host, user, passwd, True))
            break
        except ftplib.error_perm:
            continue
        except Exception:
            break
    return results


def _try_http_basic(host: str, port: int, use_ssl: bool, creds: list[dict]) -> list[CredResult]:
    results = []
    scheme = "https" if use_ssl else "http"
    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    paths = ["/manager/html", "/admin", "/login", "/wp-admin/", "/admin.php", "/"]

    for cred in creds[:5]:
        user = cred.get("user", "")
        passwd = cred.get("pass", "")
        if not user:
            continue
        token = base64.b64encode(f"{user}:{passwd}".encode()).decode()

        for path in paths:
            try:
                req = urllib.request.Request(
                    base + path,
                    headers={"Authorization": f"Basic {token}", "User-Agent": "Mozilla/5.0"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        results.append(CredResult("http", str(port), host, user, passwd, True,
                                                   f"path:{path}"))
                        return results
            except urllib.error.HTTPError as e:
                if e.code not in (401, 403):
                    pass
            except Exception:
                break
    return results


def _try_ssh(host: str, port: int, creds: list[dict]) -> list[CredResult]:
    results = []
    for cred in creds[:5]:
        user = cred.get("user", "")
        passwd = cred.get("pass", "")
        if not user:
            continue
        try:
            proc = subprocess.run(
                ["sshpass", "-p", passwd, "ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=4",
                 "-o", "BatchMode=no",
                 "-p", str(port),
                 f"{user}@{host}", "echo phantom_ok"],
                capture_output=True, text=True, timeout=8,
            )
            if "phantom_ok" in proc.stdout:
                results.append(CredResult("ssh", str(port), host, user, passwd, True))
                return results
        except FileNotFoundError:
            break
        except Exception:
            continue
    return results


SERVICE_HANDLERS = {
    "redis":      lambda h, p, _: _try_redis(h, p),
    "mongodb":    lambda h, p, _: _try_mongodb(h, p),
    "ftp":        lambda h, p, c: _try_ftp(h, p, c),
    "ssh":        lambda h, p, c: _try_ssh(h, p, c),
    "http":       lambda h, p, c: _try_http_basic(h, p, False, c),
    "https":      lambda h, p, c: _try_http_basic(h, p, True, c),
    "tomcat":     lambda h, p, c: _try_http_basic(h, p, False, c),
    "jenkins":    lambda h, p, c: _try_http_basic(h, p, False, c),
}


def check_default_creds(ports, host: str) -> list[CredResult]:
    db = _load()
    all_results = []

    for port in ports:
        svc = port.service.lower()
        matched_key = None

        for key in db:
            if key in svc or svc in key:
                matched_key = key
                break

        handler = None
        for key, fn in SERVICE_HANDLERS.items():
            if key in svc or svc in key:
                handler = fn
                break

        if not handler:
            continue

        creds = db.get(matched_key, db.get(svc, []))
        try:
            results = handler(host, int(port.number), creds)
            for r in results:
                r.port = port.number
            all_results.extend(results)
        except Exception:
            continue

    return all_results


def print_cred_results(results: list[CredResult], console) -> None:
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.text import Text

    if not results:
        console.print("[dim]Default credential testi: eşleşme yok[/dim]")
        return

    table = Table("Durum", "Servis", "Port", "Kullanıcı", "Şifre", "Not",
                  box=box.SIMPLE_HEAD, border_style="red", header_style="bold red")
    for r in results:
        status = Text("✓ BAŞARILI", style="bold green") if r.success else Text("✗", style="dim")
        table.add_row(status, r.service, r.port, r.user or "(boş)", r.password or "(boş)", r.note)

    console.print(Panel(table, title="[bold]Default Credential Testi[/bold]", border_style="red", box=box.ROUNDED))
