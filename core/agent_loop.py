import json
import re
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

console = Console()

ACTION_PATTERN = re.compile(r"ACTION:\s*(\{.*?\})", re.DOTALL)


# ─── TOOLS ───────────────────────────────────────────────────────────────────

def _tool_banner_grab(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = int(action.get("port", 80))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        try:
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        except Exception:
            pass
        banner = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        return banner.strip() or "(boş banner)"
    except Exception as e:
        return f"banner_grab başarısız: {e}"


def _tool_http_probe(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = action.get("port", "")
    path = action.get("path", "/")
    scheme = "https" if str(port) in ("443", "8443") else "http"
    if port and str(port) not in ("80", "443"):
        url = f"{scheme}://{host}:{port}{path}"
    else:
        url = action.get("url") or f"{scheme}://{host}{path}"
    if not url.startswith("http"):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            body = resp.read(1200).decode("utf-8", errors="replace")
            return (
                f"Status: {resp.status}\nURL: {resp.url}\n"
                f"Headers:\n" + "\n".join(f"  {k}: {v}" for k, v in headers.items()) +
                f"\n\nBody (ilk 800 karakter):\n{body[:800]}"
            )
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.reason}\nHeaders: {dict(e.headers)}"
    except Exception as e:
        return f"http_probe başarısız: {e}"


def _tool_nmap_targeted(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = action.get("port", "")
    scripts = action.get("scripts", "")
    flags = ["-sV", "-sC", "-T4", "-Pn"]
    if port:
        flags += [f"-p{port}"]
    if scripts:
        flags += [f"--script={scripts}"]
    try:
        result = subprocess.run(
            ["nmap"] + flags + [host],
            capture_output=True, text=True, timeout=120,
        )
        return result.stdout[:3000] or result.stderr
    except FileNotFoundError:
        return "nmap bulunamadı."
    except subprocess.TimeoutExpired:
        return "nmap zaman aşımı."
    except Exception as e:
        return f"nmap_targeted başarısız: {e}"


def _tool_dns_lookup(action: dict, default_target: str) -> str:
    domain = action.get("domain") or action.get("host", default_target)
    record_type = action.get("type", "A")
    try:
        result = subprocess.run(
            ["dig", domain, record_type, "+short"],
            capture_output=True, text=True, timeout=10,
        )
        out = result.stdout.strip()
        if not out:
            result2 = subprocess.run(
                ["dig", domain, "ANY", "+short"],
                capture_output=True, text=True, timeout=10,
            )
            out = result2.stdout.strip() or "Kayıt bulunamadı"
        return out
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + record_type, domain],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout
        except Exception as e2:
            return f"dns_lookup başarısız: {e2}"
    except Exception as e:
        return f"dns_lookup başarısız: {e}"


def _tool_ssl_cert(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = int(action.get("port", 443))
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                san = cert.get("subjectAltName", [])
                lines = [
                    f"TLS Version : {version}",
                    f"Cipher      : {cipher[0] if cipher else '?'}",
                    f"Subject     : {cert.get('subject')}",
                    f"Issuer      : {cert.get('issuer')}",
                    f"Valid From  : {cert.get('notBefore')}",
                    f"Valid Until : {cert.get('notAfter')}",
                    f"SANs        : {', '.join(v for _, v in san)}",
                ]
                return "\n".join(lines)
    except Exception as e:
        return f"ssl_cert başarısız: {e}"


def _tool_curl_check(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = action.get("port", "")
    path = action.get("path", "/")
    if port:
        url = action.get("url") or f"http://{host}:{port}{path}"
    else:
        url = action.get("url") or f"http://{host}{path}"
    if not url.startswith("http"):
        url = f"http://{url}"
    try:
        result = subprocess.run(
            ["curl", "-sIL", "--max-time", "10", "--max-redirs", "5",
             "-A", "Mozilla/5.0", url],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout[:1500] or result.stderr
    except FileNotFoundError:
        return "curl bulunamadı."
    except Exception as e:
        return f"curl_check başarısız: {e}"


def _tool_smb_enum(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    user = action.get("user", "")
    password = action.get("password", "")
    results = []
    try:
        cmd = ["smbclient", "-L", f"//{host}", "-N" if not user else f"-U{user}%{password}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.stdout:
            results.append("SMB Shares:\n" + result.stdout[:1000])
    except FileNotFoundError:
        results.append("smbclient bulunamadı — nmap SMB scripts deneniyor")
    except Exception as e:
        results.append(f"smbclient: {e}")

    try:
        nmap_result = subprocess.run(
            ["nmap", "-p445", "--script", "smb-security-mode,smb2-security-mode,smb-enum-shares",
             "-T4", "-Pn", host],
            capture_output=True, text=True, timeout=60,
        )
        if nmap_result.stdout:
            results.append("NSE Scripts:\n" + nmap_result.stdout[:1500])
    except Exception as e:
        results.append(f"nmap SMB scripts: {e}")

    return "\n\n".join(results) if results else "smb_enum başarısız"


def _tool_http_spider(action: dict, default_target: str) -> str:
    host = action.get("host", default_target)
    port = action.get("port", "80")
    scheme = "https" if str(port) in ("443", "8443") else "http"
    base = f"{scheme}://{host}:{port}" if str(port) not in ("80", "443") else f"{scheme}://{host}"
    found_links = set()
    found_forms = []
    try:
        req = urllib.request.Request(base, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(8000).decode("utf-8", errors="replace")
            for match in re.finditer(r'href=["\']([^"\']+)["\']', body):
                href = match.group(1)
                if href.startswith("/") or host in href:
                    found_links.add(href[:80])
            for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I):
                found_forms.append(match.group(1))
    except Exception as e:
        return f"http_spider başarısız: {e}"
    lines = [f"Base: {base}", f"Links ({len(found_links)}):"]
    lines += [f"  {l}" for l in list(found_links)[:30]]
    if found_forms:
        lines += [f"\nForms ({len(found_forms)}):"] + [f"  {f}" for f in found_forms[:10]]
    return "\n".join(lines)


TOOL_REGISTRY = {
    "banner_grab":   _tool_banner_grab,
    "http_probe":    _tool_http_probe,
    "nmap_targeted": _tool_nmap_targeted,
    "dns_lookup":    _tool_dns_lookup,
    "ssl_cert":      _tool_ssl_cert,
    "curl_check":    _tool_curl_check,
    "smb_enum":      _tool_smb_enum,
    "http_spider":   _tool_http_spider,
}


# ─── PARSER ──────────────────────────────────────────────────────────────────

def parse_actions(text: str) -> list[dict]:
    actions = []
    for match in ACTION_PATTERN.finditer(text):
        raw = match.group(1).strip()
        try:
            raw_clean = re.sub(r",\s*}", "}", re.sub(r",\s*]", "]", raw))
            action = json.loads(raw_clean)
            if isinstance(action, dict) and "tool" in action:
                actions.append(action)
        except json.JSONDecodeError:
            pass
    return actions


def execute_action(action: dict, target: str) -> str:
    tool_name = action.get("tool", "")
    fn = TOOL_REGISTRY.get(tool_name)
    if not fn:
        avail = ", ".join(TOOL_REGISTRY)
        return f"Bilinmeyen araç: {tool_name}. Mevcut araçlar: {avail}"
    try:
        return fn(action, target)
    except Exception as e:
        return f"{tool_name} çalıştırma hatası: {e}"


# ─── AGENTIC STEP ────────────────────────────────────────────────────────────

def agentic_step(
    llm,
    messages: list[dict],
    target: str,
    memory,
    auto_execute: bool = True,
) -> tuple[str, bool]:
    response = ""

    def on_token(token: str):
        nonlocal response
        response += token
        console.print(token, end="", markup=False)

    console.print()
    try:
        llm.chat(messages, on_token=on_token)
    except ConnectionError as e:
        console.print(f"\n[bold red]Ollama bağlantı hatası:[/bold red] {e}")
        return "", False
    console.print("\n")

    if not response.strip():
        console.print(
            "[bold yellow]⚠  Model boş yanıt döndürdü.[/bold yellow]\n"
            "[dim]Olası nedenler: context çok uzun, model yüklenmedi, Ollama meşgul.\n"
            "Daha kısa bir soru deneyin veya 'session' komutuyla bağlamı kontrol edin.[/dim]"
        )
        return "", False

    memory.add_message("assistant", response)

    actions = parse_actions(response)
    if not actions:
        return response, False

    tool_results = []
    for action in actions:
        tool_name = action.get("tool", "?")
        reason = action.get("reason", "")
        host = action.get("host", target)
        port = action.get("port", "")

        console.print(
            f"\n[bold yellow]⚡[/bold yellow] [bold]{tool_name}[/bold]"
            + (f"  [dim]{host}:{port}[/dim]" if port else f"  [dim]{host}[/dim]")
        )
        if reason:
            console.print(f"   [dim italic]{reason}[/dim italic]")

        if auto_execute:
            console.print(f"   [dim cyan]Çalıştırılıyor...[/dim cyan]")
            result = execute_action(action, target)
            snippet = result[:120].replace("\n", " ")
            console.print(f"   [dim green]✓ {snippet}...[/dim green]")
            tool_results.append(
                f"[TOOL_RESULT: {tool_name}]\n{result}\n[/TOOL_RESULT]"
            )
            risk = "critical" if any(k in result.lower() for k in ("rce", "overflow", "success", "root", "admin")) else "medium"
            memory.add_finding(f"{tool_name}({host}:{port}) → {snippet}", risk=risk)
        else:
            tool_results.append(
                f"[TOOL_RESULT: {tool_name}]\nOperator skipped.\n[/TOOL_RESULT]"
            )

    if tool_results:
        followup = (
            "\n\n".join(tool_results) +
            "\n\nBu araç sonuçlarını mevcut attack path'e entegre et. "
            "Yeni bulgular varsa kill chain'i güncelle. Bir sonraki adımı öner."
        )
        messages.append({"role": "user", "content": followup})
        memory.add_message("user", followup)
        return response, True

    return response, False


# ─── AGENTIC LOOP ────────────────────────────────────────────────────────────

MAX_RESPONSE_CHARS = 8000

def run_agentic_loop(
    llm,
    initial_prompt: str,
    target: str,
    memory,
    max_rounds: int = 6,
    auto_execute: bool = True,
) -> str:
    from core.prompt_guard import check_response_loop

    messages = memory.get_messages() + [{"role": "user", "content": initial_prompt}]
    memory.add_message("user", initial_prompt)

    last_response = ""
    recent_responses: list[str] = []

    for round_num in range(max_rounds):
        response, has_actions = agentic_step(
            llm, messages, target, memory, auto_execute=auto_execute
        )

        # Response loop tespiti
        if check_response_loop(response, recent_responses):
            console.print("[bold red]⚠  Tekrar döngüsü tespit edildi — döngü kırılıyor[/bold red]")
            break

        # Aşırı uzun yanıt tespiti
        if len(response) > MAX_RESPONSE_CHARS:
            console.print(f"[dim yellow]ℹ  Yanıt uzunluk limitine ulaştı ({MAX_RESPONSE_CHARS} karakter)[/dim yellow]")
            response = response[:MAX_RESPONSE_CHARS]

        recent_responses.append(response)
        messages.append({"role": "assistant", "content": response})
        last_response = response

        if not has_actions:
            break

        if round_num == max_rounds - 1:
            console.print(
                f"[dim yellow]ℹ  Maks tur: {max_rounds} — araç döngüsü tamamlandı[/dim yellow]"
            )

    return last_response
