import urllib.request
import urllib.error
import socket
from dataclasses import dataclass

WAF_SIGNATURES = {
    "Cloudflare":    {"headers": ["cf-ray", "cf-cache-status"], "server": "cloudflare", "body": ["cloudflare", "__cf_bm"]},
    "AWS WAF":       {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "server": "", "body": ["aws waf", "request blocked"]},
    "Akamai":        {"headers": ["x-akamai-transformed", "x-check-cacheable"], "server": "akamaighost", "body": []},
    "F5 BIG-IP":     {"headers": ["x-cnection", "x-wa-info"], "server": "big-ip", "body": ["the requested url was rejected", "f5"]},
    "ModSecurity":   {"headers": ["x-mod-security-message"], "server": "mod_security", "body": ["not acceptable", "406 not acceptable"]},
    "Imperva":       {"headers": ["x-iinfo", "x-cdn"], "server": "incapsula", "body": ["incapsula incident id", "_incap_ses"]},
    "Barracuda":     {"headers": ["x-barracuda-start-time"], "server": "", "body": ["barracuda", "barra_counter_session"]},
    "Sucuri":        {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": "sucuri", "body": ["sucuri website firewall"]},
    "Fortinet":      {"headers": [], "server": "fortigate", "body": ["fortigate", "fortiwaf"]},
    "Citrix":        {"headers": ["cneonction", "via"], "server": "citrix", "body": ["netscaler", "citrix"]},
    "Wallarm":       {"headers": ["x-wallarm-node"], "server": "", "body": []},
    "Nginx WAF":     {"headers": [], "server": "nginx", "body": ["nginx", "403 forbidden"]},
}

PROBE_PAYLOADS = [
    "/?id=1' OR '1'='1",
    "/?q=<script>alert(1)</script>",
    "/?file=../../../../etc/passwd",
    "/?cmd=whoami",
]

@dataclass
class WAFResult:
    detected: bool = False
    name: str = ""
    confidence: str = ""
    evidence: list[str] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


def detect_waf(target: str, port: int = 80, ssl: bool = False) -> WAFResult:
    scheme = "https" if ssl or port == 443 else "http"
    base_url = f"{scheme}://{target}"
    if port not in (80, 443):
        base_url = f"{scheme}://{target}:{port}"

    result = WAFResult()

    for payload in PROBE_PAYLOADS:
        url = base_url + payload
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; phantom/2.0)"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body = resp.read(2000).decode("utf-8", errors="replace").lower()
                _match_signatures(headers, body, result)
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v.lower() for k, v in e.headers.items()}
            try:
                body = e.read(2000).decode("utf-8", errors="replace").lower()
            except Exception:
                body = ""
            if e.code in (403, 406, 429, 503):
                result.evidence.append(f"HTTP {e.code} on probe")
            _match_signatures(headers, body, result)
        except Exception:
            continue

        if result.detected:
            break

    return result


def _match_signatures(headers: dict, body: str, result: WAFResult) -> None:
    server = headers.get("server", "")

    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0
        evidence = []

        for h in sigs.get("headers", []):
            if h in headers:
                score += 2
                evidence.append(f"header:{h}")

        if sigs.get("server") and sigs["server"] in server:
            score += 2
            evidence.append(f"server:{server}")

        for keyword in sigs.get("body", []):
            if keyword in body:
                score += 1
                evidence.append(f"body:{keyword}")

        if score >= 2:
            result.detected = True
            result.name = waf_name
            result.confidence = "HIGH" if score >= 4 else "MEDIUM"
            result.evidence.extend(evidence)
            return


def print_waf_result(result: WAFResult, console) -> None:
    from rich.panel import Panel
    from rich import box

    if result.detected:
        text = (
            f"[bold red]WAF TESPİT EDİLDİ: {result.name}[/bold red]\n"
            f"Güven: [yellow]{result.confidence}[/yellow]\n"
            f"Kanıt: {', '.join(result.evidence[:5])}"
        )
    else:
        text = "[green]WAF tespit edilmedi — direkt erişim mümkün olabilir[/green]"

    console.print(Panel(text, title="[bold]WAF Analizi[/bold]", border_style="red", box=box.ROUNDED))
