import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field

@dataclass
class TechResult:
    target: str
    technologies: list[dict] = field(default_factory=list)
    server: str = ""
    cms: str = ""
    language: str = ""
    framework: str = ""
    cdn: str = ""
    waf_hint: str = ""
    interesting_headers: dict = field(default_factory=dict)

TECH_SIGNATURES = {
    "headers": {
        "x-powered-by": {
            "PHP":        r"PHP/[\d.]+",
            "ASP.NET":    r"ASP\.NET",
            "Express":    r"Express",
            "Servlet":    r"Servlet",
        },
        "server": {
            "Apache":     r"Apache/?[\d.]*",
            "Nginx":      r"nginx/?[\d.]*",
            "IIS":        r"Microsoft-IIS/?[\d.]*",
            "Tomcat":     r"Apache-Coyote|Tomcat",
            "LiteSpeed":  r"LiteSpeed",
            "Caddy":      r"Caddy",
            "OpenResty":  r"openresty",
        },
        "x-generator":    {"Generator": r"(.+)"},
        "x-drupal-cache": {"Drupal": r".*"},
        "x-wp-total":     {"WordPress": r".*"},
        "set-cookie": {
            "PHP":        r"PHPSESSID",
            "ASP.NET":    r"ASP\.NET_SessionId|\.ASPXAUTH",
            "Java":       r"JSESSIONID",
            "ColdFusion": r"CFID|CFTOKEN",
            "Laravel":    r"laravel_session",
            "Rails":      r"_session_id",
            "Django":     r"csrftoken|sessionid",
        },
    },
    "body": {
        "WordPress":  [r'wp-content/', r'wp-includes/', r'/wp-json/', r'wordpress'],
        "Joomla":     [r'Joomla!', r'/components/com_', r'option=com_'],
        "Drupal":     [r'Drupal\.settings', r'sites/default/files', r'drupal\.js'],
        "Magento":    [r'Mage\.', r'magento', r'skin/frontend/'],
        "Shopify":    [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "Laravel":    [r'laravel', r'csrf-token'],
        "Django":     [r'csrfmiddlewaretoken', r'django'],
        "React":      [r'__react', r'data-reactroot', r'_reactFiber'],
        "Angular":    [r'ng-version', r'ng-app', r'angular\.js'],
        "Vue":        [r'__vue__', r'v-app', r'vue\.js'],
        "jQuery":     [r'jquery\.min\.js', r'jquery-[\d]'],
        "Bootstrap":  [r'bootstrap\.min\.css', r'bootstrap\.min\.js'],
        "phpMyAdmin": [r'phpMyAdmin', r'pma_', r'phpmyadmin'],
        "Grafana":    [r'grafana', r'GrafanaAppFactory'],
        "Jenkins":    [r'Jenkins', r'hudson'],
        "Kibana":     [r'kbn-name.*kibana', r'kibana'],
    },
    "paths": {
        "WordPress":  ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
        "Joomla":     ["/administrator/", "/joomla/"],
        "Drupal":     ["/user/login", "/core/CHANGELOG.txt"],
        "phpMyAdmin": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
        "Jenkins":    ["/jenkins/", "/j/"],
        "Grafana":    ["/grafana/login", "/grafana/"],
    },
}


def fingerprint(target: str, port: int = 80, use_ssl: bool = False) -> TechResult:
    scheme = "https" if use_ssl or port == 443 else "http"
    base = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
    result = TechResult(target=target)

    try:
        req = urllib.request.Request(base + "/", headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(8000).decode("utf-8", errors="replace")
            _analyze_headers(headers, result)
            _analyze_body(body, result)
    except Exception:
        pass

    _check_paths(base, result)
    return result


def _analyze_headers(headers: dict, result: TechResult) -> None:
    interesting = ["server", "x-powered-by", "x-generator", "x-frame-options",
                   "content-security-policy", "x-aspnet-version", "via"]
    for h in interesting:
        if h in headers:
            result.interesting_headers[h] = headers[h]

    result.server = headers.get("server", "")

    for header_name, patterns in TECH_SIGNATURES["headers"].items():
        val = headers.get(header_name, "")
        if not val:
            continue
        for tech, pattern in patterns.items():
            if re.search(pattern, val, re.IGNORECASE):
                _add_tech(result, tech, f"header:{header_name}")


def _analyze_body(body: str, result: TechResult) -> None:
    for tech, patterns in TECH_SIGNATURES["body"].items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                _add_tech(result, tech, "body-pattern")
                break


def _check_paths(base: str, result: TechResult) -> None:
    for tech, paths in TECH_SIGNATURES["paths"].items():
        for path in paths:
            try:
                req = urllib.request.Request(base + path, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        _add_tech(result, tech, f"path:{path}")
                        break
            except Exception:
                continue


def _add_tech(result: TechResult, name: str, source: str) -> None:
    if not any(t["name"] == name for t in result.technologies):
        result.technologies.append({"name": name, "source": source})
        if name in ("WordPress", "Joomla", "Drupal", "Magento", "Shopify", "phpMyAdmin"):
            result.cms = name
        elif name in ("PHP", "ASP.NET", "Java", "Python", "Ruby", "ColdFusion"):
            result.language = name
        elif name in ("Laravel", "Django", "Rails", "Express"):
            result.framework = name


def format_for_llm(fp: TechResult) -> str:
    if not fp.technologies:
        return ""
    lines = ["\nWEB TEKNOLOJİ PANELİ:"]
    if fp.server:
        lines.append(f"  Server: {fp.server}")
    if fp.cms:
        lines.append(f"  CMS: {fp.cms}")
    if fp.language:
        lines.append(f"  Dil: {fp.language}")
    if fp.framework:
        lines.append(f"  Framework: {fp.framework}")
    techs = ", ".join(t["name"] for t in fp.technologies)
    lines.append(f"  Teknolojiler: {techs}")
    return "\n".join(lines)


def print_fingerprint(fp: TechResult, console) -> None:
    if not fp.technologies and not fp.server:
        return
    from rich.table import Table
    from rich import box
    from rich.panel import Panel

    info_lines = []
    if fp.server:
        info_lines.append(f"[dim]Server:[/dim]    [bold]{fp.server}[/bold]")
    if fp.cms:
        info_lines.append(f"[dim]CMS:[/dim]       [bold red]{fp.cms}[/bold red]")
    if fp.language:
        info_lines.append(f"[dim]Dil:[/dim]       [bold]{fp.language}[/bold]")
    if fp.framework:
        info_lines.append(f"[dim]Framework:[/dim] [bold]{fp.framework}[/bold]")
    if fp.technologies:
        names = ", ".join(t["name"] for t in fp.technologies)
        info_lines.append(f"[dim]Tümü:[/dim]      {names}")
    if fp.interesting_headers:
        for k, v in list(fp.interesting_headers.items())[:3]:
            info_lines.append(f"[dim]{k}:[/dim] {v[:60]}")

    console.print(Panel("\n".join(info_lines),
                        title="[bold]Web Teknoloji Parmak İzi[/bold]",
                        border_style="red", box=box.ROUNDED))
