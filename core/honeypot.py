import socket
import time
import re
import urllib.request
from dataclasses import dataclass, field

@dataclass
class HoneypotResult:
    target: str
    score: int = 0
    indicators: list = field(default_factory=list)
    safe_indicators: list = field(default_factory=list)
    verdict: str = "UNKNOWN"


def _check_latency_consistency(host: str, port: int, rounds: int = 5) -> tuple[float, float]:
    times = []
    for _ in range(rounds):
        try:
            t0 = time.monotonic()
            s = socket.create_connection((host, port), timeout=4)
            s.close()
            times.append(time.monotonic() - t0)
        except Exception:
            pass
        time.sleep(0.1)
    if len(times) < 2:
        return 0.0, 0.0
    avg = sum(times) / len(times)
    variance = sum((t - avg) ** 2 for t in times) / len(times)
    return avg, variance


def _check_banner_anomaly(host: str, port: int) -> list[str]:
    anomalies = []
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        if re.search(r"(kippo|cowrie|honeyd|glastopf|dionaea|opencanary|thinkst|canarytokens)", banner, re.I):
            anomalies.append(f"Bilinen honeypot imzası: banner içinde tespit edildi")
        if banner.count("\r\n") == 0 and len(banner) > 50:
            anomalies.append("Banner'da CRLF satır sonu yok — anormal HTTP yanıtı")
        if re.search(r"(Ubuntu|Debian|CentOS).{0,20}(Windows|IIS)", banner, re.I):
            anomalies.append("Banner'da çelişen OS bilgisi")
    except Exception:
        pass
    return anomalies


def _check_port_response_timing(host: str, ports: list) -> list[str]:
    anomalies = []
    timings = {}
    for p in ports:
        try:
            t0 = time.monotonic()
            s = socket.create_connection((host, int(p)), timeout=4)
            s.close()
            timings[p] = time.monotonic() - t0
        except Exception:
            timings[p] = None

    valid = {p: t for p, t in timings.items() if t is not None}
    if len(valid) >= 3:
        avg = sum(valid.values()) / len(valid)
        variance = sum((t - avg) ** 2 for t in valid.values()) / len(valid)
        if variance < 0.0001:
            anomalies.append(f"Tüm portlar neredeyse aynı latency ({avg*1000:.1f}ms) — honeypot davranışı")
    return anomalies


def _check_too_vulnerable(ports: list, cves: list) -> list[str]:
    flags = []
    critical_cves = [c for c in cves if c.get("cvss", 0) >= 9.5]
    if len(critical_cves) >= 4:
        flags.append(f"{len(critical_cves)} adet CVSS 9.5+ CVE aynı hedefte — şüpheli derecede savunmasız")
    open_dangerous = [p for p in ports if p.get("number") in ("23", "512", "513", "514", "6667")]
    if open_dangerous:
        flags.append(f"Alışılmamış riskli portlar açık: {[p['number'] for p in open_dangerous]} — cazibe mi?")
    return flags


def _check_http_honeypot(host: str, port: int) -> list[str]:
    flags = []
    fake_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php"]
    hits = 0
    for path in fake_paths:
        try:
            url = f"http://{host}:{port}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    hits += 1
        except Exception:
            pass
    if hits >= 3:
        flags.append(f"{hits}/5 honeypot cazibe path'i 200 döndürdü — web honeypot olabilir")
    return flags


def detect_honeypot(target: str, ports: list, cves: list = None) -> HoneypotResult:
    result = HoneypotResult(target=target)
    if cves is None:
        cves = []

    port_numbers = [p.get("number", "") for p in ports]

    # Latency consistency check
    if port_numbers:
        try:
            avg_lat, variance = _check_latency_consistency(target, int(port_numbers[0]))
            if variance < 0.00005 and avg_lat > 0:
                result.indicators.append(f"Port latency çok tutarlı (variance={variance:.6f}) — sanal/simüle sistem")
                result.score += 20
            else:
                result.safe_indicators.append("Latency variance normal")
        except Exception:
            pass

    # Banner anomaly check
    for p in port_numbers[:3]:
        try:
            anomalies = _check_banner_anomaly(target, int(p))
            for a in anomalies:
                result.indicators.append(a)
                result.score += 25
        except Exception:
            pass

    # Port timing consistency
    if len(port_numbers) >= 3:
        timing_issues = _check_port_response_timing(target, port_numbers[:5])
        for issue in timing_issues:
            result.indicators.append(issue)
            result.score += 30

    # Too vulnerable check
    vuln_flags = _check_too_vulnerable(ports, cves)
    for flag in vuln_flags:
        result.indicators.append(flag)
        result.score += 15

    # HTTP honeypot check
    http_ports = [p for p in ports if p.get("service", "") in ("http", "https") or p.get("number") in ("80", "8080", "8000")]
    for p in http_ports[:2]:
        try:
            http_flags = _check_http_honeypot(target, int(p.get("number", 80)))
            for flag in http_flags:
                result.indicators.append(flag)
                result.score += 20
        except Exception:
            pass

    if not result.indicators:
        result.safe_indicators.append("Bilinen honeypot imzası tespit edilmedi")
        result.safe_indicators.append("Banner anomalisi yok")

    result.score = min(result.score, 100)
    if result.score >= 60:
        result.verdict = "MUHTEMEL HONEYPOT"
    elif result.score >= 35:
        result.verdict = "ŞÜPHELİ"
    else:
        result.verdict = "GERÇEK GÖRÜNÜYOR"

    return result


def print_honeypot_result(result: HoneypotResult, console) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    color = "#ff2244" if result.score >= 60 else "#ffcc00" if result.score >= 35 else "#00cc66"
    score_bar = "█" * (result.score // 10) + "░" * (10 - result.score // 10)

    lines = [
        f"[bold]Hedef:[/bold] {result.target}",
        f"[bold]Skor :[/bold] [{color}]{score_bar}[/{color}] {result.score}/100",
        f"[bold]Karar:[/bold] [{color}]{result.verdict}[/{color}]",
    ]
    if result.indicators:
        lines.append("\n[bold red]⚠ Honeypot İndikatörleri:[/bold red]")
        for ind in result.indicators:
            lines.append(f"  [red]• {ind}[/red]")
    if result.safe_indicators:
        lines.append("\n[bold green]✓ Temiz Göstergeler:[/bold green]")
        for ind in result.safe_indicators:
            lines.append(f"  [green]• {ind}[/green]")

    console.print(Panel(
        "\n".join(lines),
        title="[bold]🍯 HONEYPOT TESPİT ANALİZİ[/bold]",
        border_style="red" if result.score >= 60 else "yellow" if result.score >= 35 else "green",
        box=box.ROUNDED,
    ))
