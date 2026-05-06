#!/usr/bin/env python3
"""
Phantom — Red Team AI Agent
MITRE ATT&CK + CVE Intelligence + Agentic Loop

YASAL UYARI: Yalnızca yetkili penetrasyon testi ortamlarında kullanın.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.rule import Rule

from core.llm import OllamaClient, check_ollama
from core.memory import SessionMemory, list_sessions, load_session
from core.mitre import map_scan_to_ttps, build_context_for_llm
from core.cve import scan_ports_to_cves, format_cves_for_llm, print_cve_table
from core.tools import (
    run_nmap, run_whois, run_ping, format_scan_for_llm,
    run_nuclei, run_masscan, run_nikto, run_gobuster, run_dnsrecon,
    format_nuclei_for_llm, format_nikto_for_llm,
    format_gobuster_for_llm, format_dnsrecon_for_llm, format_masscan_for_llm,
)
from core.agent_loop import run_agentic_loop
from core.subdomain import enumerate_subdomains, format_for_llm as sub_for_llm, print_subdomains
from core.waf import detect_waf, print_waf_result
from core.fingerprint import fingerprint, format_for_llm as fp_for_llm, print_fingerprint
from core.default_creds import check_default_creds, print_cred_results
from core.adversary import build_adversary_prompt, filter_ttps_for_adversary, print_adversary_profile
from core.navigator import export_navigator_layer
from core.graph import build_attack_path_graph
from core.html_report import generate_html_report
from core.spray import run_spray, print_spray_results
from core.honeypot import detect_honeypot, print_honeypot_result
from core.drift import detect_drift, print_drift_result
from core.blindspot import analyze_blind_spots, print_blind_spots
from core.redvsblue import run_red_vs_blue
from core.trustgraph import build_trust_graph
from core.prompt_guard import check_prompt, check_response_loop
from core.agents import run_agent_team
from core import mapper

console = Console()

VERSION = "3.0.0"
REPORTS_DIR = Path(__file__).parent / "reports"


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom v3 — Red Team AI Agent | MITRE ATT&CK + CVE + Agentic Loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python phantom.py --target 192.168.1.1
  python phantom.py --target example.com --scope external --fast --sub --waf
  python phantom.py --target 10.0.0.1 --adv APT29
  python phantom.py --target 10.0.0.1 --report --html
  python phantom.py --sessions
  python bot.py                          # Telegram bot başlat
        """,
    )
    p.add_argument("--target", "-t", help="Hedef IP veya domain")
    p.add_argument("--scope", "-s", default="external",
                   choices=["external", "internal", "web", "full"],
                   help="Pentest kapsamı (varsayılan: external)")
    p.add_argument("--fast", "-f", action="store_true",
                   help="Hızlı tarama modu (top 1000 port)")
    p.add_argument("--sub", action="store_true",
                   help="Subdomain enumeration (crt.sh + DNS brute)")
    p.add_argument("--waf", action="store_true",
                   help="WAF tespiti")
    p.add_argument("--fp", action="store_true",
                   help="Web teknoloji parmak izi")
    p.add_argument("--creds", action="store_true",
                   help="Default credential testi")
    p.add_argument("--adv", metavar="APT_NAME",
                   help="Adversary simulation modu (örn: APT29, Lazarus)")
    p.add_argument("--navigator", action="store_true",
                   help="MITRE Navigator JSON layer export")
    p.add_argument("--graph", action="store_true",
                   help="Attack path graph göster")
    p.add_argument("--report", "-r", action="store_true",
                   help="Markdown rapor oluştur")
    p.add_argument("--html", action="store_true",
                   help="HTML rapor oluştur")
    p.add_argument("--no-scan", action="store_true",
                   help="Tarama yapmadan direkt interaktif mod")
    p.add_argument("--sessions", action="store_true",
                   help="Geçmiş sessionları listele")
    p.add_argument("--model", "-m", help="Ollama model adı (varsayılan: otomatik)")
    p.add_argument("--honeypot", action="store_true", help="Honeypot/tuzak tespiti çalıştır")
    p.add_argument("--drift", action="store_true", help="Attack surface drift analizi")
    p.add_argument("--blindspot", action="store_true", help="Defender kör nokta matrisi")
    p.add_argument("--redvsblue", action="store_true", help="Red vs Blue simülasyonu")
    p.add_argument("--trust", metavar="IP1,IP2,...", help="Multi-target trust graph")
    p.add_argument("--auto", action="store_true", help="İnteraktif moda girme, tara ve çık")
    p.add_argument("--agents", action="store_true", help="Çok ajanlı ekip analizi çalıştır (B+C hibrit)")
    # ── Yeni araçlar ──────────────────────────────────────────────────────────
    p.add_argument("--nuclei", action="store_true", help="Nuclei zafiyet taraması çalıştır")
    p.add_argument("--nuclei-sev", default="medium,high,critical", metavar="SEV",
                   help="Nuclei önem filtresi (varsayılan: medium,high,critical)")
    p.add_argument("--masscan", action="store_true", help="Masscan hızlı port taraması")
    p.add_argument("--masscan-rate", type=int, default=1000, metavar="RATE",
                   help="Masscan paket/sn hızı (varsayılan: 1000)")
    p.add_argument("--nikto", action="store_true", help="Nikto web sunucu taraması")
    p.add_argument("--gobuster", action="store_true", help="Gobuster dizin keşfi")
    p.add_argument("--gobuster-wl", default="", metavar="WORDLIST", help="Gobuster wordlist yolu")
    p.add_argument("--dns", action="store_true", help="DNS keşfi (dnsrecon/dig)")
    p.add_argument("--version", "-v", action="version", version=f"Phantom v{VERSION}")
    return p


# ─── SESSION LİSTESİ ─────────────────────────────────────────────────────────

def cmd_sessions() -> None:
    sessions = list_sessions()
    if not sessions:
        mapper.print_info("Kayıtlı session bulunamadı.")
        return
    console.print(Rule("[bold red]GEÇMİŞ SESSIONLAR[/bold red]", style="red"))
    for i, path in enumerate(sessions[:20], 1):
        try:
            data = load_session(path)
            started = data.get("started_at", "")[:19].replace("T", " ")
            findings = len(data.get("findings", []))
            ttps = len(data.get("ttps", []))
            cves = len(data.get("cves", []))
            console.print(
                f"  [dim]{i:02d}.[/dim] [bold]{data['target']}[/bold]  "
                f"[dim]{started}  findings={findings}  ttps={ttps}  cves={cves}[/dim]"
            )
        except Exception:
            console.print(f"  [dim]{i:02d}. {path.name}[/dim]")


# ─── RECON FAZI ──────────────────────────────────────────────────────────────

def run_recon(target: str, fast: bool, memory: SessionMemory):
    mapper.print_info(f"Hedef kontrol ediliyor: {target}")
    alive = run_ping(target)
    if alive:
        mapper.print_success("Host erişilebilir (ICMP veya TCP)")
    else:
        mapper.print_info("Host'a ulaşılamadı (ICMP + TCP knock başarısız) — yine de taranıyor")

    mapper.print_info(f"nmap taraması ({'hızlı' if fast else 'tam'} mod)...")
    scan = run_nmap(target, fast=fast)

    mapper.print_info("whois sorgusu...")
    whois = run_whois(target)

    memory.save_scan({
        "target": scan.target,
        "host_up": scan.host_up,
        "ports": [{"number": p.number, "protocol": p.protocol,
                   "service": p.service, "version": p.version} for p in scan.ports],
        "os_guess": scan.os_guess,
        "hostnames": scan.hostnames,
    })
    memory.save_whois({
        "registrar": whois.registrar,
        "org": whois.org,
        "country": whois.country,
        "nameservers": whois.nameservers,
    })

    return scan, whois


# ─── EK ARAÇ FAZLARI ─────────────────────────────────────────────────────────

def run_extra_tools(args, scan, memory: SessionMemory) -> list[str]:
    """Seçilen ek araçları çalıştır, sonuçları memory'e kaydet, LLM kontekst döndür."""
    extra_contexts = []
    target = args.target

    if args.masscan:
        mapper.print_info("Masscan hızlı port taraması...")
        ms = run_masscan(target, rate=args.masscan_rate)
        memory.save_tool_result("masscan", [
            {"number": p.number, "protocol": p.protocol} for p in ms.ports
        ])
        if ms.ports:
            mapper.print_success(f"Masscan: {len(ms.ports)} port")
            extra_contexts.append(format_masscan_for_llm(ms))
        else:
            mapper.print_info(f"Masscan: {ms.raw[:80]}")

    if args.dns:
        mapper.print_info("DNS keşfi başlatılıyor...")
        dns = run_dnsrecon(target)
        memory.save_tool_result("dnsrecon", dns.records)
        if dns.records:
            mapper.print_success(f"DNS: {len(dns.records)} kayıt")
            extra_contexts.append(format_dnsrecon_for_llm(dns))
        else:
            mapper.print_info(f"DNS: {dns.raw[:80]}")

    if args.nuclei:
        mapper.print_info(f"Nuclei taraması ({args.nuclei_sev})...")
        nu = run_nuclei(target, severity=args.nuclei_sev)
        memory.save_tool_result("nuclei", [
            {"template_id": f.template_id, "name": f.name, "severity": f.severity,
             "matched_at": f.matched_at, "description": f.description, "cve_id": f.cve_id}
            for f in nu.findings
        ])
        if nu.findings:
            mapper.print_success(f"Nuclei: {len(nu.findings)} bulgu")
            for f in nu.findings:
                if f.severity in ("critical", "high"):
                    memory.add_finding(f"Nuclei [{f.severity}] {f.template_id} @ {f.matched_at}", f.severity)
            extra_contexts.append(format_nuclei_for_llm(nu))
        else:
            mapper.print_info("Nuclei: Zafiyet bulunamadı")

    if args.nikto and scan:
        http_ports = [p for p in scan.ports if p.service in ("http", "https") or p.number in ("80", "443", "8080", "8443")]
        if http_ports:
            port = http_ports[0]
            mapper.print_info(f"Nikto web taraması (:{port.number})...")
            nk = run_nikto(target, port=int(port.number), ssl=(port.service == "https"))
            memory.save_tool_result("nikto", [
                {"uri": f.uri, "description": f.description, "osvdb": f.osvdb}
                for f in nk.findings
            ])
            if nk.findings:
                mapper.print_success(f"Nikto: {len(nk.findings)} bulgu")
                extra_contexts.append(format_nikto_for_llm(nk))
            else:
                mapper.print_info("Nikto: Bulgu yok")
        else:
            mapper.print_info("Nikto: HTTP portu bulunamadı, atlanıyor")

    if args.gobuster and scan:
        http_ports = [p for p in scan.ports if p.service in ("http", "https") or p.number in ("80", "443", "8080")]
        if http_ports:
            port = http_ports[0]
            mapper.print_info(f"Gobuster dizin keşfi (:{port.number})...")
            gb = run_gobuster(target, port=int(port.number), ssl=(port.service == "https"),
                              wordlist=args.gobuster_wl)
            memory.save_tool_result("gobuster", [
                {"path": f.path, "status": f.status, "size": f.size}
                for f in gb.findings
            ])
            if gb.findings:
                mapper.print_success(f"Gobuster: {len(gb.findings)} yol")
                extra_contexts.append(format_gobuster_for_llm(gb))
            else:
                mapper.print_info(f"Gobuster: {gb.raw[:80]}")
        else:
            mapper.print_info("Gobuster: HTTP portu bulunamadı, atlanıyor")

    return extra_contexts


# ─── İLK ANALİZ (AGENTİC LOOP) ───────────────────────────────────────────────

def run_initial_analysis(
    llm: OllamaClient,
    scan,
    whois,
    ttps,
    cves: list,
    scope: str,
    memory: SessionMemory,
    extra_contexts: list | None = None,
) -> str:
    scan_text = format_scan_for_llm(scan, whois)
    ttp_context = build_context_for_llm(ttps)
    cve_context = format_cves_for_llm(cves)
    intel_ctx = memory.intel.build_context_for_llm()
    extra_block = "\n".join(extra_contexts) if extra_contexts else ""

    prompt = f"""PENTEST ENGAGEMENT
Scope: {scope}
Target: {scan.target}

{scan_text}
{ttp_context}
{cve_context}
{extra_block}
{intel_ctx}

Görevin:
1. Bu recon verisini senior bir red team analistinin gözüyle incele
2. En kritik attack vektörlerini önceliklendir (Impact × Exploitability × Stealth)
3. Her vektör için MITRE TTP, CVE (varsa), araç ve komut ver
4. Full kill chain projeksiyonu yap (Initial Access → Objective)
5. Gerekirse araç talep et (ACTION: ...) — versiyon belirsizse banner grab iste
6. OPSEC notu ekle: her tekniğin detection riski nedir?

Yanıtını yapılandır: Attack Surface Summary → Prioritized Vectors → Kill Chain → Next Steps
"""

    mapper.print_thinking()
    result = run_agentic_loop(llm, prompt, scan.target, memory, max_rounds=5)
    return result


# ─── İNTERAKTİF MOD ──────────────────────────────────────────────────────────

def interactive_loop(llm: OllamaClient, memory: SessionMemory, target: str, version: str = "3.0.0") -> None:
    import subprocess as _sp
    import sys as _sys

    def _restore_echo():
        try:
            _sp.run(["stty", "echo"], check=False, capture_output=True)
        except Exception:
            pass

    _restore_echo()

    console.print(Rule("[bold red]İNTERAKTİF MOD[/bold red]", style="red"))
    console.print(
        "[dim]── TEMEL KOMUTLAR ──────────────────────────────────────────────────────[/dim]\n"
        "  [bold]rapor[/bold]              → Markdown rapor oluştur\n"
        "  [bold]html[/bold]               → HTML rapor oluştur ve aç\n"
        "  [bold]not <metin>[/bold]        → Session'a not ekle\n"
        "  [bold]session[/bold]            → Session özeti\n"
        "  [bold]portlar[/bold]            → Açık portları göster\n"
        "  [bold]cve[/bold]                → CVE listesini göster\n"
        "  [bold]ttp[/bold]                → TTP haritasını göster\n"
        "\n[dim]── GELİŞMİŞ MODLAR ─────────────────────────────────────────────────────[/dim]\n"
        "  [bold red]honeypot[/bold red]           → Hedefin honeypot/tuzak olup olmadığını analiz et\n"
        "  [bold red]drift[/bold red]              → Saldırı yüzeyi değişim tespiti (önceki taramalarla karşılaştır)\n"
        "  [bold red]blindspot[/bold red]          → Defender kör nokta matrisi (EDR tespit oranları)\n"
        "  [bold red]redvsblue[/bold red]          → Kırmızı vs Mavi takım simülasyonu\n"
        "  [bold red]trustgraph <ip1,ip2>[/bold red] → Çok hedef güven grafiği\n"
        "  [bold red]agentlar[/bold red]           → Çok ajanlı ekip analizi (B+C hibrit paralel)\n"
        "\n[dim]── EK ARAÇLAR ───────────────────────────────────────────────────────────[/dim]\n"
        "  [bold yellow]nuclei[/bold yellow]             → Nuclei zafiyet taraması\n"
        "  [bold yellow]nikto[/bold yellow]              → Nikto web sunucu taraması\n"
        "  [bold yellow]gobuster[/bold yellow]           → Gobuster dizin keşfi\n"
        "  [bold yellow]dns[/bold yellow]                → DNS keşfi (dnsrecon/dig)\n"
        "  [bold yellow]masscan[/bold yellow]            → Masscan hızlı port taraması\n"
        "\n[dim]── DİĞER ────────────────────────────────────────────────────────────────[/dim]\n"
        "  [bold]çıkış[/bold]              → Oturumu kapat\n"
        "  [dim]Veya doğrudan soru sor → AI analiz yapar[/dim]\n"
    )

    while True:
        try:
            _restore_echo()
            console.print("[bold red]phantom ❯[/bold red] ", end="")
            user_input = input()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Oturum kapatılıyor...[/dim]")
            break

        stripped = user_input.strip()
        if not stripped:
            continue

        cmd = stripped.lower()

        if cmd in ("çıkış", "exit", "quit", "q"):
            console.print("[dim]Oturum kapatılıyor...[/dim]")
            break

        if cmd == "rapor":
            generate_report(memory)
            continue

        if cmd == "html":
            html_path = generate_html_report(memory.data, version)
            mapper.print_success(f"HTML rapor: {html_path}")
            import subprocess as _sp2
            try:
                _sp2.run(["open", str(html_path)], check=False)
            except Exception:
                pass
            continue

        if cmd.startswith("not "):
            note = stripped[4:].strip()
            memory.add_note(note)
            mapper.print_success(f"Not eklendi: {note}")
            continue

        if cmd == "session":
            console.print(memory.export_summary())
            continue

        if cmd == "portlar":
            ports = memory.data.get("scan", {}).get("ports", [])
            if ports:
                for p in ports:
                    console.print(f"  [green]{p.get('number')}/tcp[/green]  {p.get('service','')}  [dim]{p.get('version','')}[/dim]")
            else:
                console.print("[dim]Port verisi yok[/dim]")
            continue

        if cmd == "cve":
            cves = memory.data.get("cves", [])
            if cves:
                for c in sorted(cves, key=lambda x: x.get("cvss", 0), reverse=True):
                    msf = " [green][MSF][/green]" if c.get("metasploit") else ""
                    console.print(f"  [red]{c['id']}[/red] CVSS:{c.get('cvss',0)}{msf}  {c.get('description','')[:60]}")
            else:
                console.print("[dim]CVE verisi yok[/dim]")
            continue

        if cmd == "ttp":
            ttps = memory.data.get("ttps", [])
            if ttps:
                for t in ttps:
                    risk_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}.get(t.get("risk", "low"), "white")
                    console.print(f"  [{risk_color}]{t.get('tid')}[/{risk_color}]  {t.get('name','')}  [dim]:{t.get('port','')}[/dim]")
            else:
                console.print("[dim]TTP verisi yok[/dim]")
            continue

        if cmd == "honeypot":
            mapper.print_info("Honeypot analizi yapılıyor...")
            ports = memory.data.get("scan", {}).get("ports", [])
            cves = memory.data.get("cves", [])
            hp_result = detect_honeypot(target, ports, cves)
            print_honeypot_result(hp_result, console)
            continue

        if cmd == "drift":
            ports = memory.data.get("scan", {}).get("ports", [])
            drift_result = detect_drift(target, ports)
            print_drift_result(drift_result, console)
            continue

        if cmd == "blindspot":
            ttps = memory.data.get("ttps", [])
            bs_results = analyze_blind_spots(ttps)
            print_blind_spots(bs_results, console)
            continue

        if cmd == "redvsblue":
            ttps = memory.data.get("ttps", [])
            cves = memory.data.get("cves", [])
            run_red_vs_blue(llm, ttps, cves, target, memory, console)
            continue

        if cmd.startswith("trustgraph"):
            parts = stripped.split(None, 1)
            if len(parts) < 2:
                console.print("[dim]Kullanım: trustgraph 10.10.10.1,10.10.10.2[/dim]")
                continue
            targets_list = [t.strip() for t in parts[1].split(",") if t.strip()]
            build_trust_graph(targets_list, console)
            continue

        if cmd == "nuclei":
            mapper.print_info("Nuclei taraması başlatılıyor...")
            nu = run_nuclei(target)
            if nu.findings:
                for f in nu.findings:
                    color = {"critical": "red", "high": "orange3", "medium": "yellow"}.get(f.severity, "dim")
                    console.print(f"  [{color}][{f.severity.upper()}][/{color}] {f.template_id} — {f.name}")
                    if f.cve_id:
                        console.print(f"       [dim]{f.cve_id}[/dim]")
            else:
                mapper.print_info("Nuclei: Zafiyet bulunamadı")
            memory.save_tool_result("nuclei", [
                {"template_id": f.template_id, "name": f.name, "severity": f.severity,
                 "matched_at": f.matched_at, "description": f.description, "cve_id": f.cve_id}
                for f in nu.findings
            ])
            continue

        if cmd == "nikto":
            ports = memory.data.get("scan", {}).get("ports", [])
            http_p = [p for p in ports if p.get("service") in ("http","https") or p.get("number") in ("80","443","8080")]
            port_num = int(http_p[0]["number"]) if http_p else 80
            mapper.print_info(f"Nikto web taraması (:{port_num})...")
            nk = run_nikto(target, port=port_num)
            for f in nk.findings[:20]:
                console.print(f"  [yellow]{f.uri}[/yellow] {f.description[:100]}")
            if not nk.findings:
                mapper.print_info("Nikto: Bulgu yok")
            memory.save_tool_result("nikto", [{"uri": f.uri, "description": f.description} for f in nk.findings])
            continue

        if cmd == "gobuster":
            ports = memory.data.get("scan", {}).get("ports", [])
            http_p = [p for p in ports if p.get("service") in ("http","https") or p.get("number") in ("80","443","8080")]
            port_num = int(http_p[0]["number"]) if http_p else 80
            mapper.print_info(f"Gobuster dizin keşfi (:{port_num})...")
            gb = run_gobuster(target, port=port_num)
            for f in gb.findings[:30]:
                color = "green" if f.status == 200 else "yellow"
                console.print(f"  [{color}][{f.status}][/{color}] {f.path} [dim]({f.size} byte)[/dim]")
            if not gb.findings:
                mapper.print_info(f"Gobuster: {gb.raw[:80]}")
            memory.save_tool_result("gobuster", [{"path": f.path, "status": f.status, "size": f.size} for f in gb.findings])
            continue

        if cmd == "dns":
            mapper.print_info("DNS keşfi başlatılıyor...")
            dns = run_dnsrecon(target)
            for r in dns.records[:25]:
                console.print(f"  [cyan]{r.get('type','?'):6}[/cyan] {r.get('name','')} → [white]{r.get('address','')}[/white]")
            if not dns.records:
                mapper.print_info(f"DNS: {dns.raw[:80]}")
            memory.save_tool_result("dnsrecon", dns.records)
            continue

        if cmd == "masscan":
            mapper.print_info("Masscan hızlı tarama başlatılıyor...")
            ms = run_masscan(target)
            for p in ms.ports[:50]:
                console.print(f"  [green]{p.number}/{p.protocol}[/green]")
            if not ms.ports:
                mapper.print_info(f"Masscan: {ms.raw[:80]}")
            memory.save_tool_result("masscan", [{"number": p.number, "protocol": p.protocol} for p in ms.ports])
            continue

        if cmd == "agentlar":
            ports = memory.data.get("scan", {}).get("ports", [])
            agent_context = {
                "ports": [
                    {"port": p.get("number"), "servis": p.get("service"), "versiyon": p.get("version", "")}
                    for p in ports if isinstance(p, dict)
                ],
                "nmap_raw": "",
            }
            run_agent_team(llm, target, context=agent_context, verbose=True)
            continue

        guard = check_prompt(stripped)
        if not guard.allowed:
            console.print(f"\n[bold red]⛔ ENGELLENDI[/bold red]\n[dim]{guard.reason}[/dim]\n")
            continue

        run_agentic_loop(llm, guard.sanitized, target, memory, max_rounds=4)


# ─── RAPOR ───────────────────────────────────────────────────────────────────

def generate_report(memory: SessionMemory) -> None:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = memory.target.replace(".", "_").replace("/", "_")
    report_path = REPORTS_DIR / f"phantom_report_{safe_target}_{ts}.md"

    data = memory.data
    lines = [
        "# PHANTOM Red Team Report",
        "",
        f"**Target:** `{data['target']}`",
        f"**Scope:** {data.get('scope', 'N/A')}",
        f"**Started:** {data.get('started_at', '')[:19].replace('T', ' ')}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Tool:** Phantom v{VERSION} — Red Team AI Agent",
        "",
        "---",
        "",
    ]

    scan = data.get("scan", {})
    if scan:
        lines += ["## Target Overview", ""]
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Status | {'🟢 UP' if scan.get('host_up') else '🔴 DOWN'} |")
        if scan.get("os_guess"):
            lines.append(f"| OS | {scan['os_guess']} |")
        if scan.get("hostnames"):
            lines.append(f"| Hostnames | {', '.join(scan['hostnames'])} |")
        whois = data.get("whois", {})
        if whois.get("org"):
            lines.append(f"| Organization | {whois['org']} |")
        if whois.get("country"):
            lines.append(f"| Country | {whois['country']} |")

        ports = scan.get("ports", [])
        if ports:
            lines += ["", f"## Open Ports ({len(ports)})", "",
                      "| Port | Protocol | Service | Version |",
                      "|----|----|----|---|"]
            for p in ports:
                lines.append(f"| {p['number']} | {p['protocol'].upper()} | {p['service']} | {p.get('version', '—')} |")

    ttps = data.get("ttps", [])
    if ttps:
        lines += ["", f"## MITRE ATT&CK TTPs ({len(ttps)})", "",
                  "| Risk | Technique | Name | Tactic | Port | OPSEC |",
                  "|----|----|----|----|----|---|"]
        for t in ttps:
            lines.append(
                f"| **{t['risk'].upper()}** | {t['tid']} | {t['name']} | "
                f"{t['tactic']} | {t['port']} | {t.get('opsec', '—')} |"
            )

    cves = data.get("cves", [])
    if cves:
        lines += ["", f"## CVE Intelligence ({len(cves)})", "",
                  "| CVSS | CVE ID | Port | MITRE | Metasploit | Description |",
                  "|----|----|----|----|----|---|"]
        for c in cves:
            msf = c.get("metasploit") or "—"
            lines.append(
                f"| **{c.get('cvss', '?')}** | {c['id']} | {c.get('port', '?')} | "
                f"{c.get('mitre', '—')} | `{msf}` | {c.get('description', '')[:70]} |"
            )

    messages = data.get("messages", [])
    if messages:
        lines += ["", "## AI Analysis & Recommendations", ""]
        for msg in messages:
            if msg["role"] == "assistant":
                lines.append(msg["content"])
                lines.append("")

    findings = data.get("findings", [])
    if findings:
        lines += ["", "## Tool Findings", ""]
        for f in findings:
            lines.append(f"- **[{f['risk'].upper()}]** {f['finding']}")

    notes = data.get("notes", [])
    if notes:
        lines += ["", "## Operator Notes", ""]
        for n in notes:
            lines.append(f"- {n['note']}")

    lines += ["", "---", "", f"*Generated by Phantom v{VERSION} — Red Team AI Agent*", ""]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    mapper.print_report_saved(str(report_path))


# ─── ANA AKIŞ ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    mapper.print_banner()

    if args.sessions:
        cmd_sessions()
        return

    if not args.target and not args.trust:
        parser.print_help()
        sys.exit(0)

    # ── Trust graph (standalone mod) ──────────────────────────────────────────
    if args.trust:
        targets = [t.strip() for t in args.trust.split(",") if t.strip()]
        build_trust_graph(targets, console)
        return

    ok, info = check_ollama()
    if not ok:
        mapper.print_error(f"Ollama hatası: {info}")
        sys.exit(1)

    model_name = args.model or info
    mapper.print_success(f"Ollama OK — model: {model_name}")

    llm = OllamaClient(model=model_name)
    memory = SessionMemory(target=args.target)
    memory.set_scope(args.scope)

    mapper.print_info(f"Hedef: {args.target}  |  Kapsam: {args.scope}")

    if args.adv:
        print_adversary_profile(args.adv, console)

    scan = None
    whois = None
    ttps = []
    cves = []
    subdomains = []

    if not args.no_scan:
        scan, whois = run_recon(args.target, args.fast, memory)
        mapper.print_scan_summary(scan, whois)

        # ── Drift analizi ──────────────────────────────────────────────────
        ports_as_dicts = memory.data.get("scan", {}).get("ports", [])
        drift_result = detect_drift(args.target, ports_as_dicts)
        if drift_result.has_changes or args.drift:
            print_drift_result(drift_result, console)

        if args.sub:
            mapper.print_info("Subdomain enumeration başlatılıyor...")
            subdomains = enumerate_subdomains(args.target)
            print_subdomains(subdomains, console)
            memory.data["subdomains"] = [{"name": s.name, "ip": s.ip} for s in subdomains]

        if args.waf:
            mapper.print_info("WAF tespiti yapılıyor...")
            http_ports = [p for p in scan.ports if p.service in ("http", "https") or p.number in ("80", "443", "8080", "8443")]
            if http_ports:
                port = http_ports[0]
                waf_result = detect_waf(args.target, int(port.number), port.service == "https")
                print_waf_result(waf_result, console)

        if args.fp:
            mapper.print_info("Web teknoloji parmak izi alınıyor...")
            http_ports = [p for p in scan.ports if p.service in ("http", "https") or p.number in ("80", "443", "8080")]
            if http_ports:
                port = http_ports[0]
                fp_result = fingerprint(args.target, int(port.number), port.service == "https")
                print_fingerprint(fp_result, console)

        # ── Honeypot tespiti ───────────────────────────────────────────────
        if args.honeypot:
            mapper.print_info("Honeypot tespiti yapılıyor...")
            hp_result = detect_honeypot(args.target, ports_as_dicts)
            print_honeypot_result(hp_result, console)
            if hp_result.score >= 60:
                mapper.print_error("⚠  Yüksek honeypot ihtimali! Devam etmek riskli.")
                memory.add_finding(f"Honeypot şüphesi: skor={hp_result.score}", "high")

        ttps = map_scan_to_ttps(scan.ports)
        if args.adv:
            ttps = filter_ttps_for_adversary(ttps, args.adv)
            mapper.print_info(f"TTPs {args.adv} profiline göre filtrelendi")

        memory.save_ttps(ttps)
        mapper.print_attack_map(ttps, args.target)

        if args.graph:
            build_attack_path_graph(ttps, [], args.target, console)

        cves = scan_ports_to_cves(scan.ports)
        if cves:
            memory.data["cves"] = [
                {"id": c["id"], "cvss": c.get("cvss"), "port": c.get("port"),
                 "service": c.get("service_key", ""), "mitre": c.get("mitre"),
                 "metasploit": c.get("metasploit"), "poc": c.get("poc"),
                 "description": c.get("description"), "service_key": c.get("service_key")}
                for c in cves
            ]
            print_cve_table(cves, console)
            if args.graph:
                build_attack_path_graph(ttps, cves, args.target, console)
        else:
            mapper.print_info("Versiyon eşleşmesi bulunamadı — banner grab deneyin")

        # ── Blind spot analizi ─────────────────────────────────────────────
        if args.blindspot:
            ttp_dicts = memory.data.get("ttps", [])
            bs_results = analyze_blind_spots(ttp_dicts)
            print_blind_spots(bs_results, console)

        if args.creds:
            mapper.print_info("Default credential testi başlatılıyor...")
            cred_hits = check_default_creds(scan.ports, args.target)
            print_cred_results(cred_hits, console)
            for h in cred_hits:
                if h.success:
                    memory.add_finding(f"Default cred: {h.service}:{h.port} — {h.user}/{h.password}", "critical")

        if args.navigator:
            nav_path = export_navigator_layer(ttps, args.target, cves)
            mapper.print_success(f"Navigator layer: {nav_path}")

        # ── Red vs Blue simülasyonu ────────────────────────────────────────
        if args.redvsblue:
            run_red_vs_blue(llm, memory.data.get("ttps", []), cves, args.target, memory, console)

        # ── Ek araçlar (nuclei, masscan, nikto, gobuster, dns) ────────────
        extra_contexts = run_extra_tools(args, scan, memory)

        run_initial_analysis(llm, scan, whois, ttps, cves, args.scope, memory, extra_contexts)

        if args.agents:
            ports_for_agents = [
                {"port": p.get("number"), "servis": p.get("service"), "versiyon": p.get("version", "")}
                for p in memory.data.get("scan", {}).get("ports", [])
                if isinstance(p, dict)
            ]
            agent_context = {"ports": ports_for_agents}
            team_report = run_agent_team(llm, args.target, context=agent_context, verbose=True)
            memory.data["agent_team_report"] = team_report.get("referee", {})
            memory.add_finding(
                f"Ajan Ekibi — Risk: {team_report.get('referee', {}).get('genel_risk_skoru', '?')}/100 "
                f"| Başarı: {team_report.get('referee', {}).get('saldırı_başarı_ihtimali', '?')}",
                "critical" if team_report.get("referee", {}).get("genel_risk_skoru", 0) >= 70 else "high"
            )
    else:
        mapper.print_info("Tarama atlandı — interaktif moda geçiliyor...")

    if not args.auto:
        interactive_loop(llm, memory, args.target, VERSION)

    if args.report:
        generate_report(memory)

    if args.html:
        html_path = generate_html_report(memory.data, VERSION)
        mapper.print_success(f"HTML rapor: {html_path}")
        import subprocess as _sp
        try:
            _sp.run(["open", str(html_path)], check=False)
        except Exception:
            pass

    # Cross-session hafızaya öğren
    memory.finalize()
    mapper.print_session_saved(str(memory.session_file))


if __name__ == "__main__":
    main()
