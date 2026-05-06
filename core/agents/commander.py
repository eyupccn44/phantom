"""
CommanderAgent — Paralel ajan orkestratörü.
Faz 1: Recon (veri topla)
Faz 2: Threat + Intel + Exploit + Web + Opsec (paralel uzmanlar)
Faz 3: Attack (kill chain sentezi)
Faz 4: Defense (adversarial debate)
Faz 5: Referee (nihai değerlendirme)
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .base import AgentResult
from .recon import ReconAgent
from .threat import ThreatAgent
from .exploit import ExploitAgent
from .intel import IntelAgent
from .web import WebAgent
from .opsec import OpsecAgent
from .attack import AttackAgent
from .defense import DefenseAgent
from .referee import RefereeAgent

console = Console()


def _run_agent_safe(agent_class, llm, target: str, context: dict) -> tuple[str, AgentResult]:
    try:
        agent = agent_class(llm, target, context.copy())
        result = agent.run()
        return agent.name, result
    except Exception as e:
        name = getattr(agent_class, "name", "?")
        return name, AgentResult(agent=name, status="error", summary=str(e))


def _print_result(result: AgentResult, elapsed: float):
    icon = "✓" if result.status == "ok" else "✗"
    color = "green" if result.status == "ok" else "red"
    role_map = {
        "recon": "Keşif", "threat": "Tehdit", "exploit": "İstismar",
        "intel": "İstihbarat", "web": "Web", "opsec": "OPSEC",
        "attack": "Saldırı", "defense": "Savunma", "referee": "Hakem",
    }
    label = role_map.get(result.agent, result.agent.upper())
    summary = result.summary[:120] if result.summary else "(çıktı yok)"
    console.print(
        f"  [{color}]{icon}[/{color}] [bold]{label}[/bold] "
        f"[dim]({elapsed:.1f}s)[/dim]  {summary}"
    )
    # Grounding uyarıları varsa göster
    if result.grounding_warnings:
        for w in result.grounding_warnings[:3]:
            console.print(f"    [yellow]⚠ Grounding:[/yellow] [dim]{w}[/dim]")


def run_agent_team(
    llm,
    target: str,
    context: dict = None,
    max_workers: int = 4,
    verbose: bool = True,
) -> dict:
    """
    Tüm ajan ekibini çalıştır ve birleşik sonuç döndür.
    context: önceki tarama verisi (ports, nmap_raw, vb.) varsa aktar.
    """
    ctx = context.copy() if context else {}
    results = {}
    t0 = time.time()

    if verbose:
        console.print(Panel(
            f"[bold cyan]PHANTOM AJAN EKİBİ[/bold cyan]\n"
            f"Hedef: [yellow]{target}[/yellow]\n"
            f"B+C Hibrit: Paralel Uzmanlar + Adversarial Tartışma",
            border_style="cyan"
        ))

    # ── FAZ 1: RECON ─────────────────────────────────────────────────────────
    if verbose:
        console.print("\n[bold blue]▶ Faz 1 — Keşif[/bold blue]")

    t1 = time.time()
    _, recon_result = _run_agent_safe(ReconAgent, llm, target, ctx)
    elapsed = time.time() - t1

    if verbose:
        _print_result(recon_result, elapsed)

    results["recon"] = recon_result
    ctx["recon_result"] = recon_result.data
    # Recon verilerini üst context'e taşı — diğer ajanlar kullanabilsin
    if "ports" in recon_result.data:
        ctx["ports"] = recon_result.data["ports"]
    if "nmap_raw" in recon_result.data:
        ctx["nmap_raw"] = recon_result.data["nmap_raw"]

    # ── FAZ 2: PARALEL UZMANLAR ───────────────────────────────────────────────
    if verbose:
        console.print("\n[bold blue]▶ Faz 2 — Paralel Uzman Analizi[/bold blue]")

    specialist_classes = [ThreatAgent, ExploitAgent, IntelAgent, WebAgent, OpsecAgent]
    specialist_results = {}

    with ThreadPoolExecutor(max_workers=min(max_workers, len(specialist_classes))) as executor:
        future_map = {
            executor.submit(_run_agent_safe, cls, llm, target, ctx): cls
            for cls in specialist_classes
        }
        for future in as_completed(future_map):
            t_start = time.time()
            name, result = future.result()
            elapsed = time.time() - t_start
            specialist_results[name] = result
            if verbose:
                _print_result(result, elapsed)

    results.update(specialist_results)

    # Specialist sonuçlarını context'e ekle
    for name, res in specialist_results.items():
        ctx[f"{name}_result"] = res.data
    # OPSEC'e intel TTP'lerini aktar
    if "intel" in specialist_results:
        intel_data = specialist_results["intel"].data
        ctx["local_ttps"] = intel_data.get("local_ttps", ctx.get("local_ttps", []))
        ctx["intel_result"] = intel_data

    # ── FAZ 3: SALDIRI PLANI ─────────────────────────────────────────────────
    if verbose:
        console.print("\n[bold blue]▶ Faz 3 — Kill Chain Oluşturma[/bold blue]")

    t3 = time.time()
    _, attack_result = _run_agent_safe(AttackAgent, llm, target, ctx)
    elapsed = time.time() - t3

    if verbose:
        _print_result(attack_result, elapsed)

    results["attack"] = attack_result
    ctx["attack_result"] = attack_result.data

    # ── FAZ 4: SAVUNMA TARTIŞMASI ─────────────────────────────────────────────
    if verbose:
        console.print("\n[bold blue]▶ Faz 4 — Adversarial Tartışma[/bold blue]")

    t4 = time.time()
    _, defense_result = _run_agent_safe(DefenseAgent, llm, target, ctx)
    elapsed = time.time() - t4

    if verbose:
        _print_result(defense_result, elapsed)

    results["defense"] = defense_result
    ctx["defense_result"] = defense_result.data

    # ── FAZ 5: HAKEMİ ────────────────────────────────────────────────────────
    if verbose:
        console.print("\n[bold blue]▶ Faz 5 — Nihai Değerlendirme[/bold blue]")

    t5 = time.time()
    _, referee_result = _run_agent_safe(RefereeAgent, llm, target, ctx)
    elapsed = time.time() - t5

    if verbose:
        _print_result(referee_result, elapsed)

    results["referee"] = referee_result

    total_elapsed = time.time() - t0

    # ── ÖZET TABLO ───────────────────────────────────────────────────────────
    if verbose:
        _print_summary_table(results, target, total_elapsed)

    return {
        "target": target,
        "elapsed": total_elapsed,
        "results": {name: res.data for name, res in results.items()},
        "summaries": {name: res.summary for name, res in results.items()},
        "statuses": {name: res.status for name, res in results.items()},
        "referee": referee_result.data,
    }


def _print_summary_table(results: dict, target: str, elapsed: float):
    referee = results.get("referee")
    if not referee or not isinstance(referee.data, dict):
        return

    data = referee.data
    risk_score = data.get("genel_risk_skoru", "?")
    opsec_score = data.get("opsec_skoru", "?")
    success_rate = data.get("saldırı_başarı_ihtimali", "?")
    exec_summary = data.get("yönetici_özeti", "")

    console.print()
    console.print(Panel(
        f"[bold]Hedef:[/bold] {target}\n"
        f"[bold]Risk Skoru:[/bold] [red]{risk_score}/100[/red]  "
        f"[bold]OPSEC:[/bold] [yellow]{opsec_score}/100[/yellow]  "
        f"[bold]Başarı İhtimali:[/bold] [magenta]{success_rate}[/magenta]\n\n"
        f"[italic]{exec_summary}[/italic]\n\n"
        f"[dim]Toplam süre: {elapsed:.1f}s[/dim]",
        title="[bold cyan]PHANTOM EKİP RAPORU[/bold cyan]",
        border_style="cyan",
    ))

    # Kritik bulgular
    findings = data.get("kritik_bulgular", [])
    if findings:
        table = Table(title="Kritik Bulgular", border_style="dim")
        table.add_column("Bulgu", style="white")
        table.add_column("Etki", style="bold")
        table.add_column("Öneri", style="dim")
        for f in findings[:8]:
            etki = f.get("etki", "?")
            color = {"Kritik": "red", "Yüksek": "yellow", "Orta": "blue"}.get(etki, "white")
            table.add_row(
                f.get("bulgu", "?")[:60],
                f"[{color}]{etki}[/{color}]",
                f.get("öneri", "?")[:60],
            )
        console.print(table)

    # Aksiyon planı
    actions = data.get("öncelikli_aksiyon_planı", [])
    if actions:
        console.print("\n[bold]Öncelikli Aksiyonlar:[/bold]")
        for a in actions[:5]:
            console.print(
                f"  [{a.get('öncelik', '?')}] {a.get('aksiyon', '?')[:80]} "
                f"[dim]— {a.get('süre', '?')}[/dim]"
            )
