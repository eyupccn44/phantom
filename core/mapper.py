from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich.rule import Rule

from .mitre import MappedTechnique, RISK_COLORS, RISK_EMOJI

console = Console()

RISK_STYLE = {
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold green",
}


def print_banner() -> None:
    banner = Text()
    banner.append("\n")
    banner.append("██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗\n", style="bold red")
    banner.append("██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║\n", style="bold red")
    banner.append("██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║\n", style="bold red")
    banner.append("██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║\n", style="bold red")
    banner.append("██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║\n", style="bold red")
    banner.append("╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝\n", style="bold red")
    banner.append("                   Red Team AI Agent  •  MITRE ATT&CK v16.1\n", style="dim")
    banner.append("          ⚠  Yalnızca yetkili pentest ortamlarında kullanın  ⚠\n", style="dim yellow")
    console.print(Align.center(banner))


def print_scan_summary(scan, whois=None) -> None:
    console.print(Rule("[bold red]RECON SONUÇLARI[/bold red]", style="red"))

    info = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    info.add_column("Key", style="dim", width=16)
    info.add_column("Value", style="bold")

    info.add_row("Hedef", scan.target)
    info.add_row("Durum", "[bold green]ÇEVRİMİÇİ[/bold green]" if scan.host_up else "[bold red]ÇEVRİMDIŞI[/bold red]")
    if scan.hostnames:
        info.add_row("Hostname", ", ".join(scan.hostnames))
    if scan.os_guess:
        info.add_row("İşletim Sistemi", scan.os_guess)
    if whois and whois.org:
        info.add_row("Organizasyon", whois.org)
    if whois and whois.country:
        info.add_row("Ülke", whois.country)

    console.print(Panel(info, title="[bold]Hedef Bilgisi[/bold]", border_style="red", box=box.ROUNDED))

    if scan.ports:
        port_table = Table(
            "Port", "Protokol", "Servis", "Versiyon",
            box=box.SIMPLE_HEAD,
            border_style="red",
            header_style="bold red",
            show_lines=False,
        )
        for p in scan.ports:
            port_table.add_row(p.number, p.protocol.upper(), p.service, p.version or "—")

        console.print(Panel(
            port_table,
            title=f"[bold]Açık Portlar — {len(scan.ports)} Bulundu[/bold]",
            border_style="red",
            box=box.ROUNDED,
        ))
    else:
        console.print(Panel("[dim]Açık port bulunamadı[/dim]", border_style="dim"))


def print_attack_map(ttps: list[MappedTechnique], target: str) -> None:
    console.print(Rule("[bold red]SALDIRI HARİTASI[/bold red]", style="red"))

    if not ttps:
        console.print(Panel("[dim]TTP eşleşmesi bulunamadı[/dim]", border_style="dim"))
        return

    tactic_groups: dict[str, list[MappedTechnique]] = {}
    for t in ttps:
        tactic_groups.setdefault(t.tactic, []).append(t)

    kill_chain_order = [
        "Reconnaissance", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion",
        "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact",
        "Command and Control",
    ]

    tree = Tree(
        f"[bold red]⬡  {target}[/bold red]",
        guide_style="red",
    )

    ordered_tactics = [t for t in kill_chain_order if t in tactic_groups]
    ordered_tactics += [t for t in tactic_groups if t not in kill_chain_order]

    for tactic in ordered_tactics:
        items = tactic_groups[tactic]
        branch = tree.add(f"[bold white]{tactic}[/bold white]")
        for item in items:
            style = RISK_STYLE.get(item.risk, "white")
            emoji = RISK_EMOJI.get(item.risk, "○")
            branch.add(
                f"{emoji}  [{style}]{item.tid}[/{style}] "
                f"[white]— {item.name}[/white] "
                f"[dim](Port {item.port} / {item.service})[/dim]"
            )

    console.print(Panel(tree, title="[bold]Kill Chain → TTP Haritası[/bold]", border_style="red", box=box.ROUNDED))

    ttp_table = Table(
        "Risk", "Teknik ID", "İsim", "Taktik", "Port", "Servis", "Araçlar",
        box=box.SIMPLE_HEAD,
        border_style="red",
        header_style="bold red",
        show_lines=True,
    )

    for t in ttps[:20]:
        risk_text = Text(t.risk.upper(), style=RISK_STYLE.get(t.risk, "white"))
        ttp_table.add_row(
            risk_text,
            t.tid,
            t.name,
            t.tactic,
            t.port,
            t.service,
            ", ".join(t.tools[:3]) if t.tools else "—",
        )

    console.print(Panel(
        ttp_table,
        title="[bold]Detaylı TTP Tablosu[/bold]",
        border_style="red",
        box=box.ROUNDED,
    ))


def print_thinking() -> None:
    console.print("\n[dim red]◈  PHANTOM analiz ediyor...[/dim red]\n")


def print_llm_response(response: str) -> None:
    console.print(Panel(
        response.strip(),
        title="[bold red]PHANTOM[/bold red]",
        border_style="red",
        box=box.ROUNDED,
        padding=(1, 2),
    ))


def print_report_saved(path: str) -> None:
    console.print(f"\n[bold green]✓ Rapor kaydedildi:[/bold green] {path}")


def print_session_saved(path: str) -> None:
    console.print(f"[dim]Session: {path}[/dim]")


def print_error(msg: str) -> None:
    console.print(f"[bold red]✗ {msg}[/bold red]")


def print_info(msg: str) -> None:
    console.print(f"[dim cyan]ℹ  {msg}[/dim cyan]")


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓ {msg}[/bold green]")
