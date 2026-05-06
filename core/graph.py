from rich.tree import Tree
from rich.console import Console
from rich.panel import Panel
from rich import box

KILL_CHAIN_PHASES = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact",
]

RISK_STYLE = {
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold green",
}

RISK_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def build_attack_path_graph(ttps, cves: list, target: str, console: Console) -> None:
    tree = Tree(
        f"[bold red]⬡ ATTACK PATH GRAPH — {target}[/bold red]",
        guide_style="dim red",
    )

    tactic_map: dict[str, list] = {}
    for t in ttps:
        tactic_map.setdefault(t.tactic, []).append(t)

    cve_by_port: dict[str, list] = {}
    for c in cves:
        cve_by_port.setdefault(str(c.get("port", "?")), []).append(c)

    prev_branch = None
    for phase in KILL_CHAIN_PHASES:
        if phase not in tactic_map:
            continue

        items = tactic_map[phase]
        connector = "└─▶" if prev_branch else "┌──"
        branch = tree.add(f"[bold white]{connector} {phase}[/bold white]")

        for t in items:
            style = RISK_STYLE.get(t.risk, "white")
            emoji = RISK_EMOJI.get(t.risk, "○")
            node_text = (
                f"{emoji} [{style}]{t.tid}[/{style}] "
                f"[white]{t.name}[/white] "
                f"[dim](:{t.port}/{t.service})[/dim]"
            )
            tech_node = branch.add(node_text)

            port_cves = cve_by_port.get(t.port, [])
            for c in port_cves[:2]:
                cvss = c.get("cvss", 0)
                msf = " [green]MSF✓[/green]" if c.get("metasploit") else ""
                tech_node.add(
                    f"[dim]💀 {c['id']} CVSS:{cvss}{msf} — {c.get('description','')[:50]}[/dim]"
                )

            if t.apt_groups:
                tech_node.add(f"[dim cyan]👥 APT: {', '.join(t.apt_groups[:2])}[/dim cyan]")

        prev_branch = branch

    if ttps:
        objective = tree.add("[bold red]└─▶ 🎯 OBJECTIVE[/bold red]")
        critical = [t for t in ttps if t.risk == "critical"]
        if critical:
            objective.add(f"[dim]En kritik yol: {' → '.join(t.tid for t in critical[:3])}[/dim]")

    console.print(Panel(tree, title="[bold]Kill Chain Attack Path[/bold]",
                        border_style="red", box=box.ROUNDED))
