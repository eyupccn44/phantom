import json
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

SESSIONS_DIR = Path(__file__).parent.parent / "sessions"


@dataclass
class DriftResult:
    target: str
    baseline_date: str = ""
    current_date: str = ""
    new_ports: list = field(default_factory=list)
    closed_ports: list = field(default_factory=list)
    version_changes: list = field(default_factory=list)
    service_changes: list = field(default_factory=list)
    has_changes: bool = False
    baseline_session: str = ""


def _load_previous_sessions(target: str) -> list[dict]:
    import re
    slug = re.sub(r"[^\w\-]", "_", target)
    sessions = sorted(SESSIONS_DIR.glob(f"{slug}_*.json"), reverse=True)
    results = []
    for s in sessions[1:4]:
        try:
            data = json.loads(s.read_text(encoding="utf-8"))
            if data.get("scan", {}).get("ports"):
                results.append(data)
        except Exception:
            pass
    return results


def detect_drift(target: str, current_ports: list) -> DriftResult:
    result = DriftResult(target=target, current_date=datetime.now().strftime("%Y-%m-%d %H:%M"))

    previous = _load_previous_sessions(target)
    if not previous:
        result.baseline_date = "İlk tarama — referans yok"
        return result

    baseline = previous[0]
    result.baseline_session = baseline.get("started_at", "")[:16].replace("T", " ")
    result.baseline_date = result.baseline_session

    old_ports = baseline.get("scan", {}).get("ports", [])

    old_map = {p.get("number", ""): p for p in old_ports}
    new_map = {p.get("number", ""): p for p in current_ports}

    for num, port in new_map.items():
        if num not in old_map:
            result.new_ports.append(port)
            result.has_changes = True

    for num, port in old_map.items():
        if num not in new_map:
            result.closed_ports.append(port)
            result.has_changes = True

    for num in set(old_map) & set(new_map):
        old_ver = old_map[num].get("version", "").strip()
        new_ver = new_map[num].get("version", "").strip()
        old_svc = old_map[num].get("service", "")
        new_svc = new_map[num].get("service", "")
        if old_ver and new_ver and old_ver != new_ver:
            result.version_changes.append({
                "port": num,
                "service": new_svc,
                "old_version": old_ver,
                "new_version": new_ver,
            })
            result.has_changes = True
        if old_svc != new_svc:
            result.service_changes.append({
                "port": num,
                "old_service": old_svc,
                "new_service": new_svc,
            })
            result.has_changes = True

    return result


def print_drift_result(result: DriftResult, console) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    if not result.has_changes and not result.baseline_date.startswith("İlk"):
        console.print(Panel(
            f"[green]✓ Değişiklik yok[/green]\nBaseline: {result.baseline_date}  →  Şimdi: {result.current_date}",
            title="[bold]📊 ATTACK SURFACE DRIFT[/bold]",
            border_style="green", box=box.ROUNDED,
        ))
        return

    if result.baseline_date.startswith("İlk"):
        console.print(f"[dim]Drift: İlk tarama, referans kaydedildi[/dim]")
        return

    lines = [f"[dim]Baseline: {result.baseline_date}  →  Şimdi: {result.current_date}[/dim]\n"]

    if result.new_ports:
        lines.append("[bold red]🆕 YENİ AÇIK PORTLAR (kritik — yeni saldırı yüzeyi!):[/bold red]")
        for p in result.new_ports:
            lines.append(f"  [red]+ {p.get('number')}/tcp  {p.get('service','')}  {p.get('version','')}[/red]")

    if result.closed_ports:
        lines.append("\n[bold green]🔒 KAPANAN PORTLAR:[/bold green]")
        for p in result.closed_ports:
            lines.append(f"  [green]- {p.get('number')}/tcp  {p.get('service','')}[/green]")

    if result.version_changes:
        lines.append("\n[bold yellow]⚠ VERSİYON DEĞİŞİKLİKLERİ:[/bold yellow]")
        for v in result.version_changes:
            lines.append(f"  [yellow]~ Port {v['port']} ({v['service']}): {v['old_version']} → {v['new_version']}[/yellow]")

    if result.service_changes:
        lines.append("\n[bold orange3]🔄 SERVİS DEĞİŞİKLİKLERİ:[/bold orange3]")
        for s in result.service_changes:
            lines.append(f"  ~ Port {s['port']}: {s['old_service']} → {s['new_service']}")

    console.print(Panel(
        "\n".join(lines),
        title="[bold]📊 ATTACK SURFACE DRIFT DETECTOR[/bold]",
        border_style="red" if result.new_ports else "yellow",
        box=box.ROUNDED,
    ))
