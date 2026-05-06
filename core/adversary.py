import json
from pathlib import Path

ADV_DB = Path(__file__).parent.parent / "data" / "adversaries.json"
_db: dict | None = None


def _load() -> dict:
    global _db
    if _db is None:
        _db = json.loads(ADV_DB.read_text(encoding="utf-8"))
    return _db


def list_adversaries() -> list[str]:
    return list(_load().keys())


def get_adversary(name: str) -> dict | None:
    db = _load()
    for key, val in db.items():
        if key.lower() == name.lower() or name.lower() in [a.lower() for a in val.get("aliases", [])]:
            return val
    return None


def build_adversary_prompt(name: str) -> str:
    adv = get_adversary(name)
    if not adv:
        return ""

    ttps_str = ", ".join(adv.get("ttps", []))
    tools_str = ", ".join(adv.get("tools", []))
    targets_str = ", ".join(adv.get("targets", []))
    aliases_str = ", ".join(adv.get("aliases", []))

    return f"""
━━━ ADVERSARY SIMULATION MODU ━━━

Sen artık {adv['name']} ({aliases_str}) gibi davranıyorsun.

Menşei: {adv.get('origin', 'Bilinmiyor')}
Hedef Sektörler: {targets_str}
OPSEC Seviyesi: {adv.get('opsec', 'MODERATE')}
Profil: {adv.get('description', '')}

Kullandığın TTPs: {ttps_str}
Tercih Ettiğin Araçlar: {tools_str}

KURALAR:
1. YALNIZCA bu grubun bilinen TTP'lerini öner
2. Bu grubun OPSEC seviyesine ({adv.get('opsec')}) uy
3. Bu grubun tercih ettiği initial access: {', '.join(adv.get('preferred_initial_access', []))}
4. Bu grubun tercih ettiği persistence: {', '.join(adv.get('preferred_persistence', []))}
5. Bu grubun tercih ettiği exfil: {', '.join(adv.get('preferred_exfil', []))}
6. Gerçek dünya incident'larına ve bu grubun taktiklerine referans ver
7. Bu grubun tarzıyla düşün: "{adv.get('description', '')}"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


def filter_ttps_for_adversary(ttps: list, adversary_name: str) -> list:
    adv = get_adversary(adversary_name)
    if not adv:
        return ttps
    allowed = set(adv.get("ttps", []))
    return [t for t in ttps if t.tid in allowed or t.tid.split(".")[0] in allowed] or ttps


def print_adversary_profile(name: str, console) -> None:
    adv = get_adversary(name)
    if not adv:
        console.print(f"[red]Adversary bulunamadı: {name}[/red]")
        console.print(f"Mevcut: {', '.join(list_adversaries())}")
        return

    from rich.panel import Panel
    from rich import box

    lines = [
        f"[bold red]{adv['name']}[/bold red]",
        f"[dim]Aliases:[/dim] {', '.join(adv.get('aliases', []))}",
        f"[dim]Menşei:[/dim]  {adv.get('origin', '?')}",
        f"[dim]OPSEC:[/dim]   {adv.get('opsec', '?')}",
        f"[dim]Hedefler:[/dim] {', '.join(adv.get('targets', []))}",
        f"[dim]Araçlar:[/dim] {', '.join(adv.get('tools', []))}",
        f"[dim]TTPs:[/dim]    {', '.join(adv.get('ttps', []))}",
        f"\n[italic]{adv.get('description', '')}[/italic]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]Adversary Profili[/bold]",
                        border_style="red", box=box.ROUNDED))
