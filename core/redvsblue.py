from dataclasses import dataclass, field


@dataclass
class RedBlueResult:
    target: str
    attack_vector: str
    red_analysis: str = ""
    blue_response: str = ""
    detection_gap: str = ""
    winner: str = ""


RED_PROMPT = """Sen bir kırmızı takım operatörüsün. Aşağıdaki saldırı vektörünü analiz et.

GÖREV:
1. Bu vektörden tam kill chain yaz (adım adım, exact komutlar)
2. Hangi araçları kullanırsın? Neden?
3. OPSEC rating: [SILENT/STEALTHY/MODERATE/NOISY]
4. En kritik adım nerede? Neden?
5. Bu saldırıyı durdurmak için ne YAPILMASI GEREKİR?

Kısa ve keskin cevap ver. Gereksiz teorik bilgi verme.

Hedef: {target}
Vektör: {vector}
"""

BLUE_PROMPT = """Sen bir SOC analisti ve blue team uzmanısın. Kırmızı takımın şu saldırısını incele:

KIRMIZI TAKIM ANALİZİ:
{red_analysis}

GÖREV:
1. Bu saldırıyı hangi event ID'ler tetikler? Hangi log kaynakları?
2. Detection penceresi ne kadar? (saniye/dakika/saat)
3. Hangi adımlar EDR'yi kesinlikle tetikler?
4. Hangi adımlar EDR'yi KAÇIRIR? (gerçek kör nokta)
5. Bu saldırıyı durdurabilir miydin? Hangi aşamada?

Hedef: {target}
"""


def run_red_vs_blue(llm, ttps: list, cves: list, target: str, memory, console) -> RedBlueResult:
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box

    if not ttps:
        console.print("[dim]Red vs Blue için TTP verisi gerekli[/dim]")
        return RedBlueResult(target=target, attack_vector="veri yok")

    critical = [t for t in ttps if t.get("risk") in ("critical", "high")]
    vector_ttps = (critical or ttps)[:3]

    vector_desc = " → ".join(
        f"{t.get('tid')} ({t.get('name')}, :{t.get('port')})"
        for t in vector_ttps
    )
    if cves:
        top_cve = sorted(cves, key=lambda c: c.get("cvss", 0), reverse=True)
        vector_desc += f" | CVE: {top_cve[0]['id']} CVSS:{top_cve[0].get('cvss')}"

    result = RedBlueResult(target=target, attack_vector=vector_desc)

    # ── RED TEAM TURU ────────────────────────────────────────────────────────
    console.print(Rule("[bold red]🔴 KIRMIZI TAKIM ANALIZI[/bold red]", style="red"))
    red_prompt = RED_PROMPT.format(target=target, vector=vector_desc)

    red_messages = [{"role": "user", "content": red_prompt}]
    red_response = ""

    def on_red(token: str):
        nonlocal red_response
        red_response += token
        console.print(token, end="", markup=False)

    console.print()
    llm.chat(red_messages, on_token=on_red)
    console.print("\n")
    result.red_analysis = red_response

    # ── BLUE TEAM TURU ───────────────────────────────────────────────────────
    console.print(Rule("[bold blue]🔵 MAVİ TAKIM YANITI[/bold blue]", style="blue"))
    blue_prompt = BLUE_PROMPT.format(red_analysis=red_response, target=target)

    blue_messages = [{"role": "user", "content": blue_prompt}]
    blue_response = ""

    def on_blue(token: str):
        nonlocal blue_response
        blue_response += token
        console.print(token, end="", markup=False)

    console.print()
    llm.chat(blue_messages, on_token=on_blue)
    console.print("\n")
    result.blue_response = blue_response

    # ── ÖZET ─────────────────────────────────────────────────────────────────
    gap_prompt = f"""Kırmızı ve mavi takım analizlerini karşılaştır. 3 cümleyle:
1. Kırmızı takım hangi adımda galip?
2. Mavi takımın en büyük kör noktası ne?
3. Kazanan kim ve neden?

Kırmızı: {red_response[:500]}
Mavi: {blue_response[:500]}"""

    gap_messages = [{"role": "user", "content": gap_prompt}]
    gap_response = ""

    def on_gap(token: str):
        nonlocal gap_response
        gap_response += token

    llm.chat(gap_messages, on_token=on_gap)
    result.detection_gap = gap_response

    console.print(Panel(
        gap_response,
        title="[bold]⚔ RED vs BLUE — ÖZET KARAR[/bold]",
        border_style="yellow",
        box=box.ROUNDED,
    ))

    memory.add_finding(f"RedVsBlue — {vector_desc[:80]}", risk="high")
    memory.add_message("assistant", f"[RedVsBlue]\n{red_response}\n[Blue]\n{blue_response}")

    return result
