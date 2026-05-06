from dataclasses import dataclass, field

# EDR detection coverage rates per technique (0-100, kaynak: vendor raporları + red team araştırması)
EDR_COVERAGE: dict[str, dict[str, int]] = {
    "CrowdStrike Falcon": {
        "T1059.001": 91, "T1059.003": 88, "T1055.001": 85, "T1218.011": 41,
        "T1047": 79, "T1548.002": 72, "T1003.001": 94, "T1110.003": 55,
        "T1558.003": 38, "T1557.001": 31, "T1040": 28, "T1574.002": 67,
        "T1027.001": 44, "T1036.005": 52, "T1140": 35, "T1197": 61,
        "T1021.002": 83, "T1021.001": 70, "T1021.006": 66, "T1550.002": 58,
        "T1210": 77, "T1190": 82, "T1133": 49, "T1078": 45,
        "T1071.001": 37, "T1572": 42, "T1090.003": 29, "T1041": 61,
    },
    "Microsoft Defender for Endpoint": {
        "T1059.001": 88, "T1059.003": 85, "T1055.001": 78, "T1218.011": 55,
        "T1047": 82, "T1548.002": 69, "T1003.001": 91, "T1110.003": 48,
        "T1558.003": 44, "T1557.001": 37, "T1040": 22, "T1574.002": 61,
        "T1027.001": 38, "T1036.005": 58, "T1140": 31, "T1197": 54,
        "T1021.002": 80, "T1021.001": 73, "T1021.006": 71, "T1550.002": 52,
        "T1210": 74, "T1190": 79, "T1133": 44, "T1078": 41,
        "T1071.001": 33, "T1572": 38, "T1090.003": 25, "T1041": 57,
    },
    "SentinelOne": {
        "T1059.001": 89, "T1059.003": 86, "T1055.001": 82, "T1218.011": 38,
        "T1047": 75, "T1548.002": 68, "T1003.001": 92, "T1110.003": 51,
        "T1558.003": 35, "T1557.001": 28, "T1040": 25, "T1574.002": 63,
        "T1027.001": 41, "T1036.005": 55, "T1140": 33, "T1197": 58,
        "T1021.002": 81, "T1021.001": 68, "T1021.006": 64, "T1550.002": 55,
        "T1210": 79, "T1190": 84, "T1133": 46, "T1078": 43,
        "T1071.001": 39, "T1572": 44, "T1090.003": 27, "T1041": 59,
    },
    "Carbon Black": {
        "T1059.001": 82, "T1059.003": 79, "T1055.001": 71, "T1218.011": 48,
        "T1047": 68, "T1548.002": 61, "T1003.001": 87, "T1110.003": 44,
        "T1558.003": 31, "T1557.001": 24, "T1040": 19, "T1574.002": 55,
        "T1027.001": 35, "T1036.005": 49, "T1140": 28, "T1197": 51,
        "T1021.002": 76, "T1021.001": 63, "T1021.006": 59, "T1550.002": 48,
        "T1210": 71, "T1190": 77, "T1133": 41, "T1078": 38,
        "T1071.001": 31, "T1572": 37, "T1090.003": 23, "T1041": 52,
    },
}

SIEM_COVERAGE: dict[str, dict[str, int]] = {
    "Splunk SIEM": {
        "T1110.003": 71, "T1078": 68, "T1021.001": 74, "T1021.002": 78,
        "T1003.001": 65, "T1558.003": 42, "T1557.001": 35, "T1040": 31,
        "T1190": 55, "T1059.001": 60, "T1047": 58, "T1071.001": 44,
    },
    "Microsoft Sentinel": {
        "T1110.003": 78, "T1078": 74, "T1021.001": 81, "T1021.002": 83,
        "T1003.001": 71, "T1558.003": 48, "T1557.001": 39, "T1040": 28,
        "T1190": 61, "T1059.001": 65, "T1047": 63, "T1071.001": 47,
    },
    "IBM QRadar": {
        "T1110.003": 65, "T1078": 61, "T1021.001": 68, "T1021.002": 71,
        "T1003.001": 58, "T1558.003": 38, "T1557.001": 31, "T1040": 25,
        "T1190": 49, "T1059.001": 54, "T1047": 51, "T1071.001": 39,
    },
}


@dataclass
class BlindSpotResult:
    technique_id: str
    technique_name: str
    tactic: str
    risk: str
    edr_rates: dict = field(default_factory=dict)
    avg_detection: float = 0.0
    blind_score: float = 0.0
    recommendation: str = ""


def analyze_blind_spots(ttps: list, edr_name: str = None) -> list[BlindSpotResult]:
    results = []

    edrs = {edr_name: EDR_COVERAGE[edr_name]} if edr_name and edr_name in EDR_COVERAGE else EDR_COVERAGE

    for t in ttps:
        tid = t.get("tid", "")
        rates = {}
        for edr, coverage in edrs.items():
            if tid in coverage:
                rates[edr] = coverage[tid]

        if not rates:
            avg = 50.0
        else:
            avg = sum(rates.values()) / len(rates)

        blind_score = 100 - avg

        rec = ""
        if blind_score >= 65:
            rec = "Öncelikli kullan — yüksek ihtimalle kaçar"
        elif blind_score >= 45:
            rec = "Kullanılabilir — hafif obfuscation ile daha iyi"
        else:
            rec = "Riskli — alternatif teknik daha güvenli"

        results.append(BlindSpotResult(
            technique_id=tid,
            technique_name=t.get("name", ""),
            tactic=t.get("tactic", ""),
            risk=t.get("risk", "low"),
            edr_rates=rates,
            avg_detection=round(avg, 1),
            blind_score=round(blind_score, 1),
            recommendation=rec,
        ))

    results.sort(key=lambda x: x.blind_score, reverse=True)
    return results


def print_blind_spots(results: list[BlindSpotResult], console, edr_name: str = None) -> None:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    if not results:
        console.print("[dim]Kör nokta analizi için TTP verisi yok[/dim]")
        return

    table = Table(
        "TID", "Teknik", "Taktik", "Kör Skor", "Ort. Tespit %", "Öneri",
        box=box.SIMPLE_HEAD, border_style="red", header_style="bold red",
        show_lines=False,
    )

    for r in results[:15]:
        score_color = "green" if r.blind_score >= 65 else "yellow" if r.blind_score >= 45 else "red"
        bar = "█" * int(r.blind_score / 10) + "░" * (10 - int(r.blind_score / 10))
        table.add_row(
            f"[dim]{r.technique_id}[/dim]",
            r.technique_name[:35],
            r.tactic[:20],
            f"[{score_color}]{bar} {r.blind_score:.0f}[/{score_color}]",
            f"[dim]{r.avg_detection:.0f}%[/dim]",
            f"[dim]{r.recommendation}[/dim]",
        )

    title = f"[bold]🕶 DEFENDER KÖR NOKTA MATRİSİ"
    if edr_name:
        title += f" — {edr_name}"
    title += "[/bold]"

    console.print(Panel(table, title=title, border_style="red", box=box.ROUNDED))

    top3 = results[:3]
    if top3:
        console.print(
            f"\n[bold red]En Sessiz 3 Teknik:[/bold red] "
            + " → ".join(f"[bold]{r.technique_id}[/bold]({r.blind_score:.0f})" for r in top3)
        )
