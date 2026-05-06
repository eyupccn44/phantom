"""
OpsecAgent — EDR kör nokta analizi + OPSEC risk değerlendirmesi.
Sıcaklık: 0.3
"""
from .base import BaseAgent, AgentResult


class OpsecAgent(BaseAgent):
    name = "opsec"
    role = "OPSEC ve EDR Analisti"
    temperature = 0.3

    def _build_system(self) -> str:
        return (
            "Sen bir red team OPSEC uzmanısın. "
            "EDR algılama oranlarını ve teknik kör noktalarını analiz ederek "
            "operasyonel güvenlik değerlendirmesi yaparsın.\n"
            "Yalnızca sağlanan gerçek veriyi kullan.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"kör_noktalar\": [\n"
            "    {\"tid\": \"T1055\", \"teknik\": \"...\", \"kör_skor\": 72, "
            "\"düşük_algılama_edr\": [\"CrowdStrike\", \"MDE\"]}\n"
            "  ],\n"
            "  \"yüksek_risk_teknikler\": [\"T1190\", \"T1059\"],\n"
            "  \"önerilen_opsec_önlemleri\": [\"önlem1\", \"önlem2\"],\n"
            "  \"genel_opsec_skoru\": 65,\n"
            "  \"özet\": \"kısa özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        blindspot_data = self.context.get("blindspot_analysis", [])
        ttps = self.context.get("local_ttps", [])
        intel_ttps = self.context.get("tespit_edilen_teknikler", [])

        all_tids = set()
        for t in ttps:
            if isinstance(t, dict):
                all_tids.add(t.get("tid", ""))
        for t in intel_ttps:
            if isinstance(t, dict):
                all_tids.add(t.get("tid", ""))
        all_tids.discard("")

        sections = [f"Hedef: {self.target}", f"Tespit edilen TTP sayısı: {len(all_tids)}"]

        if blindspot_data:
            lines = []
            for item in blindspot_data[:15]:
                if isinstance(item, dict):
                    tid = item.get("tid", "?")
                    name = item.get("name", "")
                    score = item.get("blind_score", "?")
                    edr_r = item.get("edr_rates", {})
                else:
                    tid = getattr(item, "technique_id", "?")
                    name = getattr(item, "technique_name", "")
                    score = getattr(item, "blind_score", "?")
                    edr_r = getattr(item, "edr_rates", {})
                low_edrs = [edr for edr, rate in edr_r.items() if rate < 40] if edr_r else []
                lines.append(f"- {tid} {name}: Kör skor {score} — Düşük algılayan EDR: {low_edrs}")
            sections.append("Kör Nokta Analizi:\n" + "\n".join(lines))
        else:
            sections.append(f"Analiz edilecek TTP'ler: {list(all_tids)[:20]}")

        sections.append("\nBu verilere dayanarak JSON şablonunu doldur.")
        return "\n\n".join(sections)

    def _fetch_data(self) -> dict:
        from core.blindspot import analyze_blind_spots

        ttps = self.context.get("local_ttps", [])
        intel_result = self.context.get("intel_result", {})
        intel_ttps = intel_result.get("tespit_edilen_teknikler", []) if isinstance(intel_result, dict) else []

        all_tids = []
        for t in ttps:
            if isinstance(t, dict) and t.get("tid"):
                all_tids.append(t["tid"])
        for t in intel_ttps:
            if isinstance(t, dict) and t.get("tid"):
                all_tids.append(t["tid"])

        unique_tids = list(dict.fromkeys(all_tids))[:25]
        ttp_dicts = [{"tid": tid} for tid in unique_tids]

        try:
            blind_results = analyze_blind_spots(ttp_dicts)
        except Exception:
            blind_results = []

        serializable = [
            {
                "tid": r.technique_id,
                "name": r.technique_name,
                "tactic": r.tactic,
                "blind_score": r.blind_score,
                "avg_detection": r.avg_detection,
                "edr_rates": r.edr_rates,
                "recommendation": r.recommendation,
            }
            for r in blind_results
        ]
        return {"blindspot_analysis": serializable}

    def run(self) -> AgentResult:
        try:
            live = self._fetch_data()
            self.context.update(live)

            system = self._build_system()
            user = self._build_user_prompt()
            raw, parsed = self._call_with_retry(system, user)

            if raw.startswith("__LLM_ERROR__"):
                return AgentResult(agent=self.name, status="error", summary=raw)

            grounded, warnings = self._apply_grounding(parsed)
            blind_count = len(live["blindspot_analysis"])
            summary = grounded.get("özet", f"{blind_count} OPSEC kör nokta analiz edildi")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data={**grounded, **live},
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
