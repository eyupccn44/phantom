"""
DefenseAgent — Saldırı planına karşı savunma perspektifi. (Adversarial Debate)
Sıcaklık: 0.5
"""
from .base import BaseAgent, AgentResult


class DefenseAgent(BaseAgent):
    name = "defense"
    role = "Savunma Analisti"
    temperature = 0.5

    def _build_system(self) -> str:
        return (
            "Sen bir kıdemli Blue Team analistisin. "
            "Red team saldırı planına karşı savunma açıklarını, "
            "tespit noktalarını ve hafifletme önlemlerini belirlersin.\n"
            "Eleştirel ve gerçekçi ol — saldırıyı zayıflat, gerçek savunma açıklarını göster.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"tespit_noktaları\": [\n"
            "    {\"aşama\": \"ilk_erişim\", \"teknik\": \"T1190\", "
            "\"tespit_yöntemi\": \"WAF/IDS alarmı\", \"güvenilirlik\": \"Yüksek/Orta/Düşük\"}\n"
            "  ],\n"
            "  \"savunma_açıkları\": [\"Yamalanmamış CVE-2021-XXXX\", \"Log analizi yok\"],\n"
            "  \"hafifletme_önlemleri\": [\"Acil yama: ...\", \"IDS kuralı ekle\"],\n"
            "  \"savunma_skoru\": 45,\n"
            "  \"en_kritik_açık\": \"Tek cümle en kritik savunma açığı\",\n"
            "  \"özet\": \"kısa özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        attack_result = self.context.get("attack_result", {})
        opsec = self.context.get("opsec_result", {})

        sections = [f"Hedef: {self.target}"]

        if isinstance(attack_result, dict):
            kill_chain = attack_result.get("kill_chain", [])
            if kill_chain:
                lines = []
                for step in kill_chain[:8]:
                    lines.append(
                        f"- [{step.get('aşama', '?')}] {step.get('teknik', '?')} "
                        f"port:{step.get('hedef_port', '?')} — {step.get('açıklama', '')[:80]}"
                    )
                sections.append("Saldırı Kill Chain:\n" + "\n".join(lines))

            entry = attack_result.get("birincil_giriş_noktası", "")
            if entry:
                sections.append(f"Birincil giriş noktası: {entry}")

            obstacles = attack_result.get("kritik_engeller", [])
            if obstacles:
                sections.append(f"Saldırganın gördüğü engeller: {obstacles}")

        if isinstance(opsec, dict):
            blind_spots = opsec.get("kör_noktalar", [])
            if blind_spots:
                lines = [f"- {b.get('tid', '?')}: EDR kör skoru {b.get('kör_skor', '?')}" for b in blind_spots[:5]]
                sections.append("EDR Kör Noktaları:\n" + "\n".join(lines))

        sections.append(
            "\nBu saldırı planına karşı savunma perspektifini analiz et. "
            "Gerçekçi savunma açıklarını belirt. JSON şablonunu doldur."
        )
        return "\n\n".join(sections)

    def run(self) -> AgentResult:
        try:
            system = self._build_system()
            user = self._build_user_prompt()
            raw, parsed = self._call_with_retry(system, user)

            if raw.startswith("__LLM_ERROR__"):
                return AgentResult(agent=self.name, status="error", summary=raw)

            grounded, warnings = self._apply_grounding(parsed)
            summary = grounded.get("özet", f"Savunma skoru: {grounded.get('savunma_skoru', '?')}")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data=grounded,
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
