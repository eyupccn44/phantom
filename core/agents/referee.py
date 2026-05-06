"""
RefereeAgent — Tüm ajan çıktılarını sentezle, nihai rapor + OPSEC skoru üret.
Sıcaklık: 0.3 (dengeli, tutarlı)
"""
from .base import BaseAgent, AgentResult


class RefereeAgent(BaseAgent):
    name = "referee"
    role = "Nihai Hakem"
    temperature = 0.3

    def _build_system(self) -> str:
        return (
            "Sen kıdemli bir güvenlik mimarısın. "
            "Red ve Blue team analizlerini sentezleyerek objektif nihai değerlendirme yaparsın.\n"
            "Abartma yok, gerçekçi risk değerlendirmesi yap.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"genel_risk_skoru\": 75,\n"
            "  \"red_team_üstünlüğü\": \"saldırının güçlü olduğu alanlar\",\n"
            "  \"blue_team_üstünlüğü\": \"savunmanın güçlü olduğu alanlar\",\n"
            "  \"kritik_bulgular\": [\n"
            "    {\"bulgu\": \"...\", \"etki\": \"Kritik/Yüksek/Orta\", \"öneri\": \"...\"}\n"
            "  ],\n"
            "  \"öncelikli_aksiyon_planı\": [\n"
            "    {\"öncelik\": 1, \"aksiyon\": \"...\", \"süre\": \"24 saat\"}\n"
            "  ],\n"
            "  \"opsec_skoru\": 60,\n"
            "  \"saldırı_başarı_ihtimali\": \"Yüksek/Orta/Düşük\",\n"
            "  \"yönetici_özeti\": \"2-3 cümle yöneticiye özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        recon = self.context.get("recon_result", {})
        threat = self.context.get("threat_result", {})
        exploit = self.context.get("exploit_result", {})
        intel = self.context.get("intel_result", {})
        web = self.context.get("web_result", {})
        opsec = self.context.get("opsec_result", {})
        attack = self.context.get("attack_result", {})
        defense = self.context.get("defense_result", {})

        sections = [f"Hedef: {self.target}", "=" * 50, "AJAN SONUÇLARI ÖZETİ:"]

        def _add(label: str, result: dict, keys: list[str]):
            if not isinstance(result, dict):
                return
            for key in keys:
                val = result.get(key)
                if val:
                    sections.append(f"{label} — {key}: {str(val)[:150]}")

        _add("RECON", recon, ["saldırı_yüzeyi", "kritik_bulgular", "ssl_durumu"])
        _add("THREAT", threat, ["tehdit_özeti", "en_tehlikeli_cve", "cisa_kev_sayısı"])
        _add("EXPLOIT", exploit, ["özet", "saldırı_zorluğu"])
        _add("INTEL", intel, ["özet", "ilgili_apt_grupları", "kill_chain_aşamaları"])
        _add("WEB", web, ["özet", "güvenlik_başlığı_eksikleri"])
        _add("OPSEC", opsec, ["özet", "genel_opsec_skoru"])
        _add("ATTACK", attack, ["özet", "birincil_giriş_noktası", "tahmini_başarı_oranı"])
        _add("DEFENSE", defense, ["özet", "savunma_skoru", "en_kritik_açık"])

        sections.append(
            "\nTüm bu bilgileri sentezle. Objektif ve dengeli ol. "
            "JSON şablonunu doldur."
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
            summary = grounded.get("yönetici_özeti", "Analiz tamamlandı")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data=grounded,
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
