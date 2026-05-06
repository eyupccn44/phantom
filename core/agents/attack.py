"""
AttackAgent — Kill chain oluşturma, saldırı yolu planlama.
Sıcaklık: 0.7 (yaratıcı, agresif düşünce)
"""
from .base import BaseAgent, AgentResult


class AttackAgent(BaseAgent):
    name = "attack"
    role = "Saldırı Planlayıcısı"
    temperature = 0.7

    def _build_system(self) -> str:
        return (
            "Sen kıdemli bir red team operatörüsün. "
            "Diğer ajanların keşif, istismar ve tehdit verilerini birleştirerek "
            "gerçekçi, uygulanabilir bir saldırı kill chain oluşturursun.\n"
            "Saldırı yolunu aşama aşama planla. Teknik ve operasyonel.\n"
            "Yalnızca sağlanan gerçek veriyi kullan.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"kill_chain\": [\n"
            "    {\"aşama\": \"ilk_erişim\", \"teknik\": \"T1190\", "
            "\"araç\": \"Metasploit\", \"hedef_port\": 80, \"açıklama\": \"...\"},\n"
            "    {\"aşama\": \"kalıcılık\", \"teknik\": \"T1078\", \"araç\": \"...\", "
            "\"hedef_port\": null, \"açıklama\": \"...\"}\n"
            "  ],\n"
            "  \"birincil_giriş_noktası\": \"port/servis açıklaması\",\n"
            "  \"yüksek_değer_hedefler\": [\"domain controller\", \"veritabanı\"],\n"
            "  \"tahmini_başarı_oranı\": \"Yüksek/Orta/Düşük\",\n"
            "  \"kritik_engeller\": [\"firewall\", \"EDR\"],\n"
            "  \"özet\": \"3-4 cümle saldırı özeti\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        # Tüm ajan sonuçlarından veri topla
        recon = self.context.get("recon_result", {})
        threat = self.context.get("threat_result", {})
        exploit = self.context.get("exploit_result", {})
        intel = self.context.get("intel_result", {})
        web = self.context.get("web_result", {})
        opsec = self.context.get("opsec_result", {})

        sections = [f"Hedef: {self.target}"]

        # Recon özeti
        if isinstance(recon, dict):
            ports = recon.get("açık_portlar", recon.get("ports", []))
            if ports:
                sections.append(f"Açık portlar: {ports[:10]}")
            if recon.get("saldırı_yüzeyi"):
                sections.append(f"Saldırı yüzeyi: {recon['saldırı_yüzeyi']}")

        # Tehdit özeti
        if isinstance(threat, dict):
            threats = threat.get("aktif_tehditler", [])
            if threats:
                lines = [f"- {t.get('cve', '?')}: {t.get('açıklama', '')[:80]}" for t in threats[:5]]
                sections.append("Aktif tehditler:\n" + "\n".join(lines))

        # Exploit özeti
        if isinstance(exploit, dict):
            exploits = exploit.get("öncelikli_istismarlar", [])
            if exploits:
                lines = [f"- {e.get('cve', '?')} [{e.get('msf_modülü', '?')}]: {e.get('açıklama', '')[:80]}" for e in exploits[:5]]
                sections.append("İstismar edilebilir CVE'ler:\n" + "\n".join(lines))

        # Intel özeti
        if isinstance(intel, dict):
            ttps = intel.get("tespit_edilen_teknikler", [])
            kill_phases = intel.get("kill_chain_aşamaları", [])
            if ttps:
                sections.append(f"MITRE TTP'ler: {[t.get('tid') for t in ttps[:8]]}")
            if kill_phases:
                sections.append(f"Kill chain aşamaları: {kill_phases}")

        # Web özeti
        if isinstance(web, dict):
            owasp = web.get("owasp_öncelikler", [])
            if owasp:
                sections.append(f"Web saldırı yüzeyi: {[o.get('kod') for o in owasp[:5]]}")

        # OPSEC özeti
        if isinstance(opsec, dict):
            blind_spots = opsec.get("kör_noktalar", [])
            if blind_spots:
                sections.append(f"OPSEC kör noktaları: {[b.get('tid') for b in blind_spots[:5]]}")

        sections.append(
            "\nBu tüm verileri sentezleyerek gerçekçi bir kill chain oluştur. "
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
            chain_len = len(grounded.get("kill_chain", []))
            summary = grounded.get("özet", f"{chain_len} aşamalı saldırı planı oluşturuldu")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data=grounded,
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
