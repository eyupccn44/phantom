"""
IntelAgent — MITRE ATT&CK canlı + APT profilleri + tehdit aktör haritası.
Sıcaklık: 0.2 (düşürüldü — sadece gerçek TID'ler)
"""
from .base import BaseAgent, AgentResult
from .validator import extract_tids_from_context


class IntelAgent(BaseAgent):
    name = "intel"
    role = "Tehdit Aktör İstihbaratı"
    temperature = 0.2

    def _build_system(self) -> str:
        return (
            "Sen bir siber tehdit istihbarat analistisin. "
            "Sana verilen MITRE ATT&CK verilerini analiz et.\n"
            "YALNIZCA sağlanan listede bulunan T-ID'leri kullan.\n"
            "Listede OLMAYAN TID veya APT adı YAZMA.\n"
            "Bilmiyorsan 'veri yok' yaz — uydurma.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"tespit_edilen_teknikler\": [\n"
            "    {\"tid\": \"T1190\", \"isim\": \"...\", \"taktik\": \"...\", "
            "\"uygulanabilirlik\": \"Yüksek/Orta/Düşük\"}\n"
            "  ],\n"
            "  \"ilgili_apt_grupları\": [\"APT28\"],\n"
            "  \"kill_chain_aşamaları\": [\"initial-access\", \"execution\"],\n"
            "  \"opsec_riskleri\": [\"risk1\"],\n"
            "  \"özet\": \"kısa özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        mitre_data = self.context.get("mitre_techniques", [])
        ports = self.context.get("ports", [])
        local_ttps = self.context.get("local_ttps", [])

        sections = [f"Hedef: {self.target}"]
        if ports:
            port_strs = [f"{p.get('port', '?')}/{p.get('servis', '?')}" for p in ports[:10] if isinstance(p, dict)]
            sections.append(f"Açık servisler: {', '.join(port_strs)}")

        if local_ttps:
            lines = []
            for t in local_ttps[:20]:
                apt_str = ", ".join(t.get("apt_groups", [])[:3]) if t.get("apt_groups") else ""
                lines.append(
                    f"- {t.get('tid', '?')}: {t.get('name', '?')} [{t.get('tactic', '?')}]"
                    + (f" | APT: {apt_str}" if apt_str else "")
                )
            sections.append("Yerel MITRE Veritabanı (DOĞRULANMIŞ):\n" + "\n".join(lines))

        if mitre_data:
            lines = []
            for t in mitre_data[:10]:
                lines.append(
                    f"- {t.get('tid', '?')}: {t.get('name', '?')} — "
                    f"{t.get('description', '')[:100]} | "
                    f"Taktikler: {t.get('kill_chain', [])}"
                )
            sections.append("MITRE ATT&CK Canlı Veri (DOĞRULANMIŞ):\n" + "\n".join(lines))

        # TID kısıtlaması — sadece gerçek listedekiler
        real_tids = extract_tids_from_context(self.context)
        if real_tids:
            sections.append(self._inject_real_data_constraint([], real_tids))

        sections.append("\nYUKARIDAKİ GERÇEK VERİDEN analiz yap. JSON şablonunu doldur.")
        return "\n\n".join(sections)

    def _fetch_live_data(self) -> dict:
        from core.intel_feeds import search_mitre_live
        from core.mitre import get_techniques_for_port

        ports = self.context.get("ports", [])
        services = [p.get("servis", "") or p.get("service", "") for p in ports if isinstance(p, dict)]
        services = list(set(filter(None, services)))

        # Yerel MITRE DB
        local_ttps = []
        seen_tid = set()
        for p in ports[:10]:
            if not isinstance(p, dict):
                continue
            port_num = str(p.get("port", ""))
            if port_num:
                ttps = get_techniques_for_port(port_num)
                for t in ttps:
                    tid = t.get("tid", "")
                    if tid not in seen_tid:
                        seen_tid.add(tid)
                        local_ttps.append(t)

        # Canlı MITRE
        mitre_live = []
        seen_live = set()
        for svc in services[:4]:
            results = search_mitre_live(svc)
            for t in results:
                tid = t.get("tid", "")
                if tid not in seen_live:
                    seen_live.add(tid)
                    mitre_live.append(t)

        return {
            "local_ttps": local_ttps[:20],
            "mitre_techniques": mitre_live[:15],
        }

    def run(self) -> AgentResult:
        try:
            live = self._fetch_live_data()
            self.context.update(live)

            system = self._build_system()
            user = self._build_user_prompt()
            raw, parsed = self._call_with_retry(system, user)

            if raw.startswith("__LLM_ERROR__"):
                return AgentResult(agent=self.name, status="error", summary=raw)

            grounded, warnings = self._apply_grounding(parsed)

            tech_count = len(live["local_ttps"]) + len(live["mitre_techniques"])
            summary = grounded.get("özet", f"{tech_count} MITRE tekniği tespit edildi")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data={**grounded, **live},
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
