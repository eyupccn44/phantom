"""
ThreatAgent — CISA KEV canlı feed + aktif istismar tespiti.
Sıcaklık: 0.1 (maksimum gerçekçilik — yalnızca gerçek veri)
"""
from .base import BaseAgent, AgentResult
from .validator import extract_cves_from_context


class ThreatAgent(BaseAgent):
    name = "threat"
    role = "Tehdit İstihbaratı"
    temperature = 0.1   # Gerçek veri analizi — hallüsinasyon sıfıra yakın

    def _build_system(self) -> str:
        return (
            "Sen bir tehdit istihbarat analistisin. "
            "YALNIZCA sana sağlanan CISA KEV ve NVD verilerini analiz et.\n"
            "Veri listesinde OLMAYAN hiçbir CVE veya ürün adı YAZMA.\n"
            "Bilmiyorsan 'veri yetersiz' yaz — uydurma.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"aktif_tehditler\": [{\"cve\": \"CVE-XXXX\", \"servis\": \"...\", "
            "\"açıklama\": \"...\", \"kritiklik\": \"Kritik/Yüksek/Orta\"}],\n"
            "  \"cisa_kev_sayısı\": 0,\n"
            "  \"en_tehlikeli_cve\": \"CVE-XXXX\",\n"
            "  \"acil_eylem\": \"Yapılması gereken en önemli şey\",\n"
            "  \"tehdit_özeti\": \"kısa özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        ports = self.context.get("ports", [])
        services = [p.get("servis", "") or p.get("service", "") for p in ports if isinstance(p, dict)]
        services = list(set(filter(None, services)))

        cisa_data = self.context.get("cisa_kev_results", [])
        nvd_data = self.context.get("nvd_results", [])

        sections = [f"Hedef: {self.target}", f"Tespit edilen servisler: {services}"]

        if cisa_data:
            kev_lines = []
            for item in cisa_data[:15]:
                kev_lines.append(
                    f"- {item.get('cveID', '?')}: {item.get('product', '?')} — "
                    f"{item.get('shortDescription', '')[:100]}"
                )
            sections.append("CISA KEV Aktif İstismarlar (GERÇEK VERİ):\n" + "\n".join(kev_lines))
        else:
            sections.append("CISA KEV: Eşleşme bulunamadı. 'aktif_tehditler' alanını BOŞ BIRAK.")

        if nvd_data:
            nvd_lines = []
            for item in nvd_data[:10]:
                nvd_lines.append(
                    f"- {item.get('id', '?')} (CVSS {item.get('cvss', '?')}): "
                    f"{item.get('description', '')[:120]}"
                )
            sections.append("NVD Güvenlik Açıkları (GERÇEK VERİ):\n" + "\n".join(nvd_lines))
        else:
            sections.append("NVD: Veri yok.")

        # Gerçek CVE kısıtlaması inject et
        real_cves = extract_cves_from_context(self.context)
        if real_cves:
            sections.append(self._inject_real_data_constraint(real_cves, []))

        sections.append("\nYUKARIDAKİ GERÇEK VERİYİ analiz et. JSON şablonunu doldur.")
        return "\n\n".join(sections)

    def _fetch_live_data(self) -> dict:
        from core.intel_feeds import get_cisa_kev_for_service, search_nvd

        ports = self.context.get("ports", [])
        services = [p.get("servis", "") or p.get("service", "") for p in ports if isinstance(p, dict)]
        services = list(set(filter(None, services)))

        all_kev = []
        all_nvd = []
        for svc in services[:6]:
            kev = get_cisa_kev_for_service(svc)
            all_kev.extend(kev)
            nvd = search_nvd(svc, results=5)
            all_nvd.extend(nvd)

        seen_cve = set()
        unique_kev = []
        for item in all_kev:
            cid = item.get("cveID", "")
            if cid not in seen_cve:
                seen_cve.add(cid)
                unique_kev.append(item)

        return {
            "cisa_kev_results": unique_kev[:20],
            "nvd_results": all_nvd[:15],
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

            # Grounding — uydurma CVE varsa işaretle
            grounded, warnings = self._apply_grounding(parsed)

            summary = grounded.get("tehdit_özeti", f"{len(live['cisa_kev_results'])} CISA KEV eşleşmesi")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data={**grounded, **live},
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
