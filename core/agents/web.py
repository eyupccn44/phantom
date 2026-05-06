"""
WebAgent — OWASP Top 10 analizi + HTTP yüzey keşfi.
Sıcaklık: 0.4
"""
import urllib.request
import re
from .base import BaseAgent, AgentResult


class WebAgent(BaseAgent):
    name = "web"
    role = "Web Güvenlik Analisti"
    temperature = 0.4

    def _build_system(self) -> str:
        return (
            "Sen bir web uygulama güvenlik test uzmanısın. "
            "OWASP Top 10 2021 kategorilerini tespit edilen HTTP servislerine "
            "uygulayarak öncelikli test planı oluşturursun.\n"
            "Yalnızca sağlanan gerçek veriyi kullan.\n"
            "Kesinlikle Türkçe yaz.\n"
            "YALNIZCA aşağıdaki JSON şablonunu doldur:\n"
            "```json\n"
            "{\n"
            "  \"web_servisleri\": [{\"port\": 80, \"url\": \"http://...\", \"başlık\": \"...\"}],\n"
            "  \"owasp_öncelikler\": [\n"
            "    {\"kod\": \"A03\", \"isim\": \"Injection\", \"test_yöntemi\": \"...\", "
            "\"öncelik\": \"Kritik/Yüksek/Orta\"}\n"
            "  ],\n"
            "  \"tespit_edilen_başlıklar\": {\"Server\": \"Apache\", \"X-Frame-Options\": \"yok\"},\n"
            "  \"güvenlik_başlığı_eksikleri\": [\"CSP yok\", \"HSTS yok\"],\n"
            "  \"test_planı\": [\"1. SQL injection testi\", \"2. ...\"],\n"
            "  \"özet\": \"kısa özet\"\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        web_data = self.context.get("http_probes", [])
        owasp_data = self.context.get("owasp_categories", [])
        ports = self.context.get("ports", [])

        sections = [f"Hedef: {self.target}"]
        if ports:
            web_ports = [p for p in ports if isinstance(p, dict) and p.get("port") in (80, 443, 8080, 8443, 8000, 3000)]
            if web_ports:
                sections.append(f"Web portları: {web_ports}")

        if web_data:
            for probe in web_data[:5]:
                sections.append(
                    f"HTTP Probe ({probe.get('url', '?')}):\n"
                    f"  Durum: {probe.get('status', '?')}\n"
                    f"  Başlıklar: {probe.get('headers', {})}\n"
                    f"  İçerik özeti: {probe.get('body_snippet', '')[:200]}"
                )

        if owasp_data:
            lines = [f"- {o.get('code', '?')}: {o.get('name', '?')} — {o.get('tests', [])}" for o in owasp_data[:10]]
            sections.append("OWASP Top 10 Uygulanabilir Kategoriler:\n" + "\n".join(lines))

        sections.append("\nBu verilere dayanarak JSON şablonunu doldur.")
        return "\n\n".join(sections)

    def _probe_http(self, host: str, port: int) -> dict:
        scheme = "https" if port in (443, 8443) else "http"
        port_str = "" if port in (80, 443) else f":{port}"
        url = f"{scheme}://{host}{port_str}/"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = dict(resp.headers)
                body = resp.read(1000).decode("utf-8", errors="replace")
                title = ""
                m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
                if m:
                    title = m.group(1).strip()[:80]
                return {
                    "url": url,
                    "status": resp.status,
                    "headers": {k: v for k, v in headers.items() if k.lower() in (
                        "server", "x-powered-by", "x-frame-options", "content-security-policy",
                        "strict-transport-security", "x-content-type-options", "set-cookie",
                    )},
                    "title": title,
                    "body_snippet": body[:200],
                }
        except urllib.error.HTTPError as e:
            return {"url": url, "status": e.code, "headers": {}, "title": "", "body_snippet": ""}
        except Exception as e:
            return {"url": url, "status": 0, "headers": {}, "title": "", "body_snippet": str(e)[:100]}

    def _fetch_data(self) -> dict:
        from core.intel_feeds import get_owasp_for_service

        ports = self.context.get("ports", [])
        web_ports = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port") in (
            80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090
        )]

        probes = []
        for port in web_ports[:5]:
            result = self._probe_http(self.target, port)
            probes.append(result)

        # OWASP kategorileri
        services = [p.get("servis", "") for p in ports if isinstance(p, dict)]
        owasp_cats = []
        seen_codes = set()
        for svc in set(filter(None, services)):
            cats = get_owasp_for_service(svc)
            for cat in cats:
                code = cat.get("code", "")
                if code not in seen_codes:
                    seen_codes.add(code)
                    owasp_cats.append(cat)

        return {
            "http_probes": probes,
            "owasp_categories": owasp_cats,
        }

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
            web_count = len(live["http_probes"])
            summary = grounded.get("özet", f"{web_count} web servisi tespit edildi")
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data={**grounded, **live},
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))
