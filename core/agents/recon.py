"""
ReconAgent — Port tarama, banner alma, DNS, SSL sertifika analizi.
Sıcaklık: 0.2 (gerçekçi, hallüsinasyonsuz)
"""
import subprocess
import socket
import ssl
from .base import BaseAgent, AgentResult


class ReconAgent(BaseAgent):
    name = "recon"
    role = "Keşif Uzmanı"
    temperature = 0.1   # Gerçek araç çıktısı — hallüsinasyon sıfıra yakın
    allowed_tools = ["nmap", "banner_grab", "dns_lookup", "ssl_cert"]

    def _build_system(self) -> str:
        return (
            "Sen bir kıdemli ağ keşif uzmanısın. "
            "Görevin: port, servis, banner ve SSL verilerini analiz edip "
            "YALNIZCA aşağıdaki JSON şablonunu doldurmak.\n"
            "Kesinlikle Türkçe yaz. İngilizce terim kullanma.\n"
            "JSON dışında HİÇBİR şey yazma.\n\n"
            "ŞABLON:\n"
            "```json\n"
            "{\n"
            "  \"açık_portlar\": [{\"port\": 80, \"servis\": \"http\", \"versiyon\": \"Apache 2.4\"}],\n"
            "  \"kritik_bulgular\": [\"Örnek bulgu\"],\n"
            "  \"ssl_durumu\": \"Zayıf/Güçlü/Yok\",\n"
            "  \"dns_kayıtları\": [\"A: 1.2.3.4\"],\n"
            "  \"saldırı_yüzeyi\": \"özet metin\",\n"
            "  \"sonraki_adımlar\": [\"adım1\", \"adım2\"]\n"
            "}\n"
            "```"
        )

    def _build_user_prompt(self) -> str:
        ports = self.context.get("ports", [])
        nmap_raw = self.context.get("nmap_raw", "")
        banner_data = self.context.get("banners", {})
        ssl_data = self.context.get("ssl_info", "")
        dns_data = self.context.get("dns_info", "")

        sections = [f"Hedef: {self.target}"]
        if ports:
            sections.append(f"Açık portlar: {ports}")
        if nmap_raw:
            sections.append(f"Nmap çıktısı (ilk 1500):\n{nmap_raw[:1500]}")
        if banner_data:
            sections.append(f"Banner bilgisi: {banner_data}")
        if ssl_data:
            sections.append(f"SSL: {ssl_data}")
        if dns_data:
            sections.append(f"DNS: {dns_data}")

        sections.append(
            "\nBu verileri analiz et. JSON şablonunu doldur. "
            "Gerçek olmayan veri üretme — yalnızca yukarıdaki verileri kullan."
        )
        return "\n\n".join(sections)

    def _gather_data(self) -> dict:
        """Gerçek araçları çalıştır."""
        data = {}

        # Nmap
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-T4", "-Pn", "--top-ports", "500", self.target],
                capture_output=True, text=True, timeout=120,
            )
            data["nmap_raw"] = result.stdout[:2000]
            # Port listesi çıkar
            import re
            ports = []
            for line in result.stdout.splitlines():
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    ports.append({"port": int(m.group(1)), "servis": m.group(2), "versiyon": m.group(3).strip()})
            data["ports"] = ports
        except Exception as e:
            data["nmap_raw"] = f"nmap hatası: {e}"
            data["ports"] = []

        # DNS
        try:
            result = subprocess.run(
                ["dig", self.target, "A", "+short"],
                capture_output=True, text=True, timeout=10,
            )
            data["dns_info"] = result.stdout.strip() or "kayıt yok"
        except Exception:
            try:
                ip = socket.gethostbyname(self.target)
                data["dns_info"] = ip
            except Exception:
                data["dns_info"] = ""

        # SSL (port 443)
        if any(p.get("port") in (443, 8443) for p in data.get("ports", [])):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.target, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        ver = ssock.version()
                        cipher = ssock.cipher()
                        san = ", ".join(v for _, v in cert.get("subjectAltName", []))
                        data["ssl_info"] = (
                            f"Versiyon: {ver}, Cipher: {cipher[0] if cipher else '?'}, "
                            f"Bitiş: {cert.get('notAfter', '?')}, SANs: {san}"
                        )
            except Exception as e:
                data["ssl_info"] = f"SSL bağlantı hatası: {e}"

        return data

    def run(self) -> AgentResult:
        try:
            gathered = _gather_data_safe(self)
            self.context.update(gathered)

            system = self._build_system()
            user = self._build_user_prompt()
            raw, parsed = self._call_with_retry(system, user)

            if raw.startswith("__LLM_ERROR__"):
                return AgentResult(agent=self.name, status="error", summary=raw)

            grounded, warnings = self._apply_grounding(parsed)
            summary = grounded.get("saldırı_yüzeyi", "") or f"{len(gathered.get('ports', []))} port açık"
            return AgentResult(
                agent=self.name, status="ok",
                summary=summary, data={**grounded, **gathered},
                raw=raw, grounding_warnings=warnings
            )
        except Exception as e:
            return AgentResult(agent=self.name, status="error", summary=str(e))


def _gather_data_safe(agent: ReconAgent) -> dict:
    """Context'te zaten veri varsa toplamayı atla."""
    if agent.context.get("nmap_raw") or agent.context.get("ports"):
        return agent.context
    return agent._gather_data()
