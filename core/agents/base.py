"""
BaseAgent — Tüm ajan sınıflarının temel sınıfı.
Her ajan: tek görev, kendi araç seti, kendi sıcaklığı, yapılandırılmış JSON çıktı.
Hallüsinasyon önleme: grounding + JSON retry + gerçek veri zorlama.
"""
import json
import re
import urllib.request
from dataclasses import dataclass, field


@dataclass
class AgentResult:
    agent: str
    status: str          # "ok" | "error" | "skipped"
    summary: str
    data: dict = field(default_factory=dict)
    raw: str = ""
    grounding_warnings: list = field(default_factory=list)


class BaseAgent:
    name: str = "base"
    role: str = "Genel"
    temperature: float = 0.5
    max_retries: int = 2        # JSON parse başarısız olursa kaç kez tekrar dene
    ground_output: bool = True  # Çıktıyı gerçek veriyle doğrula

    def __init__(self, llm_client, target: str, context: dict = None):
        self.llm = llm_client
        self.target = target
        self.context = context or {}

    # ── Prompt Oluşturma ──────────────────────────────────────────────────────

    def _build_system(self) -> str:
        raise NotImplementedError

    def _build_user_prompt(self) -> str:
        raise NotImplementedError

    # ── LLM Çağrısı ──────────────────────────────────────────────────────────

    def _call_llm(self, system: str, user: str, attempt: int = 0) -> str:
        """Tek turlu, sıcaklık kontrollü LLM çağrısı."""
        # Her tekrarda temperature biraz artır — takılmayı önle
        temp = min(self.temperature + attempt * 0.1, 0.9)

        full_messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        payload = json.dumps({
            "model": self.llm.model,
            "messages": full_messages,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_ctx": 4096,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            "http://localhost:11434/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "")
        except Exception as e:
            return f"__LLM_ERROR__: {e}"

    # ── JSON Ayrıştırma + Retry ───────────────────────────────────────────────

    def _extract_json(self, text: str) -> dict | None:
        """LLM çıktısından JSON bloğu çıkar."""
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        m = re.search(r"(\{.*\})", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                # Trailing comma düzeltme denemesi
                cleaned = re.sub(r",\s*([}\]])", r"\1", m.group(1))
                try:
                    return json.loads(cleaned)
                except Exception:
                    pass
        return None

    def _call_with_retry(self, system: str, user: str) -> tuple[str, dict]:
        """
        LLM'i çağır, JSON parse et. Başarısız olursa max_retries kadar tekrar dene.
        Returns: (raw_text, parsed_dict)
        """
        retry_suffix = (
            "\n\nÖNEMLİ: Yanıtın YALNIZCA geçerli JSON olmalı. "
            "```json ... ``` bloğu içinde döndür. "
            "Açıklama, başlık veya JSON dışı metin YAZMA."
        )

        for attempt in range(self.max_retries + 1):
            prompt = user if attempt == 0 else user + retry_suffix
            raw = self._call_llm(system, prompt, attempt=attempt)

            if raw.startswith("__LLM_ERROR__"):
                return raw, {}

            parsed = self._extract_json(raw)
            if parsed is not None:
                return raw, parsed

        # Son deneme — ham metni kısalt
        return raw, {"ham_analiz": raw[:400], "_parse_başarısız": True}

    # ── Grounding ─────────────────────────────────────────────────────────────

    def _apply_grounding(self, data: dict) -> tuple[dict, list]:
        """Çıktıyı context'teki gerçek veriyle doğrula."""
        if not self.ground_output:
            return data, []
        from .validator import ground_agent_output, extract_cves_from_context, extract_tids_from_context
        available_cves = extract_cves_from_context(self.context)
        available_tids = extract_tids_from_context(self.context)
        grounded = ground_agent_output(data, available_cves, available_tids)
        warnings = grounded.pop("_grounding_uyarıları", [])
        return grounded, warnings

    # ── Yardımcı ─────────────────────────────────────────────────────────────

    def run(self) -> AgentResult:
        raise NotImplementedError

    def _safe_list(self, val) -> list:
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            return [val] if val.strip() else []
        return []

    def _truncate(self, text: str, limit: int = 300) -> str:
        return text[:limit] + "..." if len(text) > limit else text

    def _inject_real_data_constraint(self, real_cves: list[str], real_tids: list[str]) -> str:
        """
        Prompta gerçek veri listesi + 'sadece bunları kullan' kuralı ekle.
        Bu en güçlü hallüsinasyon önleyici.
        """
        lines = ["\n\n─── ZORUNLU KISITLAMA ───"]
        if real_cves:
            lines.append(f"Kullanabileceğin CVE'ler (SADECE BUNLAR): {real_cves[:20]}")
            lines.append("Bu listede OLMAYAN hiçbir CVE ID'si yazma.")
        if real_tids:
            lines.append(f"Kullanabileceğin TID'ler (SADECE BUNLAR): {real_tids[:20]}")
            lines.append("Bu listede OLMAYAN hiçbir T-ID yazma.")
        lines.append("Gerçek veriden bulamadığın alanları boş bırak veya 'veri yok' yaz.")
        lines.append("─────────────────────────")
        return "\n".join(lines)
