import re
import math
import base64
import time
from dataclasses import dataclass, field


@dataclass
class GuardResult:
    allowed: bool
    reason: str = ""
    sanitized: str = ""
    threat_level: str = "none"  # none / low / high / critical


# ─── PATTERN TANIMLARI ────────────────────────────────────────────────────────

# Tier-1: Prompt injection / jailbreak
INJECTION_PATTERNS = [
    r"\bignore\b.{0,40}\b(instructions?|rules?|prompts?|context|constraints?)\b",
    r"you\s+are\s+now\s+(a\s+|an\s+)?(different|new|another|general|helpful|uncensored|unrestricted)",
    r"act\s+as\s+(a\s+|an\s+)?(different|new|general|coding|developer|evil|unrestricted)",
    r"\bforget\b.{0,30}\b(everything|all|rules?|training|instructions?|previous)\b",
    r"new\s+(persona|role|identity|instructions?|directives?|system\s+prompt)",
    r"pretend\s+(you\s+are|to\s+be|that\s+you|you\s+don)",
    r"(system|admin|root|developer|anthropic|openai)\s*(prompt|instruction|override|access|mode)",
    r"\bDAN\b|do\s+anything\s+now|jailbreak|unrestricted\s+mode|god\s+mode",
    r"from\s+now\s+on\s+you\s+(are|will|must|should)",
    r"your\s+(new|real|true|actual)\s+(purpose|goal|role|job|task|instructions?)",
    r"\[SYSTEM\]|\[INST\]|\[OVERRIDE\]|\[ADMIN\]|<\|system\|>|<\|im_start\|>",
    r"roleplay\s+as|role[\s-]play.*?(hacker|attacker|criminal|threat\s+actor)",
    r"disregard\s+(your|all|any|previous)\s+(rules?|guidelines?|restrictions?|constraints?)",
    r"you\s+have\s+no\s+(restrictions?|limitations?|guidelines?|rules?)",
    r"(bypass|override|disable)\s+(safety|filter|guard|restriction|rule)",
    r"in\s+(developer|debug|maintenance|test)\s+mode",
    r"sudo\s+(mode|access|override)|root\s+override",
    # Türkçe
    r"kural(lar)?ı\s+(unut|yoksay|geç|sıfırla)",
    r"(yeni|farklı)\s+(persona|kimlik|rol|talimat)",
    r"(sistem|admin|kök)\s+(komut|talimat|erişim|modu)",
    r"kısıtlama\s+(yok|kaldır|devre\s+dışı)",
]

# Tier-2: Kapsam dışı görevler
OFF_TOPIC_PATTERNS = [
    r"\b(write|create|build|make|develop|generate)\b.{0,50}\b(website|webapp|mobile\s+app|game|social\s+bot)\b",
    r"\b(recipe|cooking|food|weather\s+forecast|news\s+feed|jokes?|bedtime\s+story)\b",
    r"\b(help\s+me\s+with|explain|teach\s+me)\b.{0,40}\b(react|vue|angular|django|flask)\b",
    r"\bwrite\s+(me\s+)?(a\s+|an\s+)?(function|class|module)\b.{0,30}\b(sort|fibonacci|calculator)\b",
    r"\b(math\s+homework|algebra|calculus\s+problem|physics\s+question)\b",
    # Türkçe
    r"\b(yemek\s+tarifi|hava\s+durumu|günlük\s+haber|şiir\s+yaz)\b",
    r"\b(sosyal\s+medya|instagram|tiktok)\b.{0,20}\b(içerik|gönderi|strateji)\b",
]

# Güvenlik bağlamı anahtar kelimeleri — bunlar varsa kapsam dışı kontrolü atla
SECURITY_KEYWORDS = {
    "exploit", "vulnerability", "cve", "payload", "shellcode", "bypass",
    "injection", "rce", "lfi", "rfi", "sqli", "xss", "csrf", "ssrf",
    "privilege", "escalation", "lateral", "movement", "persistence",
    "credential", "hash", "mimikatz", "metasploit", "msfvenom",
    "nmap", "nuclei", "nikto", "gobuster", "masscan", "dnsrecon",
    "enum", "recon", "footprint", "pentest", "red team", "redteam",
    "attack", "scan", "port", "service", "banner", "ssl", "smb", "rdp",
    "ttp", "mitre", "apt", "malware", "ransomware", "c2", "beacon",
    "token", "kerberos", "ntlm", "ldap", "active directory", "ad",
    "buffer overflow", "heap", "stack", "ret2libc", "rop",
    "honeypot", "drift", "blindspot", "trustgraph", "kill chain",
    "zafiyet", "saldırı", "tarama", "hedef", "istismar", "güvenlik",
    "kimlik", "oturum", "yetki", "servis", "rapor", "analiz",
    "nasıl", "neden", "hangisi", "öner", "açıkla", "göster", "listele",
}

MAX_INPUT_LEN = 4000
MAX_LINE_LEN = 500


# ─── YARDIMCI FONKSİYONLAR ───────────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _has_encoded_payload(text: str) -> bool:
    """Base64 / hex encode edilmiş injection denemelerini tespit eder."""
    # Base64 kalıpları
    b64_re = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')
    for match in b64_re.finditer(text):
        try:
            decoded = base64.b64decode(match.group() + "==").decode("utf-8", errors="ignore").lower()
            if any(kw in decoded for kw in
                   ["ignore", "forget", "jailbreak", "system", "override",
                    "prompt", "instruction", "unrestricted", "bypass"]):
                return True
        except Exception:
            pass

    # Hex encode kalıpları
    hex_re = re.compile(r'(?:0x)?[0-9a-fA-F]{16,}')
    for match in hex_re.finditer(text):
        try:
            raw = bytes.fromhex(match.group().replace("0x", "")).decode("utf-8", errors="ignore").lower()
            if any(kw in raw for kw in ["ignore", "jailbreak", "system", "override"]):
                return True
        except Exception:
            pass
    return False


def _unicode_normalize(text: str) -> str:
    """Unicode homoglyph ve invisible char temizliği."""
    import unicodedata
    normalized = unicodedata.normalize("NFKC", text)
    # Invisible / control karakterleri kaldır
    cleaned = "".join(c for c in normalized if unicodedata.category(c) not in ("Cf", "Cc") or c in ("\n", "\t"))
    return cleaned


def _has_multi_stage_injection(text: str) -> bool:
    """Birden fazla injection imzası bir arada → çok aşamalı saldırı."""
    lower = text.lower()
    hits = sum(1 for p in INJECTION_PATTERNS if re.search(p, lower, re.IGNORECASE))
    return hits >= 2


def _has_suspicious_structure(text: str) -> bool:
    """Anormal uzunlukta satırlar veya aşırı yüksek entropi."""
    for line in text.splitlines():
        if len(line) > MAX_LINE_LEN:
            ent = _entropy(line)
            if ent > 4.8:
                return True
    return False


# ─── ANA KONTROL ─────────────────────────────────────────────────────────────

_blocked_log: list[dict] = []
_rate_window: list[float] = []
_RATE_LIMIT = 30       # 30 saniyede max 30 istek
_RATE_WINDOW_SEC = 30


def check_prompt(text: str) -> GuardResult:
    global _rate_window

    if not text or not text.strip():
        return GuardResult(allowed=False, reason="Boş girdi", threat_level="none")

    # Rate limiting
    now = time.monotonic()
    _rate_window = [t for t in _rate_window if now - t < _RATE_WINDOW_SEC]
    if len(_rate_window) >= _RATE_LIMIT:
        return GuardResult(allowed=False,
                           reason=f"Hız limiti aşıldı — {_RATE_WINDOW_SEC}s içinde {_RATE_LIMIT} istek",
                           threat_level="low")
    _rate_window.append(now)

    # Uzunluk kontrolü
    if len(text) > MAX_INPUT_LEN:
        return GuardResult(allowed=False,
                           reason=f"Girdi çok uzun ({len(text)} > {MAX_INPUT_LEN} karakter)",
                           threat_level="low")

    # Unicode normalize
    text = _unicode_normalize(text)
    lower = text.lower()

    # Tier-0: Encode edilmiş payload kontrolü
    if _has_encoded_payload(text):
        _log_block(text, "encoded_payload")
        return GuardResult(
            allowed=False,
            reason="Encode edilmiş injection payload tespit edildi",
            threat_level="critical",
        )

    # Tier-0: Çok aşamalı injection
    if _has_multi_stage_injection(text):
        _log_block(text, "multi_stage_injection")
        return GuardResult(
            allowed=False,
            reason="Çok aşamalı prompt injection saldırısı tespit edildi",
            threat_level="critical",
        )

    # Tier-1: Tekil injection kalıpları
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            _log_block(text, "injection")
            return GuardResult(
                allowed=False,
                reason="Prompt injection tespit edildi — Phantom manipüle edilemez",
                threat_level="high",
            )

    # Tier-1: Şüpheli yapısal anomali
    if _has_suspicious_structure(text):
        _log_block(text, "structural_anomaly")
        return GuardResult(
            allowed=False,
            reason="Şüpheli yapısal anomali tespit edildi (yüksek entropi)",
            threat_level="high",
        )

    # Güvenlik bağlamı varsa kapsam dışı kontrolü atla
    if any(kw in lower for kw in SECURITY_KEYWORDS):
        return GuardResult(allowed=True, sanitized=text.strip(), threat_level="none")

    # Tier-2: Kapsam dışı
    for pattern in OFF_TOPIC_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return GuardResult(
                allowed=False,
                reason=(
                    "Bu görev red team kapsamı dışında.\n"
                    "Phantom: port analizi, CVE, MITRE TTP, exploit araştırması,\n"
                    "ağ keşfi, credential testi, nuclei/nikto/gobuster analizi,\n"
                    "attack path planlama konularında çalışır."
                ),
                threat_level="low",
            )

    return GuardResult(allowed=True, sanitized=text.strip(), threat_level="none")


def check_response_loop(response: str, previous_responses: list[str], threshold: float = 0.85) -> bool:
    if not previous_responses:
        return False
    r = response.strip()[:300]
    for prev in previous_responses[-2:]:
        p = prev.strip()[:300]
        if not p:
            continue
        r_words = set(r.split())
        p_words = set(p.split())
        overlap = len(r_words & p_words)
        union = len(r_words | p_words)
        if union > 0 and overlap / union > threshold:
            return True
    return False


def check_llm_response(response: str) -> bool:
    """LLM yanıtının içinde injection yönlendirmesi var mı kontrol et."""
    lower = response.lower()
    suspicious = [
        r"ignore (previous|all|prior) instructions",
        r"new system prompt",
        r"[OVERRIDE]",
        r"disregard (your|all) (rules|guidelines)",
    ]
    return any(re.search(p, lower, re.IGNORECASE) for p in suspicious)


def _log_block(text: str, reason_type: str) -> None:
    _blocked_log.append({
        "ts": time.time(),
        "type": reason_type,
        "preview": text[:80],
    })
    # Max 500 kayıt tut
    if len(_blocked_log) > 500:
        _blocked_log.pop(0)


def get_blocked_log() -> list[dict]:
    return list(_blocked_log)
