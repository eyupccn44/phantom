import re
from dataclasses import dataclass

@dataclass
class GuardResult:
    allowed: bool
    reason: str = ""
    sanitized: str = ""


# Prompt injection / jailbreak kalıpları
INJECTION_PATTERNS = [
    r"ignore (previous|all|prior|above) (instructions?|rules?|prompts?|context)",
    r"you are now (a |an )?(different|new|another|general|helpful)",
    r"act as (a |an )?(different|new|general|coding|developer)",
    r"forget (everything|all|your|previous|prior)",
    r"new (persona|role|identity|instructions?)",
    r"pretend (you are|to be|that)",
    r"(system|admin|root|developer|anthropic)\s*(prompt|instruction|override|access)",
    r"DAN|do anything now|jailbreak|unrestricted mode",
    r"from now on you (are|will|must)",
    r"your (new|real|true|actual) (purpose|goal|role|job|task)",
    r"\[SYSTEM\]|\[INST\]|\[OVERRIDE\]|<\|system\|>",
    r"roleplay as|role-play|role play.*(?:hacker|attacker|criminal)",
]

# Kapsam dışı görev kalıpları
OFF_TOPIC_PATTERNS = [
    # İngilizce
    r"\b(write|create|build|make|code|develop|generate)\b.{0,40}\b(website|app|application|game|script for|program for|bot for)\b",
    r"\b(recipe|cook|food|weather|news|joke|story|poem|essay|translate)\b",
    r"\b(who is|what is|explain|teach me|help me with|how to)\b.{0,30}\b(python|javascript|react|django|flask|html|css)\b",
    r"\bwrite me (a |an )?(function|class|module|script|code|program|app)\b",
    r"\b(math|algebra|calculus|physics|chemistry|biology)\b",
    r"\b(social media|twitter|instagram|tiktok|youtube)\b.{0,20}\b(post|content|caption|strategy)\b",
    # Türkçe
    r"\bbana\b.{0,30}\b(yaz|oluştur|kur|geliştir|yap)\b",
    r"\b(yazılım|uygulama|website|web sitesi|oyun|program)\b.{0,20}\b(yaz|oluştur|kur|geliştir|yap)\b",
    r"\b(kod yaz|kodla|kodlama yap|script yaz)\b",
    r"\b(tarif|yemek|hava|haber|şaka|hikaye|şiir|çevir|translate)\b",
    r"\b(sosyal medya|instagram|twitter|tiktok)\b.{0,20}\b(içerik|gönderi|strateji)\b",
]

# Zorunlu güvenlik bağlamı kontrolü — bu kelimeler varsa izin ver
SECURITY_KEYWORDS = {
    "exploit", "vulnerability", "cve", "payload", "shellcode", "bypass",
    "injection", "rce", "lfi", "rfi", "sqli", "xss", "csrf", "ssrf",
    "privilege", "escalation", "lateral", "movement", "persistence",
    "credential", "hash", "mimikatz", "metasploit", "msfvenom",
    "nmap", "enum", "recon", "footprint", "pentest", "red team",
    "attack", "scan", "port", "service", "banner", "ssl", "smb", "rdp",
    "ttp", "mitre", "apt", "malware", "ransomware", "c2", "beacon",
    "token", "kerberos", "ntlm", "ldap", "active directory",
    "buffer overflow", "heap", "stack", "ret2", "rop", "shellcode",
    "honeypot", "drift", "blindspot", "trustgraph",
    # Türkçe
    "zafiyet", "saldırı", "tarama", "hedef", "istismar", "güvenlik",
    "kimlik", "oturum", "yetki", "port", "servis", "rapor", "analiz",
    "nasıl", "neden", "ne", "hangisi", "öner", "açıkla", "göster",
}

MAX_INPUT_LEN = 2000


def check_prompt(text: str) -> GuardResult:
    if not text or not text.strip():
        return GuardResult(allowed=False, reason="Boş girdi")

    if len(text) > MAX_INPUT_LEN:
        return GuardResult(allowed=False, reason=f"Girdi çok uzun ({len(text)} > {MAX_INPUT_LEN} karakter)")

    lower = text.lower()

    # Prompt injection kontrolü
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return GuardResult(
                allowed=False,
                reason=f"Prompt injection tespit edildi — bu bir red team ajanıdır, manipüle edilemez",
            )

    # Güvenlik kelimesi varsa direkt geç
    if any(kw in lower for kw in SECURITY_KEYWORDS):
        return GuardResult(allowed=True, sanitized=text.strip())

    # Kapsam dışı görev kontrolü
    for pattern in OFF_TOPIC_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return GuardResult(
                allowed=False,
                reason=(
                    "Bu görev red team kapsamı dışında.\n"
                    "Phantom yalnızca: port analizi, CVE araştırması, MITRE TTP haritalama, "
                    "exploit araştırması, kimlik bilgisi testi, ağ keşfi, saldırı yolu planlama "
                    "konularında çalışır.\n"
                    "Sorunuzu güvenlik bağlamında yeniden çerçeveleyebilirsiniz."
                ),
            )

    return GuardResult(allowed=True, sanitized=text.strip())


def check_response_loop(response: str, previous_responses: list[str], threshold: float = 0.85) -> bool:
    if not previous_responses:
        return False
    r = response.strip()[:300]
    for prev in previous_responses[-2:]:
        p = prev.strip()[:300]
        if not p:
            continue
        overlap = len(set(r.split()) & set(p.split()))
        union = len(set(r.split()) | set(p.split()))
        similarity = overlap / union if union > 0 else 0
        if similarity > threshold:
            return True
    return False
