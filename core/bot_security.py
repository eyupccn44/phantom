import json
import time
import hashlib
import re
from pathlib import Path
from collections import defaultdict

CONFIG_PATH = Path(__file__).parent.parent / "telegram.json"

_rate_store: dict[str, list[float]] = defaultdict(list)
_auth_sessions: dict[str, float] = {}

RATE_LIMIT = 5
RATE_WINDOW = 60
SESSION_TTL = 3600

ALLOWED_COMMANDS = {
    "/help", "/scan", "/whois", "/sub", "/creds", "/spray",
    "/status", "/report", "/sessions", "/adv", "/auth", "/ping",
}

DANGEROUS_PATTERNS = [
    r"[;&|`$(){}]",
    r"\.\./",
    r"\\",
    r"\beval\b",
    r"\bexec\b",
    r"\bos\.",
    r"\bsystem\b",
    r"\brm\s+-rf\b",
]


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def get_allowed_users() -> list[str]:
    cfg = _load_config()
    allowed = cfg.get("allowed_users", [])
    own_id = cfg.get("chat_id", "")
    if own_id and str(own_id) not in [str(u) for u in allowed]:
        allowed.append(str(own_id))
    return [str(u) for u in allowed]


def get_pin_hash() -> str:
    return _load_config().get("pin_hash", "")


def requires_auth() -> bool:
    return bool(get_pin_hash())


def is_authorized(chat_id: str) -> bool:
    allowed = get_allowed_users()
    if not allowed:
        return True
    return str(chat_id) in allowed


def is_authenticated(chat_id: str) -> bool:
    if not requires_auth():
        return True
    expiry = _auth_sessions.get(str(chat_id), 0)
    return time.time() < expiry


def authenticate(chat_id: str, pin: str) -> bool:
    pin_hash = get_pin_hash()
    if not pin_hash:
        return True
    attempt_hash = hashlib.sha256(pin.strip().encode()).hexdigest()
    if attempt_hash == pin_hash:
        _auth_sessions[str(chat_id)] = time.time() + SESSION_TTL
        return True
    return False


def check_rate_limit(chat_id: str) -> tuple[bool, int]:
    now = time.time()
    key = str(chat_id)
    _rate_store[key] = [t for t in _rate_store[key] if now - t < RATE_WINDOW]
    if len(_rate_store[key]) >= RATE_LIMIT:
        wait = int(RATE_WINDOW - (now - _rate_store[key][0]))
        return False, wait
    _rate_store[key].append(now)
    return True, 0


def sanitize_target(target: str) -> tuple[bool, str]:
    target = target.strip()
    if not target:
        return False, "Hedef boş olamaz"

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            return False, f"Geçersiz karakter tespit edildi"

    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
    domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$"

    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True, target

    return False, "Geçersiz hedef formatı (IP veya domain olmalı)"


def validate_command(text: str) -> tuple[bool, str, list[str]]:
    parts = text.strip().split()
    if not parts:
        return False, "Boş komut", []

    cmd = parts[0].lower()
    if cmd not in ALLOWED_COMMANDS:
        return False, f"Bilinmeyen komut: {cmd}", []

    args = parts[1:]
    for arg in args:
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, arg, re.IGNORECASE):
                return False, f"Tehlikeli argüman tespit edildi: {arg}", []

    return True, cmd, args


def security_check(chat_id: str, text: str) -> tuple[bool, str]:
    if not is_authorized(chat_id):
        return False, "⛔ Yetkisiz erişim"

    ok, wait = check_rate_limit(chat_id)
    if not ok:
        return False, f"⏳ Rate limit — {wait}s bekle"

    valid, cmd, _ = validate_command(text)
    if not valid:
        return False, f"❌ {cmd}"

    if cmd != "/auth" and not is_authenticated(chat_id):
        return False, "🔐 Önce /auth <pin> ile giriş yap"

    return True, cmd


def set_pin(pin: str) -> None:
    cfg = _load_config()
    cfg["pin_hash"] = hashlib.sha256(pin.encode()).hexdigest()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def add_allowed_user(chat_id: str) -> None:
    cfg = _load_config()
    allowed = cfg.get("allowed_users", [])
    if str(chat_id) not in [str(u) for u in allowed]:
        allowed.append(str(chat_id))
    cfg["allowed_users"] = allowed
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
