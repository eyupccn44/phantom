import json
import urllib.request
import urllib.error
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "telegram.json"

_config: dict | None = None


def _load_config() -> dict:
    global _config
    if _config is None:
        if not CONFIG_PATH.exists():
            _config = {}
        else:
            _config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return _config


def is_configured() -> bool:
    cfg = _load_config()
    return bool(cfg.get("token") and cfg.get("chat_id"))


def _send(text: str, parse_mode: str = "HTML") -> bool:
    cfg = _load_config()
    token = cfg.get("token")
    chat_id = cfg.get("chat_id")
    if not token or not chat_id:
        return False

    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def _send_file(file_path: Path, caption: str = "") -> bool:
    cfg = _load_config()
    token = cfg.get("token")
    chat_id = str(cfg.get("chat_id", ""))
    if not token or not chat_id:
        return False

    import urllib.parse
    import mimetypes

    boundary = "PhantomBoundary"
    file_data = file_path.read_bytes()
    mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
        f"{chat_id}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="caption"\r\n\r\n'
        f"{caption}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="document"; filename="{file_path.name}"\r\n'
        f"Content-Type: {mime_type}\r\n\r\n"
    ).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode("utf-8")

    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status == 200
    except Exception:
        return False


# ─── MESAJ ŞABLONLARI ────────────────────────────────────────────────────────

def notify_session_start(target: str, scope: str, model: str) -> None:
    _send(
        f"🎯 <b>PHANTOM — Oturum Başladı</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n"
        f"<b>Kapsam:</b> {scope}\n"
        f"<b>Model:</b> {model}"
    )


def notify_scan_complete(target: str, port_count: int, os_guess: str) -> None:
    os_line = f"\n<b>OS:</b> {os_guess}" if os_guess else ""
    _send(
        f"📡 <b>Tarama Tamamlandı</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n"
        f"<b>Açık Port:</b> {port_count}{os_line}"
    )


def notify_critical_cve(target: str, cve_id: str, cvss: float, description: str,
                         port: str, metasploit: str | None) -> None:
    msf_line = f"\n🔫 <b>MSF:</b> <code>{metasploit}</code>" if metasploit else ""
    _send(
        f"🔴 <b>KRİTİK CVE BULUNDU</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n"
        f"<b>CVE:</b> <code>{cve_id}</code>\n"
        f"<b>CVSS:</b> {cvss}\n"
        f"<b>Port:</b> {port}{msf_line}\n\n"
        f"<i>{description[:200]}</i>"
    )


def notify_critical_ttp(target: str, tid: str, name: str, tactic: str, port: str) -> None:
    _send(
        f"⚡ <b>KRİTİK TTP TESPİT EDİLDİ</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n"
        f"<b>Teknik:</b> <code>{tid}</code> — {name}\n"
        f"<b>Taktik:</b> {tactic}\n"
        f"<b>Port:</b> {port}"
    )


def notify_tool_result(tool_name: str, target: str, result_snippet: str) -> None:
    _send(
        f"🔧 <b>Araç Sonucu — {tool_name}</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n\n"
        f"<pre>{result_snippet[:500]}</pre>"
    )


def notify_llm_finding(target: str, finding: str, risk: str) -> None:
    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk, "⚪")
    _send(
        f"{emoji} <b>PHANTOM Bulgusu [{risk.upper()}]</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n\n"
        f"{finding[:600]}"
    )


def notify_session_end(target: str, findings: int, ttps: int, cves: int,
                        session_file: str) -> None:
    _send(
        f"✅ <b>Oturum Tamamlandı</b>\n\n"
        f"<b>Hedef:</b> <code>{target}</code>\n"
        f"<b>Bulgular:</b> {findings}\n"
        f"<b>TTP:</b> {ttps}\n"
        f"<b>CVE:</b> {cves}\n"
        f"<b>Session:</b> <code>{Path(session_file).name}</code>"
    )


def send_report(report_path: Path, target: str) -> bool:
    return _send_file(report_path, caption=f"📄 Phantom Raporu — {target}")


def test_connection() -> tuple[bool, str]:
    cfg = _load_config()
    token = cfg.get("token")
    chat_id = cfg.get("chat_id")
    if not token or not chat_id:
        return False, "telegram.json bulunamadı veya token/chat_id eksik"
    ok = _send("🤖 <b>Phantom</b> bağlantı testi başarılı.")
    if ok:
        return True, "Telegram bağlantısı OK"
    return False, "Mesaj gönderilemedi — token veya chat_id hatalı olabilir"
