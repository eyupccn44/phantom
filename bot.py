#!/usr/bin/env python3
"""
Phantom Telegram Bot — Komut dinleyici
Telegram'dan red team komutları alır, sonuçları gönderir.

Kullanım: python bot.py
"""

import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.bot_security import security_check, authenticate, sanitize_target, validate_command
from core.tools import run_nmap, run_whois, run_ping, format_scan_for_llm
from core.mitre import map_scan_to_ttps
from core.cve import scan_ports_to_cves
from core.subdomain import enumerate_subdomains
from core.default_creds import check_default_creds
from core.adversary import list_adversaries, get_adversary

CONFIG_PATH = Path(__file__).parent / "telegram.json"

HELP_TEXT = """🤖 <b>PHANTOM Bot Komutları</b>

/auth &lt;pin&gt; — Kimlik doğrulama
/scan &lt;hedef&gt; — Hızlı nmap taraması
/whois &lt;hedef&gt; — Whois sorgusu
/sub &lt;domain&gt; — Subdomain keşfi
/creds &lt;hedef&gt; — Default credential testi
/spray &lt;hedef&gt; &lt;user:pass,...&gt; — Password spray (dikkatli kullan)
/adv [isim] — Adversary profilleri listele / görüntüle
/sessions — Son sessionları listele
/status — Bot durumu
/ping — Bağlantı testi

<i>⚠ Yalnızca yetkili sistemlerde kullanın</i>"""


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        print("telegram.json bulunamadı")
        sys.exit(1)
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _api(token: str, method: str, **params) -> dict:
    payload = json.dumps(params).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"ok": False, "error": str(e)}


def send(token: str, chat_id: str, text: str, parse_mode: str = "HTML") -> None:
    _api(token, "sendMessage",
         chat_id=chat_id, text=text[:4096],
         parse_mode=parse_mode, disable_web_page_preview=True)


def get_updates(token: str, offset: int = 0) -> list[dict]:
    data = _api(token, "getUpdates", offset=offset, timeout=30, limit=10)
    return data.get("result", []) if data.get("ok") else []


# ─── KOMUT İŞLEYİCİLER ───────────────────────────────────────────────────────

def handle_scan(token: str, chat_id: str, args: list[str]) -> None:
    if not args:
        send(token, chat_id, "Kullanım: /scan &lt;hedef&gt;")
        return

    ok, target_or_err = sanitize_target(args[0])
    if not ok:
        send(token, chat_id, f"❌ {target_or_err}")
        return

    target = target_or_err
    send(token, chat_id, f"📡 <code>{target}</code> taranıyor (hızlı mod)...")

    scan = run_nmap(target, fast=True)
    ttps = map_scan_to_ttps(scan.ports)
    cves = scan_ports_to_cves(scan.ports)

    lines = [f"✅ <b>Tarama tamamlandı: {target}</b>"]
    lines.append(f"Durum: {'🟢 UP' if scan.host_up else '🔴 DOWN'}")
    if scan.os_guess:
        lines.append(f"OS: {scan.os_guess}")

    if scan.ports:
        lines.append(f"\n<b>Açık Portlar ({len(scan.ports)}):</b>")
        for p in scan.ports[:15]:
            lines.append(f"  <code>{p.number}/{p.protocol}</code> {p.service} {p.version[:30] if p.version else ''}")

    if cves:
        critical_cves = [c for c in cves if c.get("cvss", 0) >= 9.0]
        lines.append(f"\n<b>CVE Eşleşmeleri: {len(cves)}</b>")
        for c in critical_cves[:3]:
            msf = " [MSF✓]" if c.get("metasploit") else ""
            lines.append(f"  🔴 <code>{c['id']}</code> CVSS:{c.get('cvss')}{msf}")

    if ttps:
        critical_ttps = [t for t in ttps if t.risk == "critical"]
        lines.append(f"\n<b>Kritik TTPs: {len(critical_ttps)}</b>")
        for t in critical_ttps[:3]:
            lines.append(f"  ⚡ <code>{t.tid}</code> — {t.name}")

    send(token, chat_id, "\n".join(lines))


def handle_whois(token: str, chat_id: str, args: list[str]) -> None:
    if not args:
        send(token, chat_id, "Kullanım: /whois &lt;hedef&gt;")
        return
    ok, target_or_err = sanitize_target(args[0])
    if not ok:
        send(token, chat_id, f"❌ {target_or_err}")
        return

    send(token, chat_id, f"🔍 Whois sorgusu: <code>{target_or_err}</code>")
    result = run_whois(target_or_err)

    lines = [f"<b>Whois: {target_or_err}</b>"]
    if result.registrar:
        lines.append(f"Registrar: {result.registrar}")
    if result.org:
        lines.append(f"Org: {result.org}")
    if result.country:
        lines.append(f"Ülke: {result.country}")
    if result.creation_date:
        lines.append(f"Oluşturulma: {result.creation_date[:20]}")
    if result.nameservers:
        lines.append(f"NS: {', '.join(result.nameservers[:3])}")

    send(token, chat_id, "\n".join(lines) if len(lines) > 1 else "Whois verisi alınamadı")


def handle_sub(token: str, chat_id: str, args: list[str]) -> None:
    if not args:
        send(token, chat_id, "Kullanım: /sub &lt;domain&gt;")
        return
    ok, target_or_err = sanitize_target(args[0])
    if not ok:
        send(token, chat_id, f"❌ {target_or_err}")
        return

    send(token, chat_id, f"🌐 Subdomain taranıyor: <code>{target_or_err}</code>")
    subs = enumerate_subdomains(target_or_err, brute=True)

    if not subs:
        send(token, chat_id, "Aktif subdomain bulunamadı")
        return

    lines = [f"<b>Subdomains: {target_or_err} ({len(subs)} aktif)</b>"]
    for s in subs[:20]:
        lines.append(f"  <code>{s.name}</code> → {s.ip}")
    if len(subs) > 20:
        lines.append(f"  ... ve {len(subs) - 20} tane daha")

    send(token, chat_id, "\n".join(lines))


def handle_creds(token: str, chat_id: str, args: list[str]) -> None:
    if not args:
        send(token, chat_id, "Kullanım: /creds &lt;hedef&gt;")
        return
    ok, target_or_err = sanitize_target(args[0])
    if not ok:
        send(token, chat_id, f"❌ {target_or_err}")
        return

    send(token, chat_id, f"🔑 Default credential testi: <code>{target_or_err}</code>")
    scan = run_nmap(target_or_err, fast=True)
    hits = check_default_creds(scan.ports, target_or_err)

    if not hits:
        send(token, chat_id, "Default credential bulunamadı")
        return

    lines = [f"<b>💥 Default Credential Bulundu!</b>"]
    for h in hits:
        if h.success:
            lines.append(f"  ✅ {h.service}:{h.port} — <code>{h.user}</code> / <code>{h.password}</code>")

    send(token, chat_id, "\n".join(lines))


def handle_adv(token: str, chat_id: str, args: list[str]) -> None:
    if not args:
        names = list_adversaries()
        send(token, chat_id, f"<b>Mevcut Adversary Profilleri:</b>\n" + "\n".join(f"  • {n}" for n in names))
        return

    adv = get_adversary(args[0])
    if not adv:
        send(token, chat_id, f"Bulunamadı: {args[0]}")
        return

    lines = [
        f"<b>{adv['name']}</b>",
        f"Aliases: {', '.join(adv.get('aliases', []))}",
        f"Menşei: {adv.get('origin', '?')}",
        f"OPSEC: {adv.get('opsec', '?')}",
        f"Hedefler: {', '.join(adv.get('targets', []))}",
        f"TTPs: {', '.join(adv.get('ttps', []))}",
        f"\n<i>{adv.get('description', '')}</i>",
    ]
    send(token, chat_id, "\n".join(lines))


def handle_sessions(token: str, chat_id: str) -> None:
    from core.memory import list_sessions, load_session
    sessions = list_sessions()
    if not sessions:
        send(token, chat_id, "Kayıtlı session yok")
        return

    lines = ["<b>Son Sessionlar:</b>"]
    for s in sessions[:10]:
        try:
            data = load_session(s)
            started = data.get("started_at", "")[:16].replace("T", " ")
            lines.append(f"  📁 <code>{data['target']}</code> — {started} ({len(data.get('ttps',[]))} ttp)")
        except Exception:
            lines.append(f"  {s.name}")
    send(token, chat_id, "\n".join(lines))


COMMAND_HANDLERS = {
    "/scan":     handle_scan,
    "/whois":    handle_whois,
    "/sub":      handle_sub,
    "/creds":    handle_creds,
    "/adv":      handle_adv,
}


# ─── ANA DÖNGÜ ───────────────────────────────────────────────────────────────

def run_bot() -> None:
    cfg = _load_config()
    token = cfg.get("token")
    if not token:
        print("Token bulunamadı")
        sys.exit(1)

    print(f"🤖 Phantom Bot başladı — polling...")
    offset = 0

    while True:
        try:
            updates = get_updates(token, offset)
            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message") or update.get("edited_message")
                if not msg:
                    continue

                chat_id = str(msg["chat"]["id"])
                text = msg.get("text", "").strip()
                if not text or not text.startswith("/"):
                    continue

                ok, result = security_check(chat_id, text)
                if not ok:
                    send(token, chat_id, result)
                    continue

                parts = text.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd == "/help":
                    send(token, chat_id, HELP_TEXT)

                elif cmd == "/ping":
                    send(token, chat_id, "🟢 Phantom Bot aktif")

                elif cmd == "/status":
                    from core.llm import check_ollama
                    ok_ollama, info = check_ollama()
                    status = "🟢 OK" if ok_ollama else "🔴 Kapalı"
                    send(token, chat_id, f"<b>Bot Durumu</b>\nOllama: {status} ({info})")

                elif cmd == "/auth":
                    if not args:
                        send(token, chat_id, "Kullanım: /auth &lt;pin&gt;")
                    elif authenticate(chat_id, args[0]):
                        send(token, chat_id, "✅ Kimlik doğrulandı — oturum 1 saat geçerli")
                    else:
                        send(token, chat_id, "❌ Yanlış PIN")

                elif cmd == "/sessions":
                    handle_sessions(token, chat_id)

                elif cmd in COMMAND_HANDLERS:
                    try:
                        COMMAND_HANDLERS[cmd](token, chat_id, args)
                    except Exception as e:
                        send(token, chat_id, f"❌ Hata: {str(e)[:200]}")

                else:
                    send(token, chat_id, f"Bilinmeyen komut. /help için yaz.")

        except KeyboardInterrupt:
            print("\nBot durduruldu.")
            break
        except Exception as e:
            print(f"Hata: {e}")
            time.sleep(5)


if __name__ == "__main__":
    run_bot()
