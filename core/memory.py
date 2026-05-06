import json
import re
from datetime import datetime
from pathlib import Path

SESSIONS_DIR = Path(__file__).parent.parent / "sessions"


def _slug(target: str) -> str:
    return re.sub(r"[^\w\-]", "_", target)


class SessionMemory:
    def __init__(self, target: str):
        self.target = target
        SESSIONS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_file = SESSIONS_DIR / f"{_slug(target)}_{ts}.json"
        self.data: dict = {
            "target": target,
            "started_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "scope": "",
            "scan": {},
            "whois": {},
            "ttps": [],
            "findings": [],
            "messages": [],
            "notes": [],
        }

    def set_scope(self, scope: str) -> None:
        self.data["scope"] = scope
        self._save()

    def save_scan(self, scan_dict: dict) -> None:
        self.data["scan"] = scan_dict
        self._save()

    def save_whois(self, whois_dict: dict) -> None:
        self.data["whois"] = whois_dict
        self._save()

    def save_ttps(self, ttps: list) -> None:
        self.data["ttps"] = [
            {
                "tid": t.tid,
                "name": t.name,
                "tactic": t.tactic,
                "risk": t.risk,
                "port": t.port,
                "service": t.service,
                "apt_groups": getattr(t, "apt_groups", []),
                "tools": getattr(t, "tools", []),
                "bypass": getattr(t, "bypass", ""),
            }
            for t in ttps
        ]
        self._save()

    def add_finding(self, finding: str, risk: str = "medium") -> None:
        self.data["findings"].append({
            "ts": datetime.now().isoformat(),
            "risk": risk,
            "finding": finding,
        })
        self._save()

    def add_message(self, role: str, content: str) -> None:
        self.data["messages"].append({"role": role, "content": content})
        self._save()

    def add_note(self, note: str) -> None:
        self.data["notes"].append({
            "ts": datetime.now().isoformat(),
            "note": note,
        })
        self._save()

    MAX_MESSAGES = 40
    COMPRESS_AFTER = 30

    def get_messages(self) -> list[dict]:
        msgs = self.data["messages"]
        if len(msgs) <= self.MAX_MESSAGES:
            return msgs
        # Rolling window: keep first 2 (system context) + last (MAX_MESSAGES - 4)
        # and inject a summary stub in between
        recent = msgs[-(self.MAX_MESSAGES - 4):]
        summary_stub = {
            "role": "user",
            "content": (
                f"[CONTEXT WINDOW COMPRESSED — {len(msgs) - len(recent)} earlier messages omitted. "
                f"Key findings so far: "
                + "; ".join(f['finding'][:60] for f in self.data['findings'][:8])
                + "]"
            ),
        }
        return msgs[:2] + [summary_stub] + recent

    def get_context_snapshot(self) -> str:
        scan = self.data.get("scan", {})
        ttps = self.data.get("ttps", [])
        findings = self.data.get("findings", [])
        cves = self.data.get("cves", [])
        lines = [
            f"TARGET: {self.data['target']}  |  SCOPE: {self.data.get('scope','')}",
            f"PORTS: {len(scan.get('ports', []))} open  |  OS: {scan.get('os_guess','')}",
            f"TTPs: {len(ttps)}  |  CVEs: {len(cves)}  |  FINDINGS: {len(findings)}",
        ]
        critical = [t for t in ttps if t.get("risk") == "critical"]
        if critical:
            lines.append("CRITICAL TTPs: " + ", ".join(t["tid"] for t in critical[:5]))
        crit_cves = [c for c in cves if c.get("cvss", 0) >= 9.0]
        if crit_cves:
            lines.append("CRITICAL CVEs: " + ", ".join(c["id"] for c in crit_cves[:5]))
        return "\n".join(lines)

    def _save(self) -> None:
        self.data["updated_at"] = datetime.now().isoformat()
        self.session_file.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def export_summary(self) -> str:
        lines = [
            f"SESSION SUMMARY",
            f"Target:   {self.data['target']}",
            f"Scope:    {self.data['scope'] or 'not set'}",
            f"Started:  {self.data['started_at'][:19].replace('T', ' ')}",
            f"File:     {self.session_file.name}",
            "",
        ]
        if self.data["findings"]:
            lines.append(f"FINDINGS ({len(self.data['findings'])}):")
            for f in self.data["findings"]:
                lines.append(f"  [{f['risk'].upper()}] {f['finding']}")
        if self.data["ttps"]:
            lines.append(f"\nTTPs MAPPED ({len(self.data['ttps'])}):")
            for t in self.data["ttps"]:
                lines.append(f"  {t['tid']} — {t['name']} (Port {t['port']})")
        return "\n".join(lines)


def list_sessions(target: str | None = None) -> list[Path]:
    SESSIONS_DIR.mkdir(exist_ok=True)
    if target:
        pattern = f"{_slug(target)}_*.json"
    else:
        pattern = "*.json"
    return sorted(SESSIONS_DIR.glob(pattern), reverse=True)


def load_session(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
