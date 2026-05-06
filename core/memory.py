import json
import re
from datetime import datetime
from pathlib import Path

SESSIONS_DIR = Path(__file__).parent.parent / "sessions"
INTEL_DIR = Path(__file__).parent.parent / "intel"


def _slug(target: str) -> str:
    return re.sub(r"[^\w\-]", "_", target)


class IntelligenceBase:
    """Cross-session learning — her session'dan öğrenir, sonrakine aktarır."""

    def __init__(self):
        INTEL_DIR.mkdir(exist_ok=True)
        self._path = INTEL_DIR / "intel_base.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "sessions_analyzed": 0,
            "common_ports": {},
            "common_services": {},
            "recurring_cves": {},
            "recurring_ttps": {},
            "tactic_frequencies": {},
            "critical_findings": [],
            "tool_patterns": {},
        }

    def ingest_session(self, session_data: dict) -> None:
        self._data["sessions_analyzed"] += 1

        for p in session_data.get("scan", {}).get("ports", []):
            port = str(p.get("number", ""))
            svc = p.get("service", "")
            if port:
                self._data["common_ports"][port] = self._data["common_ports"].get(port, 0) + 1
            if svc:
                self._data["common_services"][svc] = self._data["common_services"].get(svc, 0) + 1

        for c in session_data.get("cves", []):
            cid = c.get("id", "")
            if cid:
                self._data["recurring_cves"][cid] = self._data["recurring_cves"].get(cid, 0) + 1

        for t in session_data.get("ttps", []):
            tid = t.get("tid", "")
            tactic = t.get("tactic", "")
            if tid:
                self._data["recurring_ttps"][tid] = self._data["recurring_ttps"].get(tid, 0) + 1
            if tactic:
                self._data["tactic_frequencies"][tactic] = self._data["tactic_frequencies"].get(tactic, 0) + 1

        for f in session_data.get("findings", []):
            if f.get("risk") in ("critical", "high"):
                lesson = f.get("finding", "")[:150]
                if lesson and lesson not in self._data["critical_findings"]:
                    self._data["critical_findings"].append(lesson)

        # Nuclei/nikto/gobuster pattern öğrenme
        tools = session_data.get("tools", {})
        for tool_name, results in tools.items():
            if not isinstance(results, list):
                continue
            self._data["tool_patterns"].setdefault(tool_name, {})
            for item in results:
                key = item.get("template_id") or item.get("uri") or item.get("path", "")
                if key:
                    self._data["tool_patterns"][tool_name][key] = \
                        self._data["tool_patterns"][tool_name].get(key, 0) + 1

        # Max 200 kritik bulgu tut
        self._data["critical_findings"] = self._data["critical_findings"][-200:]
        self._save()

    def build_context_for_llm(self) -> str:
        n = self._data["sessions_analyzed"]
        if n == 0:
            return ""
        lines = [f"[PHANTOM INTELLIGENCE — {n} geçmiş session'dan öğrenildi]"]

        top_ports = sorted(self._data["common_ports"].items(), key=lambda x: x[1], reverse=True)[:6]
        if top_ports:
            lines.append("Sık görülen portlar: " + ", ".join(f"{p}({c}x)" for p, c in top_ports))

        top_cves = sorted(self._data["recurring_cves"].items(), key=lambda x: x[1], reverse=True)[:4]
        if top_cves:
            lines.append("Tekrar eden CVE'ler: " + ", ".join(f"{c}({n}x)" for c, n in top_cves))

        top_ttps = sorted(self._data["recurring_ttps"].items(), key=lambda x: x[1], reverse=True)[:6]
        if top_ttps:
            lines.append("En sık TTP'ler: " + ", ".join(f"{t}({n}x)" for t, n in top_ttps))

        top_tactics = sorted(self._data["tactic_frequencies"].items(), key=lambda x: x[1], reverse=True)[:4]
        if top_tactics:
            lines.append("Baskın taktikler: " + ", ".join(f"{t}({n}x)" for t, n in top_tactics))

        if self._data["critical_findings"]:
            lines.append(f"Son kritik bulgular ({len(self._data['critical_findings'])} toplam):")
            for lesson in self._data["critical_findings"][-4:]:
                lines.append(f"  • {lesson}")

        return "\n".join(lines)

    def _save(self):
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
        )


class SessionMemory:
    def __init__(self, target: str):
        self.target = target
        SESSIONS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_file = SESSIONS_DIR / f"{_slug(target)}_{ts}.json"
        self.intel = IntelligenceBase()
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
            "tools": {},
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

    MAX_MESSAGES = 20
    MAX_MSG_CHARS = 1200  # her mesajı kırp

    def get_messages(self) -> list[dict]:
        msgs = self.data["messages"]
        # Her mesajı karakter sınırında kırp
        trimmed = [
            {"role": m["role"], "content": m["content"][:self.MAX_MSG_CHARS] + ("…" if len(m["content"]) > self.MAX_MSG_CHARS else "")}
            for m in msgs
        ]
        if len(trimmed) <= self.MAX_MESSAGES:
            return trimmed
        # Çok uzunsa: ilk 2 + özet + son N
        recent = trimmed[-(self.MAX_MESSAGES - 3):]
        findings_summary = "; ".join(f['finding'][:60] for f in self.data['findings'][:6])
        summary_stub = {
            "role": "user",
            "content": (
                f"[{len(msgs) - len(recent)} eski mesaj sıkıştırıldı. "
                f"Önemli bulgular: {findings_summary or 'henüz yok'}]"
            ),
        }
        return trimmed[:2] + [summary_stub] + recent

    def save_tool_result(self, tool_name: str, results: list) -> None:
        self.data["tools"][tool_name] = results
        self._save()

    def get_context_snapshot(self) -> str:
        scan = self.data.get("scan", {})
        ttps = self.data.get("ttps", [])
        findings = self.data.get("findings", [])
        cves = self.data.get("cves", [])
        tools = self.data.get("tools", {})
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
        if tools:
            tool_summary = []
            for tn, tr in tools.items():
                if isinstance(tr, list) and tr:
                    tool_summary.append(f"{tn}={len(tr)}")
            if tool_summary:
                lines.append("TOOLS: " + ", ".join(tool_summary))
        intel_ctx = self.intel.build_context_for_llm()
        if intel_ctx:
            lines.append("")
            lines.append(intel_ctx)
        return "\n".join(lines)

    def finalize(self) -> None:
        """Session sonunda intelligence base'i güncelle."""
        try:
            self.intel.ingest_session(self.data)
        except Exception:
            pass

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
