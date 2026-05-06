import json
from pathlib import Path
from dataclasses import dataclass, field

_DATA_PATH = Path(__file__).parent.parent / "data" / "techniques.json"
_db_list: list | None = None
_port_index: dict | None = None
_service_index: dict | None = None


def _load() -> list:
    global _db_list
    if _db_list is None:
        raw = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
        _db_list = raw if isinstance(raw, list) else list(raw.get("techniques", raw).values())
    return _db_list


def _get_port_index() -> dict:
    global _port_index
    if _port_index is not None:
        return _port_index
    _port_index = {}
    for t in _load():
        for p in t.get("ports", []):
            _port_index.setdefault(str(p), []).append(t)
    return _port_index


def _get_service_index() -> dict:
    global _service_index
    if _service_index is not None:
        return _service_index
    _service_index = {}
    for t in _load():
        for s in t.get("services", []):
            _service_index.setdefault(s.lower(), []).append(t)
    return _service_index


def get_technique(tid: str) -> dict | None:
    for t in _load():
        if t.get("id") == tid:
            return t
    return None


def get_techniques_for_port(port: str) -> list[dict]:
    return _get_port_index().get(str(port), [])


def get_techniques_for_service(service: str) -> list[dict]:
    idx = _get_service_index()
    service_lower = service.lower()
    results = []
    seen_ids = set()
    for key, techs in idx.items():
        if key in service_lower or service_lower in key:
            for t in techs:
                if t["id"] not in seen_ids:
                    results.append(t)
                    seen_ids.add(t["id"])
    return results


@dataclass
class MappedTechnique:
    tid: str
    name: str
    tactic: str
    risk: str
    tools: list[str]
    port: str
    service: str
    apt_groups: list[str] = field(default_factory=list)
    opsec: str = "MODERATE"
    detection_sources: list[str] = field(default_factory=list)
    bypass: str = ""


def map_scan_to_ttps(ports) -> list[MappedTechnique]:
    seen: set[str] = set()
    results: list[MappedTechnique] = []

    for port in ports:
        combined = get_techniques_for_port(port.number) + get_techniques_for_service(port.service)
        for t in combined:
            tid = t.get("id", "")
            key = f"{port.number}:{tid}"
            if key in seen:
                continue
            seen.add(key)
            results.append(MappedTechnique(
                tid=tid,
                name=t["name"],
                tactic=t["tactic"],
                risk=t.get("risk", "medium"),
                tools=t.get("tools", []),
                port=port.number,
                service=port.service,
                apt_groups=t.get("apt_groups", []),
                opsec=t.get("opsec", "MODERATE"),
                detection_sources=t.get("detection_sources", []),
                bypass=t.get("bypass", ""),
            ))

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: risk_order.get(x.risk, 4))
    return results


def build_context_for_llm(ttps: list[MappedTechnique]) -> str:
    if not ttps:
        return ""
    lines = ["\nMITRE ATT&CK MAPPINGS (pre-analyzed, prioritized):"]
    for t in ttps:
        apts = ", ".join(t.apt_groups[:3]) if t.apt_groups else "—"
        detections = ", ".join(t.detection_sources[:2]) if t.detection_sources else "—"
        lines.append(
            f"  [{t.risk.upper()}][{t.opsec}] {t.tid} — {t.name} "
            f"(Tactic: {t.tactic}) | Port {t.port}/{t.service}\n"
            f"    APT Groups: {apts} | Detection: {detections}"
        )
        if t.bypass:
            lines.append(f"    Bypass: {t.bypass}")
    return "\n".join(lines)


RISK_COLORS = {
    "critical": "red",
    "high":     "orange3",
    "medium":   "yellow",
    "low":      "green",
}

RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

OPSEC_STYLE = {
    "NOISY":    "bold red",
    "MODERATE": "yellow",
    "STEALTHY": "green",
}
