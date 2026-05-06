import json
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_MAP = {
    "Reconnaissance":       "reconnaissance",
    "Initial Access":       "initial-access",
    "Execution":            "execution",
    "Persistence":          "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion":      "defense-evasion",
    "Credential Access":    "credential-access",
    "Discovery":            "discovery",
    "Lateral Movement":     "lateral-movement",
    "Collection":           "collection",
    "Command and Control":  "command-and-control",
    "Exfiltration":         "exfiltration",
    "Impact":               "impact",
}

RISK_COLORS = {
    "critical": "#ff0000",
    "high":     "#ff6600",
    "medium":   "#ffcc00",
    "low":      "#00aa00",
}


def export_navigator_layer(ttps, target: str, cves: list = None) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = target.replace(".", "_").replace("/", "_")
    path = REPORTS_DIR / f"navigator_{safe}_{ts}.json"

    techniques = []
    seen = set()

    for t in ttps:
        tid = t.tid.split(".")[0]
        sub = t.tid if "." in t.tid else None
        key = t.tid

        if key in seen:
            continue
        seen.add(key)

        tactic = TACTIC_MAP.get(t.tactic, "initial-access")
        color = RISK_COLORS.get(t.risk, "#cccccc")

        entry = {
            "techniqueID": tid,
            "tactic": tactic,
            "color": color,
            "comment": f"Port {t.port}/{t.service} | Risk: {t.risk.upper()} | OPSEC: {t.opsec}",
            "enabled": True,
            "score": {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(t.risk, 50),
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        if sub:
            entry["techniqueID"] = t.tid

        techniques.append(entry)

    layer = {
        "name": f"Phantom — {target}",
        "versions": {
            "attack": "16",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Phantom Red Team Agent — {target} — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Network", "Cloud"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "CRITICAL", "color": "#ff0000"},
            {"label": "HIGH",     "color": "#ff6600"},
            {"label": "MEDIUM",   "color": "#ffcc00"},
            {"label": "LOW",      "color": "#00aa00"},
        ],
        "metadata": [
            {"name": "target",    "value": target},
            {"name": "generated", "value": datetime.now().isoformat()},
            {"name": "tool",      "value": "Phantom Red Team Agent v2"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a1a",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    path.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
