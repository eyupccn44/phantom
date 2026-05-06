from datetime import datetime
from pathlib import Path
import json
import re
import html as _html

REPORTS_DIR = Path(__file__).parent.parent / "reports"

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

RISK_HEX = {"critical": "#ff2244", "high": "#ff6600", "medium": "#ffcc00", "low": "#00cc66"}


def _e(text) -> str:
    return _html.escape(str(text or ""))


def _risk_score(memory_data: dict) -> int:
    ports = memory_data.get("scan", {}).get("ports", [])
    ttps = memory_data.get("ttps", [])
    cves = memory_data.get("cves", [])
    port_score = min(len(ports) * 2, 20)
    ttp_score = min(
        sum({"critical": 8, "high": 4, "medium": 2, "low": 1}.get(t.get("risk", "low"), 0) for t in ttps),
        50,
    )
    cve_scores = sorted([c.get("cvss", 0) or 0 for c in cves], reverse=True)[:5]
    cve_score = min(int(sum(cve_scores) / max(len(cve_scores), 1) * 3), 30)
    return min(port_score + ttp_score + cve_score, 100)


def _risk_color(score: int) -> str:
    if score >= 70:
        return "#ff2244"
    if score >= 40:
        return "#ff6600"
    if score >= 15:
        return "#ffcc00"
    return "#00cc66"


def _risk_label(score: int) -> str:
    if score >= 70:
        return "KRİTİK"
    if score >= 40:
        return "YÜKSEK"
    if score >= 15:
        return "ORTA"
    return "DÜŞÜK"


# ─── SEKME İÇERİKLERİ ────────────────────────────────────────────────────────

def _tab_overview(memory_data: dict, version: str) -> str:
    scan = memory_data.get("scan", {})
    ttps = memory_data.get("ttps", [])
    cves = memory_data.get("cves", [])
    findings = memory_data.get("findings", [])
    ports = scan.get("ports", [])
    whois = memory_data.get("whois", {})
    target = memory_data.get("target", "?")
    scope = memory_data.get("scope", "N/A")

    risk_counts = {r: sum(1 for t in ttps if t.get("risk") == r) for r in ("critical", "high", "medium", "low")}
    score = _risk_score(memory_data)
    score_color = _risk_color(score)
    score_label = _risk_label(score)

    host_status = (
        '<span style="color:#00cc66">● ÇEVRİMİÇİ</span>'
        if scan.get("host_up")
        else '<span style="color:#ff2244">● ÇEVRİMDIŞI</span>'
    )

    # Kill chain timeline
    tactic_counts = {}
    for t in ttps:
        tac = t.get("tactic", "")
        if tac:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    kc_boxes = ""
    for tac in KILL_CHAIN_ORDER:
        cnt = tactic_counts.get(tac, 0)
        if cnt:
            max_risk = "critical"
            for r in ("critical", "high", "medium", "low"):
                if any(t.get("risk") == r and t.get("tactic") == tac for t in ttps):
                    max_risk = r
                    break
            color = RISK_HEX.get(max_risk, "#666")
            kc_boxes += f'<div class="kc-box active" style="border-color:{color};color:{color}" title="{_e(tac)}: {cnt} TTP"><span class="kc-label">{_e(tac[:4].upper())}</span><span class="kc-cnt">{cnt}</span></div>'
        else:
            short = tac[:4].upper()
            kc_boxes += f'<div class="kc-box" title="{_e(tac)}"><span class="kc-label">{short}</span></div>'

    # Top findings
    top_findings_html = ""
    critical_findings = [f for f in findings if f.get("risk") in ("critical", "high")][:5]
    for f in critical_findings:
        risk = f.get("risk", "medium")
        color = RISK_HEX.get(risk, "#666")
        ts = f.get("ts", "")[:16].replace("T", " ")
        text = _e(f.get("finding", ""))
        top_findings_html += f'<div class="finding-card" style="border-left:3px solid {color}"><span class="badge badge-{risk}">{risk.upper()}</span> {text} <span class="meta">{ts}</span></div>'

    if not top_findings_html:
        top_findings_html = '<div class="meta" style="padding:12px">Henüz kritik bulgu yok.</div>'

    # Whois info rows
    whois_rows = ""
    for label, key in [("Durum", None), ("OS", "os_guess"), ("Hostname", None), ("Org", "org"), ("Ülke", "country")]:
        if key == "os_guess" and scan.get("os_guess"):
            whois_rows += f'<tr><td class="meta-td">İşletim Sistemi</td><td>{_e(scan["os_guess"])}</td></tr>'
        elif key in ("org", "country") and whois.get(key):
            whois_rows += f'<tr><td class="meta-td">{label}</td><td>{_e(whois[key])}</td></tr>'
        elif key is None and label == "Hostname" and scan.get("hostnames"):
            whois_rows += f'<tr><td class="meta-td">Hostname</td><td>{_e(", ".join(scan["hostnames"]))}</td></tr>'

    return f"""
<div class="overview-grid">
  <div class="risk-card card">
    <canvas id="riskDonut" width="180" height="180"></canvas>
    <div class="risk-score-label" style="color:{score_color}">{score}</div>
    <div class="risk-score-sub">{score_label} RİSK</div>
  </div>
  <div class="stats-grid">
    <div class="stat-card critical"><div class="stat-num">{risk_counts["critical"]}</div><div class="stat-lbl">KRİTİK TTP</div></div>
    <div class="stat-card high"><div class="stat-num">{risk_counts["high"]}</div><div class="stat-lbl">YÜKSEK TTP</div></div>
    <div class="stat-card medium"><div class="stat-num">{risk_counts["medium"]}</div><div class="stat-lbl">ORTA TTP</div></div>
    <div class="stat-card" style="border-color:#4488ff"><div class="stat-num" style="color:#4488ff">{len(cves)}</div><div class="stat-lbl">CVE</div></div>
    <div class="stat-card" style="border-color:#888"><div class="stat-num" style="color:#aaa">{len(ports)}</div><div class="stat-lbl">AÇIK PORT</div></div>
    <div class="stat-card" style="border-color:#888"><div class="stat-num" style="color:#aaa">{len(findings)}</div><div class="stat-lbl">BULGU</div></div>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <table style="width:auto;min-width:340px">
    <tr><td class="meta-td" width="140">Hedef</td><td><code>{_e(target)}</code></td></tr>
    <tr><td class="meta-td">Durum</td><td>{host_status}</td></tr>
    <tr><td class="meta-td">Kapsam</td><td>{_e(scope)}</td></tr>
    {whois_rows}
    <tr><td class="meta-td">Başlangıç</td><td>{_e(memory_data.get("started_at","")[:19].replace("T"," "))}</td></tr>
    <tr><td class="meta-td">Phantom</td><td>v{_e(version)}</td></tr>
  </table>
</div>

<div class="section-title" style="margin-top:24px">Kill Chain Haritası</div>
<div class="kc-timeline">{kc_boxes}</div>

<div class="section-title" style="margin-top:24px">Kritik Bulgular</div>
{top_findings_html}

<script>
(function(){{
  const data = {json.dumps(risk_counts)};
  const canvas = document.getElementById('riskDonut');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = 90, cy = 90, r = 70;
  const colors = {{critical:'#ff2244',high:'#ff6600',medium:'#ffcc00',low:'#00cc66'}};
  const total = Object.values(data).reduce((a,b)=>a+b,0);
  if (total === 0) {{
    ctx.fillStyle='#1e1e2e'; ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2); ctx.fill();
    ctx.fillStyle='#444'; ctx.font='12px Consolas'; ctx.textAlign='center'; ctx.fillText('N/A',cx,cy+4); return;
  }}
  let start = -Math.PI/2;
  for (const [risk, count] of Object.entries(data)) {{
    if (!count) continue;
    const angle = (count/total)*2*Math.PI;
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,start,start+angle);
    ctx.fillStyle=colors[risk]; ctx.fill(); start+=angle;
  }}
  ctx.beginPath(); ctx.arc(cx,cy,r*0.55,0,Math.PI*2);
  ctx.fillStyle='#12121a'; ctx.fill();
  ctx.fillStyle='{score_color}'; ctx.font='bold 22px Consolas'; ctx.textAlign='center'; ctx.textBaseline='middle';
  ctx.fillText({score},cx,cy);
}})();
</script>
"""


def _tab_ports(ports: list) -> str:
    if not ports:
        return '<div class="meta" style="padding:20px">Port verisi yok.</div>'
    rows = ""
    for p in ports:
        svc = _e(p.get("service", ""))
        ver = _e(p.get("version", ""))
        rows += f'<tr><td><code>{_e(p.get("number",""))}/{_e(p.get("protocol","tcp"))}</code></td><td>{svc}</td><td>{ver or "<span class=meta>—</span>"}</td><td><span style="color:#00cc66">OPEN</span></td></tr>'
    return f"""
<div class="toolbar">
  <input class="search-input" id="port-search" placeholder="Port / servis ara..." oninput="filterTable('port-search','port-table')">
  <span class="meta">{len(ports)} port</span>
</div>
<div class="table-wrap">
<table id="port-table">
  <thead><tr>
    <th onclick="sortTable('port-table',0)" class="sortable">Port</th>
    <th onclick="sortTable('port-table',1)" class="sortable">Servis</th>
    <th onclick="sortTable('port-table',2)" class="sortable">Versiyon</th>
    <th>Durum</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>"""


def _tab_ttps(ttps: list) -> str:
    if not ttps:
        return '<div class="meta" style="padding:20px">TTP verisi yok.</div>'
    tactics = sorted(set(t.get("tactic", "") for t in ttps if t.get("tactic")))
    tactic_opts = "".join(f'<option value="{_e(t)}">{_e(t)}</option>' for t in tactics)
    rows = ""
    for t in ttps:
        risk = _e(t.get("risk", "low"))
        tid = _e(t.get("tid", ""))
        apts = _e(", ".join(t.get("apt_groups", [])[:3]))
        tools_ = _e(", ".join(t.get("tools", [])[:3]))
        bypass_ = _e(t.get("bypass", "") or "—")
        opsec_ = _e(t.get("opsec", "") or "—")
        rows += (
            f'<tr data-risk="{risk}" data-tactic="{_e(t.get("tactic",""))}">'
            f'<td><span class="badge badge-{risk}">{risk.upper()}</span></td>'
            f'<td><code>{tid}</code></td>'
            f'<td>{_e(t.get("name",""))}</td>'
            f'<td><span class="meta">{_e(t.get("tactic",""))}</span></td>'
            f'<td><code>{_e(t.get("port",""))}</code></td>'
            f'<td>{_e(t.get("service",""))}</td>'
            f'<td><small>{apts or "—"}</small></td>'
            f'<td><small>{tools_ or "—"}</small></td>'
            f'<td><small class="meta">{bypass_}</small></td>'
            f'</tr>'
        )
    return f"""
<div class="toolbar">
  <div class="risk-btns">
    <button class="risk-btn active" data-risk="all" onclick="filterRisk(this,'ttp-table','data-risk')">Tümü ({len(ttps)})</button>
    <button class="risk-btn" data-risk="critical" onclick="filterRisk(this,'ttp-table','data-risk')">Kritik</button>
    <button class="risk-btn" data-risk="high" onclick="filterRisk(this,'ttp-table','data-risk')">Yüksek</button>
    <button class="risk-btn" data-risk="medium" onclick="filterRisk(this,'ttp-table','data-risk')">Orta</button>
    <button class="risk-btn" data-risk="low" onclick="filterRisk(this,'ttp-table','data-risk')">Düşük</button>
  </div>
  <select class="search-input" id="tactic-filter" onchange="filterTactic('tactic-filter','ttp-table')">
    <option value="">Tüm Taktikler</option>{tactic_opts}
  </select>
  <input class="search-input" id="ttp-search" placeholder="TTP ara..." oninput="filterTable('ttp-search','ttp-table')">
</div>
<div class="table-wrap">
<table id="ttp-table">
  <thead><tr>
    <th onclick="sortTable('ttp-table',0)" class="sortable">Risk</th>
    <th onclick="sortTable('ttp-table',1)" class="sortable">ID</th>
    <th onclick="sortTable('ttp-table',2)" class="sortable">Teknik</th>
    <th>Taktik</th>
    <th>Port</th>
    <th>Servis</th>
    <th>APT</th>
    <th>Araçlar</th>
    <th>Bypass</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>"""


def _tab_cves(cves: list) -> str:
    if not cves:
        return '<div class="meta" style="padding:20px">CVE verisi yok.</div>'
    rows = ""
    for c in sorted(cves, key=lambda x: x.get("cvss", 0) or 0, reverse=True):
        cvss = c.get("cvss", 0) or 0
        if cvss >= 9.0:
            sev, badge = "critical", "KRİTİK"
        elif cvss >= 7.0:
            sev, badge = "high", "YÜKSEK"
        elif cvss >= 4.0:
            sev, badge = "medium", "ORTA"
        else:
            sev, badge = "low", "DÜŞÜK"
        extras = ""
        if c.get("metasploit"):
            extras += ' <code class="tag-msf">[MSF]</code>'
        if c.get("poc"):
            extras += ' <code class="tag-poc">[PoC]</code>'
        rows += (
            f'<tr data-risk="{sev}">'
            f'<td><code>{_e(c.get("id",""))}</code></td>'
            f'<td><span class="badge badge-{sev}">{badge}</span></td>'
            f'<td><b style="color:{RISK_HEX.get(sev,"#aaa")}">{cvss}</b></td>'
            f'<td>{_e(c.get("service","") or c.get("service_key",""))}</td>'
            f'<td>{_e((c.get("description","") or "")[:90])}{extras}</td>'
            f'<td>{_e(c.get("mitre","") or "—")}</td>'
            f'</tr>'
        )
    return f"""
<div class="toolbar">
  <div class="risk-btns">
    <button class="risk-btn active" data-risk="all" onclick="filterRisk(this,'cve-table','data-risk')">Tümü ({len(cves)})</button>
    <button class="risk-btn" data-risk="critical" onclick="filterRisk(this,'cve-table','data-risk')">Kritik</button>
    <button class="risk-btn" data-risk="high" onclick="filterRisk(this,'cve-table','data-risk')">Yüksek</button>
    <button class="risk-btn" data-risk="medium" onclick="filterRisk(this,'cve-table','data-risk')">Orta</button>
  </div>
  <input class="search-input" id="cve-search" placeholder="CVE ara..." oninput="filterTable('cve-search','cve-table')">
</div>
<div class="table-wrap">
<table id="cve-table">
  <thead><tr>
    <th onclick="sortTable('cve-table',0)" class="sortable">CVE ID</th>
    <th>Önem</th>
    <th onclick="sortTable('cve-table',2)" class="sortable">CVSS</th>
    <th>Servis</th>
    <th>Açıklama</th>
    <th>MITRE</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>"""


def _tab_tools(tools_data: dict) -> str:
    if not tools_data:
        return '<div class="meta" style="padding:20px">Araç sonucu yok — --nuclei / --nikto / --gobuster / --dns / --masscan ile çalıştırın.</div>'

    tool_tabs = ""
    tool_panels = ""
    first = True
    for tool_name, results in tools_data.items():
        active_cls = "active" if first else ""
        tool_tabs += f'<button class="tool-tab-btn {active_cls}" onclick="showToolTab(\'{tool_name}\')" id="ttab-{tool_name}">{tool_name.upper()} ({len(results) if isinstance(results, list) else "?"})</button>'
        content = _render_tool_result(tool_name, results)
        hidden = "" if first else 'style="display:none"'
        tool_panels += f'<div id="tpanel-{tool_name}" {hidden}>{content}</div>'
        first = False

    return f"""
<div class="tool-tabs">{tool_tabs}</div>
{tool_panels}"""


def _render_tool_result(tool_name: str, results) -> str:
    if not isinstance(results, list) or not results:
        return '<div class="meta" style="padding:16px">Sonuç bulunamadı.</div>'

    if tool_name == "nuclei":
        sev_order = ["critical", "high", "medium", "low", "info"]
        sorted_r = sorted(results, key=lambda x: sev_order.index(x.get("severity", "info")) if x.get("severity") in sev_order else 5)
        rows = ""
        for f in sorted_r:
            sev = f.get("severity", "info")
            badge_cls = sev if sev in ("critical", "high", "medium", "low") else ""
            badge_lbl = sev.upper()
            rows += (
                f'<tr><td><span class="badge badge-{badge_cls}">{badge_lbl}</span></td>'
                f'<td><code>{_e(f.get("template_id",""))}</code></td>'
                f'<td>{_e(f.get("name",""))}</td>'
                f'<td><small>{_e(f.get("matched_at",""))}</small></td>'
                f'<td><small>{_e(f.get("cve_id","") or "—")}</small></td>'
                f'<td><small class="meta">{_e((f.get("description","") or "")[:80])}</small></td></tr>'
            )
        return f'<div class="table-wrap"><table><thead><tr><th>Önem</th><th>Template</th><th>İsim</th><th>Hedef</th><th>CVE</th><th>Açıklama</th></tr></thead><tbody>{rows}</tbody></table></div>'

    if tool_name == "nikto":
        rows = "".join(
            f'<tr><td><code>{_e(f.get("uri",""))}</code></td><td>{_e(f.get("description","")[:120])}</td><td><small class="meta">{_e(f.get("osvdb",""))}</small></td></tr>'
            for f in results
        )
        return f'<div class="table-wrap"><table><thead><tr><th>URI</th><th>Açıklama</th><th>OSVDB</th></tr></thead><tbody>{rows}</tbody></table></div>'

    if tool_name == "gobuster":
        rows = "".join(
            f'<tr><td><code>{_e(f.get("path",""))}</code></td>'
            f'<td style="color:{("#00cc66" if f.get("status",0) == 200 else "#ffcc00") if f.get("status",0) < 400 else "#ff2244"}">{f.get("status","")}</td>'
            f'<td class="meta">{f.get("size","")}</td></tr>'
            for f in results
        )
        return f'<div class="table-wrap"><table><thead><tr><th>Yol</th><th>HTTP Status</th><th>Boyut</th></tr></thead><tbody>{rows}</tbody></table></div>'

    if tool_name == "dnsrecon":
        rows = "".join(
            f'<tr><td><code style="color:#4af">{_e(r.get("type",""))}</code></td>'
            f'<td>{_e(r.get("name",""))}</td>'
            f'<td><code>{_e(r.get("address",""))}</code></td></tr>'
            for r in results
        )
        return f'<div class="table-wrap"><table><thead><tr><th>Tip</th><th>İsim</th><th>Adres</th></tr></thead><tbody>{rows}</tbody></table></div>'

    if tool_name == "masscan":
        rows = "".join(
            f'<tr><td><code>{_e(r.get("number",""))}/{_e(r.get("protocol",""))}</code></td><td><span style="color:#00cc66">OPEN</span></td></tr>'
            for r in results
        )
        return f'<div class="table-wrap"><table><thead><tr><th>Port</th><th>Durum</th></tr></thead><tbody>{rows}</tbody></table></div>'

    # Generic
    rows = ""
    for item in results[:100]:
        if isinstance(item, dict):
            rows += "<tr>" + "".join(f"<td>{_e(v)}</td>" for v in list(item.values())[:5]) + "</tr>"
    return f'<div class="table-wrap"><table><tbody>{rows}</tbody></table></div>'


def _tab_analysis(messages: list) -> str:
    if not messages:
        return '<div class="meta" style="padding:20px">AI analizi yok.</div>'
    ai_msgs = [m for m in messages if m.get("role") == "assistant"]
    if not ai_msgs:
        return '<div class="meta" style="padding:20px">AI yanıtı bulunamadı.</div>'
    latest = ai_msgs[-1]["content"]
    safe = _e(latest)
    history_html = ""
    if len(ai_msgs) > 1:
        history_html = '<details style="margin-top:16px"><summary class="meta" style="cursor:pointer">Tüm konuşma geçmişi (' + str(len(messages)) + ' mesaj)</summary><div style="margin-top:12px">'
        for m in messages:
            role_style = "color:#ff2244" if m["role"] == "assistant" else "color:#888"
            history_html += f'<div style="margin-bottom:8px"><span style="{role_style};font-size:0.8em">[{m["role"].upper()}]</span><div class="analysis-block">{_e(m["content"][:500])}{"..." if len(m["content"]) > 500 else ""}</div></div>'
        history_html += '</div></details>'
    return f'<div class="analysis-block">{safe}</div>{history_html}'


def _tab_notes(findings: list, notes: list) -> str:
    items = []
    for f in findings:
        items.append({"ts": f.get("ts", ""), "type": "finding", "risk": f.get("risk", "medium"), "text": f.get("finding", "")})
    for n in notes:
        if isinstance(n, dict):
            items.append({"ts": n.get("ts", ""), "type": "note", "risk": "low", "text": n.get("note", "")})
    items.sort(key=lambda x: x.get("ts", ""), reverse=True)
    if not items:
        return '<div class="meta" style="padding:20px">Not yok.</div>'
    html_items = ""
    for item in items:
        risk = item.get("risk", "medium")
        color = RISK_HEX.get(risk, "#666")
        ts = item.get("ts", "")[:16].replace("T", " ")
        icon = "⚑" if item["type"] == "finding" else "✎"
        html_items += (
            f'<div class="timeline-item">'
            f'<div class="timeline-dot" style="background:{color}"></div>'
            f'<div class="timeline-content">'
            f'<span class="meta">{ts}</span> '
            f'<span class="badge badge-{risk}">{risk.upper()}</span> '
            f'{icon} {_e(item["text"])}'
            f'</div></div>'
        )
    return f'<div class="timeline">{html_items}</div>'


# ─── ANA GENERATOR ───────────────────────────────────────────────────────────

def generate_html_report(memory_data: dict, version: str = "3.0") -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = memory_data.get("target", "unknown")
    safe = re.sub(r"[^\w\-]", "_", target)
    path = REPORTS_DIR / f"phantom_report_{safe}_{ts}.html"

    scan = memory_data.get("scan", {})
    ttps = memory_data.get("ttps", [])
    cves = memory_data.get("cves", [])
    messages = memory_data.get("messages", [])
    findings = memory_data.get("findings", [])
    notes = memory_data.get("notes", [])
    ports = scan.get("ports", [])
    tools_data = memory_data.get("tools", {})

    tabs = [
        ("overview", "Genel Bakış"),
        ("ports", f"Portlar ({len(ports)})"),
        ("ttps", f"TTPs ({len(ttps)})"),
        ("cves", f"CVEs ({len(cves)})"),
        ("tools", f"Araçlar ({sum(len(v) for v in tools_data.values() if isinstance(v, list))})"),
        ("analysis", "AI Analiz"),
        ("notes", f"Notlar ({len(findings) + len(notes)})"),
    ]

    tab_buttons = "".join(
        f'<button class="tab-btn{"  active" if i == 0 else ""}" data-tab="{tid}" onclick="showTab(\'{tid}\')">{tlbl}</button>'
        for i, (tid, tlbl) in enumerate(tabs)
    )

    panels = {
        "overview": _tab_overview(memory_data, version),
        "ports": _tab_ports(ports),
        "ttps": _tab_ttps(ttps),
        "cves": _tab_cves(cves),
        "tools": _tab_tools(tools_data),
        "analysis": _tab_analysis(messages),
        "notes": _tab_notes(findings, notes),
    }

    tab_panels = "".join(
        f'<div id="panel-{tid}" class="tab-panel{"" if i == 0 else " hidden"}">{panels[tid]}</div>'
        for i, (tid, _) in enumerate(tabs)
    )

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Phantom Report — {_e(target)}</title>
<style>
:root{{--bg:#09090e;--card:#111118;--border:#1e1e2e;--red:#ff2244;--orange:#ff6600;--yellow:#ffcc00;--green:#00cc66;--blue:#4488ff;--text:#dde;--dim:#667;--font:'Consolas','Courier New',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;min-height:100vh}}
a{{color:var(--blue);text-decoration:none}}
/* ── HEADER ── */
.header{{background:linear-gradient(135deg,#09090e 0%,#190010 100%);border-bottom:2px solid var(--red);padding:28px 40px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
.header-title{{font-size:1.8em;color:var(--red);letter-spacing:.25em;font-weight:bold}}
.header-meta{{color:var(--dim);font-size:.85em;line-height:1.8}}
.header-meta code{{background:#1a0010;padding:2px 6px;border-radius:3px;color:var(--text)}}
/* ── TABS ── */
.tab-bar{{background:#0d0d16;border-bottom:1px solid var(--border);display:flex;overflow-x:auto;position:sticky;top:0;z-index:100}}
.tab-btn{{background:none;border:none;color:var(--dim);cursor:pointer;font-family:var(--font);font-size:.82em;padding:13px 18px;transition:color .15s,border-bottom .15s;white-space:nowrap;border-bottom:2px solid transparent;letter-spacing:.05em}}
.tab-btn:hover{{color:var(--text)}}
.tab-btn.active{{color:var(--red);border-bottom-color:var(--red)}}
/* ── CONTENT ── */
.content{{max-width:1380px;margin:0 auto;padding:28px 24px}}
.tab-panel.hidden{{display:none}}
/* ── CARDS ── */
.card{{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:20px;margin-bottom:16px}}
.overview-grid{{display:grid;grid-template-columns:220px 1fr;gap:20px;align-items:start}}
@media(max-width:600px){{.overview-grid{{grid-template-columns:1fr}}}}
.risk-card{{text-align:center;padding:24px 16px;position:relative}}
.risk-score-label{{font-size:2.4em;font-weight:bold;margin-top:-48px;position:relative}}
.risk-score-sub{{color:var(--dim);font-size:.78em;margin-top:4px;letter-spacing:.1em}}
.stats-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
.stat-card{{background:var(--card);border:1px solid var(--border);border-radius:5px;padding:14px;text-align:center}}
.stat-card.critical{{border-color:var(--red)}}
.stat-card.high{{border-color:var(--orange)}}
.stat-card.medium{{border-color:var(--yellow)}}
.stat-num{{font-size:2em;font-weight:bold}}
.stat-card.critical .stat-num{{color:var(--red)}}
.stat-card.high .stat-num{{color:var(--orange)}}
.stat-card.medium .stat-num{{color:var(--yellow)}}
.stat-lbl{{color:var(--dim);font-size:.72em;letter-spacing:.08em;margin-top:3px}}
/* ── KILL CHAIN ── */
.kc-timeline{{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}}
.kc-box{{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:6px 8px;text-align:center;min-width:60px;color:var(--dim)}}
.kc-box.active{{background:#1a0010}}
.kc-label{{display:block;font-size:.7em;letter-spacing:.08em}}
.kc-cnt{{display:block;font-size:1.1em;font-weight:bold;margin-top:2px}}
/* ── FINDINGS ── */
.finding-card{{background:var(--card);border:1px solid var(--border);border-radius:5px;padding:12px 16px;margin-bottom:8px;line-height:1.5}}
/* ── SECTION TITLE ── */
.section-title{{color:var(--red);font-size:.95em;text-transform:uppercase;letter-spacing:.15em;border-bottom:1px solid var(--border);padding-bottom:6px;margin-bottom:12px}}
/* ── TOOLBAR ── */
.toolbar{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}}
.search-input{{background:var(--card);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:var(--font);font-size:.82em;padding:7px 12px;outline:none;min-width:200px}}
.search-input:focus{{border-color:var(--red)}}
/* ── RISK FILTER BTNS ── */
.risk-btns{{display:flex;gap:4px;flex-wrap:wrap}}
.risk-btn{{background:var(--card);border:1px solid var(--border);border-radius:4px;color:var(--dim);cursor:pointer;font-family:var(--font);font-size:.78em;padding:5px 10px;transition:.15s}}
.risk-btn:hover{{color:var(--text)}}
.risk-btn.active{{border-color:var(--red);color:var(--red)}}
/* ── TABLE ── */
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.82em}}
th{{background:#160010;color:var(--red);text-align:left;padding:9px 12px;font-weight:400;text-transform:uppercase;font-size:.78em;letter-spacing:.08em;border-bottom:1px solid var(--red);white-space:nowrap}}
th.sortable{{cursor:pointer;user-select:none}}
th.sortable:hover{{color:#fff}}
th.sort-asc::after{{content:" ▲"}}
th.sort-desc::after{{content:" ▼"}}
td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:#131322}}
/* ── BADGES ── */
.badge{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.75em;font-weight:bold;letter-spacing:.04em}}
.badge-critical{{background:rgba(255,34,68,.15);color:var(--red);border:1px solid var(--red)}}
.badge-high{{background:rgba(255,102,0,.15);color:var(--orange);border:1px solid var(--orange)}}
.badge-medium{{background:rgba(255,204,0,.15);color:var(--yellow);border:1px solid var(--yellow)}}
.badge-low{{background:rgba(0,204,102,.15);color:var(--green);border:1px solid var(--green)}}
.tag-msf{{background:rgba(0,204,102,.15);color:var(--green);font-size:.75em;padding:1px 5px;border-radius:3px}}
.tag-poc{{background:rgba(255,204,0,.15);color:var(--yellow);font-size:.75em;padding:1px 5px;border-radius:3px}}
/* ── ANALYSIS ── */
.analysis-block{{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:5px;padding:18px 20px;white-space:pre-wrap;line-height:1.65;font-size:.85em;margin-bottom:12px}}
/* ── TOOL TABS ── */
.tool-tabs{{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:12px}}
.tool-tab-btn{{background:var(--card);border:1px solid var(--border);border-radius:4px;color:var(--dim);cursor:pointer;font-family:var(--font);font-size:.8em;padding:6px 14px;transition:.15s}}
.tool-tab-btn:hover{{color:var(--text)}}
.tool-tab-btn.active{{border-color:var(--red);color:var(--red)}}
/* ── TIMELINE ── */
.timeline{{padding:8px 0}}
.timeline-item{{display:flex;gap:14px;margin-bottom:14px;align-items:flex-start}}
.timeline-dot{{width:10px;height:10px;border-radius:50%;margin-top:3px;flex-shrink:0}}
.timeline-content{{line-height:1.6}}
/* ── META ── */
.meta{{color:var(--dim);font-size:.82em}}
.meta-td{{color:var(--dim);font-size:.85em;padding:7px 12px;width:140px;white-space:nowrap}}
code{{background:#1a1a2e;padding:2px 5px;border-radius:3px;font-family:var(--font)}}
details summary{{outline:none}}
/* ── FOOTER ── */
.footer{{text-align:center;padding:24px;color:var(--dim);font-size:.78em;border-top:1px solid var(--border);margin-top:40px}}
/* ── PRINT ── */
@media print{{.tab-bar,.toolbar{{display:none}}.tab-panel.hidden{{display:block!important}}}}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-title">⬡ PHANTOM</div>
    <div class="meta" style="margin-top:4px">Red Team AI Agent v{_e(version)} — MITRE ATT&CK v16.1</div>
  </div>
  <div class="header-meta">
    <div>Hedef: <code>{_e(target)}</code></div>
    <div>Başlangıç: {_e(memory_data.get("started_at","")[:19].replace("T"," "))}</div>
    <div>Oluşturulma: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  </div>
</div>

<div class="tab-bar">{tab_buttons}</div>

<div class="content">
{tab_panels}
</div>

<div class="footer">
  Phantom v{_e(version)} &nbsp;|&nbsp; MITRE ATT&CK v16.1 &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  &nbsp;|&nbsp; <a href="#" onclick="window.print();return false">Yazdır / PDF</a>
  <br><span style="color:var(--red)">⚠ YALNIZCA YETKİLİ PENTEST ORTAMLARINDA KULLANIN ⚠</span>
</div>

<script>
// ─── TAB NAVİGASYON ───────────────────────────────────────────────────────
function showTab(id){{
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const panel=document.getElementById('panel-'+id);
  const btn=document.querySelector('[data-tab="'+id+'"]');
  if(panel)panel.classList.remove('hidden');
  if(btn)btn.classList.add('active');
}}

// ─── TOOL SUB-TABS ────────────────────────────────────────────────────────
function showToolTab(name){{
  document.querySelectorAll('[id^="tpanel-"]').forEach(p=>p.style.display='none');
  document.querySelectorAll('.tool-tab-btn').forEach(b=>b.classList.remove('active'));
  const p=document.getElementById('tpanel-'+name);
  const b=document.getElementById('ttab-'+name);
  if(p)p.style.display='';
  if(b)b.classList.add('active');
}}

// ─── TABLO FİLTRE ────────────────────────────────────────────────────────
function filterTable(inputId,tableId){{
  const q=document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#'+tableId+' tbody tr').forEach(row=>{{
    row.style.display=row.textContent.toLowerCase().includes(q)?'':'none';
  }});
}}

// ─── RİSK FİLTRE ─────────────────────────────────────────────────────────
function filterRisk(btn,tableId,attr){{
  const risk=btn.dataset.risk;
  btn.closest('.risk-btns').querySelectorAll('.risk-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#'+tableId+' tbody tr').forEach(row=>{{
    row.style.display=(risk==='all'||row.getAttribute(attr)===risk)?'':'none';
  }});
}}

// ─── TAKTİK FİLTRE ───────────────────────────────────────────────────────
function filterTactic(selectId,tableId){{
  const tac=document.getElementById(selectId).value.toLowerCase();
  document.querySelectorAll('#'+tableId+' tbody tr').forEach(row=>{{
    row.style.display=(!tac||row.getAttribute('data-tactic')===document.getElementById(selectId).value)?'':'none';
  }});
}}

// ─── TABLO SIRALAMA ───────────────────────────────────────────────────────
const _sortStates={{}};
function sortTable(tableId,col){{
  const table=document.getElementById(tableId);
  if(!table)return;
  const tbody=table.querySelector('tbody');
  const rows=Array.from(tbody.querySelectorAll('tr'));
  const key=tableId+'_'+col;
  _sortStates[key]=!_sortStates[key];
  const asc=_sortStates[key];
  rows.sort((a,b)=>{{
    const aV=(a.cells[col]?.textContent||'').trim();
    const bV=(b.cells[col]?.textContent||'').trim();
    const aN=parseFloat(aV), bN=parseFloat(bV);
    if(!isNaN(aN)&&!isNaN(bN))return asc?aN-bN:bN-aN;
    return asc?aV.localeCompare(bV):bV.localeCompare(aV);
  }});
  rows.forEach(r=>tbody.appendChild(r));
  table.querySelectorAll('th').forEach((th,i)=>{{
    th.classList.remove('sort-asc','sort-desc');
    if(i===col)th.classList.add(asc?'sort-asc':'sort-desc');
  }});
}}
</script>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path
