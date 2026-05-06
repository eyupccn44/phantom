from datetime import datetime
from pathlib import Path
import json

REPORTS_DIR = Path(__file__).parent.parent / "reports"

RISK_COLORS = {
    "critical": "#ff2244",
    "high":     "#ff6600",
    "medium":   "#ffcc00",
    "low":      "#00cc66",
}

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def _ports_section(ports: list) -> str:
    if not ports:
        return ""
    rows = ""
    for p in ports:
        rows += (
            "<tr>"
            f"<td><code>{p.get('number','')}/{p.get('protocol','tcp')}</code></td>"
            f"<td>{p.get('service','')}</td>"
            f"<td>{p.get('version','')}</td>"
            "<td><span style='color:#00cc66'>OPEN</span></td>"
            "</tr>"
        )
    return (
        '<div class="section">'
        '<div class="section-title">Açık Portlar</div>'
        '<div class="card"><table>'
        "<thead><tr><th>Port</th><th>Servis</th><th>Versiyon</th><th>Durum</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table></div></div>"
    )


def _ttps_section(ttps: list) -> str:
    if not ttps:
        return ""
    rows = ""
    for t in ttps:
        risk = t.get("risk", "low")
        apts = ", ".join(t.get("apt_groups", []))
        tools = ", ".join(t.get("tools", []))
        rows += (
            "<tr>"
            f"<td><code>{t.get('tid','')}</code></td>"
            f"<td>{t.get('name','')}</td>"
            f"<td>{t.get('tactic','')}</td>"
            f'<td><span class="badge badge-{risk}">{risk.upper()}</span></td>'
            f"<td><code>{t.get('port','')}</code> {t.get('service','')}</td>"
            f"<td><small>{apts}</small></td>"
            "</tr>"
        )
    return (
        '<div class="section">'
        '<div class="section-title">MITRE ATT&amp;CK TTPs</div>'
        '<div class="card"><table>'
        "<thead><tr><th>ID</th><th>Teknik</th><th>Taktik</th><th>Risk</th><th>Port/Servis</th><th>APT Grupları</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table></div></div>"
    )


def _cves_section(cves: list) -> str:
    if not cves:
        return ""
    rows = ""
    for c in cves:
        cvss = c.get("cvss", 0)
        if cvss >= 9.0:
            badge = '<span class="badge badge-critical">CRITICAL</span>'
        elif cvss >= 7.0:
            badge = '<span class="badge badge-high">HIGH</span>'
        elif cvss >= 4.0:
            badge = '<span class="badge badge-medium">MEDIUM</span>'
        else:
            badge = '<span class="badge badge-low">LOW</span>'
        extras = ""
        if c.get("metasploit"):
            extras += ' <code style="color:#00cc66">[MSF]</code>'
        if c.get("poc"):
            extras += ' <code style="color:#ffcc00">[PoC]</code>'
        rows += (
            "<tr>"
            f"<td><code>{c.get('id','')}</code></td>"
            f"<td>{badge}</td>"
            f"<td>{c.get('cvss','')}</td>"
            f"<td>{c.get('service','')}</td>"
            f"<td>{c.get('description','')[:80]}{extras}</td>"
            "</tr>"
        )
    return (
        '<div class="section">'
        '<div class="section-title">CVE İstihbaratı</div>'
        '<div class="card"><table>'
        "<thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Servis</th><th>Açıklama</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table></div></div>"
    )


def _analysis_section(messages: list) -> str:
    last = ""
    for m in reversed(messages):
        if m.get("role") == "assistant":
            last = m.get("content", "")
            break
    if not last:
        return ""
    safe = last.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        '<div class="section">'
        '<div class="section-title">AI Analiz</div>'
        f'<div class="analysis">{safe}</div>'
        "</div>"
    )


def _findings_section(findings: list) -> str:
    if not findings:
        return ""
    items = ""
    for f in findings:
        risk = f.get("risk", "medium")
        color = RISK_COLORS.get(risk, "#666")
        text = f.get("finding", f.get("title", f.get("detail", "")))
        ts = f.get("ts", "")[:16].replace("T", " ")
        items += (
            f'<div class="card" style="border-left:3px solid {color}">'
            f'<span class="badge badge-{risk}">{risk.upper()}</span> '
            f"{text}"
            f'<br><span class="meta">{ts}</span>'
            "</div>"
        )
    return (
        '<div class="section">'
        '<div class="section-title">Bulgular</div>'
        f"{items}"
        "</div>"
    )


def _notes_section(notes: list) -> str:
    if not notes:
        return ""
    items = ""
    for n in notes:
        if isinstance(n, dict):
            text = n.get("note", "")
            ts = n.get("ts", "")[:16].replace("T", " ")
            items += f"<li>{text} <span class='meta'>— {ts}</span></li>"
        else:
            items += f"<li>{n}</li>"
    return (
        '<div class="section">'
        '<div class="section-title">Notlar</div>'
        f'<div class="card"><ul style="padding-left:20px;line-height:2">{items}</ul></div>'
        "</div>"
    )


def _graph_section(ttps: list, target: str) -> str:
    if not ttps:
        return ""

    tactic_map: dict[str, list] = {}
    for t in ttps:
        tactic = t.get("tactic", "Unknown")
        tactic_map.setdefault(tactic, []).append(t)

    ordered = [p for p in KILL_CHAIN_ORDER if p in tactic_map]
    for k in tactic_map:
        if k not in ordered:
            ordered.append(k)

    if not ordered:
        return ""

    nodes_js = []
    edges_js = []
    node_html = []

    node_id = 0
    phase_nodes: dict[str, list[int]] = {}

    for phase in ordered:
        items = tactic_map[phase]
        phase_nodes[phase] = []
        for t in items:
            risk = t.get("risk", "low")
            color = RISK_COLORS.get(risk, "#666")
            nid = node_id
            nodes_js.append({
                "id": nid,
                "label": t.get("tid", ""),
                "name": t.get("name", ""),
                "phase": phase,
                "risk": risk,
                "color": color,
                "port": t.get("port", ""),
                "service": t.get("service", ""),
            })
            phase_nodes[phase].append(nid)
            node_id += 1

    prev_phase_nodes: list[int] = []
    for phase in ordered:
        curr = phase_nodes[phase]
        if prev_phase_nodes:
            for src in prev_phase_nodes[-1:]:
                for dst in curr[:1]:
                    edges_js.append({"from": src, "to": dst})
        prev_phase_nodes = curr

    nodes_json = json.dumps(nodes_js)
    edges_json = json.dumps(edges_js)
    phases_json = json.dumps(ordered)

    return f"""
<div class="section">
  <div class="section-title">Attack Path Graph — Kill Chain</div>
  <div class="card" style="padding:0;overflow:hidden">
    <canvas id="attackGraph" style="width:100%;height:420px;background:#0a0a0f;display:block"></canvas>
  </div>
</div>
<script>
(function(){{
  const nodes = {nodes_json};
  const edges = {edges_json};
  const phases = {phases_json};
  const canvas = document.getElementById('attackGraph');
  const ctx = canvas.getContext('2d');

  function resize() {{
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    draw();
  }}

  const COLORS = {{critical:'#ff2244',high:'#ff6600',medium:'#ffcc00',low:'#00cc66'}};
  const PAD = 60;

  function draw() {{
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0,0,W,H);

    if (!phases.length) return;

    const colW = (W - PAD*2) / phases.length;
    const phaseX = {{}};
    phases.forEach((p,i) => {{ phaseX[p] = PAD + colW*i + colW/2; }});

    const nodePos = {{}};
    phases.forEach(p => {{
      const pnodes = nodes.filter(n => n.phase === p);
      const x = phaseX[p];
      pnodes.forEach((n,i) => {{
        const y = PAD + 60 + (H - PAD*2 - 60) / (pnodes.length+1) * (i+1);
        nodePos[n.id] = {{x,y}};
      }});
    }});

    // phase labels
    ctx.font = '10px Consolas,monospace';
    ctx.textAlign = 'center';
    phases.forEach(p => {{
      ctx.fillStyle = '#ff2244';
      ctx.fillText(p.toUpperCase(), phaseX[p], PAD + 16);
      ctx.strokeStyle = '#1e1e2e';
      ctx.beginPath();
      ctx.moveTo(phaseX[p], PAD + 22);
      ctx.lineTo(phaseX[p], H - PAD);
      ctx.stroke();
    }});

    // edges
    ctx.strokeStyle = '#2a2a3e';
    ctx.lineWidth = 1.5;
    edges.forEach(e => {{
      const a = nodePos[e.from], b = nodePos[e.to];
      if (!a||!b) return;
      ctx.beginPath();
      const mx = (a.x+b.x)/2;
      ctx.moveTo(a.x,a.y);
      ctx.bezierCurveTo(mx,a.y,mx,b.y,b.x,b.y);
      ctx.stroke();
      // arrowhead
      const angle = Math.atan2(b.y-a.y, b.x-a.x);
      ctx.fillStyle='#2a2a3e';
      ctx.beginPath();
      ctx.moveTo(b.x,b.y);
      ctx.lineTo(b.x-10*Math.cos(angle-0.4),b.y-10*Math.sin(angle-0.4));
      ctx.lineTo(b.x-10*Math.cos(angle+0.4),b.y-10*Math.sin(angle+0.4));
      ctx.fill();
    }});

    // nodes
    nodes.forEach(n => {{
      const pos = nodePos[n.id];
      if (!pos) return;
      const col = COLORS[n.risk] || '#666';
      const r = 22;
      // glow
      const grad = ctx.createRadialGradient(pos.x,pos.y,0,pos.x,pos.y,r*2);
      grad.addColorStop(0, col+'44');
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(pos.x,pos.y,r*2,0,Math.PI*2);
      ctx.fill();
      // circle
      ctx.strokeStyle = col;
      ctx.lineWidth = 2;
      ctx.fillStyle = '#12121a';
      ctx.beginPath();
      ctx.arc(pos.x,pos.y,r,0,Math.PI*2);
      ctx.fill();
      ctx.stroke();
      // tid label
      ctx.fillStyle = col;
      ctx.font = 'bold 9px Consolas,monospace';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, pos.x, pos.y+3);
      // name below
      ctx.fillStyle = '#aaa';
      ctx.font = '8px Consolas,monospace';
      const shortName = n.name.length>16 ? n.name.slice(0,14)+'..' : n.name;
      ctx.fillText(shortName, pos.x, pos.y+r+12);
      if (n.port) {{
        ctx.fillStyle='#444';
        ctx.fillText(':'+n.port, pos.x, pos.y+r+22);
      }}
    }});
  }}

  window.addEventListener('resize', resize);
  resize();
}})();
</script>"""


def generate_html_report(memory_data: dict, version: str = "2.0") -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = memory_data.get("target", "unknown")
    safe = target.replace(".", "_").replace("/", "_")
    path = REPORTS_DIR / f"phantom_report_{safe}_{ts}.html"

    scan = memory_data.get("scan", {})
    whois = memory_data.get("whois", {})
    ports = scan.get("ports", [])
    ttps = memory_data.get("ttps", [])
    cves = memory_data.get("cves", [])
    messages = memory_data.get("messages", [])
    findings = memory_data.get("findings", [])
    notes = memory_data.get("notes", [])

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in ttps:
        r = t.get("risk", "low")
        risk_counts[r] = risk_counts.get(r, 0) + 1

    host_status = (
        '<span style="color:#00cc66">● ÇEVRİMİÇİ</span>'
        if scan.get("host_up")
        else '<span style="color:#ff2244">● ÇEVRİMDIŞI</span>'
    )

    os_row = ""
    if scan.get("os_guess"):
        os_row = f'<tr><td class="meta">OS</td><td>{scan["os_guess"]}</td></tr>'

    hn_row = ""
    if scan.get("hostnames"):
        hn_row = f'<tr><td class="meta">Hostnames</td><td>{", ".join(scan["hostnames"])}</td></tr>'

    org_row = ""
    if whois.get("org"):
        org_row = f'<tr><td class="meta">Organizasyon</td><td>{whois["org"]}</td></tr>'

    country_row = ""
    if whois.get("country"):
        country_row = f'<tr><td class="meta">Ülke</td><td>{whois["country"]}</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Report — {target}</title>
<style>
  :root {{
    --bg: #0a0a0f;
    --card: #12121a;
    --border: #1e1e2e;
    --red: #ff2244;
    --orange: #ff6600;
    --yellow: #ffcc00;
    --green: #00cc66;
    --text: #e0e0e0;
    --dim: #666;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Consolas', 'Courier New', monospace; font-size: 14px; }}
  .header {{ background: linear-gradient(135deg, #0a0a0f 0%, #1a0010 100%); border-bottom: 1px solid var(--red); padding: 40px; text-align: center; }}
  .header h1 {{ font-size: 2.5em; color: var(--red); letter-spacing: 0.3em; text-transform: uppercase; }}
  .header .subtitle {{ color: var(--dim); margin-top: 8px; font-size: 0.9em; }}
  .header .target {{ color: var(--text); font-size: 1.2em; margin-top: 16px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
  .section {{ margin-bottom: 30px; }}
  .section-title {{ color: var(--red); font-size: 1.1em; text-transform: uppercase; letter-spacing: 0.2em; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 20px; margin-bottom: 16px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 20px; text-align: center; }}
  .stat-card .number {{ font-size: 2.5em; font-weight: bold; }}
  .stat-card .label {{ color: var(--dim); font-size: 0.85em; margin-top: 4px; }}
  .critical {{ color: var(--red); border-color: var(--red) !important; }}
  .high {{ color: var(--orange); border-color: var(--orange) !important; }}
  .medium {{ color: var(--yellow); border-color: var(--yellow) !important; }}
  .low {{ color: var(--green); border-color: var(--green) !important; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #1a0010; color: var(--red); text-align: left; padding: 10px 12px; font-weight: normal; text-transform: uppercase; font-size: 0.8em; letter-spacing: 0.1em; border-bottom: 1px solid var(--red); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #151520; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
  .badge-critical {{ background: rgba(255,34,68,0.2); color: var(--red); border: 1px solid var(--red); }}
  .badge-high {{ background: rgba(255,102,0,0.2); color: var(--orange); border: 1px solid var(--orange); }}
  .badge-medium {{ background: rgba(255,204,0,0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
  .badge-low {{ background: rgba(0,204,102,0.2); color: var(--green); border: 1px solid var(--green); }}
  .analysis {{ background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--red); border-radius: 4px; padding: 20px; white-space: pre-wrap; line-height: 1.6; font-size: 0.9em; }}
  .meta {{ color: var(--dim); font-size: 0.85em; }}
  .footer {{ text-align: center; padding: 30px; color: var(--dim); font-size: 0.8em; border-top: 1px solid var(--border); margin-top: 40px; }}
  code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
</style>
</head>
<body>

<div class="header">
  <h1>⬡ PHANTOM</h1>
  <div class="subtitle">Red Team AI Agent v{version} — MITRE ATT&CK v16.1</div>
  <div class="target">Target: <code>{target}</code></div>
  <div class="meta" style="margin-top:8px">
    Scope: {memory_data.get('scope','N/A')} &nbsp;|&nbsp;
    Started: {memory_data.get('started_at','')[:19].replace('T',' ')} &nbsp;|&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </div>
</div>

<div class="container">

  <div class="section">
    <div class="section-title">Risk Özeti</div>
    <div class="grid">
      <div class="stat-card critical"><div class="number">{risk_counts.get('critical',0)}</div><div class="label">CRITICAL TTPs</div></div>
      <div class="stat-card high"><div class="number">{risk_counts.get('high',0)}</div><div class="label">HIGH TTPs</div></div>
      <div class="stat-card medium"><div class="number">{risk_counts.get('medium',0)}</div><div class="label">MEDIUM TTPs</div></div>
      <div class="stat-card" style="border-color:#333"><div class="number">{len(cves)}</div><div class="label">CVEs MATCHED</div></div>
      <div class="stat-card" style="border-color:#333"><div class="number">{len(ports)}</div><div class="label">OPEN PORTS</div></div>
      <div class="stat-card" style="border-color:#333"><div class="number">{len(findings)}</div><div class="label">FINDINGS</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Hedef Bilgisi</div>
    <div class="card">
      <table>
        <tr><td class="meta" width="160">Hedef</td><td><code>{target}</code></td></tr>
        <tr><td class="meta">Durum</td><td>{host_status}</td></tr>
        {os_row}
        {hn_row}
        {org_row}
        {country_row}
      </table>
    </div>
  </div>

  {_ports_section(ports)}
  {_graph_section(ttps, target)}
  {_ttps_section(ttps)}
  {_cves_section(cves)}
  {_analysis_section(messages)}
  {_findings_section(findings)}
  {_notes_section(notes)}

</div>

<div class="footer">
  Phantom Red Team AI Agent v{version} &nbsp;|&nbsp; MITRE ATT&CK v16.1 &nbsp;|&nbsp;
  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  <br><span style="color:#ff2244">⚠ YALNIZCA YETKİLİ PENTEST ORTAMLARINDA KULLANIN ⚠</span>
</div>

</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path
