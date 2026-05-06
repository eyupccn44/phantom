import socket
import subprocess
import re
import ssl
from dataclasses import dataclass, field
from rich.tree import Tree
from rich.panel import Panel
from rich.console import Console
from rich import box


@dataclass
class TrustRelation:
    source: str
    target: str
    relation_type: str
    evidence: str
    risk: str = "medium"


@dataclass
class TrustNode:
    ip: str
    hostname: str = ""
    os_hint: str = ""
    open_ports: list = field(default_factory=list)
    ssl_names: list = field(default_factory=list)
    relations: list = field(default_factory=list)


def _quick_scan(ip: str) -> TrustNode:
    node = TrustNode(ip=ip)
    key_ports = [21, 22, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 8080, 8443]
    for port in key_ports:
        try:
            s = socket.create_connection((ip, port), timeout=2)
            s.close()
            node.open_ports.append(str(port))
        except Exception:
            pass

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        node.hostname = hostname
    except Exception:
        pass

    if "135" in node.open_ports or "445" in node.open_ports:
        node.os_hint = "Windows"
    elif "22" in node.open_ports and "135" not in node.open_ports:
        node.os_hint = "Linux/Unix"

    for ssl_port in [443, 8443, 3389]:
        if str(ssl_port) in node.open_ports:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, ssl_port), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        san = cert.get("subjectAltName", [])
                        names = [v for _, v in san]
                        subject = cert.get("subject", ())
                        for field_group in subject:
                            for key, val in field_group:
                                if key == "commonName":
                                    names.append(val)
                        node.ssl_names.extend(names)
            except Exception:
                pass

    return node


def _find_trust_relations(nodes: list[TrustNode]) -> list[TrustRelation]:
    relations = []

    # Shared SSL cert names
    name_to_nodes: dict[str, list[str]] = {}
    for node in nodes:
        for name in node.ssl_names:
            clean = name.strip("*. ").lower()
            if len(clean) > 3:
                name_to_nodes.setdefault(clean, []).append(node.ip)

    for name, ips in name_to_nodes.items():
        if len(ips) >= 2:
            for i in range(len(ips)):
                for j in range(i + 1, len(ips)):
                    relations.append(TrustRelation(
                        source=ips[i], target=ips[j],
                        relation_type="SHARED_CERT",
                        evidence=f"Ortak SSL SAN: {name}",
                        risk="medium",
                    ))

    # SMB + same domain hint
    smb_nodes = [n for n in nodes if "445" in n.open_ports]
    if len(smb_nodes) >= 2:
        for i in range(len(smb_nodes)):
            for j in range(i + 1, len(smb_nodes)):
                a, b = smb_nodes[i], smb_nodes[j]
                ip_a = a.ip.rsplit(".", 1)[0]
                ip_b = b.ip.rsplit(".", 1)[0]
                if ip_a == ip_b:
                    relations.append(TrustRelation(
                        source=a.ip, target=b.ip,
                        relation_type="SMB_SUBNET",
                        evidence="Aynı /24 subnet'te SMB açık — relay saldırısı potansiyeli",
                        risk="high",
                    ))

    # RDP açık → WinRM açık → lateral movement path
    for node in nodes:
        if "3389" in node.open_ports and "5985" in node.open_ports:
            relations.append(TrustRelation(
                source=node.ip, target=node.ip,
                relation_type="SELF_LATERAL",
                evidence="RDP + WinRM aynı anda açık — çoklu lateral movement vektörü",
                risk="high",
            ))

    # Hostname domain matching
    domain_nodes: dict[str, list[str]] = {}
    for node in nodes:
        if node.hostname and "." in node.hostname:
            parts = node.hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                domain_nodes.setdefault(domain, []).append(node.ip)

    for domain, ips in domain_nodes.items():
        if len(ips) >= 2:
            for i in range(len(ips)):
                for j in range(i + 1, len(ips)):
                    relations.append(TrustRelation(
                        source=ips[i], target=ips[j],
                        relation_type="SAME_DOMAIN",
                        evidence=f"Ortak domain: {domain}",
                        risk="high",
                    ))

    return relations


def build_trust_graph(targets: list[str], console: Console) -> dict:
    console.print(f"[bold red]🕸  TRUST GRAPH — {len(targets)} hedef taranıyor...[/bold red]")
    nodes = []
    for ip in targets:
        console.print(f"   [dim]→ {ip}...[/dim]", end="")
        node = _quick_scan(ip)
        nodes.append(node)
        console.print(f" [green]{len(node.open_ports)} port, {node.os_hint or '?'}[/green]")

    relations = _find_trust_relations(nodes)

    _print_trust_graph(nodes, relations, console)

    return {
        "nodes": [{"ip": n.ip, "hostname": n.hostname, "os": n.os_hint,
                   "ports": n.open_ports, "ssl_names": n.ssl_names} for n in nodes],
        "relations": [{"source": r.source, "target": r.target,
                       "type": r.relation_type, "evidence": r.evidence,
                       "risk": r.risk} for r in relations],
    }


def _print_trust_graph(nodes: list[TrustNode], relations: list[TrustRelation], console: Console) -> None:
    tree = Tree("[bold red]🕸  MULTI-TARGET TRUST GRAPH[/bold red]", guide_style="dim red")

    risk_color = {"high": "red", "medium": "yellow", "low": "green", "critical": "bold red"}

    for node in nodes:
        label = f"[bold white]{node.ip}[/bold white]"
        if node.hostname:
            label += f"  [dim]({node.hostname})[/dim]"
        if node.os_hint:
            label += f"  [dim cyan]{node.os_hint}[/dim cyan]"
        node_branch = tree.add(label)

        if node.open_ports:
            node_branch.add(f"[dim]Portlar: {', '.join(node.open_ports[:10])}[/dim]")
        if node.ssl_names:
            node_branch.add(f"[dim]SSL Names: {', '.join(set(node.ssl_names)[:3])}[/dim]")

        node_rels = [r for r in relations if r.source == node.ip and r.source != r.target]
        for rel in node_rels:
            col = risk_color.get(rel.risk, "white")
            node_branch.add(
                f"[{col}]⟶ {rel.target}[/{col}]  "
                f"[dim][{rel.relation_type}] {rel.evidence}[/dim]"
            )

    console.print(Panel(tree, border_style="red", box=box.ROUNDED))

    if relations:
        high_risk = [r for r in relations if r.risk == "high"]
        if high_risk:
            console.print(f"\n[bold red]⚡ {len(high_risk)} kritik güven ilişkisi tespit edildi[/bold red]")
            for r in high_risk:
                console.print(f"  [red]• {r.source} ↔ {r.target}: {r.evidence}[/red]")
    else:
        console.print("[dim]Güven ilişkisi tespit edilmedi[/dim]")
