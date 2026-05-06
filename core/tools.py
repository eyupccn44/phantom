import subprocess
import shutil
import re
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Port:
    number: str
    protocol: str
    state: str
    service: str
    version: str


@dataclass
class ScanResult:
    target: str
    host_up: bool = False
    ports: list[Port] = field(default_factory=list)
    os_guess: str = ""
    hostnames: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class WhoisResult:
    target: str
    registrar: str = ""
    org: str = ""
    country: str = ""
    creation_date: str = ""
    expiry_date: str = ""
    nameservers: list[str] = field(default_factory=list)
    raw: str = ""


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_nmap(target: str, fast: bool = False) -> ScanResult:
    result = ScanResult(target=target)

    if not _tool_available("nmap"):
        result.raw = "[!] nmap bulunamadı. Lütfen nmap yükleyin."
        return result

    flags = ["-sV", "--open", "-T4", "-Pn"]
    if fast:
        flags += ["-F"]
    else:
        flags += ["--top-ports", "1000"]

    cmd = ["nmap"] + flags + [target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        output = proc.stdout + proc.stderr
        result.raw = output
        result.host_up = "Host is up" in output or "open" in output
        result.ports = _parse_nmap_ports(output)
        result.os_guess = _parse_nmap_os(output)
        result.hostnames = _parse_nmap_hostnames(output)
    except subprocess.TimeoutExpired:
        result.raw = "[!] nmap zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] nmap hatası: {e}"

    return result


def _parse_nmap_ports(output: str) -> list[Port]:
    ports = []
    pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)"
    )
    for match in pattern.finditer(output):
        ports.append(Port(
            number=match.group(1),
            protocol=match.group(2),
            state=match.group(3),
            service=match.group(4),
            version=match.group(5).strip(),
        ))
    return ports


def _parse_nmap_os(output: str) -> str:
    match = re.search(r"OS details?:\s*(.+)", output)
    if match:
        return match.group(1).strip()
    match = re.search(r"Aggressive OS guesses?:\s*(.+)", output)
    if match:
        return match.group(1).split(",")[0].strip()
    return ""


def _parse_nmap_hostnames(output: str) -> list[str]:
    names = []
    match = re.search(r"Nmap scan report for (.+)", output)
    if match:
        raw = match.group(1).strip()
        parts = raw.split(" ")
        for p in parts:
            p = p.strip("()")
            if p:
                names.append(p)
    return names


def run_whois(target: str) -> WhoisResult:
    result = WhoisResult(target=target)

    if not _tool_available("whois"):
        result.raw = "[!] whois bulunamadı."
        return result

    try:
        proc = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout
        result.raw = output
        result.registrar = _whois_field(output, ["Registrar:", "registrar:"])
        result.org = _whois_field(output, ["Registrant Organization:", "org:", "OrgName:"])
        result.country = _whois_field(output, ["Registrant Country:", "country:", "Country:"])
        result.creation_date = _whois_field(output, ["Creation Date:", "created:", "Created On:"])
        result.expiry_date = _whois_field(output, ["Expiry Date:", "expires:", "Registry Expiry Date:"])
        result.nameservers = _whois_nameservers(output)
    except subprocess.TimeoutExpired:
        result.raw = "[!] whois zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] whois hatası: {e}"

    return result


def _whois_field(text: str, keys: list[str]) -> str:
    for key in keys:
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*(.+)", re.MULTILINE | re.IGNORECASE)
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return ""


def _whois_nameservers(text: str) -> list[str]:
    pattern = re.compile(r"^\s*Name Server:\s*(.+)", re.MULTILINE | re.IGNORECASE)
    return [m.group(1).strip().lower() for m in pattern.finditer(text)]


def run_ping(target: str) -> bool:
    """ICMP ping + TCP port knock. ICMP engellenmiş hedeflerde de çalışır."""
    import socket

    # 1. ICMP ping
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            capture_output=True,
            timeout=6,
        )
        if proc.returncode == 0:
            return True
    except Exception:
        pass

    # 2. TCP knock — yaygın portlara bağlan, biri açıksa host UP
    for port in (80, 443, 22, 8080, 445, 3389, 21, 23, 8443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass

    return False


# ─── YENİ ARAÇ DATACLASS'LARI ────────────────────────────────────────────────

@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str = ""
    cve_id: str = ""

@dataclass
class NucleiResult:
    target: str
    findings: list = field(default_factory=list)
    raw: str = ""

@dataclass
class MasscanResult:
    target: str
    ports: list = field(default_factory=list)
    raw: str = ""

@dataclass
class NiktoFinding:
    uri: str
    description: str
    osvdb: str = ""

@dataclass
class NiktoResult:
    target: str
    findings: list = field(default_factory=list)
    raw: str = ""

@dataclass
class GobusterFinding:
    path: str
    status: int
    size: int = 0

@dataclass
class GobusterResult:
    target: str
    findings: list = field(default_factory=list)
    raw: str = ""

@dataclass
class DnsReconResult:
    target: str
    records: list = field(default_factory=list)
    raw: str = ""


# ─── YENİ ARAÇ FONKSİYONLARI ─────────────────────────────────────────────────

def run_nuclei(target: str, severity: str = "medium,high,critical", templates: str = "") -> NucleiResult:
    result = NucleiResult(target=target)
    if not _tool_available("nuclei"):
        result.raw = "[!] nuclei bulunamadı — brew install nuclei"
        return result
    cmd = ["nuclei", "-u", target, "-severity", severity, "-json", "-silent", "-no-color", "-timeout", "10"]
    if templates:
        cmd += ["-t", templates]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                info = d.get("info", {})
                clf = info.get("classification", {}) or {}
                cve_list = clf.get("cve-id", []) or []
                result.findings.append(NucleiFinding(
                    template_id=d.get("template-id", ""),
                    name=info.get("name", ""),
                    severity=info.get("severity", "info"),
                    matched_at=d.get("matched-at", target),
                    description=info.get("description", ""),
                    cve_id=cve_list[0] if cve_list else "",
                ))
            except Exception:
                pass
        result.raw = proc.stdout[:3000]
    except subprocess.TimeoutExpired:
        result.raw = "[!] nuclei zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] nuclei hatası: {e}"
    return result


def run_masscan(target: str, ports: str = "1-10000", rate: int = 1000) -> MasscanResult:
    result = MasscanResult(target=target)
    if not _tool_available("masscan"):
        result.raw = "[!] masscan bulunamadı — brew install masscan"
        return result
    import tempfile, os
    tmp = tempfile.mktemp(suffix=".json")
    cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}", "-oJ", tmp]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        result.raw = (proc.stdout + proc.stderr)[:2000]
        if Path(tmp).exists():
            raw = Path(tmp).read_text(encoding="utf-8").strip()
            os.unlink(tmp)
            if raw:
                try:
                    entries = json.loads(raw)
                    for entry in entries:
                        for p in entry.get("ports", []):
                            result.ports.append(Port(
                                number=str(p.get("port", "")),
                                protocol=p.get("proto", "tcp"),
                                state=p.get("status", "open"),
                                service="",
                                version="",
                            ))
                except Exception:
                    pass
    except subprocess.TimeoutExpired:
        result.raw = "[!] masscan zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] masscan hatası: {e}"
    return result


def run_nikto(target: str, port: int = 80, ssl: bool = False) -> NiktoResult:
    result = NiktoResult(target=target)
    if not _tool_available("nikto"):
        result.raw = "[!] nikto bulunamadı — brew install nikto"
        return result
    scheme = "https" if ssl else "http"
    url = f"{scheme}://{target}:{port}"
    cmd = ["nikto", "-h", url, "-Format", "json", "-nointeractive", "-maxtime", "120"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        result.raw = proc.stdout[:3000]
        try:
            data = json.loads(proc.stdout)
            for item in data.get("vulnerabilities", []):
                result.findings.append(NiktoFinding(
                    uri=item.get("url", "/"),
                    description=item.get("msg", ""),
                    osvdb=str(item.get("osvdbid", "")),
                ))
        except Exception:
            for line in proc.stdout.splitlines():
                if line.startswith("+ ") and len(line) > 4:
                    result.findings.append(NiktoFinding(uri="/", description=line[2:].strip()))
    except subprocess.TimeoutExpired:
        result.raw = "[!] nikto zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] nikto hatası: {e}"
    return result


_GOBUSTER_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/local/share/wordlists/dirb/common.txt",
    "/opt/homebrew/share/wordlists/dirb/common.txt",
]

def run_gobuster(target: str, port: int = 80, ssl: bool = False,
                 wordlist: str = "", extensions: str = "php,html,txt,js") -> GobusterResult:
    result = GobusterResult(target=target)
    if not _tool_available("gobuster"):
        result.raw = "[!] gobuster bulunamadı — brew install gobuster"
        return result
    wl = wordlist or next((w for w in _GOBUSTER_WORDLISTS if Path(w).exists()), "")
    if not wl:
        result.raw = "[!] Wordlist bulunamadı. Lütfen --wordlist belirtin ya da dirb yükleyin."
        return result
    scheme = "https" if ssl else "http"
    url = f"{scheme}://{target}:{port}"
    cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-x", extensions,
           "-q", "--no-error", "-t", "20", "--timeout", "5s"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result.raw = proc.stdout[:3000]
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("="):
                continue
            m = re.search(r"(\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                size_m = re.search(r"\[Size:\s*(\d+)\]", line)
                result.findings.append(GobusterFinding(
                    path=m.group(1),
                    status=int(m.group(2)),
                    size=int(size_m.group(1)) if size_m else 0,
                ))
    except subprocess.TimeoutExpired:
        result.raw = "[!] gobuster zaman aşımına uğradı."
    except Exception as e:
        result.raw = f"[!] gobuster hatası: {e}"
    return result


def run_dnsrecon(target: str) -> DnsReconResult:
    result = DnsReconResult(target=target)
    if _tool_available("dnsrecon"):
        import tempfile, os
        tmp = tempfile.mktemp(suffix=".json")
        cmd = ["dnsrecon", "-d", target, "-t", "std", "-j", tmp]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            result.raw = proc.stdout[:3000]
            if Path(tmp).exists():
                raw = Path(tmp).read_text(encoding="utf-8")
                os.unlink(tmp)
                records = json.loads(raw)
                for r in records:
                    if isinstance(r, dict):
                        result.records.append({
                            "type": r.get("type", ""),
                            "name": r.get("name", ""),
                            "address": r.get("address", r.get("strings", "")),
                        })
        except subprocess.TimeoutExpired:
            result.raw = "[!] dnsrecon zaman aşımına uğradı."
        except Exception as e:
            result.raw = f"[!] dnsrecon hatası: {e}"
        return result
    # dig fallback
    return _run_dig_fallback(target)


def _run_dig_fallback(target: str) -> DnsReconResult:
    result = DnsReconResult(target=target)
    if not _tool_available("dig"):
        result.raw = "[!] dig/dnsrecon bulunamadı"
        return result
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            proc = subprocess.run(
                ["dig", "+short", rtype, target],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    result.records.append({"type": rtype, "name": target, "address": line})
        except Exception:
            pass
    result.raw = f"dig fallback — {len(result.records)} kayıt"
    return result


# ─── LLM FORMAT FONKSİYONLARI ────────────────────────────────────────────────

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

def format_nuclei_for_llm(result: NucleiResult) -> str:
    if not result.findings:
        return f"NUCLEI ({result.target}): Zafiyet bulunamadı"
    sorted_f = sorted(result.findings,
                      key=lambda x: _SEV_ORDER.index(x.severity) if x.severity in _SEV_ORDER else 5)
    lines = [f"NUCLEI FINDINGS ({len(result.findings)}):"]
    for f in sorted_f:
        lines.append(f"  [{f.severity.upper()}] {f.template_id} — {f.name} @ {f.matched_at}")
        if f.cve_id:
            lines.append(f"         CVE: {f.cve_id}")
        if f.description:
            lines.append(f"         {f.description[:100]}")
    return "\n".join(lines)


def format_nikto_for_llm(result: NiktoResult) -> str:
    if not result.findings:
        return f"NIKTO ({result.target}): Bulgu yok"
    lines = [f"NIKTO WEB SCANNER ({len(result.findings)} bulgu):"]
    for f in result.findings[:20]:
        lines.append(f"  [{f.uri}] {f.description[:120]}")
    return "\n".join(lines)


def format_gobuster_for_llm(result: GobusterResult) -> str:
    if not result.findings:
        return f"GOBUSTER ({result.target}): Endpoint bulunamadı"
    lines = [f"GOBUSTER DIR ENUM ({len(result.findings)} yol):"]
    for f in sorted(result.findings, key=lambda x: x.status)[:30]:
        lines.append(f"  [{f.status}] {f.path} ({f.size} byte)")
    return "\n".join(lines)


def format_dnsrecon_for_llm(result: DnsReconResult) -> str:
    if not result.records:
        return f"DNS ({result.target}): Kayıt bulunamadı"
    lines = [f"DNS RECORDS ({len(result.records)}):"]
    for r in result.records[:25]:
        lines.append(f"  {r.get('type','?'):6} {r.get('name','')} → {r.get('address','')}")
    return "\n".join(lines)


def format_masscan_for_llm(result: MasscanResult) -> str:
    if not result.ports:
        return f"MASSCAN ({result.target}): Port bulunamadı"
    lines = [f"MASSCAN PORTS ({len(result.ports)} açık):"]
    for p in result.ports[:50]:
        lines.append(f"  {p.number}/{p.protocol}")
    return "\n".join(lines)


def format_scan_for_llm(scan: ScanResult, whois: WhoisResult | None = None) -> str:
    lines = [f"TARGET: {scan.target}"]
    lines.append(f"HOST STATUS: {'UP' if scan.host_up else 'DOWN/FILTERED'}")

    if scan.hostnames:
        lines.append(f"HOSTNAMES: {', '.join(scan.hostnames)}")

    if scan.os_guess:
        lines.append(f"OS GUESS: {scan.os_guess}")

    if scan.ports:
        lines.append(f"\nOPEN PORTS ({len(scan.ports)} found):")
        for p in scan.ports:
            lines.append(f"  {p.number}/{p.protocol}  {p.service}  {p.version}")
    else:
        lines.append("\nOPEN PORTS: none detected")

    if whois and whois.org:
        lines.append(f"\nWHOIS INFO:")
        if whois.registrar:
            lines.append(f"  Registrar: {whois.registrar}")
        if whois.org:
            lines.append(f"  Org: {whois.org}")
        if whois.country:
            lines.append(f"  Country: {whois.country}")
        if whois.nameservers:
            lines.append(f"  Nameservers: {', '.join(whois.nameservers[:3])}")

    return "\n".join(lines)
