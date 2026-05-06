import subprocess
import shutil
import re
from dataclasses import dataclass, field


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
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            capture_output=True,
            timeout=10,
        )
        return proc.returncode == 0
    except Exception:
        return False


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
