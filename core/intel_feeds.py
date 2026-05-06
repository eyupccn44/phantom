"""
Phantom — Canlı İstihbarat Beslemeleri
API anahtarı gerektirmeden dış kaynaklardan güvenlik verisi çeker.
"""
import json
import re
import urllib.request
import urllib.error
from functools import lru_cache
from pathlib import Path

CACHE_DIR = Path(__file__).parent.parent / ".cache"
TIMEOUT = 15
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; security-research/1.0)",
    "Accept": "application/json, text/html, */*",
}


def _get(url: str, timeout: int = TIMEOUT) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"__ERROR__: {e}"


def _cache_get(key: str, url: str, max_age_hours: int = 6) -> str:
    CACHE_DIR.mkdir(exist_ok=True)
    cache_file = CACHE_DIR / f"{key}.json"
    import time
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < max_age_hours * 3600:
            return cache_file.read_text(encoding="utf-8")
    data = _get(url)
    if not data.startswith("__ERROR__"):
        cache_file.write_text(data, encoding="utf-8")
    return data


# ─── CISA KEV ────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> list[dict]:
    """CISA Known Exploited Vulnerabilities — aktif istismar edilen CVE'ler."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    raw = _cache_get("cisa_kev", url, max_age_hours=12)
    if raw.startswith("__ERROR__"):
        return []
    try:
        data = json.loads(raw)
        return data.get("vulnerabilities", [])
    except Exception:
        return []


def check_cisa_kev(cve_id: str) -> dict | None:
    """Verilen CVE'nin CISA KEV listesinde olup olmadığını kontrol et."""
    vulns = fetch_cisa_kev()
    for v in vulns:
        if v.get("cveID", "").upper() == cve_id.upper():
            return v
    return None


def get_cisa_kev_for_service(service_name: str) -> list[dict]:
    """Bir servis adına göre CISA KEV'den ilgili CVE'leri döndür."""
    vulns = fetch_cisa_kev()
    service_lower = service_name.lower()
    matches = []
    for v in vulns:
        product = (v.get("product", "") + " " + v.get("vendorProject", "")).lower()
        if service_lower in product or any(w in product for w in service_lower.split()):
            matches.append(v)
    return matches[:10]


# ─── CIRCL CVE ───────────────────────────────────────────────────────────────

def lookup_cve_circl(cve_id: str) -> dict:
    """CIRCL üzerinden CVE detayları — ücretsiz, anahtarsız."""
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    raw = _cache_get(f"circl_{cve_id}", url, max_age_hours=24)
    if raw.startswith("__ERROR__"):
        return {"error": raw}
    try:
        return json.loads(raw)
    except Exception:
        return {"error": "parse hatası"}


def search_cve_circl_vendor(vendor: str, product: str) -> list[dict]:
    """Vendor/product'a göre CVE ara."""
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    raw = _cache_get(f"circl_search_{vendor}_{product}", url, max_age_hours=6)
    if raw.startswith("__ERROR__"):
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else data.get("results", [])
    except Exception:
        return []


# ─── NVD ─────────────────────────────────────────────────────────────────────

def search_nvd(keyword: str, results: int = 10) -> list[dict]:
    """NVD CVE arama — anahtar gerektirmez (rate limit var)."""
    encoded = urllib.request.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage={results}"
    raw = _cache_get(f"nvd_{keyword}", url, max_age_hours=6)
    if raw.startswith("__ERROR__"):
        return []
    try:
        data = json.loads(raw)
        items = data.get("vulnerabilities", [])
        result = []
        for item in items:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
                metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) or
                metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            )
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            result.append({
                "id": cve.get("id", ""),
                "description": desc[:200],
                "cvss": cvss_data.get("baseScore", 0),
                "severity": cvss_data.get("baseSeverity", ""),
                "published": cve.get("published", "")[:10],
            })
        return result
    except Exception:
        return []


# ─── MITRE ATT&CK LIVE ───────────────────────────────────────────────────────

def fetch_mitre_technique(tid: str) -> dict:
    """MITRE ATT&CK CTI GitHub'dan canlı teknik verisi çek."""
    url = f"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--{_tid_to_stix(tid)}.json"
    raw = _get(url, timeout=10)
    if raw.startswith("__ERROR__"):
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def search_mitre_live(query: str) -> list[dict]:
    """MITRE ATT&CK canlı arama — GitHub CTI üzerinden."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    raw = _cache_get("mitre_attack_full", url, max_age_hours=24)
    if raw.startswith("__ERROR__"):
        return []
    try:
        data = json.loads(raw)
        objects = data.get("objects", [])
        query_lower = query.lower()
        results = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            if query_lower in name or query_lower in desc:
                ext = obj.get("external_references", [{}])[0]
                results.append({
                    "tid": ext.get("external_id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:300],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "kill_chain": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
                })
        return results[:10]
    except Exception:
        return []


def _tid_to_stix(tid: str) -> str:
    KNOWN = {
        "T1190": "3f886f2a-1ed1-4f88-a5c5-51568ee7dab8",
        "T1059.001": "970a3432-3237-47ad-bcca-7d8cbb217736",
        "T1078": "b17a1a56-e99c-403c-8948-561df0cffe81",
    }
    return KNOWN.get(tid, tid.lower().replace(".", "_"))


# ─── EXPLOIT-DB ───────────────────────────────────────────────────────────────

def search_exploitdb(query: str) -> list[dict]:
    """Exploit-DB arama (web scraping)."""
    encoded = urllib.request.quote(query)
    url = f"https://www.exploit-db.com/search?q={encoded}&type=&platform=&highlighted="
    req = urllib.request.Request(url, headers={
        **HEADERS,
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            results = []
            for item in data.get("data", [])[:8]:
                results.append({
                    "id": item.get("id", ""),
                    "title": item.get("description", ""),
                    "type": item.get("type", {}).get("name", ""),
                    "platform": item.get("platform", {}).get("name", ""),
                    "date": item.get("date_published", ""),
                    "url": f"https://www.exploit-db.com/exploits/{item.get('id','')}",
                })
            return results
    except Exception:
        return []


# ─── GITHUB PoC ARAŞTIRMA ────────────────────────────────────────────────────

def search_github_pocs(cve_id: str) -> list[dict]:
    """GitHub'da CVE PoC araştır — auth gerektirmez."""
    encoded = urllib.request.quote(f"{cve_id} PoC exploit")
    url = f"https://api.github.com/search/repositories?q={encoded}&sort=stars&per_page=5"
    req = urllib.request.Request(url, headers={
        **HEADERS,
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            results = []
            for repo in data.get("items", [])[:5]:
                results.append({
                    "name": repo.get("full_name", ""),
                    "description": repo.get("description", ""),
                    "stars": repo.get("stargazers_count", 0),
                    "url": repo.get("html_url", ""),
                    "updated": repo.get("updated_at", "")[:10],
                })
            return results
    except Exception:
        return []


# ─── OWASP TOP 10 ────────────────────────────────────────────────────────────

OWASP_TOP10_2021 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Kısıtlamalar yetkilendirilmemiş kullanıcılara uygulanmıyor.",
        "techniques": ["T1078", "T1548", "T1134"],
        "tests": ["IDOR testi", "Yatay/dikey ayrıcalık yükseltme", "Path traversal"],
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Hassas verileri açığa çıkaran kriptografi hataları.",
        "techniques": ["T1040", "T1557"],
        "tests": ["SSL/TLS analizi", "Zayıf şifre tespiti", "Cleartext veri"],
    },
    "A03": {
        "name": "Injection",
        "description": "SQL, NoSQL, OS, LDAP injection.",
        "techniques": ["T1190", "T1059"],
        "tests": ["SQLi (manual + sqlmap)", "Command injection", "LDAP injection"],
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Güvenli tasarım prensiplerinin eksikliği.",
        "techniques": ["T1190"],
        "tests": ["Threat model gözden geçirme", "İş mantığı hataları"],
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Hatalı güvenlik konfigürasyonları.",
        "techniques": ["T1592", "T1078", "T1133"],
        "tests": ["Default credential testi", "Gereksiz servis tespiti", "Debug modu"],
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Eski/savunmasız bileşenler.",
        "techniques": ["T1190"],
        "tests": ["CVE taraması", "Versiyon tespiti", "Dependency analizi"],
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Kimlik doğrulama zayıflıkları.",
        "techniques": ["T1110", "T1078", "T1539"],
        "tests": ["Password spray", "Brute force", "Session fixation", "MFA bypass"],
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Yazılım ve veri bütünlüğü varsayımları.",
        "techniques": ["T1195", "T1553"],
        "tests": ["Supply chain kontrolü", "Güvensiz deserialization"],
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Yetersiz loglama ve izleme.",
        "techniques": ["T1562", "T1070"],
        "tests": ["Log silinme testi", "Alert tetikleme", "SIEM kör nokta"],
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Sunucu tarafı istek sahteciliği.",
        "techniques": ["T1190", "T1071"],
        "tests": ["SSRF payload testi", "Cloud metadata erişim", "Internal port scan"],
    },
}


def get_owasp_top10() -> dict:
    return OWASP_TOP10_2021


def get_owasp_for_service(service: str) -> list[dict]:
    """Servis tipine göre ilgili OWASP kategorilerini döndür."""
    service_lower = service.lower()
    relevant = []
    mapping = {
        "http": ["A01", "A03", "A05", "A07", "A10"],
        "https": ["A01", "A02", "A03", "A05", "A07", "A10"],
        "mysql": ["A03", "A05", "A06"],
        "redis": ["A05", "A06"],
        "ssh": ["A07", "A05"],
        "smb": ["A05", "A06", "A07"],
        "ftp": ["A02", "A05", "A07"],
        "ldap": ["A03", "A07"],
    }
    for svc_key, owasp_keys in mapping.items():
        if svc_key in service_lower:
            for k in owasp_keys:
                item = OWASP_TOP10_2021.get(k, {})
                relevant.append({"code": k, **item})
            break
    return relevant or [{"code": "A05", **OWASP_TOP10_2021["A05"]}]


# ─── KOMBİNE ARAŞTIRMA ────────────────────────────────────────────────────────

def research_service(service: str, version: str = "") -> dict:
    """Bir servis için tam kapsamlı dış istihbarat topla."""
    results = {
        "service": service,
        "version": version,
        "cisa_kev": [],
        "nvd_cves": [],
        "exploits": [],
        "owasp": [],
    }

    results["cisa_kev"] = get_cisa_kev_for_service(service)

    query = f"{service} {version}".strip() if version else service
    results["nvd_cves"] = search_nvd(query, results=5)

    results["exploits"] = search_exploitdb(query)

    results["owasp"] = get_owasp_for_service(service)

    return results
