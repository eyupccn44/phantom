"""
GroundingValidator — LLM çıktısındaki CVE ve TID'leri gerçek veriyle doğrula.
Uydurma değerleri filtreler veya işaretler.
"""
import re
from pathlib import Path
import json

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

_TECHNIQUES_PATH = Path(__file__).parent.parent.parent / "data" / "techniques.json"
_known_tids: set[str] | None = None


def _load_known_tids() -> set[str]:
    global _known_tids
    if _known_tids is not None:
        return _known_tids
    try:
        raw = json.loads(_TECHNIQUES_PATH.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else list(raw.values())
        _known_tids = {t.get("tid", "").upper() for t in items if t.get("tid")}
    except Exception:
        _known_tids = set()
    return _known_tids


def is_valid_cve_format(cve_id: str) -> bool:
    """CVE-YYYY-NNNNN formatı kontrolü."""
    return bool(_CVE_RE.match(cve_id.strip()))


def is_valid_tid_format(tid: str) -> bool:
    """T1234 veya T1234.001 formatı kontrolü."""
    return bool(_TID_RE.match(tid.strip()))


def is_known_tid(tid: str) -> bool:
    """Yerel techniques.json'da mevcut mu?"""
    known = _load_known_tids()
    return tid.upper() in known or not known  # DB boşsa hepsine izin ver


def verify_cve_exists(cve_id: str) -> bool:
    """CIRCL CVE API üzerinden CVE'nin gerçekten var olup olmadığını kontrol et."""
    if not is_valid_cve_format(cve_id):
        return False
    try:
        from core.intel_feeds import lookup_cve_circl
        result = lookup_cve_circl(cve_id)
        return "error" not in result and bool(result)
    except Exception:
        return True  # API erişilemezse şüpheci olma


def filter_cves(cve_list: list[str], verify_online: bool = False) -> tuple[list[str], list[str]]:
    """
    CVE listesini doğrula.
    Returns: (geçerli_cve_listesi, reddedilen_cve_listesi)
    """
    valid = []
    rejected = []
    for cve in cve_list:
        cve = cve.strip().upper()
        if not is_valid_cve_format(cve):
            rejected.append(f"{cve} [format hatası]")
            continue
        if verify_online:
            if verify_cve_exists(cve):
                valid.append(cve)
            else:
                rejected.append(f"{cve} [CIRCL'de bulunamadı]")
        else:
            valid.append(cve)
    return valid, rejected


def filter_tids(tid_list: list[str]) -> tuple[list[str], list[str]]:
    """
    TID listesini doğrula.
    Returns: (geçerli_tid_listesi, reddedilen_tid_listesi)
    """
    valid = []
    rejected = []
    known = _load_known_tids()
    for tid in tid_list:
        tid = tid.strip().upper()
        if not is_valid_tid_format(tid):
            rejected.append(f"{tid} [format hatası]")
            continue
        if known and tid not in known:
            rejected.append(f"{tid} [yerel DB'de yok]")
            continue
        valid.append(tid)
    return valid, rejected


def ground_agent_output(data: dict, available_cves: list[str] = None, available_tids: list[str] = None) -> dict:
    """
    Ajan JSON çıktısını gerçek veriyle zemine bağla.
    - CVE alanlarını doğrula, uydurmaları sil
    - TID alanlarını doğrula, uydurmaları sil
    - Her reddedilen alan için '_grounding_uyarıları' ekle
    """
    if not isinstance(data, dict):
        return data

    allowed_cves = {c.upper() for c in (available_cves or [])}
    allowed_tids = {t.upper() for t in (available_tids or [])}
    warnings = []

    data = _ground_recursive(data, allowed_cves, allowed_tids, warnings)

    if warnings:
        data["_grounding_uyarıları"] = warnings

    return data


def _ground_recursive(obj, allowed_cves: set, allowed_tids: set, warnings: list):
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            result[k] = _ground_recursive(v, allowed_cves, allowed_tids, warnings)
        return result

    if isinstance(obj, list):
        return [_ground_recursive(item, allowed_cves, allowed_tids, warnings) for item in obj]

    if isinstance(obj, str):
        # CVE referansı mı?
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", obj, re.IGNORECASE)
        if cve_match:
            found_cve = cve_match.group(0).upper()
            if not is_valid_cve_format(found_cve):
                warnings.append(f"Geçersiz format: {found_cve}")
                return obj.replace(cve_match.group(0), f"[GEÇERSİZ:{found_cve}]")
            if allowed_cves and found_cve not in allowed_cves:
                warnings.append(f"Doğrulanamayan CVE: {found_cve}")
                return obj.replace(cve_match.group(0), f"[DOĞRULANMADI:{found_cve}]")

        # TID referansı mı?
        tid_match = re.search(r"\bT\d{4}(\.\d{3})?\b", obj, re.IGNORECASE)
        if tid_match:
            found_tid = tid_match.group(0).upper()
            if not is_valid_tid_format(found_tid):
                warnings.append(f"Geçersiz TID format: {found_tid}")
            elif allowed_tids and found_tid not in allowed_tids:
                known = _load_known_tids()
                if known and found_tid not in known:
                    warnings.append(f"Yerel DB'de bulunmayan TID: {found_tid}")
                    return obj.replace(tid_match.group(0), f"[DOĞRULANMADI:{found_tid}]")

    return obj


def extract_cves_from_context(context: dict) -> list[str]:
    """Context'teki tüm gerçek CVE ID'lerini topla."""
    cves = set()

    # CISA KEV
    for item in context.get("cisa_kev_results", []):
        if isinstance(item, dict) and item.get("cveID"):
            cves.add(item["cveID"].upper())

    # NVD
    for item in context.get("nvd_results", []):
        if isinstance(item, dict) and item.get("id"):
            cves.add(item["id"].upper())

    # Yerel CVE DB
    for item in context.get("cves", []):
        if isinstance(item, dict) and item.get("id"):
            cves.add(item["id"].upper())

    # CIRCL
    for item in context.get("circl_cves", []):
        if isinstance(item, dict):
            cid = item.get("id") or item.get("cveID")
            if cid:
                cves.add(cid.upper())

    return list(cves)


def extract_tids_from_context(context: dict) -> list[str]:
    """Context'teki tüm gerçek TID'leri topla."""
    tids = set()

    for item in context.get("local_ttps", []):
        if isinstance(item, dict) and item.get("tid"):
            tids.add(item["tid"].upper())

    for item in context.get("mitre_techniques", []):
        if isinstance(item, dict) and item.get("tid"):
            tids.add(item["tid"].upper())

    # Yerel DB'den bilinen tüm TID'leri de ekle
    known = _load_known_tids()
    tids.update(known)

    return list(tids)
