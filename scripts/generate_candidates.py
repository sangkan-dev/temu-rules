#!/usr/bin/env python3
"""Generate non-executable CVE detection candidates for analyst review."""

import csv
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "staging" / "candidates"


def load_kev_ids() -> set[str]:
    path = ROOT / "upstream" / "cve" / "cisa-kev.json"
    if not path.exists():
        return set()
    catalog = json.loads(path.read_text(encoding="utf-8"))
    return {
        item.get("cveID")
        for item in catalog.get("vulnerabilities", [])
        if item.get("cveID")
    }


def load_exploit_db_ids() -> set[str]:
    path = ROOT / "upstream" / "cve" / "exploitdb-files.csv"
    if not path.exists():
        return set()
    ids = set()
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        for row in csv.DictReader(handle):
            text = " ".join(row.values())
            ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE))
    return {item.upper() for item in ids}


def description_of(cve: dict) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def severity_of(cve: dict) -> tuple[str, float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return str(data.get("baseSeverity", "unknown")).lower(), float(data.get("baseScore", 0.0))
    return "unknown", 0.0


def references_of(cve_id: str, cve: dict, known_exploited: bool) -> list[str]:
    references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    for item in cve.get("references", []):
        url = item.get("url")
        if url and url.startswith("https://") and url not in references:
            references.append(url)
        if len(references) >= 5:
            break
    if known_exploited:
        references.append(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )
    return references


def candidate(cve: dict, kev_ids: set[str], exploit_ids: set[str]) -> dict | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    severity, cvss = severity_of(cve)
    description = description_of(cve)
    known_exploited = cve_id in kev_ids
    exploitdb_match = cve_id in exploit_ids
    return {
        "status": "candidate",
        "executable": False,
        "id": f"{cve_id}-CANDIDATE",
        "cve_id": cve_id,
        "name": f"Candidate detection for {cve_id}",
        "severity": severity,
        "cvss": cvss,
        "risk_level": "unknown",
        "requires_confirmation": True,
        "priority": {
            "cisa_kev": known_exploited,
            "exploitdb_reference": exploitdb_match,
        },
        "description": description,
        "detection": {
            "payload": None,
            "verify": None,
            "review_required": "Define a read-only matcher and classify execution risk before promotion.",
        },
        "remediation": "Apply the vendor remediation or patched version documented in the advisory.",
        "references": references_of(cve_id, cve, known_exploited),
        "generated_from": ["nvd", *(["cisa_kev"] if known_exploited else []), *(["exploit_db"] if exploitdb_match else [])],
    }


def main() -> None:
    recent_path = ROOT / "upstream" / "cve" / "recent.json"
    if not recent_path.exists():
        raise SystemExit("upstream/cve/recent.json is required")
    recent = json.loads(recent_path.read_text(encoding="utf-8"))
    kev_ids = load_kev_ids()
    exploit_ids = load_exploit_db_ids()
    STAGING.mkdir(parents=True, exist_ok=True)

    candidates = []
    for vulnerability in recent.get("vulnerabilities", []):
        item = candidate(vulnerability.get("cve", {}), kev_ids, exploit_ids)
        if item is None:
            continue
        candidates.append(item)
    output = STAGING / "recent.yaml"
    output.write_text(yaml.safe_dump(candidates, sort_keys=False), encoding="utf-8")
    print(f"generated {len(candidates)} staging candidate(s) in {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
