#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERATED_BY = "temu-rules-upstream"
PATH_SEEDS = [
    "admin",
    "login",
    "signin",
    "signup",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "swagger",
    "swagger-ui",
    "swagger.json",
    "openapi.json",
    "api-docs",
    "docs",
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".git/HEAD",
    ".git/config",
    "config.php",
    "wp-config.php",
    "status",
    "health",
    "healthcheck",
    "ping",
    "info",
    "version",
    "metrics",
    "actuator",
    "actuator/health",
    "actuator/env",
    "debug",
    "server-status",
    "server-info",
    "upload",
    "uploads",
    "files",
    "backup",
    "backups",
]
PARAMETER_SEEDS = [
    "id",
    "q",
    "query",
    "search",
    "page",
    "redirect",
    "redirect_uri",
    "url",
    "next",
    "return",
    "file",
    "path",
    "debug",
    "callback",
    "callback_url",
]
SUBDOMAIN_SEEDS = [
    "www",
    "api",
    "admin",
    "app",
    "dev",
    "staging",
    "test",
    "mail",
    "vpn",
    "portal",
    "docs",
    "status",
]


def clean_lines(path: Path, limit: int) -> list[str]:
    if not path.exists():
        return []
    seen = set()
    entries = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if any(token in value.lower() for token in ("..", "%00", "\x00")):
            continue
        if value in seen:
            continue
        seen.add(value)
        entries.append(value)
        if len(entries) >= limit:
            break
    return entries


def write_dictionary(path: Path, entries: list[str]) -> None:
    if not entries:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")


def merge_unique(seed: list[str], upstream: list[str], limit: int) -> list[str]:
    seen = set()
    entries = []
    for value in seed + upstream:
        value = value.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        entries.append(value)
        if len(entries) >= limit:
            break
    return entries


def promote_dictionaries() -> None:
    upstream = ROOT / "upstream" / "dictionaries"
    write_dictionary(
        ROOT / "dictionaries" / "paths-small.txt",
        merge_unique(PATH_SEEDS, clean_lines(upstream / "seclists-web-common.txt", 240), 200),
    )
    write_dictionary(
        ROOT / "dictionaries" / "parameters-small.txt",
        merge_unique(
            PARAMETER_SEEDS,
            clean_lines(upstream / "seclists-burp-parameter-names.txt", 180),
            150,
        ),
    )
    subdomains = merge_unique(
        SUBDOMAIN_SEEDS,
        clean_lines(upstream / "seclists-subdomains-top5000.txt", 1400),
        1200,
    )
    write_dictionary(ROOT / "dictionaries" / "subdomains-small.txt", subdomains[:200])
    write_dictionary(ROOT / "dictionaries" / "subdomains-medium.txt", subdomains[:1200])


def load_existing_fingerprint_rules() -> list[dict]:
    path = ROOT / "fingerprint" / "fingerprint_rules.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [rule for rule in data if rule.get("generated_by") != GENERATED_BY]


def safe_regex(pattern: str) -> str | None:
    pattern = str(pattern).strip()
    if not pattern or len(pattern) > 180:
        return None
    if any(token in pattern for token in ("{{", "}}", "\x00")):
        return None
    try:
        re.compile(pattern)
    except re.error:
        return re.escape(pattern)
    return pattern


def normalize_patterns(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, list):
        return []
    patterns = []
    for item in value:
        if isinstance(item, dict):
            item = item.get("string") or item.get("value")
        if not isinstance(item, str):
            continue
        for part in item.split("\\;"):
            pattern = safe_regex(part)
            if pattern:
                patterns.append(pattern)
    return patterns[:4]


def generated_wappalyzer_rules(existing_names: set[str], limit: int = 350) -> list[dict]:
    source = ROOT / "upstream" / "fingerprint" / "wappalyzer-technologies-a.json"
    if not source.exists():
        return []
    data = json.loads(source.read_text(encoding="utf-8", errors="ignore"))
    generated = []
    for name, spec in sorted(data.items()):
        if name in existing_names:
            continue
        body = []
        body.extend(normalize_patterns(spec.get("html")))
        body.extend(normalize_patterns(spec.get("scriptSrc")))
        if not body:
            continue
        generated.append(
            {
                "name": name,
                "category": "Other",
                "confidence": 0.60,
                "body": body[:4],
                "generated_by": GENERATED_BY,
            }
        )
        if len(generated) >= limit:
            break
    return generated


def generated_fingerprinthub_rules(existing_names: set[str], limit: int = 350) -> list[dict]:
    source = ROOT / "upstream" / "fingerprint" / "fingerprinthub-web-v4.json"
    if not source.exists():
        return []
    data = json.loads(source.read_text(encoding="utf-8", errors="ignore"))
    generated = []
    for item in data:
        info = item.get("info") or {}
        name = info.get("name") or item.get("id")
        if not name or name in existing_names:
            continue
        words = []
        for http in item.get("http") or []:
            for matcher in http.get("matchers") or []:
                if matcher.get("type") != "word":
                    continue
                for word in matcher.get("words") or []:
                    if isinstance(word, str) and 4 <= len(word) <= 120:
                        words.append(re.escape(word))
        if not words:
            continue
        generated.append(
            {
                "name": name,
                "category": "Other",
                "confidence": 0.55,
                "body": words[:4],
                "generated_by": GENERATED_BY,
            }
        )
        if len(generated) >= limit:
            break
    return generated


def promote_fingerprints() -> None:
    curated = load_existing_fingerprint_rules()
    existing_names = {rule.get("name") for rule in curated}
    generated = generated_wappalyzer_rules(existing_names)
    existing_names.update(rule["name"] for rule in generated)
    generated.extend(generated_fingerprinthub_rules(existing_names))

    path = ROOT / "fingerprint" / "fingerprint_rules.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(curated + generated, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def write_manifest() -> None:
    manifest = {
        "fingerprint": "fingerprint/fingerprint_rules.yaml",
        "vulnerability": sorted(
            str(path.relative_to(ROOT)) for path in (ROOT / "vulnerability").rglob("*.yaml")
        ),
        "network": sorted(str(path.relative_to(ROOT)) for path in (ROOT / "network").rglob("*.yaml")),
        "dictionaries": sorted(
            str(path.relative_to(ROOT)) for path in (ROOT / "dictionaries").rglob("*.txt")
        ),
    }
    (ROOT / "rules-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rule-type",
        default="all",
        choices=["all", "fingerprint", "vulnerability", "network", "dictionaries"],
    )
    args = parser.parse_args()

    if args.rule_type in ("all", "dictionaries"):
        promote_dictionaries()
    if args.rule_type in ("all", "fingerprint"):
        promote_fingerprints()
    write_manifest()


if __name__ == "__main__":
    main()
