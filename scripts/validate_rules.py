#!/usr/bin/env python3
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DANGEROUS = ("drop ", "delete ", "update ", "insert ", "truncate ", "xp_cmdshell", "reverse shell")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
MATCH_TYPES = {"BodyContains", "BodyRegex", "TimeBased", "StatusCode", "HeaderContains"}


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def validate_manifest() -> None:
    manifest_path = ROOT / "rules-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = []
    if manifest.get("fingerprint"):
        paths.append(manifest["fingerprint"])
    paths.extend(manifest.get("vulnerability", []))
    paths.extend(manifest.get("network", []))
    paths.extend(manifest.get("dictionaries", []))
    for item in paths:
        if ".." in item:
            raise SystemExit(f"invalid manifest path: {item}")
        if not (ROOT / item).is_file():
            raise SystemExit(f"manifest path does not exist: {item}")


def validate_yaml_files() -> None:
    for path in ROOT.rglob("*.yaml"):
        load_yaml(path)
    for path in ROOT.rglob("*.yml"):
        load_yaml(path)


def validate_payload_safety() -> None:
    for folder in ("vulnerability", "network"):
        for path in (ROOT / folder).rglob("*.yaml"):
            data = load_yaml(path) or {}
            payload = str(data.get("payload") or "").lower()
            if any(token in payload for token in DANGEROUS):
                raise SystemExit(f"dangerous payload token in {path}")


def validate_temu_rule_shape() -> None:
    for folder in ("vulnerability", "network"):
        for path in (ROOT / folder).rglob("*.yaml"):
            data = load_yaml(path) or {}
            severity = data.get("severity")
            if severity not in SEVERITIES:
                raise SystemExit(f"invalid severity in {path}: {severity}")
            method = data.get("request_method")
            if method not in METHODS:
                raise SystemExit(f"invalid request_method in {path}: {method}")
            verify = data.get("verify") or {}
            match_type = verify.get("match_type")
            if match_type not in MATCH_TYPES:
                raise SystemExit(f"invalid verify.match_type in {path}: {match_type}")
            if match_type == "BodyContains" and not verify.get("body_contains"):
                raise SystemExit(f"BodyContains rule must define verify.body_contains: {path}")
            if match_type == "BodyRegex" and not verify.get("body_regex"):
                raise SystemExit(f"BodyRegex rule must define verify.body_regex: {path}")


def validate_dictionaries() -> None:
    dictionary_root = ROOT / "dictionaries"
    if not dictionary_root.exists():
        return
    for path in dictionary_root.rglob("*.txt"):
        entries = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                if "\x00" in value:
                    raise SystemExit(f"dictionary contains null byte: {path}:{line_number}")
                entries.append(value)
        if not entries:
            raise SystemExit(f"dictionary has no entries: {path}")


def main() -> None:
    validate_manifest()
    validate_yaml_files()
    validate_payload_safety()
    validate_temu_rule_shape()
    validate_dictionaries()
    print("rules validation passed")


if __name__ == "__main__":
    main()
