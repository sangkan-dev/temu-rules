#!/usr/bin/env python3
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DANGEROUS = ("drop ", "delete ", "update ", "insert ", "truncate ", "xp_cmdshell", "reverse shell")


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


def main() -> None:
    validate_manifest()
    validate_yaml_files()
    validate_payload_safety()
    print("rules validation passed")


if __name__ == "__main__":
    main()
