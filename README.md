# Temu Rules

Rules-as-code repository for Temu.

This repository stores externally updateable detection rules for:

- Fingerprint detection.
- Vulnerability detection.
- Network and banner detection.
- Fuzzing and discovery dictionaries.
- Upstream rule/data snapshots used for review and conversion.

Temu can consume this repository without recompilation:

```bash
temu rules update --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
```

The manifest can publish both active rules and reviewed dictionaries. Temu writes rules into `rules_dir` and dictionaries into `dictionaries_dir`.

Rules must be detection-only and read-only. Do not add destructive payloads, exploit chains, reverse shells, file writes, or denial-of-service payloads.
