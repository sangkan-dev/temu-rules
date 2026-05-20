# Temu Rules

Rules-as-code repository for Temu.

This repository stores externally updateable detection rules for:

- Fingerprint detection.
- Vulnerability detection.
- Network and banner detection.
- Fuzzing and discovery dictionaries.
- Upstream rule/data snapshots used for automated promotion and review.

Temu can consume this repository without recompilation:

```bash
temu rules update --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
```

The manifest publishes both active rules and reviewed dictionaries. Temu writes rules into `rules_dir` and dictionaries into `dictionaries_dir`.

`Update Security Rules` runs on a schedule and manual dispatch. It fetches upstream sources, promotes low-risk fingerprint and dictionary changes into active Temu files, validates the repository, and opens a pull request. CVE data is refreshed automatically as upstream context. CVE-specific active probes can be published when they declare risk metadata because NVD does not distinguish read-only checks from crash, write, or RCE validation paths.

Safe rules should be detection-only and read-only. Intrusive, destructive, RCE-like, write/delete, or denial-of-service probes must set `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, or `requires_confirmation: true`; Temu only executes those rules when the operator explicitly enables risky rules.
