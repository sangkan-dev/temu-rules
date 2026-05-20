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

`Update Security Rules` runs on a schedule and manual dispatch. It fetches upstream sources, promotes low-risk fingerprint and dictionary changes into active Temu files, validates the repository, and opens a pull request. CVE data is refreshed automatically as upstream context, but new CVE-specific active probes still need safe detection templates because NVD does not publish scanner-safe payloads.

Rules must be detection-only and read-only. Do not add destructive payloads, exploit chains, reverse shells, file writes, or denial-of-service payloads.
