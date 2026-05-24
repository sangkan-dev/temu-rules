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

`Update Security Rules` runs on a schedule and manual dispatch. It fetches upstream sources, promotes low-risk fingerprint and dictionary changes into active Temu files, generates non-executable CVE candidate descriptors in `staging/candidates/`, validates the repository, and opens a pull request. Candidate generation enriches recent NVD entries with CISA KEV and Exploit-DB references; it never promotes a probe automatically.

Candidate descriptors always declare `executable: false`, `risk_level: unknown`, and `requires_confirmation: true`. An analyst must design a read-only matcher, validate it, and move it into `vulnerability/` before it can enter `rules-manifest.json`.

Safe rules should be detection-only and read-only. Intrusive, destructive, RCE-like, write/delete, or denial-of-service probes must set `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, or `requires_confirmation: true`; Temu only executes those rules when the operator explicitly enables risky rules.
