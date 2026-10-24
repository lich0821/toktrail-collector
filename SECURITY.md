# Security Policy

## Supported versions

Security updates are provided for the current `main` branch and for any release line explicitly marked as supported in the release notes.

This project is still pre-1.0. Until a stable release policy is published, assume that only the latest released collector version receives fixes.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for vulnerabilities or privacy leaks.

When reporting, include:

- A short description of the issue and impact.
- Affected version or commit.
- Reproduction steps using synthetic data.
- Relevant platform details.

Do **not** include real secrets or private user data in a report. In particular, do not paste:

- Device secrets or bind tickets.
- Server bearer tokens.
- Real Codex or Claude Code session files.
- Prompts, message contents, session identifiers, absolute local paths, or private model route names.
- Production signing keys or release-key material.

If a proof of concept requires input data, reduce it to the smallest synthetic fixture that demonstrates the issue.

## Security model summary

TokTrail Collector is local-first:

- `scan`, `preview`, and `export` operate without an account and without network access.
- Scheduled collection reads only explicitly granted local paths.
- A scheduled run with no enabled source grants performs no scan and no network request.
- Uploads require a bound device credential and a fresh server-side consent preflight.
- The collector must not upload prompts, message bodies, raw session IDs, absolute paths, or private model route names.
- Release artifacts are verified with an Ed25519-signed manifest and SHA-256 checks before installation.

## Disclosure expectations

Please allow a reasonable remediation window before public disclosure. The project maintainers will acknowledge valid reports, assess impact, prepare fixes, and credit reporters when desired.
