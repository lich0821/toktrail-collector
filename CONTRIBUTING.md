# Contributing to TokTrail Collector

Thank you for contributing. This repository contains a local-first usage collector, so privacy and fail-closed behavior are part of the product contract, not optional implementation details.

## Development setup

Requirements:

- Go 1.24 or newer.
- No third-party Go modules are currently required.

Run the standard checks from the repository root:

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
```

The release end-to-end test is slower and must be enabled explicitly:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 go test ./tools/release/ -run '^TestEndToEndRelease$' -count=1 -v
```

## Architecture

Read [Architecture and adapter extension](docs/ARCHITECTURE.md) before adding a source. Parsers and their fixtures belong to the source package. Shared orchestration must use registry descriptors rather than switch on source identifiers.

## Privacy requirements

Adapters and sync code must preserve these invariants:

- Do not upload prompts or message bodies.
- Do not upload raw session IDs or message IDs.
- Do not upload absolute local paths.
- Preserve each source's recorded model identifier without a public allowlist, including local route aliases. Report missing or ambiguous attribution as `unknown`; reject malformed identifiers. Do not infer backend identities or add gateway metadata. Public disclosure is controlled by the leaderboard.
- Unknown token counters must stay unknown; do not silently coerce unknown values to zero.
- Uploads must happen only after device binding and a fresh server-side consent preflight.
- Local read grants, upload consent, and public leaderboard consent remain separate.

Tests should use synthetic fixtures. Never commit real user session files, device state, bind tickets, release keys, or production service credentials.

## Coding guidelines

- Keep comments and engineering documents in English unless a document is intentionally bilingual.
- Prefer explicit validation and fail-closed behavior.
- Keep local-first commands usable without a TokTrail account.
- Keep release and installer code deterministic and auditable.
- Avoid new dependencies unless they are clearly justified.

## Pull request checklist

Before opening a pull request, verify:

- [ ] `gofmt -l` returns no files.
- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] No secrets, real logs, local state, release keys, or cache directories are included.
- [ ] New adapters include privacy projection tests.
- [ ] Changes to release logic include manifest, archive, or installer tests as appropriate.
- [ ] Documentation is updated when behavior or command-line flags change.

## Release artifacts

Do not commit generated release artifacts, signing keys, local binaries, or Go build caches. The repository `.gitignore` excludes the expected local paths, including `.gocache/`, `.gotmp/`, `bin/`, `dist/`, `.local/`, `.release-keys/`, logs, and local environment files.
