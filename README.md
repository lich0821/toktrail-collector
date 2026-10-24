# TokTrail Collector

[Chinese](README.zh-CN.md)

TokTrail Collector is a local-first Go CLI for collecting privacy-filtered token usage metadata from supported local developer tools.

The collector is designed so that local inspection stays useful without an account: `scan`, `preview`, `export`, and diagnostics work offline. Uploading requires an explicit device binding and a fresh server-side consent preflight.

## What it collects

Supported sources in the current implementation:

- Codex session JSONL (`codex-jsonl`).
- Claude Code session JSONL (`claude-code-jsonl`).
- Synthetic/free-form `usage-json` fixtures for integration and compatibility testing.

The collector uploads token usage counters and stable privacy-safe record identifiers. It must not upload prompts, message bodies, raw session IDs, raw message IDs, absolute local paths, or private model route names.

## Privacy and consent model

TokTrail Collector keeps three permissions separate:

1. **Local read grant**: which local paths scheduled collection may read.
2. **Upload consent**: whether a bound device may upload usage records to a TokTrail-compatible server.
3. **Public leaderboard consent**: whether projected usage can appear publicly.

Important invariants:

- `scan`, `preview`, and `export` do not require a TokTrail account.
- Scheduled collection reads only paths explicitly enabled through `sources` or `service install --grant`.
- A scheduled run with no enabled source grants performs no scan and no network request.
- `sync` performs `GET /v1/devices/self` before uploading and sends the learned consent revision with the ingest request.
- Unknown token counters remain unknown; they are not silently coerced to zero.
- Private model routes collapse to `unknown` unless they match the public allowlist.

## Repository layout

```text
cmd/toktrail/            Main collector CLI
cmd/toktrail-installer/  User installer and verifier
cmd/toktrail-release/    Maintainer CLI and legacy command compatibility
scripts/release.sh      Local and CI build orchestration
.github/workflows/      Tests and tag-driven draft releases
tools/release/          Archive assembly, signing, bootstrap templates and release E2E
internal/source/
  adapter/              Shared record contracts, validation, token and privacy helpers
  jsonl/                Shared JSONL file discovery, line reading, and decoding
  usagejson/            usage-json parser and tests
  codexjsonl/            Codex parser, replay filtering, and tests
  claudecodejsonl/       Claude Code parser, interval integrity, and tests
  registry/             Explicit compiled-in adapter registry
  pipeline/             Scan, preview, export, and batch splitting
internal/local/         Local state, grants, outbox, commit, progress, lock, and quarantine
internal/app/           Application workflows: collection, diagnostics, and status
internal/bind/          Device binding
internal/syncclient/    Server sync, ACK handling, reorganization, and recovery
internal/distribution/  Manifest, version, signature, hash and naming protocol
internal/installer/     Download, verification, extraction and safe binary replacement
internal/scheduler/     launchd, systemd user timer, and Windows Task Scheduler plans
docs/                   Architecture, release, and scheduling design notes
```

See [Architecture and adapter extension](docs/ARCHITECTURE.md) for dependency rules and the source extension path.

## Command surface

Common commands:

- `toktrail version` prints the collector version.
- `toktrail help` prints the available command surface.
- `toktrail scan` summarizes local records without account or network access.
- `toktrail preview` validates and previews local records.
- `toktrail export` writes a server ingest batch and registers it in the local outbox.
- `toktrail bind` generates or reuses a local device secret and binds the device to a server-issued ticket.
- `toktrail status` checks the current bound device state.
- `toktrail sync` uploads either an explicit batch or the oldest pending local outbox batch.
- `toktrail sources` manages explicit local read grants for scheduled collection.
- `toktrail periodic` collects from enabled grants and drains a bounded number of pending batches.
- `toktrail service` installs or uninstalls the user-level scheduled task.
- `toktrail privacy` and `toktrail doctor` provide local diagnostics.

## Quick start for local development

Build and inspect the CLI:

```sh
go run ./cmd/toktrail version
go run ./cmd/toktrail help
```

Scan and export Codex usage from a local directory:

```sh
go run ./cmd/toktrail scan --source codex-jsonl --input ~/.codex/sessions
go run ./cmd/toktrail export --source codex-jsonl --input ~/.codex/sessions --out ./codex-batch.json --batch codex-demo-1
```

Scan and export Claude Code usage from a local directory:

```sh
go run ./cmd/toktrail scan --source claude-code-jsonl --input ~/.claude/projects
go run ./cmd/toktrail export --source claude-code-jsonl --input ~/.claude/projects --out ./claude-batch.json --batch claude-demo-1
```

Bind and sync against a local development server:

```sh
TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail bind \
  --server http://127.0.0.1:3211 \
  --application leaderboard-local \
  --subject demo-user \
  --device-name my-mac

TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail status \
  --server http://127.0.0.1:3211

go run ./cmd/toktrail sync --server http://127.0.0.1:3211
```

`TOKTRAIL_BIND_TICKET=dev-ticket` is a local placeholder. Production deployments should provide one-time bind tickets through their own account and setup flow.

## Scheduled collection

Scheduled collection is opt-in. Enable explicit source grants before installing a user-level task:

```sh
go run ./cmd/toktrail service install \
  --grant codex-jsonl=$HOME/.codex/sessions \
  --grant claude-code-jsonl=$HOME/.claude/projects \
  --interval 30m
```

The installed task runs only:

```text
<toktrail binary> periodic --state-dir <absolute state dir>
```

No server URL or secret appears on the scheduler command line. See [Scheduled collection](docs/SCHEDULING.md) for the full model and platform notes.

## Signed releases and installation

GitHub Actions and `scripts/release.sh` build six platform targets. Maintainer tooling assembles archives and signs the manifest; the standalone installer verifies signatures and SHA-256 hashes before replacement. The tag workflow creates a draft GitHub Release for review. See [Release and installation](docs/RELEASE.md).

Production operators must provide their own release signing keys, trusted public-key distribution channel, download hosting, and any platform-specific notarization or code signing.

## Development checks

Run these before committing:

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
```

The release end-to-end test is slower and gated explicitly:

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 go test ./tools/release/ -run '^TestEndToEndRelease$' -count=1 -v
```

## Contributing and security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules and pull request expectations.
- See [SECURITY.md](SECURITY.md) before reporting vulnerabilities or privacy issues.

## License

MIT. See [LICENSE](LICENSE).
