# TokTrail Collector

[中文](README.zh-CN.md)

TokTrail Collector is a local-first Go CLI for collecting privacy-filtered token usage metadata from supported local developer tools.

The collector is designed so that local inspection stays useful without an account: `scan`, `preview`, `export`, and diagnostics work offline. Uploading requires an explicit device binding and a fresh server-side consent preflight.

## What it collects

Supported sources in the current implementation:

- Codex session JSONL (`codex-jsonl`).
- Claude Code session JSONL (`claude-code-jsonl`).
- DeepSeek Harness session JSONL (`deepseek-harness`).
- WorkBuddy AI session JSONL (`workbuddy-jsonl`): passive JSONL only.
- Synthetic/free-form `usage-json` fixtures for integration and compatibility testing.

The collector uploads token usage counters, stable privacy-safe record identifiers, and source-specific model identifiers described below. It must not upload prompts, message bodies, raw session IDs, raw message IDs, or absolute local paths.

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
- Recorded model identifiers, including private names and local aliases, are preserved and uploaded when attribution is reliable. Missing or ambiguous attribution is `unknown`. Invalid identifiers are reported rather than silently changed. Identifiers are nonempty UTF-8 strings of at most 128 bytes without control characters; no aliases are resolved to backend identities. The leaderboard controls public disclosure.

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
  deepseekharness/       DeepSeek Harness parser and tests
  workbuddyjsonl/        WorkBuddy JSONL parser and tests
  registry/             Explicit compiled-in adapter registry
  pipeline/             Scan, preview, export, and batch splitting
internal/local/         Local state, grants, outbox, commit, progress, lock, and quarantine
internal/app/           Application workflows: collection, diagnostics, and status
internal/bind/          Device binding
internal/connect/       One-step connect orchestration
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
- `toktrail connect '<URL>'` binds the device, applies the current authorization, installs the scheduled service, and resynchronizes authorized usage.
- `toktrail scan` summarizes local records without account or network access.
- `toktrail preview` validates and previews local records.
- `toktrail export` writes a server ingest batch and registers it in the local outbox.
- `toktrail bind` generates or reuses a local device secret and binds the device to a server-issued ticket.
- `toktrail status` checks the current bound device state.
- `toktrail sync` uploads either an explicit batch or the oldest pending local outbox batch.
- `toktrail resync --all --dry-run` previews archived, already-synced device batches for currently enabled local grants without network or writes. This is only the archive plan: it does not scan sources, inspect recoverable records, or verify remote consent.
- `toktrail resync --all` asks for confirmation, then scans enabled sources, recovers records eligible under current authorization, drains pending batches, and retransmits archived history. Cursor account usage receives a full-window sync when enabled. `--yes` skips the prompt; `--max-batches N` limits archive retransmissions in one invocation. Incomplete work is reported and can be resumed.
- The current authorization determines what can be uploaded; narrowing it does not delete previously uploaded history. Deletion and revocation are managed on the leaderboard. Missing source data or archives cannot be reconstructed reliably, and cross-device deduplication is not guaranteed; preserve the collector state directory on reinstall.
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

Scan and export DeepSeek Harness usage from a local directory:

```sh
go run ./cmd/toktrail scan --source deepseek-harness --input ~/.dsh/sessions
go run ./cmd/toktrail export --source deepseek-harness --input ~/.dsh/sessions --out ./deepseek-batch.json --batch deepseek-demo-1
```

Scan and export WorkBuddy usage from a local directory:

```sh
go run ./cmd/toktrail scan --source workbuddy-jsonl --input ~/.workbuddy-ai/projects
go run ./cmd/toktrail export --source workbuddy-jsonl --input ~/.workbuddy-ai/projects --out ./workbuddy-batch.json --batch workbuddy-demo-1
```

WorkBuddy specifics:

- The source is passive JSONL only: it reads the session JSONL files WorkBuddy appends to and never writes to them.
- It does not cover the WorkBuddy SQLite history database; usage recorded only there is not collected.
- Recorded request model identifiers are included in uploads when they can be attributed reliably; they do not imply a verified backend identity.
- The default directory is `~/.workbuddy-ai/projects` (current WorkBuddy AI versions). Older WorkBuddy versions used `~/.workbuddy/projects`; there is no automatic fallback for the old layout, so grant it explicitly, for example `toktrail sources enable --source workbuddy-jsonl --input ~/.workbuddy/projects`.
- `connect` reapplies the server-authorized grants and disables manually enabled grants that are not part of them. Add the old-layout `~/.workbuddy/projects` grant after running `connect`, and re-check it after every reconnect.

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
  --grant deepseek-harness=$HOME/.dsh/sessions \
  --grant workbuddy-jsonl=$HOME/.workbuddy-ai/projects \
  --interval 30m
```

The installed task runs only:

```text
<toktrail binary> periodic --state-dir <absolute state dir>
```

No server URL or secret appears on the scheduler command line. See [Scheduled collection](docs/SCHEDULING.md) for the full model and platform notes.

## Signed releases and installation

GitHub Actions and `scripts/release.sh` build six platform targets. Maintainer tooling assembles archives and signs the manifest; the standalone installer verifies signatures and SHA-256 hashes before replacement. The tag workflow creates a draft GitHub Release for review. The installer and bootstrap scripts also support an explicit in-place `upgrade` that reuses the original install path, keeps the previous binary as `<binary>.previous`, and never touches state, grants, outbox, device binding or scheduler registration. See [Release and installation](docs/RELEASE.md).

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

## Known Cursor limitations (account-level network source)

- The desktop login state is read strictly read-only (SQLite `mode=ro`, auth keys only); the credential stays in memory and never reaches disk, logs, or uploads.
- The state database's WAL content is immutable but not readable in every state: already-checkpointed logins read fine at any time; a freshly created login may live only in the WAL until Cursor itself closes and checkpoints it. The error messages state this honestly — no claim is made that every login state is readable.
- An unattended scheduled run can never complete the first-time authorization: the local confirmation must be given interactively via connect or `toktrail cursor enable`.
- Account-level totals are aggregated by Cursor and may include usage from other machines. The first version supports one Cursor account source per user with one designated collector device; takeover is a website-side reassignment — the collector never claims an occupied executor slot.

## Contributing and security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules and pull request expectations.
- See [SECURITY.md](SECURITY.md) before reporting vulnerabilities or privacy issues.

## License

MIT. See [LICENSE](LICENSE).
