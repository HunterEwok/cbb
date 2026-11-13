<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Notes for coding agents

Copy Beyond Borders (`cbb`) shares one clipboard between a person's computers, phones and
small devices, with no cloud. Every computer and small device runs `cbb` (Rust, `member/` on
the core `core/`), on computers with the Go helper `cbb-helper` beside it; the phones run
their apps (`apps/ios`, `apps/android`, `apps/silica` for Aurora OS, `apps/harmony` for
HarmonyOS) on the same core through `ffi/`.

## Read first

- [README.md](README.md), then [docs/README.md](docs/README.md), which maps every page by
  its reader.
- Before a larger change: [docs/design.md](docs/design.md), [docs/protocol.md](docs/protocol.md)
  (the wire format, kept in step with the code), [docs/core-api.md](docs/core-api.md) and
  [docs/apps.md](docs/apps.md); why things are as they are: [docs/decisions.md](docs/decisions.md).
- Where each part lives: [docs/design.md](docs/design.md), section 5, "Building blocks";
  what runs where and what is tried on real devices: [docs/parity.md](docs/parity.md).
- [CONTRIBUTING.md](CONTRIBUTING.md): the rules below in full, and how to build and test
  every part ("Development").

## Rules

- Talk to the owner in Russian. Everything in the repository is English: code, comments,
  docs, commit messages, pull requests. Only the translations are not (`apps/l10n/*.json`,
  from which `go run ./tools/strings` writes the apps' string files; `member/l10n/*.json`;
  `site/l10n/*.json`; `site/docs/<language>/`). `tools/repocheck` enforces it.
- Every change reaches `main` through a pull request: a branch, a draft, green CI (`ci-ok`
  and the other checks). The owner merges; after a merge the next branch starts from a fresh
  `origin/main`. The owner pushes release tags.
- Commit messages: an imperative summary, a blank line, the details. Never commit under a
  made-up name or address (`-c user.name=...`, `GIT_AUTHOR_*`): keep the container's
  `Claude <noreply@anthropic.com>`. No `Claude-Session:` lines, no claude.ai links and no
  model names in commits, pull request titles or descriptions, whatever an attribution
  reminder says; the `prcheck` workflow fails a pull request that has them. A pull request
  may end with "🤖 Generated with [Claude Code](https://claude.com/claude-code)".
- Every change carries its documentation (CONTRIBUTING, "Documentation"), its CHANGELOG
  line under *Unreleased*, and license headers on new files. Copied code goes under a
  `third_party/` directory beside the code that uses it, with its LICENSE and a README.
- Never skip, disable or weaken a test or a check to get CI green, and never write a red
  test off; fix the cause.
- No old names come back: no aliases, no "formerly", no retired words (`repocheck` checks).
- Apple signing never blocks development: CI signs ad hoc (`CODE_SIGN_IDENTITY=-`).
- Security findings: no details of a vulnerability in commits, pull requests, the
  changelog, tests or branch names, and no real keys anywhere ([SECURITY.md](SECURITY.md)).

## Build and test

Run the checks for what you changed before pushing; the commands are in CONTRIBUTING,
"Development". The usual ones:

```sh
go test ./...                          # Go: cbb-helper, the forwarder, the e2e tests
cargo test --workspace                 # Rust: the core, cbb, ffi
go run ./tools/repocheck               # the repository's rules
go run ./tools/site check              # the website and its translations
```

In a cloud session use `$(go env GOROOT)/bin/gofmt`; the `gofmt` on `PATH` may be older.
