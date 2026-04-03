# prehook

Stop secrets before they ship. `prehook` is a single-binary CLI that installs local `pre-commit` and `pre-push` Git hooks to scan for leaked secrets, vulnerable dependencies, and code quality issues -- before your code ever leaves your machine.

## Install

### From source (requires Go 1.23+)

```bash
go install github.com/arunlabs/prehook@latest
```

### Homebrew (macOS / Linux)

```bash
brew tap arunlabs/tap
brew install prehook
```

### Scoop (Windows)

```powershell
scoop bucket add arunlabs https://github.com/arunlabs/scoop-bucket
scoop install prehook
```

### Binary download

Download the latest release from the [Releases](https://github.com/arunlabs/prehook/releases) page.

| Platform | Archive                                   | Binary        |
| -------- | ----------------------------------------- | ------------- |
| macOS    | `prehook_*_darwin_amd64.tar.gz` / `arm64` | `prehook`     |
| Linux    | `prehook_*_linux_amd64.tar.gz` / `arm64`  | `prehook`     |
| Windows  | `prehook_*_windows_amd64.zip` / `arm64`   | `prehook.exe` |

Extract and place the binary somewhere on your `PATH`.

## Quickstart

1. Initialize config in your repository root:

```bash
prehook init
```

2. Install managed hooks:

```bash
prehook install
```

3. Check local dependencies:

```bash
prehook doctor
```

4. Enforce pinned scanner versions (optional hard mode):

```bash
prehook doctor --require-pins
```

## Commands

- `prehook init` creates `.prehook.yaml` with secure defaults.
- `prehook install` installs managed `pre-commit` and `pre-push` hooks.
- `prehook doctor` validates required scanner binaries and configured version pins.
- `prehook run --stage pre-commit|pre-push` runs stage gates directly.
- `prehook cleanup` prints manual secret remediation guidance.
- `prehook version` prints the CLI version.

## Stage Behavior

### `pre-commit`

- Builds a temporary snapshot from the Git index (not the working tree).
- Runs `gitleaks` and `trufflehog` against staged content.
- `trufflehog` policy defaults to block verified secrets and warn on unknown/unverified findings.
- Blocks commit on scanner failures by default.

### `pre-push`

- Computes changed files from pre-push refs; falls back to `HEAD~1..HEAD` when refs are absent.
- Runs `semgrep` on changed files.
- Runs `osv-scanner` when dependency manifest or lock files changed.
- Runs `trivy` filesystem scan with configured severity.
- Runs quality test command and optional coverage command + threshold gate.
- Blocks push on failures by default.

## Tool Dependencies

prehook delegates scanning to external tools. Install the ones you enable in `.prehook.yaml`:

| Tool              | Required by        | macOS / Linux                                  | Windows                                                                   |
| ----------------- | ------------------ | ---------------------------------------------- | ------------------------------------------------------------------------- |
| `git`             | all                | preinstalled / `apt install git`               | [git-scm.com](https://git-scm.com)                                        |
| `gitleaks`        | pre-commit         | `brew install gitleaks`                        | `scoop install gitleaks`                                                  |
| `trufflehog`      | pre-commit         | `brew install trufflehog`                      | [GitHub releases](https://github.com/trufflesecurity/trufflehog/releases) |
| `semgrep`         | pre-push           | `brew install semgrep` / `pip install semgrep` | `pip install semgrep`                                                     |
| `osv-scanner`     | pre-push           | `brew install osv-scanner`                     | `scoop install osv-scanner`                                               |
| `trivy`           | pre-push           | `brew install trivy`                           | `scoop install trivy`                                                     |
| `git-filter-repo` | cleanup (optional) | `brew install git-filter-repo`                 | `pip install git-filter-repo`                                             |

Run `prehook doctor` after installing to verify everything is found and version-compatible.

## Example Config

```yaml
version: 1
pre_commit:
  blocking: true
  gitleaks:
    enabled: true
    blocking: true
    timeout: 2m
  trufflehog:
    enabled: true
    blocking: true
    timeout: 2m
    block_verified: true
    block_unknown: false
pre_push:
  blocking: true
  semgrep:
    enabled: true
    blocking: true
    timeout: 5m
  osv:
    enabled: true
    blocking: true
    timeout: 5m
  trivy:
    enabled: true
    blocking: true
    timeout: 8m
    severity: HIGH,CRITICAL
  quality:
    enabled: true # opt-in: set your own test command
    blocking: true
    test_command: go test ./... # replace with your language's test runner
    test_timeout: 10m
    coverage:
      enabled: true
      blocking: true
      command: go test ./... -coverprofile=coverage.out
      timeout: 15m
      threshold: 60
      file: coverage.out
tool_versions:
  gitleaks: ">=8.0.0"
  trufflehog: ">=3.0.0"
  semgrep: ">=1.0.0"
  osv_scanner: ">=1.0.0"
  trivy: ">=0.50.0"
allowlist:
  - pattern: "example-test-secret"
    reason: "fixture data"
    owner: "security@company.com"
    expires_on: "2026-12-31"
```

## Homebrew Tap Packaging

1. Compute source tarball sha256 for `vX.Y.Z`.
2. Render formula from template:

```bash
packaging/scripts/prepare-homebrew-formula.sh \
  --owner <github-owner> \
  --repo <github-repo> \
  --version <x.y.z>
```

3. Copy `packaging/homebrew/prehook.rb` into your tap repo under `Formula/prehook.rb`.
4. Publish release artifacts with `goreleaser`.

Advanced manual rendering: `packaging/scripts/render-homebrew-formula.sh`.
Template file: `packaging/homebrew/prehook.rb.tmpl`.

## Caveat

Git hooks are local controls and can be bypassed intentionally with `--no-verify`. Treat `prehook` as a local guardrail, not a complete enforcement layer.
