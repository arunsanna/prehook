# prehook MVP Specification

## Objective

Provide local Git hook security gates with small operational footprint and actionable failures.

## Policy Model

- Config file: `.prehook.yaml` at repository root.
- Default posture: blocking for both stages.
- Allowlist records must include `reason`, `owner`, and `expires_on` metadata.
- Stage and tool-level blocking toggles allow controlled downgrade to warnings.
- Toolchain version pins can be enforced via `prehook doctor --require-pins`.

## Stage: pre-commit

1. Collect staged file list from index (`git diff --cached --name-only --diff-filter=ACMR`).
2. Materialize index blobs into temporary snapshot directory.
3. Run `gitleaks detect --no-git --source <snapshot>`.
4. Run `trufflehog filesystem --json --no-update <snapshot>`.
5. Apply trufflehog policy split:
   - block verified findings by default,
   - warn unknown/unverified findings by default.
6. Fail commit if blocking gates fail.

## Stage: pre-push

1. Parse pre-push ref lines from stdin.
2. Compute changed files from `<remote_sha>..<local_sha>` per ref.
3. Fallback path when refs absent: changed files from `HEAD~1..HEAD`; if unavailable, use tracked files.
4. Run `semgrep scan --error --config auto <changed_files>`.
5. Run `osv-scanner --recursive .` only when dependency manifests/lockfiles changed.
6. Run `trivy fs --scanners vuln,config --severity <configured> --exit-code 1 .`.
7. Run quality test command.
8. Run optional coverage command and enforce threshold.
9. Fail push if blocking gates fail.

## Hook Installation

- Install managed `.git/hooks/pre-commit` and `.git/hooks/pre-push` scripts.
- Scripts execute `prehook run --stage <stage>`.
- Idempotent behavior:
  - Existing managed hooks are updated in place.
  - Unmanaged hooks are preserved unless `--force` is supplied.
  - Forced replacement creates timestamped backup.

## Doctor Checks

Validate binary presence and version command execution:

- Required: `git`, `go`, `gitleaks`, `trufflehog`, `semgrep`, `osv-scanner`, `trivy`.
- Optional: `git-filter-repo`.
- Version pin checks:
  - supports `=`, `>`, `>=`, `<`, `<=` operators,
  - defaults are configured in `tool_versions`,
  - `--require-pins` fails when required binaries are unpinned.

## Cleanup Command

`cleanup` prints operator guidance only:

- credential rotation,
- staged/worktree secret removal,
- optional `git-filter-repo` examples,
- coordination reminders for forced history updates.

No history rewrite is performed automatically.

## Homebrew Packaging

- Formula template lives at `packaging/homebrew/prehook.rb.tmpl`.
- Renderer script `scripts/render-homebrew-formula.sh` writes `packaging/homebrew/prehook.rb`.
- Release helper `scripts/prepare-homebrew-formula.sh` computes tarball sha256 and renders a ready formula.
- Formula depends on scanner tools and builds prehook from source with Go.
