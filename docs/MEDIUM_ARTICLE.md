# I Built a Tool to Stop Secrets Before They Leave the Developer's Machine

## Why CI-based secret scanning isn't early enough, and what I did about it

---

Last year, I watched a colleague rotate an AWS key, scrub commit history, file an incident report, and burn half a day -- all because one config file slipped through `git push` with a hardcoded credential. CI caught it in six minutes. By then, the secret was in the remote, in reflog, and mirrored.

The fix worked. The process worked. But the question stuck: **why did that secret ever leave his machine?**

---

## The problem is timing, not tooling

CI-based secret scanning is good. GitHub Advanced Security, GitGuardian, TruffleHog CI -- they all work. The problem is _when_ they work: three to ten minutes after `git push`.

In that window, the credential is exposed. Even if the PR is blocked, the secret exists in Git history. Rotation mitigates it. It doesn't undo it.

The GitGuardian 2026 State of Secrets Sprawl report puts the number at **29 million secrets** detected on GitHub in 2025 alone. A 34% year-over-year increase. And 64% of secrets from 2022 are still unrevoked today. The pipeline isn't catching everything, and what it catches, it catches late.

I wanted something that ran _before_ `git commit` finalized. Not in CI. Not in a PR review. On the developer's machine, before the secret ever touches the network.

---

## What I built

[prehook](https://github.com/arunsanna/prehook) is a single Go binary that installs local `pre-commit` and `pre-push` Git hooks. No runtime dependencies beyond the scanner tools it orchestrates. Three commands to set up:

```bash
prehook init       # generates .prehook.yaml with secure defaults
prehook install    # wires into .git/hooks/pre-commit and pre-push
prehook doctor     # validates all scanner binaries are present
```

That's the entire setup. From here, every `git commit` and `git push` runs through security gates automatically.

---

## The two-gate architecture

The key design decision was separating the hooks into two gates with different performance profiles and purposes.

### Gate 1: pre-commit (fast, every commit)

This gate runs two secret scanners:

- **gitleaks** -- pattern-based detection for API keys, tokens, passwords
- **trufflehog** -- with a critical distinction: it can _verify_ whether a detected secret is actually live

The important implementation detail: **the scan targets the Git index, not the working tree.** Before scanning, prehook materializes the staged snapshot into a temporary directory and points the scanners there. This means you're scanning exactly what will be committed -- not your unstaged experiments, editor temp files, or that `.env` you haven't committed.

This eliminates an entire class of false positives that make developers bypass hooks.

```yaml
pre_commit:
  blocking: true
  gitleaks:
    enabled: true
    timeout: 2m
  trufflehog:
    enabled: true
    block_verified: true # confirmed live secret = hard block
    block_unknown: false # regex match but unverified = warn
```

The verified vs. unverified distinction matters. A confirmed live AWS key is a different severity than a string that looks like a key but might be a test fixture. `block_verified: true` and `block_unknown: false` is the sweet spot for most teams -- hard-block real threats, surface potential issues without blocking flow.

### Gate 2: pre-push (heavier, at push time)

Push is a natural checkpoint -- the developer is already context-switching. This gate handles:

- **semgrep** -- static analysis on changed files only
- **osv-scanner** -- known dependency vulnerabilities, but only when dependency manifests actually changed (smart-skipped otherwise)
- **trivy** -- filesystem vulnerability and misconfiguration scan
- **test + coverage** -- your own test suite with an enforced coverage threshold

```yaml
pre_push:
  semgrep:
    enabled: true
  osv:
    enabled: true
  trivy:
    severity: HIGH,CRITICAL
  quality:
    enabled: true
    test_command: go test ./...
    coverage:
      enabled: true
      threshold: 60
```

The OSV smart-skip is worth calling out. Most commits are code changes, not dependency updates. Running a full dependency vulnerability scan on every push when no manifests changed is pure waste. prehook recognizes 20+ manifest and lockfile formats (Go, npm, Python, Rust, Ruby, Java, PHP, NuGet) and skips the scan when none are in the changeset.

---

## The allowlist: accountability built in

Every codebase has false positives. The question is how you suppress them.

Most tools let you add a comment like `# nosec` or a regex to an ignore file with no context. Six months later, nobody knows why it's there or whether it's still valid.

prehook requires four fields for every allowlist entry:

```yaml
allowlist:
  - pattern: "AKIAIOSFODNN7EXAMPLE"
    reason: "AWS documentation example key, not a real credential"
    owner: "arun@example.com"
    expires_on: 2026-07-01
```

- **pattern** -- what to suppress
- **reason** -- why it's safe to suppress
- **owner** -- who made this decision
- **expires_on** -- when to re-evaluate

No anonymous suppressions. No permanent exceptions. When an entry expires, prehook emits a warning on every run, forcing the team to re-evaluate whether the suppression is still valid.

This is a small design choice that produces outsized cultural effects. It turns "we ignore this" into "Sarah decided on March 3rd that this is a test fixture, and we'll re-evaluate in July."

---

## The doctor command: onboarding solved

The biggest friction with local security tools is setup. Every developer needs the scanner binaries installed locally. prehook addresses this with `prehook doctor`:

```
$ prehook doctor

[ OK ] git            2.43.0 (pin >=2.0.0)
[ OK ] gitleaks       8.24.2 (pin >=8.0.0)
[ OK ] trufflehog     3.90.0 (pin >=3.0.0)
[ OK ] semgrep        1.58.0 (pin >=1.0.0)
[FAIL] osv-scanner    missing (required by pre-push dependency scan)
[ OK ] trivy          0.50.1 (pin >=0.50.0)
```

It validates every enabled scanner is installed, checks version pins (with operators: `=`, `>`, `>=`, `<`, `<=`), and tells you exactly what's missing. Add `prehook doctor` to your onboarding documentation or Makefile. New developers know their environment is ready before writing a single commit.

The `--require-pins` flag enforces that all required binaries have version pins configured. Useful in teams where scanner version drift has caused inconsistent results.

---

## What happens when it catches something

```
$ git commit -m "add payment integration"

pre-commit: scanning 3 staged files from index snapshot
[ OK ] gitleaks
[FAIL] trufflehog: Detected 1 verified secret finding(s).
error: pre-commit blocked by 1 failing gate(s)
```

The commit doesn't happen. The secret never enters Git history. The developer:

1. Rotates the credential (it may have been used locally)
2. Removes it from the code
3. Re-commits

`prehook cleanup` prints a remediation checklist including `git-filter-repo` commands if the secret did make it into local history. It deliberately does _not_ auto-rewrite history -- that's a destructive operation that should be intentional.

---

## Honest about the limits

I want to be direct about what this doesn't solve:

**Git hooks are bypassable.** `git commit --no-verify` skips all hooks. This is Git's design, not a bug. prehook is a guardrail, not a fence. It catches mistakes. It doesn't prevent malicious intent. CI scanning is the backstop.

**This doesn't replace secrets management.** The right answer is to never have secrets in code -- use vault systems, environment variables, or cloud IAM roles. Local hooks catch the cases where that discipline breaks down, which it always does.

**Scanners need to be installed locally.** Unlike a SaaS CI integration, every developer needs the binaries. `prehook doctor` reduces the friction, but the dependency exists.

The value isn't perfection. It's catching the 90% of accidental leaks that happen because someone was moving fast, testing locally, or copied from a Stack Overflow answer where the "example" key was real.

---

## Getting started

```bash
# Install prehook
go install github.com/arunsanna/prehook@latest
# or: brew tap arunsanna/tap && brew install prehook

# Set up in any repo
cd your-repo
prehook init
prehook install
prehook doctor
```

The `.prehook.yaml` file is designed to be checked into your repository. Secure defaults ship out of the box -- every scanner is enabled and blocking. Opt in to quality gates (test commands, coverage thresholds) when your team is ready.

The source is on [GitHub](https://github.com/arunsanna/prehook). It's a single Go binary, MIT licensed, with builds for macOS, Linux, and Windows on both amd64 and arm64.

---

_You can't un-push a secret. But you can stop it from being pushed in the first place._

---

**Tags:** DevSecOps, Git, Security, Open Source, Developer Tools, Secrets Management, Go, Shift Left

---

_Arun Sanna is a software engineer focused on developer security tooling and cloud infrastructure. Find him on [GitHub](https://github.com/arunsanna) and [LinkedIn](https://linkedin.com/in/arunsanna)._
