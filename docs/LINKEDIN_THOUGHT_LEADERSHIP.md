# Why Your Secret Scanner Is 5 Minutes Too Late

## A LinkedIn Article by Arun Sanna

---

Here's a scenario most engineering teams have lived through:

A developer pushes a commit. CI runs. Six minutes later, a secret scanner flags an AWS key in a config file. The developer rotates the key, scrubs the commit history, and files an incident report.

The system worked. And the secret was still exposed for six minutes in a remote repository, in reflog, potentially mirrored and forked.

**This is the five-minute gap.** The window between `git push` and CI detection where credentials are live, public, and unrecoverable by rotation alone.

---

## The numbers tell the story

GitGuardian's 2026 State of Secrets Sprawl report:

- **29 million** secrets detected on GitHub in 2025
- **34% increase** year-over-year -- the largest single-year jump recorded
- **64%** of secrets leaked in 2022 remain unrevoked today

CI-based scanning is necessary. It is not sufficient. The secret has already left the developer's machine by the time CI sees it.

---

## The shift most teams haven't made

We talk about "shift left" constantly in DevSecOps. But most secret scanning still happens in CI -- which is the middle of the pipeline, not the left edge.

The actual left edge is the developer's machine. Specifically, the moment between writing code and committing it.

Git provides two natural interception points:

1. **pre-commit** -- runs before a commit is finalized
2. **pre-push** -- runs before code reaches the remote

These hooks exist in every Git installation. Most teams don't use them for security. The ones that do typically wire up shell scripts that scan the working directory (catching unstaged files and producing false positives) or rely on framework-based tools that require complex per-language configuration.

---

## What a production-grade local gate looks like

I built **prehook** to implement this properly. It's a single Go binary -- no runtime dependencies beyond the scanner tools -- that wires into both Git hooks with three commands:

```
prehook init       # secure defaults in .prehook.yaml
prehook install    # hooks into pre-commit + pre-push
prehook doctor     # validates scanner tools are installed
```

Three design decisions set it apart:

### 1. Scan the Git index, not the working tree

Most approaches scan the working directory. This picks up unstaged experiments, editor temp files, and that `.env` you haven't committed. False positives train developers to bypass hooks.

prehook materializes the staged snapshot -- the exact bytes that will be committed -- into a temporary directory and scans that. Precision eliminates noise.

### 2. Distinguish verified from unverified secrets

A confirmed live AWS key is not the same as a string that matches a regex. prehook integrates TruffleHog's verification capability:

- **Verified secrets** (confirmed live) = hard block, always
- **Unverified findings** (pattern match, status unknown) = configurable per team

This is the difference between a tool developers trust and a tool they bypass.

### 3. Accountable suppressions

Every allowlist entry requires four fields: **pattern**, **reason**, **owner**, and **expiration date**. No anonymous exceptions. No permanent suppressions. When entries expire, the tool warns on every run.

This turns "we ignore this" into an auditable decision with a named owner and a review date.

---

## The two-gate model

**Pre-commit** handles secret detection (gitleaks + trufflehog). It's fast -- under 5 seconds -- and runs on every commit.

**Pre-push** handles deeper analysis: static analysis (semgrep), dependency vulnerability scanning (osv-scanner, trivy), and optional test/coverage enforcement. It's heavier, but push is a natural context-switch point where developers accept longer gates.

The OSV scanner is smart-skipped when no dependency manifests changed. Most commits are code, not dependency updates -- no reason to scan what hasn't changed.

---

## What this doesn't replace

I want to be clear about the boundaries:

- **Git hooks are bypassable.** `--no-verify` skips them. This is a guardrail, not a fence. CI scanning remains essential as the backstop.
- **This isn't secrets management.** The right answer is vault systems, IAM roles, and environment variables. Local hooks catch the inevitable lapses.
- **Scanners need local installation.** `prehook doctor` reduces friction, but the dependency exists.

The goal is not perfection. It's catching the 90% of accidental leaks that happen because someone was moving fast.

---

## The principle matters more than the tool

Whether you use prehook, wire up your own hooks, or use another framework -- the principle is the same:

**Stop secrets before they ship. Not after.**

Every minute a credential spends in a remote repository is a minute it can be harvested. CI tells you about the problem. Local gates prevent it.

If you're building a security program and your secret scanning starts at CI, you have a five-minute gap. Close it.

---

_You can't un-push a secret. But you can stop it from being pushed in the first place._

prehook is open source: [github.com/arunsanna/prehook](https://github.com/arunsanna/prehook)

---

#DevSecOps #GitSecurity #SecretDetection #ShiftLeft #OpenSource #AppSec #SecurityEngineering #DeveloperTools #SoftwareEngineering #CyberSecurity

---

### LinkedIn Posting Notes

**Format:** Publish as a LinkedIn Article (not a regular post) for full formatting support.

**Companion post** (for the feed, linking to the article):

> A developer pushes one file. It contains an AWS key. CI catches it 6 minutes later.
>
> By then it's in the remote, in reflog, and potentially forked.
>
> I built an open-source tool that catches secrets before `git commit` -- not after `git push`.
>
> Three design decisions that make it work:
>
> 1. Scan the Git index (staged snapshot), not the working tree
> 2. Distinguish verified secrets from pattern matches
> 3. Require accountable suppressions with owners and expiry dates
>
> Full article below. The tool is prehook -- MIT licensed, single Go binary.
>
> Link in article.

**Suggested images:**

- Use `images/diagram_secret_leak_timeline.png` as the article cover image
- Use `images/diagram_two_gate_architecture.png` inline at the two-gate section
