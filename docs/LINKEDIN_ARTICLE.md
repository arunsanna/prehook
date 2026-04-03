# prehook -- Stop Secrets Before They Ship

**A comic-style LinkedIn article for launch day**

---

## PANEL 1: The Crime Scene

_[Scene: A developer staring at a Slack message at 2 AM. Their laptop screen glows ominously. A PagerDuty alert banner reads: "AWS keys found in public repo."]_

**Developer:** "I only pushed one file..."

**Narrator:** Every year, thousands of secrets -- API keys, tokens, passwords -- leak into Git history. Once pushed, they're in reflog, forks, and caches. Rotation alone isn't enough. The commit already happened.

---

## PANEL 2: The Usual Suspects

_[Scene: A lineup of "solutions" standing against a wall. Each holds a sign.]_

- **CI Scanner:** "I catch it... 5 minutes after it's public."
- **Manual Review:** "I work great until someone's tired on a Friday."
- **Pre-commit Framework:** "I have 200 plugins. Good luck configuring me."
- **Hope:** "It probably won't happen to us."

**Narrator:** The problem? Most security scanning happens _after_ the code leaves the developer's machine. By then, the secret is already in history.

---

## PANEL 3: Enter prehook

_[Scene: A single binary drops onto a terminal like a superhero landing. The terminal shows three commands.]_

```
prehook init       # generates .prehook.yaml with secure defaults
prehook install    # wires into .git/hooks (pre-commit + pre-push)
prehook doctor     # validates all scanner tools are present
```

**prehook:** "I'm a local Git hook security gate. One binary. Two stages. Zero secrets shipped."

**Narrator:** `prehook` runs _before_ your code leaves your machine. Not in CI. Not in a review. Right here, right now, on `git commit` and `git push`.

---

## PANEL 4: The Two Gates

_[Scene: Split panel. Left side shows a commit gate, right side shows a push gate. Each has a bouncer checking IDs.]_

### Left: pre-commit (The Secret Detector)

| Scanner    | What it catches                                  |
| ---------- | ------------------------------------------------ |
| gitleaks   | API keys, tokens, passwords in staged files      |
| trufflehog | Verified secrets (confirmed live) vs. unverified |

**Bouncer:** "Verified secret? BLOCKED. Unverified? I'll warn you but let you decide."

_Scans only the staged snapshot from the Git index -- not your messy working tree._

### Right: pre-push (The Quality Gate)

| Scanner         | What it catches                                                    |
| --------------- | ------------------------------------------------------------------ |
| semgrep         | Static analysis violations in changed files                        |
| osv-scanner     | Known vulnerabilities in dependencies (only when manifests change) |
| trivy           | Filesystem vuln + config scan                                      |
| test + coverage | Your own test suite with coverage threshold                        |

**Bouncer:** "You're not pushing 40% coverage on my watch."

---

## PANEL 5: The Config (It's Just YAML)

_[Scene: A developer opens .prehook.yaml. The file is short and readable. They change one line.]_

```yaml
version: 1
pre_commit:
  blocking: true # block commit on failures
  gitleaks:
    enabled: true
    timeout: 2m
  trufflehog:
    enabled: true
    block_verified: true # block confirmed live secrets
    block_unknown: false # warn on unverified (your call)

pre_push:
  trivy:
    severity: HIGH,CRITICAL
  quality:
    enabled: true # opt-in: bring your own test runner
    test_command: go test ./... # or: npm test, pytest, cargo test...
    coverage:
      enabled: true
      command: go test ./... -coverprofile=coverage.out
      threshold: 60 # minimum coverage to push
```

**Developer:** "Wait, that's it? I just set `block_verified: true` and it blocks live AWS keys?"

**prehook:** "Yes. And when you have a known false positive, add it to the allowlist with an owner, reason, and expiry date. No anonymous suppression."

---

## PANEL 6: The Doctor Is In

_[Scene: Terminal output from `prehook doctor`. Green checkmarks and one red X.]_

```
[ OK ] git            2.43.0 (pin >=2.0.0)
[ OK ] gitleaks       8.24.2 (pin >=8.0.0)
[ OK ] trufflehog     3.90.0 (pin >=3.0.0)
[ OK ] semgrep        1.58.0 (pin >=1.0.0)
[FAIL] osv-scanner    missing (required by pre-push dependency scan)
[ OK ] trivy          0.50.1 (pin >=0.50.0)
```

**prehook:** "Install osv-scanner and run me again. I'll wait."

**Narrator:** `prehook doctor` validates that every required scanner is installed and optionally checks version pins. Run it in onboarding docs. Run it in your Makefile. It tells you exactly what's missing.

---

## PANEL 7: What Happens When It Catches Something

_[Scene: A developer tries to commit. The terminal lights up red.]_

```
$ git commit -m "add payment integration"

pre-commit: scanning 3 staged files from index snapshot
[ OK ] gitleaks
[FAIL] trufflehog: Detected 1 verified secret finding(s).
error: pre-commit blocked by 1 failing gate(s)
```

**Developer:** "It caught the Stripe key I accidentally left in the config file."

**prehook:** "You're welcome. Now rotate it, remove it, and try again. Run `prehook cleanup` if you need the remediation checklist."

---

## PANEL 8: The Philosophy

_[Scene: A whiteboard with three principles written on it. A team stands around nodding.]_

1. **Shift left to the developer's machine** -- Don't wait for CI to tell you about a leaked secret 5 minutes after it's public.

2. **Secure defaults, easy overrides** -- Everything blocks by default. Downgrade to warnings intentionally, not accidentally.

3. **Honest about its limits** -- Git hooks can be bypassed with `--no-verify`. prehook is a guardrail, not a fence. Pair it with CI scanning for defense in depth.

---

## PANEL 9: Get Started in 60 Seconds

_[Scene: A terminal with a stopwatch showing 47 seconds.]_

```bash
# Install (pick one)
go install github.com/arunsanna/prehook@latest
# or: brew tap arunsanna/tap && brew install prehook

# Set up in any repo
cd your-repo
prehook init
prehook install
prehook doctor

# That's it. Your next commit is guarded.
```

---

## PANEL 10: The Closing

_[Scene: The same developer from Panel 1, now sleeping peacefully. Their laptop shows a green terminal: "pre-commit: all gates passed."]_

**Narrator:** You can't un-push a secret. But you can stop it from being pushed in the first place.

**prehook** -- local Git hook security gates. One binary. Two stages. Zero secrets shipped.

GitHub: [link to repo]

---

### Hashtags

#DevSecOps #GitSecurity #SecretDetection #OpenSource #DeveloperTools #ShiftLeft #AppSec #SecurityEngineering #DevTools #GitHooks

---

_Tips for posting on LinkedIn:_

1. **Lead image**: Create a comic panel of Panel 1 or Panel 7 (the "catch" moment) as the post thumbnail.
2. **Post format**: Use the article/newsletter format for the full piece. For a regular post, use Panels 1 + 3 + 9 as a condensed version (hook, solution, CTA).
3. **Engagement hook**: Start the LinkedIn post with: "A developer pushed one file. It contained an AWS key. By the time CI caught it, it was already in 3 forks."
4. **Call to action**: End with "Star the repo if you think secrets should be caught before they're pushed, not after."
