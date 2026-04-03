package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type gateIssue struct {
	Gate     string
	Blocking bool
	Message  string
	Output   string
}

func cmdRun(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("run", flag.ContinueOnError)
	stage := flagSet.String("stage", "", "hook stage (pre-commit or pre-push)")
	configPath := flagSet.String("config", defaultConfigFilename, "path to prehook config")
	flagSet.SetOutput(stderr)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if *stage == "" {
		return fmt.Errorf("--stage is required")
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	cfg, err := LoadConfig(resolveConfigPath(repoRoot, *configPath))
	if err != nil {
		return err
	}

	allowlist, err := compileAllowlist(cfg.Allowlist)
	if err != nil {
		return err
	}

	switch *stage {
	case "pre-commit":
		return runPreCommitStage(repoRoot, cfg, allowlist, stdout)
	case "pre-push":
		remoteName := ""
		if extras := flagSet.Args(); len(extras) > 0 {
			remoteName = extras[0]
		}
		refs, err := parsePushRefs(stdin)
		if err != nil {
			return err
		}
		return runPrePushStage(repoRoot, remoteName, refs, cfg, stdout)
	default:
		return fmt.Errorf("unsupported stage %q", *stage)
	}
}

func runPreCommitStage(repoRoot string, cfg Config, allowlist []compiledAllowlistEntry, stdout io.Writer) error {
	snapshot, err := BuildStagedSnapshot(repoRoot)
	if err != nil {
		return err
	}
	if snapshot.Dir != "" {
		defer func() {
			_ = os.RemoveAll(snapshot.Dir)
		}()
	}

	if len(snapshot.Files) == 0 {
		fmt.Fprintln(stdout, "pre-commit: no staged files detected")
		return nil
	}

	fmt.Fprintf(stdout, "pre-commit: scanning %d staged files from index snapshot\n", len(snapshot.Files))

	issues := make([]gateIssue, 0)

	if cfg.PreCommit.Gitleaks.Enabled {
		gitleaksConfigPath, cleanupConfig, err := writeGitleaksConfig(allowlist, cfg.PreCommit.Gitleaks.Args)
		if err != nil {
			return err
		}
		if cleanupConfig != nil {
			defer cleanupConfig()
		}

		result := RunBinary(parseDurationOr(cfg.PreCommit.Gitleaks.Timeout, 2*time.Minute), repoRoot, "gitleaks", gitleaksArgs(snapshot.Dir, gitleaksConfigPath, cfg.PreCommit.Gitleaks.Args), nil)
		if issue := evaluateGate("gitleaks", cfg.PreCommit.Blocking && cfg.PreCommit.Gitleaks.Blocking, result, "Install gitleaks and rerun `prehook doctor`.", "Potential secret detected in staged content.", false); issue != nil {
			issues = append(issues, *issue)
		} else {
			fmt.Fprintln(stdout, "[ OK ] gitleaks")
		}
	}

	if cfg.PreCommit.Trufflehog.Enabled {
		result := RunBinary(parseDurationOr(cfg.PreCommit.Trufflehog.Timeout, 2*time.Minute), repoRoot, "trufflehog", trufflehogArgs(snapshot.Dir, cfg.PreCommit.Trufflehog.Args), nil)

		toolBlocking := cfg.PreCommit.Blocking && cfg.PreCommit.Trufflehog.Blocking
		if errors.Is(result.Err, exec.ErrNotFound) {
			issues = append(issues, gateIssue{
				Gate:     "trufflehog",
				Blocking: toolBlocking,
				Message:  "Binary missing. Install trufflehog and rerun `prehook doctor`.",
			})
		} else if result.TimedOut {
			issues = append(issues, gateIssue{
				Gate:     "trufflehog",
				Blocking: toolBlocking,
				Message:  "Command timed out. Increase timeout in .prehook.yaml or reduce scan scope.",
			})
		} else if result.Err != nil && result.ExitCode != 0 {
			issues = append(issues, gateIssue{
				Gate:     "trufflehog",
				Blocking: toolBlocking,
				Message:  "Trufflehog command failed. Check installation and args in .prehook.yaml.",
			})
		} else {
			findings, parseErr := parseTrufflehogFindings(result.Output)
			if parseErr != nil {
				issues = append(issues, gateIssue{
					Gate:     "trufflehog",
					Blocking: toolBlocking,
					Message:  fmt.Sprintf("Unable to parse trufflehog output: %v", parseErr),
				})
			} else {
				verifiedCount, unknownCount, suppressedCount := summarizeTrufflehogFindings(findings, allowlist)
				blocked := false

				if verifiedCount > 0 && cfg.PreCommit.Trufflehog.BlockVerified {
					message := fmt.Sprintf("Detected %d verified secret finding(s).", verifiedCount)
					if suppressedCount > 0 {
						message = fmt.Sprintf("Detected %d verified secret finding(s) after suppressing %d allowlisted finding(s).", verifiedCount, suppressedCount)
					}
					issues = append(issues, gateIssue{
						Gate:     "trufflehog",
						Blocking: toolBlocking,
						Message:  message,
					})
					blocked = true
				}

				if unknownCount > 0 {
					message := fmt.Sprintf("Detected %d unknown/unverified secret finding(s).", unknownCount)
					if suppressedCount > 0 {
						message = fmt.Sprintf("Detected %d unknown/unverified secret finding(s) after suppressing %d allowlisted finding(s).", unknownCount, suppressedCount)
					}
					issue := gateIssue{
						Gate:     "trufflehog",
						Blocking: toolBlocking && cfg.PreCommit.Trufflehog.BlockUnknown,
						Message:  message,
					}
					issues = append(issues, issue)
					if issue.Blocking {
						blocked = true
					}
				}

				if !blocked && verifiedCount == 0 && unknownCount == 0 {
					if suppressedCount > 0 {
						fmt.Fprintf(stdout, "[ OK ] trufflehog (%d finding(s) suppressed by allowlist)\n", suppressedCount)
					} else {
						fmt.Fprintln(stdout, "[ OK ] trufflehog")
					}
				}
			}
		}
	}

	warnExpiredAllowlist(cfg.Allowlist, stdout)
	issues = applyAllowlist(issues, cfg.Allowlist)
	return finalizeStageIssues("pre-commit", issues, stdout)
}

func runPrePushStage(repoRoot string, remoteName string, refs []PushRef, cfg Config, stdout io.Writer) error {
	changedFiles, err := collectPrePushFiles(repoRoot, remoteName, refs)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "pre-push: detected %d changed files in push range\n", len(changedFiles))
	issues := make([]gateIssue, 0)

	if cfg.PrePush.Semgrep.Enabled {
		targets := existingChangedFiles(repoRoot, changedFiles)
		if len(targets) == 0 {
			fmt.Fprintln(stdout, "[ SKIP ] semgrep (no changed files available on disk)")
		} else {
			args := semgrepArgs(targets, cfg.PrePush.Semgrep.Args)
			result := RunBinary(parseDurationOr(cfg.PrePush.Semgrep.Timeout, 5*time.Minute), repoRoot, "semgrep", args, nil)
			if issue := evaluateGate("semgrep", cfg.PrePush.Blocking && cfg.PrePush.Semgrep.Blocking, result, "Install semgrep and rerun `prehook doctor`.", "Semgrep found policy violations.", true); issue != nil {
				issues = append(issues, *issue)
			} else {
				fmt.Fprintln(stdout, "[ OK ] semgrep")
			}
		}
	}

	if cfg.PrePush.OSV.Enabled {
		if hasManifestChanges(changedFiles) {
			result := RunBinary(parseDurationOr(cfg.PrePush.OSV.Timeout, 5*time.Minute), repoRoot, "osv-scanner", osvArgs(cfg.PrePush.OSV.Args), nil)
			if issue := evaluateGate("osv-scanner", cfg.PrePush.Blocking && cfg.PrePush.OSV.Blocking, result, "Install osv-scanner and rerun `prehook doctor`.", "OSV scanner found vulnerable dependencies.", true); issue != nil {
				issues = append(issues, *issue)
			} else {
				fmt.Fprintln(stdout, "[ OK ] osv-scanner")
			}
		} else {
			fmt.Fprintln(stdout, "[ SKIP ] osv-scanner (no dependency manifest or lockfile changes)")
		}
	}

	if cfg.PrePush.Trivy.Enabled {
		args := trivyArgs(cfg.PrePush.Trivy.Severity, cfg.PrePush.Trivy.Args)
		result := RunBinary(parseDurationOr(cfg.PrePush.Trivy.Timeout, 8*time.Minute), repoRoot, "trivy", args, nil)
		if issue := evaluateGate("trivy", cfg.PrePush.Blocking && cfg.PrePush.Trivy.Blocking, result, "Install trivy and rerun `prehook doctor`.", "Trivy found vulnerabilities or config misconfigurations.", true); issue != nil {
			issues = append(issues, *issue)
		} else {
			fmt.Fprintln(stdout, "[ OK ] trivy")
		}
	}

	if cfg.PrePush.Quality.Enabled {
		if strings.TrimSpace(cfg.PrePush.Quality.TestCommand) != "" {
			result := RunShell(parseDurationOr(cfg.PrePush.Quality.TestTimeout, 10*time.Minute), repoRoot, cfg.PrePush.Quality.TestCommand)
			if issue := evaluateGate("quality-test", cfg.PrePush.Blocking && cfg.PrePush.Quality.Blocking, result, "Confirm your local test command in .prehook.yaml.", "Quality test command failed.", true); issue != nil {
				issues = append(issues, *issue)
			} else {
				fmt.Fprintln(stdout, "[ OK ] quality-test")
			}
		}

		coverage := cfg.PrePush.Quality.CoverageGate
		if coverage.Enabled && strings.TrimSpace(coverage.Command) != "" {
			result := RunShell(parseDurationOr(coverage.Timeout, 15*time.Minute), repoRoot, coverage.Command)
			if issue := evaluateGate("coverage-command", cfg.PrePush.Blocking && cfg.PrePush.Quality.Blocking && coverage.Blocking, result, "Fix the coverage command in .prehook.yaml.", "Coverage command failed.", true); issue != nil {
				issues = append(issues, *issue)
			} else {
				percent, parseErr := resolveCoveragePercent(repoRoot, coverage.File, result.Output)
				if parseErr != nil {
					issues = append(issues, gateIssue{
						Gate:     "coverage-threshold",
						Blocking: cfg.PrePush.Blocking && cfg.PrePush.Quality.Blocking && coverage.Blocking,
						Message:  fmt.Sprintf("Unable to parse coverage output: %v", parseErr),
						Output:   cleanOutput(result.Output),
					})
				} else if coverage.Threshold > 0 && percent < coverage.Threshold {
					issues = append(issues, gateIssue{
						Gate:     "coverage-threshold",
						Blocking: cfg.PrePush.Blocking && cfg.PrePush.Quality.Blocking && coverage.Blocking,
						Message:  fmt.Sprintf("Coverage %.2f%% is below threshold %.2f%%", percent, coverage.Threshold),
						Output:   cleanOutput(result.Output),
					})
				} else {
					fmt.Fprintf(stdout, "[ OK ] coverage-threshold (%.2f%%)\n", percent)
				}
			}
		}
	}

	warnExpiredAllowlist(cfg.Allowlist, stdout)
	issues = applyAllowlist(issues, cfg.Allowlist)
	return finalizeStageIssues("pre-push", issues, stdout)
}

func evaluateGate(gate string, blocking bool, result CommandResult, installHint string, nonZeroHint string, includeOutput bool) *gateIssue {
	if result.Err == nil && result.ExitCode == 0 {
		return nil
	}

	if errors.Is(result.Err, exec.ErrNotFound) {
		return &gateIssue{
			Gate:     gate,
			Blocking: blocking,
			Message:  fmt.Sprintf("Binary missing. %s", installHint),
		}
	}

	if result.TimedOut {
		return &gateIssue{
			Gate:     gate,
			Blocking: blocking,
			Message:  "Command timed out. Increase timeout in .prehook.yaml or reduce scan scope.",
			Output:   maybeOutput(result.Output, includeOutput),
		}
	}

	if result.ExitCode != 0 {
		return &gateIssue{
			Gate:     gate,
			Blocking: blocking,
			Message:  nonZeroHint,
			Output:   maybeOutput(result.Output, includeOutput),
		}
	}

	return &gateIssue{
		Gate:     gate,
		Blocking: blocking,
		Message:  fmt.Sprintf("Command execution failed: %v", result.Err),
		Output:   cleanOutput(result.Output),
	}
}

func maybeOutput(output string, includeOutput bool) string {
	if !includeOutput {
		return ""
	}
	return cleanOutput(output)
}

func finalizeStageIssues(stage string, issues []gateIssue, stdout io.Writer) error {
	if len(issues) == 0 {
		fmt.Fprintf(stdout, "%s: all gates passed\n", stage)
		return nil
	}

	blockingFailures := 0
	for _, issue := range issues {
		if issue.Blocking {
			blockingFailures++
			fmt.Fprintf(stdout, "[FAIL] %s: %s\n", issue.Gate, issue.Message)
		} else {
			fmt.Fprintf(stdout, "[WARN] %s: %s\n", issue.Gate, issue.Message)
		}
		if issue.Output != "" {
			fmt.Fprintf(stdout, "%s\n", issue.Output)
		}
	}

	if blockingFailures > 0 {
		return fmt.Errorf("%s blocked by %d failing gate(s)", stage, blockingFailures)
	}
	fmt.Fprintf(stdout, "%s completed with warnings only\n", stage)
	return nil
}

func parseDurationOr(value string, fallback time.Duration) time.Duration {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

func hasManifestChanges(files []string) bool {
	for _, file := range files {
		if isDependencyManifest(file) {
			return true
		}
	}
	return false
}

func isDependencyManifest(file string) bool {
	base := strings.ToLower(filepath.Base(file))
	manifestNames := map[string]struct{}{
		"go.mod":             {},
		"go.sum":             {},
		"package-lock.json":  {},
		"pnpm-lock.yaml":     {},
		"yarn.lock":          {},
		"package.json":       {},
		"requirements.txt":   {},
		"poetry.lock":        {},
		"pipfile":            {},
		"pipfile.lock":       {},
		"cargo.toml":         {},
		"cargo.lock":         {},
		"gemfile":            {},
		"gemfile.lock":       {},
		"pom.xml":            {},
		"build.gradle":       {},
		"build.gradle.kts":   {},
		"gradle.lockfile":    {},
		"composer.json":      {},
		"composer.lock":      {},
		"nuget.config":       {},
		"packages.lock.json": {},
	}
	if _, ok := manifestNames[base]; ok {
		return true
	}

	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return true
	}
	return false
}
