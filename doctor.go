package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type binaryCheck struct {
	Name        string
	VersionArgs []string
	Required    bool
	Hint        string
	Pin         string
}

func cmdDoctor(args []string, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := flagSet.String("config", defaultConfigFilename, "path to prehook config")
	requirePins := flagSet.Bool("require-pins", false, "fail if required binaries are not pinned in config")
	flagSet.SetOutput(stderr)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		repoRoot, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
	}

	cfg, err := LoadConfig(resolveConfigPath(repoRoot, *configPath))
	if err != nil {
		return err
	}

	checks := buildDoctorChecks(cfg)

	failureCount := 0
	for _, check := range checks {
		if err := runBinaryCheck(check, *requirePins, stdout); err != nil {
			failureCount++
		}
	}

	if failureCount > 0 {
		return fmt.Errorf("doctor found %d failing binary checks", failureCount)
	}

	fmt.Fprintln(stdout, "Doctor checks passed")
	return nil
}

func buildDoctorChecks(cfg Config) []binaryCheck {
	return []binaryCheck{
		{Name: "git", VersionArgs: []string{"--version"}, Required: true, Hint: "required for hook integration", Pin: cfg.ToolVersions.Git},
		{Name: "go", VersionArgs: []string{"version"}, Required: cfg.PrePush.Quality.Enabled, Hint: "required when quality/coverage gates are enabled", Pin: cfg.ToolVersions.Go},
		{Name: "gitleaks", VersionArgs: []string{"version"}, Required: cfg.PreCommit.Gitleaks.Enabled, Hint: "required by pre-commit secret scan", Pin: cfg.ToolVersions.Gitleaks},
		{Name: "trufflehog", VersionArgs: []string{"--version"}, Required: cfg.PreCommit.Trufflehog.Enabled, Hint: "required by pre-commit secret scan", Pin: cfg.ToolVersions.Trufflehog},
		{Name: "semgrep", VersionArgs: []string{"--version"}, Required: cfg.PrePush.Semgrep.Enabled, Hint: "required by pre-push static analysis", Pin: cfg.ToolVersions.Semgrep},
		{Name: "osv-scanner", VersionArgs: []string{"--version"}, Required: cfg.PrePush.OSV.Enabled, Hint: "required by pre-push dependency scan", Pin: cfg.ToolVersions.OSVScanner},
		{Name: "trivy", VersionArgs: []string{"--version"}, Required: cfg.PrePush.Trivy.Enabled, Hint: "required by pre-push repo/config scan", Pin: cfg.ToolVersions.Trivy},
		{Name: "git-filter-repo", VersionArgs: []string{"--version"}, Required: false, Hint: "optional for cleanup history rewrites", Pin: cfg.ToolVersions.GitFilterRepo},
	}
}

func runBinaryCheck(check binaryCheck, requirePins bool, stdout io.Writer) error {
	path, err := exec.LookPath(check.Name)
	if err != nil {
		if check.Required {
			fmt.Fprintf(stdout, "[FAIL] %-14s missing (%s)\n", check.Name, check.Hint)
			return err
		} else {
			fmt.Fprintf(stdout, "[WARN] %-14s missing (%s)\n", check.Name, check.Hint)
			return nil
		}
	}

	result := RunBinary(8*time.Second, ".", check.Name, check.VersionArgs, nil)
	if result.Err != nil || result.ExitCode != 0 {
		if result.TimedOut {
			fmt.Fprintf(stdout, "[WARN] %-14s timed out while running %s\n", check.Name, formatCommand(check.Name, check.VersionArgs))
		} else {
			fmt.Fprintf(stdout, "[WARN] %-14s present at %s, version check failed: %s\n", check.Name, path, cleanOutput(result.Output))
		}
		if check.Required {
			return errors.New("required binary check failed")
		}
		return nil
	}

	line := firstLine(result.Output)
	pin := strings.TrimSpace(check.Pin)
	if pin == "" {
		if check.Required && requirePins {
			fmt.Fprintf(stdout, "[FAIL] %-14s pin missing (set tool_versions.%s in .prehook.yaml)\n", check.Name, pinKeyForBinary(check.Name))
			return errors.New("required binary pin missing")
		}
		fmt.Fprintf(stdout, "[WARN] %-14s %s (un-pinned)\n", check.Name, line)
		return nil
	}

	ok, why := versionSatisfies(line, pin)
	if !ok {
		if check.Required {
			fmt.Fprintf(stdout, "[FAIL] %-14s %s (expected %s)\n", check.Name, line, pin)
			if why != "" {
				fmt.Fprintf(stdout, "       reason: %s\n", why)
			}
			return errors.New("required binary version pin mismatch")
		}
		fmt.Fprintf(stdout, "[WARN] %-14s %s (expected %s)\n", check.Name, line, pin)
		return nil
	}

	fmt.Fprintf(stdout, "[ OK ] %-14s %s (pin %s)\n", check.Name, line, pin)
	return nil
}

func firstLine(text string) string {
	if text == "" {
		return "version unknown"
	}
	parts := strings.Split(text, "\n")
	return strings.TrimSpace(parts[0])
}

func pinKeyForBinary(name string) string {
	switch name {
	case "git":
		return "git"
	case "go":
		return "go"
	case "gitleaks":
		return "gitleaks"
	case "trufflehog":
		return "trufflehog"
	case "semgrep":
		return "semgrep"
	case "osv-scanner":
		return "osv_scanner"
	case "trivy":
		return "trivy"
	case "git-filter-repo":
		return "git_filter_repo"
	default:
		return name
	}
}

var versionTokenPattern = regexp.MustCompile(`v?([0-9]+(?:\.[0-9]+){0,2})`)

func versionSatisfies(versionLine string, pin string) (bool, string) {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return true, ""
	}

	operator := "="
	candidate := pin
	for _, prefix := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(pin, prefix) {
			operator = prefix
			candidate = strings.TrimSpace(strings.TrimPrefix(pin, prefix))
			break
		}
	}

	actualVersion, ok := extractVersionToken(versionLine)
	if !ok {
		if strings.Contains(strings.ToLower(versionLine), strings.ToLower(candidate)) {
			return true, ""
		}
		return false, "no parseable version token found in command output"
	}

	expectedVersion, ok := extractVersionToken(candidate)
	if !ok {
		if strings.Contains(strings.ToLower(versionLine), strings.ToLower(candidate)) {
			return true, ""
		}
		return false, "pin is not parseable; use operators like >=1.2.3"
	}

	actualParts := parseVersionParts(actualVersion)
	expectedParts := parseVersionParts(expectedVersion)
	cmp := compareVersionParts(actualParts, expectedParts)

	switch operator {
	case "=":
		return cmp == 0, ""
	case ">":
		return cmp > 0, ""
	case ">=":
		return cmp >= 0, ""
	case "<":
		return cmp < 0, ""
	case "<=":
		return cmp <= 0, ""
	default:
		return false, "unsupported pin operator"
	}
}

func extractVersionToken(text string) (string, bool) {
	matches := versionTokenPattern.FindStringSubmatch(text)
	if len(matches) != 2 {
		return "", false
	}
	return matches[1], true
}

func parseVersionParts(version string) [3]int {
	out := [3]int{}
	segments := strings.Split(version, ".")
	for idx := 0; idx < len(segments) && idx < 3; idx++ {
		value, err := strconv.Atoi(segments[idx])
		if err != nil {
			return [3]int{}
		}
		out[idx] = value
	}
	return out
}

func compareVersionParts(a [3]int, b [3]int) int {
	for idx := 0; idx < 3; idx++ {
		if a[idx] > b[idx] {
			return 1
		}
		if a[idx] < b[idx] {
			return -1
		}
	}
	return 0
}
