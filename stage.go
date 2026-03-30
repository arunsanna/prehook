package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type gateIssue struct {
	Gate     string
	Blocking bool
	Message  string
	Output   string
}

type compiledAllowlistEntry struct {
	entry AllowlistEntry
	regex *regexp.Regexp
}

var coveragePercentPattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)%`)

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

func compileAllowlist(entries []AllowlistEntry) ([]compiledAllowlistEntry, error) {
	compiled := make([]compiledAllowlistEntry, 0, len(entries))
	for _, entry := range entries {
		rx, err := regexp.Compile(entry.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allowlist pattern %q: %w", entry.Pattern, err)
		}
		compiled = append(compiled, compiledAllowlistEntry{
			entry: entry,
			regex: rx,
		})
	}
	return compiled, nil
}

func allowlisted(text string, entries []compiledAllowlistEntry) bool {
	for _, entry := range entries {
		if entry.regex.MatchString(text) {
			return true
		}
	}
	return false
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

type trufflehogFinding struct {
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	Redacted       string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Path string `json:"path"`
			} `json:"Filesystem"`
			Git struct {
				File string `json:"file"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func gitleaksArgs(snapshotDir string, configPath string, extra []string) []string {
	args := []string{"detect", "--no-git", "--source", snapshotDir, "--redact", "--exit-code", "1"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	return append(args, extra...)
}

func trufflehogArgs(snapshotDir string, extra []string) []string {
	args := []string{"filesystem", "--json", "--no-update"}
	args = append(args, extra...)
	args = append(args, snapshotDir)
	return args
}

func semgrepArgs(targets []string, extra []string) []string {
	args := []string{"scan", "--error", "--config", "auto"}
	args = append(args, extra...)
	args = append(args, targets...)
	return args
}

func osvArgs(extra []string) []string {
	args := []string{"--recursive"}
	args = append(args, extra...)
	args = append(args, ".")
	return args
}

func trivyArgs(severity string, extra []string) []string {
	args := []string{"fs", "--scanners", "vuln,config", "--severity", severity, "--exit-code", "1"}
	args = append(args, extra...)
	args = append(args, ".")
	return args
}

func writeGitleaksConfig(allowlist []compiledAllowlistEntry, extraArgs []string) (string, func(), error) {
	if len(allowlist) == 0 {
		return "", nil, nil
	}
	if containsAnyArg(extraArgs, "--config", "-c") {
		return "", nil, fmt.Errorf("prehook allowlist cannot be combined with custom gitleaks --config args")
	}

	var builder strings.Builder
	builder.WriteString("title = \"prehook generated config\"\n\n")
	builder.WriteString("[extend]\n")
	builder.WriteString("useDefault = true\n\n")
	builder.WriteString("[allowlist]\n")
	builder.WriteString("description = \"prehook allowlist\"\n")
	builder.WriteString("regexes = [\n")
	for _, entry := range allowlist {
		builder.WriteString("  ")
		builder.WriteString(strconv.Quote(entry.entry.Pattern))
		builder.WriteString(",\n")
	}
	builder.WriteString("]\n")
	builder.WriteString("paths = [\n")
	for _, entry := range allowlist {
		builder.WriteString("  ")
		builder.WriteString(strconv.Quote(entry.entry.Pattern))
		builder.WriteString(",\n")
	}
	builder.WriteString("]\n")

	file, err := os.CreateTemp("", "prehook-gitleaks-*.toml")
	if err != nil {
		return "", nil, fmt.Errorf("create gitleaks config: %w", err)
	}
	path := file.Name()
	if _, err := file.WriteString(builder.String()); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("write gitleaks config: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("close gitleaks config: %w", err)
	}
	return path, func() {
		_ = os.Remove(path)
	}, nil
}

func containsAnyArg(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name || strings.HasPrefix(arg, name+"=") {
				return true
			}
		}
	}
	return false
}

func parseTrufflehogFindings(output string) ([]trufflehogFinding, error) {
	findings := make([]trufflehogFinding, 0)
	text := strings.TrimSpace(output)
	if text == "" {
		return findings, nil
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		finding := trufflehogFinding{}
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			return nil, fmt.Errorf("line %q: %w", line, err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func summarizeTrufflehogFindings(findings []trufflehogFinding, allowlist []compiledAllowlistEntry) (verified int, unknown int, suppressed int) {
	for _, finding := range findings {
		if trufflehogFindingAllowlisted(finding, allowlist) {
			suppressed++
			continue
		}
		if finding.Verified {
			verified++
		} else {
			unknown++
		}
	}
	return verified, unknown, suppressed
}

func trufflehogFindingAllowlisted(finding trufflehogFinding, allowlist []compiledAllowlistEntry) bool {
	for _, candidate := range trufflehogAllowlistCandidates(finding) {
		if allowlisted(candidate, allowlist) {
			return true
		}
	}
	return false
}

func trufflehogAllowlistCandidates(finding trufflehogFinding) []string {
	candidates := []string{
		strings.TrimSpace(finding.Raw),
		strings.TrimSpace(finding.RawV2),
		strings.TrimSpace(finding.Redacted),
		strings.TrimSpace(finding.SourceMetadata.Data.Filesystem.File),
		strings.TrimSpace(finding.SourceMetadata.Data.Filesystem.Path),
		strings.TrimSpace(finding.SourceMetadata.Data.Git.File),
	}

	filtered := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		filtered = append(filtered, candidate)
	}
	return filtered
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

func resolveCoveragePercent(repoRoot string, coverageFile string, commandOutput string) (float64, error) {
	if strings.TrimSpace(coverageFile) != "" {
		full := filepath.Join(repoRoot, coverageFile)
		if _, err := os.Stat(full); err == nil {
			return resolveCoveragePercentFromFile(repoRoot, coverageFile)
		}
	}

	percent, ok := parseCoveragePercentToken(commandOutput)
	if !ok {
		return 0, fmt.Errorf("coverage percent token not found in command output")
	}
	return percent, nil
}

func resolveCoveragePercentFromFile(repoRoot string, coverageFile string) (float64, error) {
	full := filepath.Join(repoRoot, coverageFile)
	data, err := os.ReadFile(full)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", coverageFile, err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return 0, fmt.Errorf("coverage file %s is empty", coverageFile)
	}

	if strings.HasPrefix(firstNonEmptyLine(text), "mode:") {
		return resolveGoCoveragePercent(repoRoot, coverageFile)
	}
	if percent, ok := parseCoberturaCoverage(text); ok {
		return percent, nil
	}
	if percent, ok := parseJacocoCoverage(text); ok {
		return percent, nil
	}
	if percent, ok := parseLCOVCoverage(text); ok {
		return percent, nil
	}
	if percent, ok := parseCoveragePercentToken(text); ok {
		return percent, nil
	}
	return 0, fmt.Errorf("unsupported coverage file format in %s", coverageFile)
}

func resolveGoCoveragePercent(repoRoot string, coverageFile string) (float64, error) {
	result := RunBinary(20*time.Second, repoRoot, "go", []string{"tool", "cover", "-func", coverageFile}, nil)
	if result.Err != nil || result.ExitCode != 0 {
		return 0, fmt.Errorf("parse %s with go tool cover: %s", coverageFile, cleanOutput(result.Output))
	}

	line := ""
	for _, candidate := range strings.Split(result.Output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(candidate), "total:") {
			line = candidate
			break
		}
	}
	if line == "" {
		return 0, fmt.Errorf("coverage summary line not found in %s", coverageFile)
	}

	percent, ok := parseCoveragePercentToken(line)
	if !ok {
		return 0, fmt.Errorf("coverage percent not found in %s", line)
	}
	return percent, nil
}

func parseCoberturaCoverage(text string) (float64, bool) {
	var report struct {
		XMLName  xml.Name `xml:"coverage"`
		LineRate string   `xml:"line-rate,attr"`
	}
	if err := xml.Unmarshal([]byte(text), &report); err != nil || report.XMLName.Local != "coverage" || strings.TrimSpace(report.LineRate) == "" {
		return 0, false
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(report.LineRate), 64)
	if err != nil {
		return 0, false
	}
	if value <= 1 {
		value *= 100
	}
	return round2(value), true
}

func parseJacocoCoverage(text string) (float64, bool) {
	type jacocoCounter struct {
		Type    string `xml:"type,attr"`
		Missed  int    `xml:"missed,attr"`
		Covered int    `xml:"covered,attr"`
	}
	var report struct {
		XMLName  xml.Name        `xml:"report"`
		Counters []jacocoCounter `xml:"counter"`
	}
	if err := xml.Unmarshal([]byte(text), &report); err != nil || report.XMLName.Local != "report" {
		return 0, false
	}

	for _, counter := range report.Counters {
		if counter.Type != "LINE" {
			continue
		}
		total := counter.Missed + counter.Covered
		if total == 0 {
			return 0, true
		}
		return round2(float64(counter.Covered) / float64(total) * 100), true
	}
	return 0, false
}

func parseLCOVCoverage(text string) (float64, bool) {
	var covered int
	var total int
	found := false

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "LH:"):
			value, err := strconv.Atoi(strings.TrimPrefix(line, "LH:"))
			if err != nil {
				return 0, false
			}
			covered += value
			found = true
		case strings.HasPrefix(line, "LF:"):
			value, err := strconv.Atoi(strings.TrimPrefix(line, "LF:"))
			if err != nil {
				return 0, false
			}
			total += value
			found = true
		}
	}

	if !found {
		return 0, false
	}
	if total == 0 {
		return 0, true
	}
	return round2(float64(covered) / float64(total) * 100), true
}

func parseCoveragePercentToken(text string) (float64, bool) {
	matches := coveragePercentPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return 0, false
	}

	value, err := strconv.ParseFloat(matches[len(matches)-1][1], 64)
	if err != nil {
		return 0, false
	}
	return round2(value), true
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}
