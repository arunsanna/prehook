package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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

var coveragePercentPattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)%`)

// Scanner argument builders

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

// Gitleaks config generation

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

// Trufflehog output parsing

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

// Coverage parsing

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
	full := filepath.Clean(filepath.Join(repoRoot, coverageFile))
	data, err := os.ReadFile(full) //nolint:gosec // coverageFile is from trusted .prehook.yaml config
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
