package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestResolveCoveragePercentFromOutput(t *testing.T) {
	percent, err := resolveCoveragePercent(t.TempDir(), "", "coverage total: 81.25%")
	if err != nil {
		t.Fatalf("resolveCoveragePercent failed: %v", err)
	}
	if percent != 81.25 {
		t.Fatalf("expected 81.25, got %.2f", percent)
	}
}

func TestResolveCoveragePercentErrorsOnInvalidCoverageFile(t *testing.T) {
	tempDir := t.TempDir()
	coverageFile := filepath.Join(tempDir, "coverage.out")
	if err := os.WriteFile(coverageFile, []byte("not a go coverprofile\n"), 0o644); err != nil {
		t.Fatalf("write coverage file: %v", err)
	}

	if _, err := resolveCoveragePercent(tempDir, "coverage.out", "TOTAL 88.50%"); err == nil {
		t.Fatalf("expected invalid coverage file to fail")
	}
}

func TestParseTrufflehogFindings(t *testing.T) {
	output := `{"Verified": true}
{"Verified": false}
`
	findings, err := parseTrufflehogFindings(output)
	if err != nil {
		t.Fatalf("parseTrufflehogFindings failed: %v", err)
	}
	verified, unknown, suppressed := summarizeTrufflehogFindings(findings, nil)
	if verified != 1 || unknown != 1 || suppressed != 0 {
		t.Fatalf("unexpected summary: verified=%d unknown=%d suppressed=%d", verified, unknown, suppressed)
	}
}

func TestParseTrufflehogFindingsEmpty(t *testing.T) {
	findings, err := parseTrufflehogFindings("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d", len(findings))
	}
}

func TestScannerArgsIncludeConfiguredArgs(t *testing.T) {
	if got := strings.Join(gitleaksArgs("/tmp/snapshot", "/tmp/config.toml", []string{"--log-level", "debug"}), " "); !strings.Contains(got, "--config /tmp/config.toml") || !strings.Contains(got, "--redact") || !strings.Contains(got, "--log-level debug") {
		t.Fatalf("expected gitleaks args to include configured flags, got %q", got)
	}

	trufflehog := strings.Join(trufflehogArgs("/tmp/snapshot", []string{"--results=verified"}), " ")
	if !strings.Contains(trufflehog, "--results=verified /tmp/snapshot") {
		t.Fatalf("expected trufflehog args to keep configured flags before path, got %q", trufflehog)
	}

	semgrep := strings.Join(semgrepArgs([]string{"app.go"}, []string{"--metrics=off"}), " ")
	if !strings.Contains(semgrep, "--metrics=off app.go") {
		t.Fatalf("expected semgrep args to keep configured flags before targets, got %q", semgrep)
	}

	osv := strings.Join(osvArgs([]string{"--lockfile=go.mod"}), " ")
	if !strings.Contains(osv, "--lockfile=go.mod .") {
		t.Fatalf("expected osv args to keep configured flags before path, got %q", osv)
	}

	trivy := strings.Join(trivyArgs("HIGH,CRITICAL", []string{"--skip-dirs", "vendor"}), " ")
	if !strings.Contains(trivy, "--skip-dirs vendor .") {
		t.Fatalf("expected trivy args to keep configured flags before path, got %q", trivy)
	}
}

func TestWriteGitleaksConfigExtendsDefaultRules(t *testing.T) {
	configPath, cleanup, err := writeGitleaksConfig([]compiledAllowlistEntry{{
		entry: AllowlistEntry{Pattern: "example-test-secret"},
	}}, nil)
	if err != nil {
		t.Fatalf("writeGitleaksConfig failed: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "useDefault = true") {
		t.Fatalf("expected generated config to extend default rules, got %q", text)
	}
	if !strings.Contains(text, "\"example-test-secret\"") {
		t.Fatalf("expected generated config to include allowlist pattern, got %q", text)
	}
}

func TestSummarizeTrufflehogFindingsMatchesRelevantFieldsOnly(t *testing.T) {
	findings := []trufflehogFinding{{
		Verified: true,
		Raw:      "token=TOPSECRET",
	}}
	allowlist := []compiledAllowlistEntry{{
		entry: AllowlistEntry{Pattern: "TOPSECRET"},
		regex: regexp.MustCompile("TOPSECRET"),
	}}

	verified, unknown, suppressed := summarizeTrufflehogFindings(findings, allowlist)
	if verified != 0 || unknown != 0 || suppressed != 1 {
		t.Fatalf("unexpected summary: verified=%d unknown=%d suppressed=%d", verified, unknown, suppressed)
	}

	allowlist = []compiledAllowlistEntry{{
		entry: AllowlistEntry{Pattern: "Verified"},
		regex: regexp.MustCompile("Verified"),
	}}
	verified, unknown, suppressed = summarizeTrufflehogFindings(findings, allowlist)
	if verified != 1 || unknown != 0 || suppressed != 0 {
		t.Fatalf("expected metadata-only pattern not to suppress finding, got verified=%d unknown=%d suppressed=%d", verified, unknown, suppressed)
	}
}
