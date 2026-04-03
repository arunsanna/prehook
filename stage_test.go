package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestIsDependencyManifest(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "go.mod", want: true},
		{path: "frontend/package-lock.json", want: true},
		{path: "api/requirements-dev.txt", want: true},
		{path: "src/main.go", want: false},
	}

	for _, tc := range cases {
		got := isDependencyManifest(tc.path)
		if got != tc.want {
			t.Fatalf("isDependencyManifest(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

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

func TestParsePushRefs(t *testing.T) {
	input := "refs/heads/main abcdef refs/heads/main 000000\n"
	refs, err := parsePushRefs(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parsePushRefs failed: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].LocalRef != "refs/heads/main" {
		t.Fatalf("unexpected local ref: %q", refs[0].LocalRef)
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

func TestParseTrufflehogFindingsEmpty(t *testing.T) {
	findings, err := parseTrufflehogFindings("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d", len(findings))
	}
}

func TestApplyAllowlistDowngradesMatchingIssue(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "found fake-api-key in config.txt"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "test fixture", Owner: "test", ExpiresOn: "2099-12-31"},
	}

	result := applyAllowlist(issues, entries)
	if result[0].Blocking {
		t.Fatal("expected allowlisted issue to be non-blocking")
	}
	if !strings.Contains(result[0].Message, "allowlisted") {
		t.Fatalf("expected allowlisted annotation, got: %s", result[0].Message)
	}
}

func TestApplyAllowlistIgnoresExpiredEntry(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "found fake-api-key"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "old exception", Owner: "test", ExpiresOn: "2020-01-01"},
	}

	result := applyAllowlist(issues, entries)
	if !result[0].Blocking {
		t.Fatal("expired allowlist entry should not downgrade the issue")
	}
}

func TestApplyAllowlistNoMatchLeavesBlocking(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "real-secret-detected"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "test fixture", Owner: "test", ExpiresOn: "2099-12-31"},
	}

	result := applyAllowlist(issues, entries)
	if !result[0].Blocking {
		t.Fatal("non-matching allowlist should leave issue blocking")
	}
}

func TestApplyAllowlistEmptyEntries(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "secret found"},
	}
	result := applyAllowlist(issues, nil)
	if !result[0].Blocking {
		t.Fatal("nil allowlist should leave issue blocking")
	}
}

func TestWarnExpiredAllowlist(t *testing.T) {
	var out bytes.Buffer
	entries := []AllowlistEntry{
		{Pattern: "old-secret", Reason: "was test data", Owner: "security@co.com", ExpiresOn: "2020-01-01"},
		{Pattern: "current-exception", Reason: "still valid", Owner: "team", ExpiresOn: "2099-12-31"},
	}
	warnExpiredAllowlist(entries, &out)

	output := out.String()
	if !strings.Contains(output, "old-secret") {
		t.Fatal("expected warning for expired entry")
	}
	if strings.Contains(output, "current-exception") {
		t.Fatal("should not warn about non-expired entry")
	}
}

func TestFinalizeStageIssuesAllPass(t *testing.T) {
	var out bytes.Buffer
	err := finalizeStageIssues("pre-commit", nil, &out)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !strings.Contains(out.String(), "all gates passed") {
		t.Fatalf("expected all-pass message, got: %s", out.String())
	}
}

func TestFinalizeStageIssuesWarningsOnly(t *testing.T) {
	var out bytes.Buffer
	issues := []gateIssue{
		{Gate: "test", Blocking: false, Message: "minor issue"},
	}
	err := finalizeStageIssues("pre-push", issues, &out)
	if err != nil {
		t.Fatalf("warnings-only should not error, got: %v", err)
	}
	if !strings.Contains(out.String(), "completed with warnings only") {
		t.Fatalf("expected warnings-only message, got: %s", out.String())
	}
}

func TestFinalizeStageIssuesBlocking(t *testing.T) {
	var out bytes.Buffer
	issues := []gateIssue{
		{Gate: "test", Blocking: true, Message: "critical failure"},
	}
	err := finalizeStageIssues("pre-commit", issues, &out)
	if err == nil {
		t.Fatal("expected blocking error")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked message, got: %v", err)
	}
}

func TestParseDurationOr(t *testing.T) {
	if d := parseDurationOr("5m", time.Minute); d != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", d)
	}
	if d := parseDurationOr("", 3*time.Minute); d != 3*time.Minute {
		t.Fatalf("expected fallback 3m, got %v", d)
	}
	if d := parseDurationOr("bogus", 2*time.Minute); d != 2*time.Minute {
		t.Fatalf("expected fallback 2m for invalid input, got %v", d)
	}
}

func TestCmdCleanupPrintsGuidance(t *testing.T) {
	var out bytes.Buffer
	err := cmdCleanup(nil, &out, &out)
	if err != nil {
		t.Fatalf("cmdCleanup: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Revoke") {
		t.Fatal("expected remediation guidance")
	}
	if !strings.Contains(output, "git filter-repo") {
		t.Fatal("expected git-filter-repo guidance")
	}
}

func TestHasManifestChanges(t *testing.T) {
	if !hasManifestChanges([]string{"src/main.go", "go.mod"}) {
		t.Fatal("expected go.mod to be detected as manifest")
	}
	if hasManifestChanges([]string{"src/main.go", "README.md"}) {
		t.Fatal("expected no manifest detected")
	}
}
