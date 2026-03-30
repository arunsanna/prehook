package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigBlockingDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.PreCommit.Blocking || !cfg.PreCommit.Gitleaks.Blocking || !cfg.PreCommit.Trufflehog.Blocking {
		t.Fatalf("expected pre-commit gates to be blocking by default")
	}

	if !cfg.PrePush.Blocking || !cfg.PrePush.Semgrep.Blocking || !cfg.PrePush.OSV.Blocking || !cfg.PrePush.Trivy.Blocking {
		t.Fatalf("expected pre-push scanner gates to be blocking by default")
	}

	if !cfg.PrePush.Quality.Blocking || !cfg.PrePush.Quality.CoverageGate.Blocking {
		t.Fatalf("expected pre-push quality and coverage gates to be blocking by default")
	}
}

func TestLoadConfigOverridesDefaults(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".prehook.yaml")
	content := `version: 1
pre_push:
  trivy:
    severity: CRITICAL
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.PrePush.Trivy.Severity != "CRITICAL" {
		t.Fatalf("expected severity override, got %q", cfg.PrePush.Trivy.Severity)
	}
	if !cfg.PrePush.Semgrep.Enabled {
		t.Fatalf("expected semgrep default to remain enabled")
	}
}

func TestValidateAllowlistMetadataRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allowlist = []AllowlistEntry{{
		Pattern:   "fake-secret",
		Reason:    "",
		Owner:     "security-team",
		ExpiresOn: "2030-01-01",
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing allowlist reason")
	}
	if !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected reason error, got %v", err)
	}
}

func TestValidateAllowlistPatternMustCompile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allowlist = []AllowlistEntry{{
		Pattern:   "(",
		Reason:    "fixture",
		Owner:     "security-team",
		ExpiresOn: "2030-01-01",
	}}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid allowlist pattern")
	}
	if !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("expected invalid pattern error, got %v", err)
	}
}
