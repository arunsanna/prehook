package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionSatisfies(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		pin    string
		wantOK bool
	}{
		{
			name:   "gte matches",
			line:   "gitleaks version 8.24.2",
			pin:    ">=8.0.0",
			wantOK: true,
		},
		{
			name:   "exact mismatch",
			line:   "trivy version 0.50.1",
			pin:    "=0.50.0",
			wantOK: false,
		},
		{
			name:   "substring fallback",
			line:   "tool release-2026.02 stable",
			pin:    "2026.02",
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := versionSatisfies(tc.line, tc.pin)
			if got != tc.wantOK {
				t.Fatalf("versionSatisfies(%q, %q) = %v, want %v", tc.line, tc.pin, got, tc.wantOK)
			}
		})
	}
}

func TestRunBinaryCheckAllowsMissingOptionalBinary(t *testing.T) {
	var out bytes.Buffer
	err := runBinaryCheck(binaryCheck{
		Name:        "definitely-not-installed-prehook-binary",
		VersionArgs: []string{"--version"},
		Required:    false,
		Hint:        "optional helper",
	}, false, &out)
	if err != nil {
		t.Fatalf("expected optional missing binary to warn only, got %v", err)
	}
	if !strings.Contains(out.String(), "[WARN]") {
		t.Fatalf("expected warning output, got %q", out.String())
	}
}

func TestVersionSatisfiesEmptyPin(t *testing.T) {
	ok, _ := versionSatisfies("tool 1.0.0", "")
	if !ok {
		t.Fatal("empty pin should always satisfy")
	}
}

func TestExtractVersionToken(t *testing.T) {
	cases := []struct {
		input string
		want  string
		ok    bool
	}{
		{"gitleaks version 8.24.2", "8.24.2", true},
		{"v1.2.3", "1.2.3", true},
		{"no version here", "", false},
	}
	for _, tc := range cases {
		got, ok := extractVersionToken(tc.input)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("extractVersionToken(%q) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("line1\nline2"); got != "line1" {
		t.Fatalf("expected 'line1', got %q", got)
	}
	if got := firstLine(""); got != "version unknown" {
		t.Fatalf("expected 'version unknown', got %q", got)
	}
}

func TestCmdDoctorGoOptionalWhenQualityDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrePush.Quality.Enabled = false

	checks := buildDoctorChecks(cfg)
	for _, check := range checks {
		if check.Name == "go" && check.Required {
			t.Fatal("go should not be required when quality gates are disabled")
		}
	}
}

func TestCmdDoctorGoRequiredWhenQualityEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrePush.Quality.Enabled = true
	checks := buildDoctorChecks(cfg)
	for _, check := range checks {
		if check.Name == "go" && !check.Required {
			t.Fatal("go should be required when quality gates are enabled")
		}
	}
}

func TestCmdDoctorScannerRequiredMatchesEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PreCommit.Gitleaks.Enabled = false
	cfg.PrePush.Trivy.Enabled = false

	checks := buildDoctorChecks(cfg)
	for _, check := range checks {
		switch check.Name {
		case "gitleaks":
			if check.Required {
				t.Fatal("gitleaks should not be required when disabled")
			}
		case "trivy":
			if check.Required {
				t.Fatal("trivy should not be required when disabled")
			}
		}
	}
}
