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
