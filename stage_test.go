package main

import (
	"strings"
	"testing"
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
	summary, err := parseTrufflehogFindings(output)
	if err != nil {
		t.Fatalf("parseTrufflehogFindings failed: %v", err)
	}
	if summary.Verified != 1 || summary.Unknown != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}
