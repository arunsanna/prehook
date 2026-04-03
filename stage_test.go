package main

import (
	"bytes"
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
