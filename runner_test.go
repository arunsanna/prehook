package main

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunBinarySuccess(t *testing.T) {
	result := RunBinary(5*time.Second, ".", "git", []string{"--version"}, nil)
	if result.Err != nil {
		t.Fatalf("expected success, got: %v", result.Err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Output, "git version") {
		t.Fatalf("expected git version output, got: %q", result.Output)
	}
}

func TestRunBinaryNotFound(t *testing.T) {
	result := RunBinary(5*time.Second, ".", "nonexistent-binary-xyz", nil, nil)
	if result.Err == nil {
		t.Fatal("expected error for missing binary")
	}
	if result.ExitCode != -1 {
		t.Fatalf("expected exit -1, got %d", result.ExitCode)
	}
}

func TestRunBinaryNonZeroExit(t *testing.T) {
	result := RunBinary(5*time.Second, ".", "git", []string{"log", "--oneline", "-1", "--not-a-real-flag"}, nil)
	if result.ExitCode == 0 {
		t.Fatal("expected non-zero exit")
	}
}

func TestRunBinaryTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep command not available on Windows")
	}
	result := RunBinary(100*time.Millisecond, ".", "sleep", []string{"10"}, nil)
	if !result.TimedOut {
		t.Fatal("expected timeout")
	}
}

func TestRunBinaryDefaultTimeout(t *testing.T) {
	// zero timeout should default to 2 minutes (not fail immediately)
	result := RunBinary(0, ".", "git", []string{"--version"}, nil)
	if result.Err != nil {
		t.Fatalf("expected success with default timeout, got: %v", result.Err)
	}
}

func TestRunShellSuccess(t *testing.T) {
	result := RunShell(5*time.Second, ".", "echo hello")
	if result.Err != nil {
		t.Fatalf("expected success, got: %v", result.Err)
	}
	if !strings.Contains(result.Output, "hello") {
		t.Fatalf("expected 'hello' in output, got: %q", result.Output)
	}
}

func TestCleanOutput(t *testing.T) {
	if cleanOutput("") != "" {
		t.Fatal("expected empty for empty input")
	}

	short := "one line"
	if cleanOutput(short) != short {
		t.Fatalf("expected pass-through for short text, got: %q", cleanOutput(short))
	}

	// long output should be truncated
	long := strings.Repeat("line\n", 100)
	cleaned := cleanOutput(long)
	if !strings.Contains(cleaned, "truncated") {
		t.Fatal("expected truncation for long output")
	}
}

func TestFormatCommand(t *testing.T) {
	if got := formatCommand("git", nil); got != "git" {
		t.Fatalf("expected 'git', got %q", got)
	}
	if got := formatCommand("git", []string{"status"}); got != "git status" {
		t.Fatalf("expected 'git status', got %q", got)
	}
}
