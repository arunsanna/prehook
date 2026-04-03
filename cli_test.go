package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCLIVersion(t *testing.T) {
	var out bytes.Buffer
	code := runCLI([]string{"version"}, nil, &out, &out)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), version) {
		t.Fatalf("expected version output, got %q", out.String())
	}
}

func TestRunCLIHelp(t *testing.T) {
	var out bytes.Buffer
	code := runCLI([]string{"help"}, nil, &out, &out)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "prehook") {
		t.Fatalf("expected usage output, got %q", out.String())
	}
}

func TestRunCLINoArgs(t *testing.T) {
	var out bytes.Buffer
	code := runCLI(nil, nil, &out, &out)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

func TestRunCLIUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	code := runCLI([]string{"bogus"}, nil, &out, &out)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(out.String(), "unknown command") {
		t.Fatalf("expected unknown command message, got %q", out.String())
	}
}

func TestRunCLIVersionFlags(t *testing.T) {
	for _, flag := range []string{"-v", "--version"} {
		var out bytes.Buffer
		code := runCLI([]string{flag}, nil, &out, &out)
		if code != 0 {
			t.Fatalf("%s: expected exit 0, got %d", flag, code)
		}
	}
}

func TestRunCLIHelpFlags(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		var out bytes.Buffer
		code := runCLI([]string{flag}, nil, &out, &out)
		if code != 0 {
			t.Fatalf("%s: expected exit 0, got %d", flag, code)
		}
	}
}
