package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookScriptContainsMarker(t *testing.T) {
	script := hookScript("pre-commit", "/usr/local/bin/prehook")
	if !bytes.Contains(script, []byte(managedHookMarker)) {
		t.Fatal("hook script missing managed marker")
	}
}

func TestHookScriptContainsStage(t *testing.T) {
	script := hookScript("pre-push", "/usr/local/bin/prehook")
	if !bytes.Contains(script, []byte("--stage pre-push")) {
		t.Fatal("hook script missing stage argument")
	}
}

func TestHookScriptContainsBinaryPath(t *testing.T) {
	script := hookScript("pre-commit", "/opt/bin/prehook")
	if !bytes.Contains(script, []byte("/opt/bin/prehook")) {
		t.Fatal("hook script missing install binary path")
	}
}

func TestCmdInstallCreatesHooks(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		// best-effort restore; tests use TempDir so this is non-critical
		_ = os.Chdir(os.TempDir())
	})

	var out bytes.Buffer
	err := cmdInstall(nil, &out, &out)
	if err != nil {
		t.Fatalf("cmdInstall: %v\n%s", err, out.String())
	}

	hooksDir := filepath.Join(repo, ".git", "hooks")
	for _, name := range []string{"pre-commit", "pre-push"} {
		path := filepath.Join(hooksDir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Contains(content, []byte(managedHookMarker)) {
			t.Fatalf("%s missing managed marker", name)
		}
		info, _ := os.Stat(path)
		if info.Mode()&0o100 == 0 {
			t.Fatalf("%s not executable", name)
		}
	}
}

func TestCmdInstallIdempotent(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	var out bytes.Buffer
	if err := cmdInstall(nil, &out, &out); err != nil {
		t.Fatalf("first install: %v", err)
	}

	out.Reset()
	if err := cmdInstall(nil, &out, &out); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already up to date") {
		t.Fatalf("expected idempotent message, got:\n%s", out.String())
	}
}

func TestCmdInstallRejectsUnmanagedHook(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	hooksDir := filepath.Join(repo, ".git", "hooks")
	_ = os.MkdirAll(hooksDir, 0o755)
	_ = os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("#!/bin/sh\necho custom\n"), 0o755)

	var out bytes.Buffer
	err := cmdInstall(nil, &out, &out)
	if err == nil {
		t.Fatal("expected error for unmanaged hook")
	}
	if !strings.Contains(err.Error(), "not managed by prehook") {
		t.Fatalf("expected unmanaged error, got: %v", err)
	}
}

func TestCmdInstallForceBacksUp(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	hooksDir := filepath.Join(repo, ".git", "hooks")
	_ = os.MkdirAll(hooksDir, 0o755)
	_ = os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("#!/bin/sh\necho custom\n"), 0o755)

	var out bytes.Buffer
	err := cmdInstall([]string{"--force"}, &out, &out)
	if err != nil {
		t.Fatalf("cmdInstall --force: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Backed up") {
		t.Fatalf("expected backup message, got:\n%s", out.String())
	}
}

func TestCmdUninstallRemovesManagedHooks(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	var out bytes.Buffer
	if err := cmdInstall(nil, &out, &out); err != nil {
		t.Fatalf("install: %v", err)
	}

	out.Reset()
	if err := cmdUninstall(nil, &out, &out); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Removed") {
		t.Fatalf("expected removed message, got:\n%s", out.String())
	}

	hooksDir := filepath.Join(repo, ".git", "hooks")
	for _, name := range []string{"pre-commit", "pre-push"} {
		if _, err := os.Stat(filepath.Join(hooksDir, name)); err == nil {
			t.Fatalf("%s should have been removed", name)
		}
	}
}

func TestCmdUninstallSkipsUnmanagedHooks(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	hooksDir := filepath.Join(repo, ".git", "hooks")
	_ = os.MkdirAll(hooksDir, 0o755)
	_ = os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("#!/bin/sh\necho custom\n"), 0o755)

	var out bytes.Buffer
	err := cmdUninstall(nil, &out, &out)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !strings.Contains(out.String(), "not managed by prehook") {
		t.Fatalf("expected skip message, got:\n%s", out.String())
	}
	// unmanaged hook should still exist
	if _, err := os.Stat(filepath.Join(hooksDir, "pre-commit")); err != nil {
		t.Fatal("unmanaged hook should not have been removed")
	}
}

func TestCmdUninstallNoHooks(t *testing.T) {
	repo := initTempRepo(t)
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(os.TempDir()) })

	var out bytes.Buffer
	err := cmdUninstall(nil, &out, &out)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !strings.Contains(out.String(), "No prehook-managed hooks found") {
		t.Fatalf("expected no-hooks message, got:\n%s", out.String())
	}
}
