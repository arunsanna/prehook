package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPreCommitBlocksOnVerifiedTrufflehogFinding(t *testing.T) {
	repo := initTempRepo(t)
	writeFile(t, filepath.Join(repo, "secret.txt"), "token=abcd\n")
	runGit(t, repo, "add", "secret.txt")

	cfg := DefaultConfig()
	cfg.PreCommit.Gitleaks.Enabled = false
	cfg.PreCommit.Trufflehog.Enabled = true
	cfg.PreCommit.Trufflehog.BlockVerified = true
	cfg.PreCommit.Trufflehog.BlockUnknown = false
	cfg.PrePush.Semgrep.Enabled = false
	cfg.PrePush.OSV.Enabled = false
	cfg.PrePush.Trivy.Enabled = false
	cfg.PrePush.Quality.Enabled = false
	writeConfig(t, repo, cfg)

	binDir := t.TempDir()
	writeStubBinary(t, binDir, "trufflehog", "--version", "trufflehog 3.90.0", `{"Verified": true}`, 0)

	withPathAndCwd(t, binDir, repo)

	var out bytes.Buffer
	err := cmdRun([]string{"--stage", "pre-commit"}, strings.NewReader(""), &out, &out)
	if err == nil {
		t.Fatalf("expected pre-commit to fail, output:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked error, got %v", err)
	}
}

func TestPreCommitWarnsOnUnknownTrufflehogFinding(t *testing.T) {
	repo := initTempRepo(t)
	writeFile(t, filepath.Join(repo, "secret.txt"), "token=abcd\n")
	runGit(t, repo, "add", "secret.txt")

	cfg := DefaultConfig()
	cfg.PreCommit.Gitleaks.Enabled = false
	cfg.PreCommit.Trufflehog.Enabled = true
	cfg.PreCommit.Trufflehog.BlockVerified = true
	cfg.PreCommit.Trufflehog.BlockUnknown = false
	cfg.PrePush.Semgrep.Enabled = false
	cfg.PrePush.OSV.Enabled = false
	cfg.PrePush.Trivy.Enabled = false
	cfg.PrePush.Quality.Enabled = false
	writeConfig(t, repo, cfg)

	binDir := t.TempDir()
	writeStubBinary(t, binDir, "trufflehog", "--version", "trufflehog 3.90.0", `{"Verified": false}`, 0)

	withPathAndCwd(t, binDir, repo)

	var out bytes.Buffer
	err := cmdRun([]string{"--stage", "pre-commit"}, strings.NewReader(""), &out, &out)
	if err != nil {
		t.Fatalf("expected pre-commit warnings only, got %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[WARN] trufflehog") {
		t.Fatalf("expected warning output, got:\n%s", out.String())
	}
}

func TestPreCommitSuppressesAllowlistedGitleaksFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses shell script stub not runnable on Windows")
	}
	repo := initTempRepo(t)
	writeFile(t, filepath.Join(repo, "secret.txt"), "token=example-test-secret\n")
	runGit(t, repo, "add", "secret.txt")

	cfg := DefaultConfig()
	cfg.PreCommit.Gitleaks.Enabled = true
	cfg.PreCommit.Trufflehog.Enabled = false
	cfg.PrePush.Semgrep.Enabled = false
	cfg.PrePush.OSV.Enabled = false
	cfg.PrePush.Trivy.Enabled = false
	cfg.PrePush.Quality.Enabled = false
	cfg.Allowlist = []AllowlistEntry{{
		Pattern:   "example-test-secret",
		Reason:    "fixture data",
		Owner:     "security@company.com",
		ExpiresOn: "2030-01-01",
	}}
	writeConfig(t, repo, cfg)

	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "gitleaks"), `#!/bin/sh
if [ "${1:-}" = "version" ]; then
  echo "gitleaks 8.24.2"
  exit 0
fi
config=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--config" ]; then
    config="$arg"
  fi
  prev="$arg"
done
if [ -n "$config" ]; then
  exit 0
fi
exit 1
`)

	withPathAndCwd(t, binDir, repo)

	var out bytes.Buffer
	err := cmdRun([]string{"--stage", "pre-commit"}, strings.NewReader(""), &out, &out)
	if err != nil {
		t.Fatalf("expected pre-commit to pass after allowlist suppression, got %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[ OK ] gitleaks") {
		t.Fatalf("expected gitleaks success output, got:\n%s", out.String())
	}
}

func TestPrePushBlocksOnSemgrepFailure(t *testing.T) {
	repo := initTempRepo(t)
	writeFile(t, filepath.Join(repo, "app.go"), "package main\n")
	runGit(t, repo, "add", "app.go")
	runGit(t, repo, "commit", "-m", "init")

	writeFile(t, filepath.Join(repo, "app.go"), "package main\n// change\n")
	runGit(t, repo, "add", "app.go")
	runGit(t, repo, "commit", "-m", "change")
	localSHA := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))

	cfg := DefaultConfig()
	cfg.PreCommit.Gitleaks.Enabled = false
	cfg.PreCommit.Trufflehog.Enabled = false
	cfg.PrePush.Semgrep.Enabled = true
	cfg.PrePush.OSV.Enabled = false
	cfg.PrePush.Trivy.Enabled = false
	cfg.PrePush.Quality.Enabled = false
	writeConfig(t, repo, cfg)

	binDir := t.TempDir()
	writeStubBinary(t, binDir, "semgrep", "--version", "semgrep 1.90.0", "rule violation", 1)

	withPathAndCwd(t, binDir, repo)

	var out bytes.Buffer
	refLine := fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", localSHA, strings.Repeat("0", 40))
	err := cmdRun([]string{"--stage", "pre-push"}, strings.NewReader(refLine), &out, &out)
	if err == nil {
		t.Fatalf("expected pre-push to fail, output:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked error, got %v", err)
	}
}

func TestCollectPrePushFilesIncludesAllUnpublishedCommitsOnNewBranch(t *testing.T) {
	repo := initTempRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")

	cmd := exec.Command("git", "init", "--bare", remote)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare failed: %v\n%s", err, string(output))
	}

	runGit(t, repo, "checkout", "-b", "main")
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", "base.txt")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "remote", "add", "origin", remote)
	runGit(t, repo, "push", "-u", "origin", "main")

	runGit(t, repo, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(repo, "first.txt"), "first\n")
	runGit(t, repo, "add", "first.txt")
	runGit(t, repo, "commit", "-m", "first feature commit")

	writeFile(t, filepath.Join(repo, "second.txt"), "second\n")
	runGit(t, repo, "add", "second.txt")
	runGit(t, repo, "commit", "-m", "second feature commit")

	localSHA := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	files, err := collectPrePushFiles(repo, "origin", []PushRef{{
		LocalRef:  "refs/heads/feature",
		LocalSHA:  localSHA,
		RemoteRef: "refs/heads/feature",
		RemoteSHA: strings.Repeat("0", 40),
	}})
	if err != nil {
		t.Fatalf("collectPrePushFiles failed: %v", err)
	}

	got := strings.Join(files, ",")
	if got != "first.txt,second.txt" {
		t.Fatalf("expected both unpublished files, got %q", got)
	}
}

func TestCollectPrePushFilesUsesPushRemoteForNewBranch(t *testing.T) {
	repo := initTempRepo(t)
	origin := filepath.Join(t.TempDir(), "origin.git")
	fork := filepath.Join(t.TempDir(), "fork.git")

	for _, remote := range []string{origin, fork} {
		cmd := exec.Command("git", "init", "--bare", remote)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git init --bare failed: %v\n%s", err, string(output))
		}
	}

	runGit(t, repo, "checkout", "-b", "main")
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", "base.txt")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "remote", "add", "origin", origin)
	runGit(t, repo, "remote", "add", "fork", fork)
	runGit(t, repo, "push", "-u", "origin", "main")

	runGit(t, repo, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	runGit(t, repo, "add", "feature.txt")
	runGit(t, repo, "commit", "-m", "feature commit")

	localSHA := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	files, err := collectPrePushFiles(repo, "fork", []PushRef{{
		LocalRef:  "refs/heads/feature",
		LocalSHA:  localSHA,
		RemoteRef: "refs/heads/feature",
		RemoteSHA: strings.Repeat("0", 40),
	}})
	if err != nil {
		t.Fatalf("collectPrePushFiles failed: %v", err)
	}

	got := strings.Join(files, ",")
	if got != "base.txt,feature.txt" {
		t.Fatalf("expected files missing from fork remote, got %q", got)
	}
}

func initTempRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "prehook-test@example.com")
	runGit(t, repo, "config", "user.name", "Prehook Test")
	return repo
}

func writeConfig(t *testing.T, repo string, cfg Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeFile(t, filepath.Join(repo, ".prehook.yaml"), string(data))
}

func withPathAndCwd(t *testing.T, binDir string, cwd string) {
	t.Helper()
	oldPath := os.Getenv("PATH")
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		_ = os.Chdir(oldCwd)
	})
}

// writeExecutable writes a raw script file. Use writeStubBinary for simple
// version/output stubs; use this for complex shell logic that cannot be
// expressed as a parameterized stub.
func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

// writeStubBinary creates a mock binary that responds to a version flag with
// versionOutput and otherwise prints defaultOutput with the given exit code.
// On Windows it writes a .cmd batch script; on Unix a sh script.
func writeStubBinary(t *testing.T, dir string, name string, versionFlag string, versionOutput string, defaultOutput string, defaultExitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, name+".cmd")
		script := fmt.Sprintf("@echo off\r\nif \"%%~1\"==\"%s\" (\r\n  echo %s\r\n  exit /b 0\r\n)\r\necho %s\r\nexit /b %d\r\n",
			versionFlag, versionOutput, defaultOutput, defaultExitCode)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", path, err)
		}
		return
	}
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nif [ \"${1:-}\" = \"%s\" ]; then\n  echo \"%s\"\n  exit 0\nfi\necho '%s'\nexit %d\n",
		versionFlag, versionOutput, defaultOutput, defaultExitCode)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", path, err)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}

func runGitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return string(output)
}
