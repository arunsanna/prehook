package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	writeExecutable(t, filepath.Join(binDir, "trufflehog"), `#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  echo "trufflehog 3.90.0"
  exit 0
fi
echo '{"Verified": true}'
exit 0
`)

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
	writeExecutable(t, filepath.Join(binDir, "trufflehog"), `#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  echo "trufflehog 3.90.0"
  exit 0
fi
echo '{"Verified": false}'
exit 0
`)

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
	writeExecutable(t, filepath.Join(binDir, "semgrep"), `#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  echo "semgrep 1.90.0"
  exit 0
fi
echo "rule violation"
exit 1
`)

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

func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
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
