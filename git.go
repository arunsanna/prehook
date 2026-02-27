package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IndexSnapshot struct {
	Dir   string
	Files []string
}

type PushRef struct {
	LocalRef  string
	LocalSHA  string
	RemoteRef string
	RemoteSHA string
}

func findRepoRoot() (string, error) {
	output, err := runGitText(".", 15*time.Second, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("not inside a git repository: %w", err)
	}
	return output, nil
}

func resolveHooksDir(repoRoot string) (string, error) {
	output, err := runGitText(repoRoot, 15*time.Second, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", fmt.Errorf("resolve git hooks path: %w", err)
	}
	if filepath.IsAbs(output) {
		return output, nil
	}
	return filepath.Join(repoRoot, output), nil
}

func listStagedFiles(repoRoot string) ([]string, error) {
	output, err := runGitText(repoRoot, 20*time.Second, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	if err != nil {
		return nil, fmt.Errorf("list staged files: %w", err)
	}
	return splitLines(output), nil
}

func BuildStagedSnapshot(repoRoot string) (*IndexSnapshot, error) {
	files, err := listStagedFiles(repoRoot)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return &IndexSnapshot{Files: []string{}}, nil
	}

	tempDir, err := os.MkdirTemp("", "prehook-staged-")
	if err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}

	for _, file := range files {
		if err := materializeIndexFile(repoRoot, file, tempDir); err != nil {
			_ = os.RemoveAll(tempDir)
			return nil, err
		}
	}

	return &IndexSnapshot{Dir: tempDir, Files: files}, nil
}

func materializeIndexFile(repoRoot string, filePath string, snapshotDir string) error {
	cleanPath := filepath.Clean(filePath)
	if cleanPath == "." || cleanPath == "" || strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
		return fmt.Errorf("refusing staged path %q", filePath)
	}

	stageLine, err := runGitText(repoRoot, 20*time.Second, "ls-files", "--stage", "--", cleanPath)
	if err != nil {
		return fmt.Errorf("read index metadata for %s: %w", cleanPath, err)
	}
	if stageLine == "" {
		return nil
	}

	line := strings.Split(stageLine, "\n")[0]
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected ls-files output for %s", cleanPath)
	}

	meta := strings.Fields(parts[0])
	if len(meta) < 2 {
		return fmt.Errorf("unexpected index metadata for %s", cleanPath)
	}
	mode := meta[0]
	sha := meta[1]

	data, err := runGitBytes(repoRoot, 30*time.Second, "cat-file", "-p", sha)
	if err != nil {
		return fmt.Errorf("read blob %s for %s: %w", sha, cleanPath, err)
	}

	destination := filepath.Join(snapshotDir, cleanPath)
	if !strings.HasPrefix(destination, filepath.Clean(snapshotDir)+string(os.PathSeparator)) {
		return fmt.Errorf("unsafe snapshot path for %s", cleanPath)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create directories for %s: %w", cleanPath, err)
	}

	if mode == "120000" {
		// Persist the symlink target as plain text to avoid scanners following links outside the snapshot.
		target := strings.TrimSpace(string(data))
		content := []byte("symlink_target: " + target + "\n")
		if err := os.WriteFile(destination, content, 0o644); err != nil {
			return fmt.Errorf("write snapshot symlink placeholder %s: %w", cleanPath, err)
		}
		return nil
	}

	parsedMode, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("parse mode %s for %s: %w", mode, cleanPath, err)
	}
	perm := os.FileMode(parsedMode) & 0o777

	if err := os.WriteFile(destination, data, perm); err != nil {
		return fmt.Errorf("write snapshot file %s: %w", cleanPath, err)
	}
	return nil
}

func parsePushRefs(r io.Reader) ([]PushRef, error) {
	if r == nil {
		return nil, nil
	}
	if file, ok := r.(*os.File); ok {
		info, err := file.Stat()
		if err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			return nil, nil
		}
	}

	var refs []PushRef
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid pre-push ref line %q", line)
		}

		refs = append(refs, PushRef{
			LocalRef:  parts[0],
			LocalSHA:  parts[1],
			RemoteRef: parts[2],
			RemoteSHA: parts[3],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read pre-push refs: %w", err)
	}
	return refs, nil
}

func collectPrePushFiles(repoRoot string, refs []PushRef) ([]string, error) {
	unique := map[string]struct{}{}

	for _, ref := range refs {
		if isZeroSHA(ref.LocalSHA) {
			continue
		}

		var output string
		var err error
		if isZeroSHA(ref.RemoteSHA) {
			output, err = runGitText(repoRoot, 45*time.Second, "diff-tree", "--no-commit-id", "--name-only", "-r", ref.LocalSHA)
		} else {
			output, err = runGitText(repoRoot, 45*time.Second, "diff", "--name-only", ref.RemoteSHA, ref.LocalSHA)
		}
		if err != nil {
			return nil, fmt.Errorf("collect changed files for %s: %w", ref.LocalRef, err)
		}

		for _, file := range splitLines(output) {
			unique[file] = struct{}{}
		}
	}

	if len(unique) == 0 {
		fallback, err := fallbackChangedFiles(repoRoot)
		if err != nil {
			return nil, err
		}
		for _, file := range fallback {
			unique[file] = struct{}{}
		}
	}

	files := make([]string, 0, len(unique))
	for file := range unique {
		if file == "" {
			continue
		}
		files = append(files, filepath.Clean(file))
	}
	sort.Strings(files)
	return files, nil
}

func fallbackChangedFiles(repoRoot string) ([]string, error) {
	output, err := runGitText(repoRoot, 20*time.Second, "diff", "--name-only", "HEAD~1", "HEAD")
	if err == nil {
		return splitLines(output), nil
	}

	output, err = runGitText(repoRoot, 20*time.Second, "ls-files")
	if err != nil {
		return nil, fmt.Errorf("fallback changed files: %w", err)
	}
	return splitLines(output), nil
}

func existingChangedFiles(repoRoot string, files []string) []string {
	existing := make([]string, 0, len(files))
	for _, file := range files {
		path := filepath.Join(repoRoot, file)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		existing = append(existing, file)
	}
	return existing
}

func runGitText(repoRoot string, timeout time.Duration, args ...string) (string, error) {
	result := RunBinary(timeout, repoRoot, "git", args, nil)
	if result.Err != nil || result.ExitCode != 0 {
		if result.TimedOut {
			return "", fmt.Errorf("git command timed out: %s", formatCommand("git", args))
		}
		if result.Err != nil {
			return "", fmt.Errorf("run %s: %w", formatCommand("git", args), result.Err)
		}
		return "", fmt.Errorf("run %s: %s", formatCommand("git", args), cleanOutput(result.Output))
	}
	return strings.TrimSpace(result.Output), nil
}

func runGitBytes(repoRoot string, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoRoot

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("git command timed out: %s", formatCommand("git", args))
		}
		return nil, fmt.Errorf("run %s: %w", formatCommand("git", args), err)
	}

	return output.Bytes(), nil
}

func isZeroSHA(sha string) bool {
	if sha == "" {
		return true
	}
	for _, r := range sha {
		if r != '0' {
			return false
		}
	}
	return true
}

func splitLines(input string) []string {
	if input == "" {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(input), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return result
}
