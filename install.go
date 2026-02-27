package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const managedHookMarker = "# prehook-managed"

func cmdInstall(args []string, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("install", flag.ContinueOnError)
	force := flagSet.Bool("force", false, "overwrite existing non-prehook hooks")
	flagSet.SetOutput(stderr)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	hooksDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory %s: %w", hooksDir, err)
	}

	hooks := []struct {
		name  string
		stage string
	}{
		{name: "pre-commit", stage: "pre-commit"},
		{name: "pre-push", stage: "pre-push"},
	}

	for _, hook := range hooks {
		path := filepath.Join(hooksDir, hook.name)
		content := hookScript(hook.stage, resolveInstallBinaryPath())
		if err := writeHook(path, content, *force, stdout); err != nil {
			return err
		}
	}

	fmt.Fprintf(stdout, "Installed hooks in %s\n", hooksDir)
	return nil
}

func hookScript(stage string, installBinary string) []byte {
	script := fmt.Sprintf(`#!/bin/sh
%s
set -eu

PREHOOK_INSTALL_BIN=%q

if command -v prehook >/dev/null 2>&1; then
  PREHOOK_BIN="$(command -v prehook)"
elif [ -n "$PREHOOK_INSTALL_BIN" ] && [ -x "$PREHOOK_INSTALL_BIN" ]; then
  PREHOOK_BIN="$PREHOOK_INSTALL_BIN"
elif [ -x "./prehook" ]; then
  PREHOOK_BIN="./prehook"
else
  echo "prehook binary not found in PATH" >&2
  exit 1
fi

exec "$PREHOOK_BIN" run --stage %s "$@"
`, managedHookMarker, installBinary, stage)
	return []byte(script)
}

func resolveInstallBinaryPath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}

	resolved, err := filepath.EvalSymlinks(executable)
	if err == nil && resolved != "" {
		return resolved
	}
	return executable
}

func writeHook(path string, content []byte, force bool, stdout io.Writer) error {
	existing, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(existing, content) {
			fmt.Fprintf(stdout, "Hook %s is already up to date\n", path)
			return nil
		}

		if !bytes.Contains(existing, []byte(managedHookMarker)) {
			if !force {
				return fmt.Errorf("hook %s already exists and is not managed by prehook (use --force to back up and replace)", path)
			}

			backupPath := fmt.Sprintf("%s.prehook.bak.%d", path, time.Now().Unix())
			if err := os.WriteFile(backupPath, existing, 0o644); err != nil {
				return fmt.Errorf("backup %s: %w", path, err)
			}
			fmt.Fprintf(stdout, "Backed up existing hook to %s\n", backupPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook %s: %w", path, err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o755); err != nil {
		return fmt.Errorf("write hook temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace hook %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("set executable mode on %s: %w", path, err)
	}

	if strings.HasSuffix(path, "pre-commit") {
		fmt.Fprintf(stdout, "Installed pre-commit hook at %s\n", path)
	} else {
		fmt.Fprintf(stdout, "Installed pre-push hook at %s\n", path)
	}
	return nil
}
