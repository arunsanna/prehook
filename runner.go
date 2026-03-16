package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type CommandResult struct {
	Name     string
	Args     []string
	ExitCode int
	Output   string
	Err      error
	TimedOut bool
}

func RunBinary(timeout time.Duration, dir string, name string, args []string, stdin io.Reader) CommandResult {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdin = stdin

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	result := CommandResult{
		Name:   name,
		Args:   args,
		Output: strings.TrimSpace(output.String()),
		Err:    err,
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
	}

	if err == nil {
		result.ExitCode = 0
		return result
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result
	}

	result.ExitCode = -1
	return result
}

func RunShell(timeout time.Duration, dir string, command string) CommandResult {
	if runtime.GOOS == "windows" {
		return RunBinary(timeout, dir, "cmd.exe", []string{"/C", command}, nil)
	}
	return RunBinary(timeout, dir, "sh", []string{"-c", command}, nil)
}

func cleanOutput(text string) string {
	if text == "" {
		return ""
	}

	const maxLines = 18
	const maxChars = 4000

	if len(text) > maxChars {
		text = text[:maxChars] + "\n... output truncated"
	}

	lines := strings.Split(text, "\n")
	if len(lines) > maxLines {
		lines = append(lines[:maxLines], "... output truncated")
	}

	return strings.Join(lines, "\n")
}

func formatCommand(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return fmt.Sprintf("%s %s", name, strings.Join(args, " "))
}
