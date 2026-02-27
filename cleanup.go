package main

import (
	"flag"
	"fmt"
	"io"
)

func cmdCleanup(args []string, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Secret remediation checklist:")
	fmt.Fprintln(stdout, "1. Revoke and rotate any exposed credentials immediately.")
	fmt.Fprintln(stdout, "2. Remove secrets from current files and commit the fixes.")
	fmt.Fprintln(stdout, "3. Update .prehook.yaml allowlist entries only for known false positives with owner, reason, and expiry.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Optional history rewrite using git-filter-repo (manual):")
	fmt.Fprintln(stdout, "  git filter-repo --path <sensitive-file> --invert-paths")
	fmt.Fprintln(stdout, "  git filter-repo --replace-text replacements.txt")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "After any rewrite:")
	fmt.Fprintln(stdout, "  - Coordinate with collaborators before force-push.")
	fmt.Fprintln(stdout, "  - Force-push rewritten branches and tags intentionally.")
	fmt.Fprintln(stdout, "  - Invalidate old clones that still contain exposed history.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "prehook cleanup does not rewrite history automatically.")
	return nil
}
