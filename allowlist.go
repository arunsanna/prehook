package main

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

type compiledAllowlistEntry struct {
	entry AllowlistEntry
	regex *regexp.Regexp
}

func compileAllowlist(entries []AllowlistEntry) ([]compiledAllowlistEntry, error) {
	compiled := make([]compiledAllowlistEntry, 0, len(entries))
	for _, entry := range entries {
		rx, err := regexp.Compile(entry.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile allowlist pattern %q: %w", entry.Pattern, err)
		}
		compiled = append(compiled, compiledAllowlistEntry{
			entry: entry,
			regex: rx,
		})
	}
	return compiled, nil
}

func allowlisted(text string, entries []compiledAllowlistEntry) bool {
	for _, entry := range entries {
		if entry.regex.MatchString(text) {
			return true
		}
	}
	return false
}

func warnExpiredAllowlist(entries []AllowlistEntry, stdout io.Writer) {
	today := time.Now().Format("2006-01-02")
	for _, entry := range entries {
		if entry.ExpiresOn != "" && entry.ExpiresOn < today {
			fmt.Fprintf(stdout, "[WARN] allowlist entry %q expired on %s (owner: %s)\n", entry.Pattern, entry.ExpiresOn, entry.Owner)
		}
	}
}

func applyAllowlist(issues []gateIssue, entries []AllowlistEntry) []gateIssue {
	today := time.Now().Format("2006-01-02")
	var active []AllowlistEntry
	for _, entry := range entries {
		if entry.ExpiresOn == "" || entry.ExpiresOn >= today {
			active = append(active, entry)
		}
	}
	if len(active) == 0 {
		return issues
	}
	for i, issue := range issues {
		for _, entry := range active {
			if strings.Contains(issue.Output, entry.Pattern) || strings.Contains(issue.Message, entry.Pattern) {
				issues[i].Blocking = false
				issues[i].Message += fmt.Sprintf(" [allowlisted: %s]", entry.Reason)
				break
			}
		}
	}
	return issues
}
