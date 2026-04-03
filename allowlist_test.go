package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestApplyAllowlistDowngradesMatchingIssue(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "found fake-api-key in config.txt"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "test fixture", Owner: "test", ExpiresOn: "2099-12-31"},
	}

	result := applyAllowlist(issues, entries)
	if result[0].Blocking {
		t.Fatal("expected allowlisted issue to be non-blocking")
	}
	if !strings.Contains(result[0].Message, "allowlisted") {
		t.Fatalf("expected allowlisted annotation, got: %s", result[0].Message)
	}
}

func TestApplyAllowlistIgnoresExpiredEntry(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "found fake-api-key"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "old exception", Owner: "test", ExpiresOn: "2020-01-01"},
	}

	result := applyAllowlist(issues, entries)
	if !result[0].Blocking {
		t.Fatal("expired allowlist entry should not downgrade the issue")
	}
}

func TestApplyAllowlistNoMatchLeavesBlocking(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "Potential secret", Output: "real-secret-detected"},
	}
	entries := []AllowlistEntry{
		{Pattern: "fake-api-key", Reason: "test fixture", Owner: "test", ExpiresOn: "2099-12-31"},
	}

	result := applyAllowlist(issues, entries)
	if !result[0].Blocking {
		t.Fatal("non-matching allowlist should leave issue blocking")
	}
}

func TestApplyAllowlistEmptyEntries(t *testing.T) {
	issues := []gateIssue{
		{Gate: "gitleaks", Blocking: true, Message: "secret found"},
	}
	result := applyAllowlist(issues, nil)
	if !result[0].Blocking {
		t.Fatal("nil allowlist should leave issue blocking")
	}
}

func TestWarnExpiredAllowlist(t *testing.T) {
	var out bytes.Buffer
	entries := []AllowlistEntry{
		{Pattern: "old-secret", Reason: "was test data", Owner: "security@co.com", ExpiresOn: "2020-01-01"},
		{Pattern: "current-exception", Reason: "still valid", Owner: "team", ExpiresOn: "2099-12-31"},
	}
	warnExpiredAllowlist(entries, &out)

	output := out.String()
	if !strings.Contains(output, "old-secret") {
		t.Fatal("expected warning for expired entry")
	}
	if strings.Contains(output, "current-exception") {
		t.Fatal("should not warn about non-expired entry")
	}
}
