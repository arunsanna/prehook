package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultConfigFilename = ".prehook.yaml"

type Config struct {
	Version      int              `yaml:"version"`
	PreCommit    PreCommitConfig  `yaml:"pre_commit"`
	PrePush      PrePushConfig    `yaml:"pre_push"`
	ToolVersions ToolVersionPins  `yaml:"tool_versions"`
	Allowlist    []AllowlistEntry `yaml:"allowlist"`
}

type PreCommitConfig struct {
	Blocking   bool             `yaml:"blocking"`
	Gitleaks   ToolConfig       `yaml:"gitleaks"`
	Trufflehog TrufflehogConfig `yaml:"trufflehog"`
}

type PrePushConfig struct {
	Blocking bool          `yaml:"blocking"`
	Semgrep  ToolConfig    `yaml:"semgrep"`
	OSV      ToolConfig    `yaml:"osv"`
	Trivy    TrivyConfig   `yaml:"trivy"`
	Quality  QualityConfig `yaml:"quality"`
}

type ToolConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Blocking bool     `yaml:"blocking"`
	Timeout  string   `yaml:"timeout"`
	Args     []string `yaml:"args,omitempty"`
}

type TrufflehogConfig struct {
	ToolConfig    `yaml:",inline"`
	BlockVerified bool `yaml:"block_verified"`
	BlockUnknown  bool `yaml:"block_unknown"`
}

type TrivyConfig struct {
	ToolConfig `yaml:",inline"`
	Severity   string `yaml:"severity"`
}

type QualityConfig struct {
	Enabled      bool           `yaml:"enabled"`
	Blocking     bool           `yaml:"blocking"`
	TestCommand  string         `yaml:"test_command"`
	TestTimeout  string         `yaml:"test_timeout"`
	CoverageGate CoverageConfig `yaml:"coverage"`
}

type CoverageConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Blocking  bool    `yaml:"blocking"`
	Command   string  `yaml:"command"`
	Timeout   string  `yaml:"timeout"`
	Threshold float64 `yaml:"threshold"`
	File      string  `yaml:"file"`
}

type AllowlistEntry struct {
	Pattern   string `yaml:"pattern"`
	Reason    string `yaml:"reason"`
	Owner     string `yaml:"owner"`
	ExpiresOn string `yaml:"expires_on"`
}

type ToolVersionPins struct {
	Git           string `yaml:"git"`
	Go            string `yaml:"go"`
	Gitleaks      string `yaml:"gitleaks"`
	Trufflehog    string `yaml:"trufflehog"`
	Semgrep       string `yaml:"semgrep"`
	OSVScanner    string `yaml:"osv_scanner"`
	Trivy         string `yaml:"trivy"`
	GitFilterRepo string `yaml:"git_filter_repo"`
}

func DefaultConfig() Config {
	return Config{
		Version: 1,
		PreCommit: PreCommitConfig{
			Blocking: true,
			Gitleaks: ToolConfig{
				Enabled:  true,
				Blocking: true,
				Timeout:  "2m",
			},
			Trufflehog: TrufflehogConfig{
				ToolConfig: ToolConfig{
					Enabled:  true,
					Blocking: true,
					Timeout:  "2m",
				},
				BlockVerified: true,
				BlockUnknown:  false,
			},
		},
		PrePush: PrePushConfig{
			Blocking: true,
			Semgrep: ToolConfig{
				Enabled:  true,
				Blocking: true,
				Timeout:  "5m",
			},
			OSV: ToolConfig{
				Enabled:  true,
				Blocking: true,
				Timeout:  "5m",
			},
			Trivy: TrivyConfig{
				ToolConfig: ToolConfig{
					Enabled:  true,
					Blocking: true,
					Timeout:  "8m",
				},
				Severity: "HIGH,CRITICAL",
			},
			Quality: QualityConfig{
				Enabled:     false,
				Blocking:    true,
				TestCommand: "",
				TestTimeout: "10m",
				CoverageGate: CoverageConfig{
					Enabled:   false,
					Blocking:  true,
					Command:   "",
					Timeout:   "15m",
					Threshold: 60,
					File:      "coverage.out",
				},
			},
		},
		ToolVersions: ToolVersionPins{
			Gitleaks:   ">=8.0.0",
			Trufflehog: ">=3.0.0",
			Semgrep:    ">=1.0.0",
			OSVScanner: ">=1.0.0",
			Trivy:      ">=0.50.0",
		},
		Allowlist: []AllowlistEntry{},
	}
}

func (c Config) Validate() error {
	if c.Version <= 0 {
		return fmt.Errorf("version must be greater than 0")
	}

	timeouts := map[string]string{
		"pre_commit.gitleaks.timeout":       c.PreCommit.Gitleaks.Timeout,
		"pre_commit.trufflehog.timeout":     c.PreCommit.Trufflehog.Timeout,
		"pre_push.semgrep.timeout":          c.PrePush.Semgrep.Timeout,
		"pre_push.osv.timeout":              c.PrePush.OSV.Timeout,
		"pre_push.trivy.timeout":            c.PrePush.Trivy.Timeout,
		"pre_push.quality.test_timeout":     c.PrePush.Quality.TestTimeout,
		"pre_push.quality.coverage.timeout": c.PrePush.Quality.CoverageGate.Timeout,
	}

	for key, value := range timeouts {
		if value == "" {
			continue
		}
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid duration for %s: %w", key, err)
		}
	}

	if c.PrePush.Quality.CoverageGate.Threshold < 0 || c.PrePush.Quality.CoverageGate.Threshold > 100 {
		return fmt.Errorf("pre_push.quality.coverage.threshold must be between 0 and 100")
	}
	if c.PrePush.Quality.CoverageGate.Enabled && c.PrePush.Quality.CoverageGate.Threshold > 0 && c.PrePush.Quality.CoverageGate.Command == "" {
		return fmt.Errorf("pre_push.quality.coverage.command is required when coverage threshold is enabled")
	}

	for idx, entry := range c.Allowlist {
		position := idx + 1
		if entry.Pattern == "" {
			return fmt.Errorf("allowlist entry %d is missing pattern", position)
		}
		if entry.Reason == "" {
			return fmt.Errorf("allowlist entry %d is missing reason", position)
		}
		if entry.Owner == "" {
			return fmt.Errorf("allowlist entry %d is missing owner", position)
		}
		if entry.ExpiresOn == "" {
			return fmt.Errorf("allowlist entry %d is missing expires_on", position)
		}
		if _, err := time.Parse("2006-01-02", entry.ExpiresOn); err != nil {
			return fmt.Errorf("allowlist entry %d has invalid expires_on, expected YYYY-MM-DD: %w", position, err)
		}
	}

	return nil
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("validate config %s: %w", path, err)
	}
	return cfg, nil
}

func cmdInit(args []string, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("init", flag.ContinueOnError)
	force := flagSet.Bool("force", false, "overwrite existing config")
	flagSet.SetOutput(stderr)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	configPath := filepath.Join(repoRoot, defaultConfigFilename)
	if !*force {
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", configPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", configPath, err)
		}
	}

	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal default config: %w", err)
	}

	content := append([]byte("# prehook configuration\n"), data...)
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}

	fmt.Fprintf(stdout, "Created %s\n", configPath)
	return nil
}

func resolveConfigPath(repoRoot string, candidate string) string {
	if candidate == "" {
		return filepath.Join(repoRoot, defaultConfigFilename)
	}
	if filepath.IsAbs(candidate) {
		return candidate
	}
	return filepath.Join(repoRoot, candidate)
}
