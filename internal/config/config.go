// Package config handles loading and validating the config.toml configuration file.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	LLM      LLMConfig       `toml:"llm"`
	Output   OutputConfig    `toml:"output"`
	Checks   map[string]bool `toml:"checks"`
	Baseline BaselineConfig  `toml:"baseline"`
}

// BaselineConfig declares known-good artifacts on this host that should not be
// flagged as attack artifacts. Paths, accounts, and processes listed here are
// annotated with a hint so the LLM understands they are expected operator infrastructure.
type BaselineConfig struct {
	// KnownPaths are directory or file paths belonging to trusted tools/operators.
	// Any collected artifact whose path starts with one of these values is annotated
	// as known-good. Example: ["D:\\tool", "C:\\monitoring\\agent"]
	KnownPaths []string `toml:"known_paths"`
	// KnownAccounts are local account names that are legitimate and expected.
	// Example: ["backup_svc", "monitoring_agent"]
	KnownAccounts []string `toml:"known_accounts"`
	// KnownProcesses are executable names (without path) that are known-good.
	// Example: ["backup.exe", "monitoring.exe"]
	KnownProcesses []string `toml:"known_processes"`
}

// LLMConfig configures the LLM provider for forensic analysis.
type LLMConfig struct {
	Provider string `toml:"provider"`
	APIKey   string `toml:"api_key"`
	Model    string `toml:"model"`
	Endpoint string `toml:"endpoint"`
	Timeout  int    `toml:"timeout"` // HTTP timeout in seconds (0 = provider default)
}

// OutputConfig configures output behavior.
type OutputConfig struct {
	Dir         string `toml:"dir"`
	OpenBrowser bool   `toml:"open_browser"`
	KeepRaw     bool   `toml:"keep_raw"`
}

// Load reads a config.toml file and returns a validated Config.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Output: OutputConfig{
			Dir:     "output",
			KeepRaw: true,
		},
		Checks: make(map[string]bool),
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s\n  Create one with: cp config.example.toml config.toml", path)
		}
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}

	// Environment variable overrides for sensitive values
	if key := os.Getenv("CORONER_API_KEY"); key != "" {
		cfg.LLM.APIKey = key
	}
	if provider := os.Getenv("CORONER_PROVIDER"); provider != "" {
		cfg.LLM.Provider = provider
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	c.LLM.Provider = strings.ToLower(c.LLM.Provider)

	switch c.LLM.Provider {
	case "anthropic", "openai", "ollama":
		// valid
	case "":
		return fmt.Errorf("llm.provider is required (anthropic, openai, ollama)")
	default:
		return fmt.Errorf("unsupported llm.provider: %q", c.LLM.Provider)
	}

	// API key required for cloud providers
	if c.LLM.Provider != "ollama" && c.LLM.APIKey == "" {
		return fmt.Errorf("llm.api_key is required for provider %q", c.LLM.Provider)
	}

	if c.LLM.Model == "" {
		return fmt.Errorf("llm.model is required")
	}

	if c.Output.Dir == "" {
		c.Output.Dir = "output"
	}

	return nil
}
