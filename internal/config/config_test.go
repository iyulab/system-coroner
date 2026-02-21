package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidAnthropicConfig(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "anthropic"
api_key  = "sk-ant-test"
model    = "claude-sonnet-4-5-20250514"

[output]
dir          = "out"
open_browser = false
keep_raw     = true

[checks]
c2_connections = true
persistence    = false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("provider = %q, want %q", cfg.LLM.Provider, "anthropic")
	}
	if cfg.LLM.Model != "claude-sonnet-4-5-20250514" {
		t.Errorf("model = %q, want %q", cfg.LLM.Model, "claude-sonnet-4-5-20250514")
	}
	if cfg.Output.Dir != "out" {
		t.Errorf("output.dir = %q, want %q", cfg.Output.Dir, "out")
	}
	if !cfg.Checks["c2_connections"] {
		t.Error("c2_connections should be enabled")
	}
	if cfg.Checks["persistence"] {
		t.Error("persistence should be disabled")
	}
}

func TestLoad_ValidOllamaConfig(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "ollama"
model    = "foundation-sec:8b"
endpoint = "http://localhost:11434"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Provider != "ollama" {
		t.Errorf("provider = %q, want %q", cfg.LLM.Provider, "ollama")
	}
	if cfg.LLM.APIKey != "" {
		t.Errorf("ollama should not require api_key, got %q", cfg.LLM.APIKey)
	}
}

func TestLoad_MissingProvider(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
model = "gpt-4o"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestLoad_MissingAPIKey(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "openai"
model    = "gpt-4o"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing api_key with openai provider")
	}
}

func TestLoad_MissingModel(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "ollama"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing model")
	}
}

func TestLoad_UnsupportedProvider(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "gemini"
api_key  = "test"
model    = "gemini-pro"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "anthropic"
api_key  = "from-file"
model    = "claude-sonnet-4-5-20250514"
`)

	t.Setenv("CORONER_API_KEY", "from-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.APIKey != "from-env" {
		t.Errorf("api_key = %q, want %q (env override)", cfg.LLM.APIKey, "from-env")
	}
}

func TestLoad_DefaultOutputDir(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "ollama"
model    = "qwen3:8b"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Output.Dir != "output" {
		t.Errorf("output.dir = %q, want default %q", cfg.Output.Dir, "output")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	// Should contain helpful guidance
	errMsg := err.Error()
	if !contains(errMsg, "not found") {
		t.Errorf("error should mention 'not found', got: %s", errMsg)
	}
	if !contains(errMsg, "config.example.toml") {
		t.Errorf("error should mention config.example.toml, got: %s", errMsg)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstr(s, substr)
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLoad_CustomTimeout(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "ollama"
model    = "qwen3:8b"
timeout  = 60
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Timeout != 60 {
		t.Errorf("timeout = %d, want 60", cfg.LLM.Timeout)
	}
}

func TestLoad_DefaultTimeout(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "ollama"
model    = "qwen3:8b"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Timeout != 0 {
		t.Errorf("timeout = %d, want 0 (default)", cfg.LLM.Timeout)
	}
}

func TestLoad_ProviderCaseInsensitive(t *testing.T) {
	path := writeTestConfig(t, `
[llm]
provider = "Anthropic"
api_key  = "test"
model    = "claude-sonnet-4-5-20250514"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Provider != "anthropic" {
		t.Errorf("provider = %q, want normalized %q", cfg.LLM.Provider, "anthropic")
	}
}
