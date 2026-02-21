package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Provider is the interface for LLM analysis backends.
type Provider interface {
	Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// FormatSetter is an optional interface for providers that support structured output schemas.
// The Analyzer uses this to set the appropriate JSON schema before each call.
type FormatSetter interface {
	SetFormat(schema interface{})
}

// NewProvider creates a Provider from configuration.
// timeoutSec overrides the default HTTP timeout; 0 uses per-provider defaults.
func NewProvider(provider, apiKey, model, endpoint string, timeoutSec int) (Provider, error) {
	switch provider {
	case "anthropic":
		ep := "https://api.anthropic.com/v1"
		if endpoint != "" {
			ep = endpoint
		}
		timeout := 120 * time.Second
		if timeoutSec > 0 {
			timeout = time.Duration(timeoutSec) * time.Second
		}
		return &AnthropicProvider{
			apiKey:   apiKey,
			model:    model,
			endpoint: ep,
			client:   &http.Client{Timeout: timeout},
		}, nil
	case "openai":
		ep := "https://api.openai.com/v1"
		if endpoint != "" {
			ep = endpoint
		}
		timeout := 120 * time.Second
		if timeoutSec > 0 {
			timeout = time.Duration(timeoutSec) * time.Second
		}
		return &OpenAIProvider{
			apiKey:   apiKey,
			model:    model,
			endpoint: ep,
			client:   &http.Client{Timeout: timeout},
		}, nil
	case "ollama":
		ep := "http://localhost:11434"
		if endpoint != "" {
			ep = endpoint
		}
		timeout := 300 * time.Second
		if timeoutSec > 0 {
			timeout = time.Duration(timeoutSec) * time.Second
		}
		return &OllamaProvider{
			model:    model,
			endpoint: ep,
			client:   &http.Client{Timeout: timeout},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %q", provider)
	}
}

// --- Anthropic Provider ---

// AnthropicProvider implements the Provider interface for Claude.
type AnthropicProvider struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
	schema   interface{} // JSON schema for tool_use structured output; nil = plain text mode
}

// SetFormat configures the provider to request structured output via tool_use.
// When set, Analyze will use the Anthropic tool_use mechanism to enforce the schema.
func (p *AnthropicProvider) SetFormat(schema interface{}) {
	p.schema = schema
}

func (p *AnthropicProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	body := map[string]interface{}{
		"model":      p.model,
		"max_tokens": 4096,
		"system":     systemPrompt,
		"messages": []map[string]interface{}{
			{"role": "user", "content": userPrompt},
		},
	}

	if p.schema != nil {
		// Use tool_use to enforce structured JSON output matching the schema.
		body["tools"] = []map[string]interface{}{
			{
				"name":         "record_result",
				"description":  "Record the forensic analysis result as structured JSON",
				"input_schema": p.schema,
			},
		}
		body["tool_choice"] = map[string]string{"type": "tool", "name": "record_result"}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/messages", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic API error %d: %s", resp.StatusCode, truncateAPIError(respBody))
	}

	// Parse response — handle both text and tool_use content blocks.
	var result struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from anthropic")
	}

	// Prefer tool_use block (structured output) over text block.
	for _, block := range result.Content {
		if block.Type == "tool_use" && len(block.Input) > 0 {
			return string(block.Input), nil
		}
	}

	// Fallback: first text block
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}

	return "", fmt.Errorf("no usable content block in anthropic response")
}

// --- OpenAI Provider ---

// OpenAIProvider implements the Provider interface for OpenAI and compatible APIs (GPUStack).
type OpenAIProvider struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

func (p *OpenAIProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	body := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"response_format": map[string]string{"type": "json_object"},
		"max_tokens":      4096,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := p.endpoint + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai API error %d: %s", resp.StatusCode, truncateAPIError(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from openai")
	}

	return result.Choices[0].Message.Content, nil
}

// --- Ollama Provider ---

// OllamaProvider implements the Provider interface for local Ollama.
type OllamaProvider struct {
	model    string
	endpoint string
	client   *http.Client
	format   interface{} // JSON schema object or "json" string
}

// SetFormat sets the JSON schema for constrained output.
func (p *OllamaProvider) SetFormat(schema interface{}) {
	p.format = schema
}

func (p *OllamaProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	format := p.format
	if format == nil {
		format = "json"
	}

	body := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"stream": false,
		"format": format,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := p.endpoint + "/api/chat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama API error %d: %s", resp.StatusCode, truncateAPIError(respBody))
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	return result.Message.Content, nil
}

// truncateAPIError limits API error response bodies to prevent sensitive information leakage.
// Returns at most 512 bytes of the response for diagnostic purposes.
func truncateAPIError(body []byte) string {
	const maxLen = 512
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "... (truncated)"
}
