package analyzer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Anthropic Provider Tests ---

// anthropicRoundTripper is an http.RoundTripper that returns a canned response for testing.
type anthropicRoundTripper struct {
	response string
	status   int
	t        *testing.T
}

func (rt *anthropicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: rt.status,
		Body:       io.NopCloser(strings.NewReader(rt.response)),
		Header:     make(http.Header),
	}, nil
}

func newAnthropicTestProvider(response string, status int, t *testing.T) *AnthropicProvider {
	return &AnthropicProvider{
		apiKey:   "test-key",
		model:    "claude-test",
		endpoint: "https://test.local/v1",
		client:   &http.Client{Transport: &anthropicRoundTripper{response: response, status: status, t: t}},
	}
}

func TestAnthropicProvider_TextResponse(t *testing.T) {
	resp := `{"content":[{"type":"text","text":"{\"check\":\"c2_connections\",\"intrusion_confidence\":\"clean\",\"risk_level\":\"none\",\"title\":\"No findings\"}"}]}`
	p := newAnthropicTestProvider(resp, http.StatusOK, t)
	result, err := p.Analyze(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "c2_connections") {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestAnthropicProvider_ToolUseResponse(t *testing.T) {
	// When schema is set, tool_use blocks should take priority over text blocks.
	resp := `{"content":[{"type":"tool_use","id":"tu_abc","name":"record_result","input":{"check":"c2_connections","intrusion_confidence":"high","risk_level":"high","title":"Suspicious C2"}}]}`
	p := newAnthropicTestProvider(resp, http.StatusOK, t)
	p.SetFormat(FindingSchema)

	result, err := p.Analyze(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Suspicious C2") {
		t.Errorf("tool_use input not returned: %s", result)
	}
	// Result should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("tool_use result is not valid JSON: %v", err)
	}
}

func TestAnthropicProvider_ToolUseFallsBackToText(t *testing.T) {
	// If no tool_use block is present, fall back to text block.
	resp := `{"content":[{"type":"text","text":"{\"check\":\"test\",\"intrusion_confidence\":\"clean\",\"risk_level\":\"none\",\"title\":\"ok\"}"}]}`
	p := newAnthropicTestProvider(resp, http.StatusOK, t)
	p.SetFormat(FindingSchema)

	result, err := p.Analyze(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "clean") {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestAnthropicProvider_EmptyContent(t *testing.T) {
	resp := `{"content":[]}`
	p := newAnthropicTestProvider(resp, http.StatusOK, t)
	_, err := p.Analyze(context.Background(), "system", "user")
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestAnthropicProvider_APIError(t *testing.T) {
	resp := `{"error":{"type":"authentication_error","message":"invalid api key"}}`
	p := newAnthropicTestProvider(resp, http.StatusUnauthorized, t)
	_, err := p.Analyze(context.Background(), "system", "user")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestAnthropicProvider_SetFormatIncludesToolInRequest(t *testing.T) {
	var capturedBody []byte
	rt := &capturingRoundTripper{
		response: `{"content":[{"type":"tool_use","id":"x","name":"record_result","input":{"check":"test","intrusion_confidence":"clean","risk_level":"none","title":"ok"}}]}`,
		status:   200,
		captured: &capturedBody,
	}
	p := &AnthropicProvider{
		apiKey:   "test",
		model:    "claude-test",
		endpoint: "https://test.local/v1",
		client:   &http.Client{Transport: rt},
	}
	p.SetFormat(FindingSchema)
	p.Analyze(context.Background(), "sys", "usr")

	var req map[string]interface{}
	if err := json.Unmarshal(capturedBody, &req); err != nil {
		t.Fatalf("could not parse captured body: %v", err)
	}
	if _, hasTools := req["tools"]; !hasTools {
		t.Error("request body should include 'tools' when schema is set")
	}
	if _, hasChoice := req["tool_choice"]; !hasChoice {
		t.Error("request body should include 'tool_choice' when schema is set")
	}
}

// capturingRoundTripper captures the request body in addition to returning a canned response.
type capturingRoundTripper struct {
	response string
	status   int
	captured *[]byte
}

func (rt *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		*rt.captured, _ = io.ReadAll(req.Body)
	}
	return &http.Response{
		StatusCode: rt.status,
		Body:       io.NopCloser(strings.NewReader(rt.response)),
		Header:     make(http.Header),
	}, nil
}

// --- OpenAI Provider Tests (endpoint is configurable) ---

func TestOpenAIProvider_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-openai-key" {
			t.Error("missing or wrong Authorization header")
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["model"] != "gpt-test" {
			t.Errorf("model = %v", req["model"])
		}

		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{"check":"test","intrusion_confidence":"clean","risk_level":"none","title":"no findings"}`,
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-openai-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	result, err := p.Analyze(context.Background(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "no findings") {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestOpenAIProvider_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestOpenAIProvider_EmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{"choices": []interface{}{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOpenAIProvider_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse response") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOpenAIProvider_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
}

// --- Ollama Provider Tests ---

func TestOllamaProvider_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/chat") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["model"] != "llama-test" {
			t.Errorf("model = %v", req["model"])
		}
		if req["stream"] != false {
			t.Error("stream should be false")
		}

		resp := map[string]interface{}{
			"message": map[string]string{
				"content": `{"check":"test","intrusion_confidence":"clean","risk_level":"none","title":"clean system"}`,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &OllamaProvider{
		model:    "llama-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	result, err := p.Analyze(context.Background(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "clean system") {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestOllamaProvider_WithFormat(t *testing.T) {
	var receivedFormat interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		receivedFormat = req["format"]

		resp := map[string]interface{}{
			"message": map[string]string{
				"content": `{"check":"test"}`,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &OllamaProvider{
		model:    "llama-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	// Set a JSON schema format
	p.SetFormat(FindingSchema)

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Format should have been sent (not the default "json" string)
	if receivedFormat == nil {
		t.Error("format should have been sent in request")
	}
	// When schema is set, it should be an object, not "json"
	if str, ok := receivedFormat.(string); ok && str == "json" {
		t.Error("format should be schema object, not 'json' string")
	}
}

func TestOllamaProvider_DefaultFormat(t *testing.T) {
	var receivedFormat interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		receivedFormat = req["format"]

		resp := map[string]interface{}{
			"message": map[string]string{"content": `{}`},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &OllamaProvider{
		model:    "llama-test",
		endpoint: server.URL,
		client:   server.Client(),
	}
	// Don't set format — should default to "json"

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedFormat != "json" {
		t.Errorf("default format should be 'json', got %v", receivedFormat)
	}
}

func TestOllamaProvider_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("model not found"))
	}))
	defer server.Close()

	p := &OllamaProvider{
		model:    "missing-model",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestOllamaProvider_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json at all`))
	}))
	defer server.Close()

	p := &OllamaProvider{
		model:    "llama-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	_, err := p.Analyze(context.Background(), "sys", "usr")
	if err == nil {
		t.Fatal("expected error for malformed response")
	}
}

// --- NewProvider Tests ---

func TestNewProvider_Anthropic(t *testing.T) {
	p, err := NewProvider("anthropic", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap, ok := p.(*AnthropicProvider)
	if !ok {
		t.Fatal("expected AnthropicProvider")
	}
	if ap.endpoint != "https://api.anthropic.com/v1" {
		t.Errorf("default endpoint = %q, want %q", ap.endpoint, "https://api.anthropic.com/v1")
	}
}

func TestNewProvider_Anthropic_CustomEndpoint(t *testing.T) {
	p, err := NewProvider("anthropic", "key", "model", "https://custom.anthropic.proxy/v1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap := p.(*AnthropicProvider)
	if ap.endpoint != "https://custom.anthropic.proxy/v1" {
		t.Errorf("custom endpoint = %q, want %q", ap.endpoint, "https://custom.anthropic.proxy/v1")
	}
}

func TestNewProvider_OpenAI(t *testing.T) {
	p, err := NewProvider("openai", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op, ok := p.(*OpenAIProvider)
	if !ok {
		t.Fatal("expected OpenAIProvider")
	}
	if op.endpoint != "https://api.openai.com/v1" {
		t.Errorf("default endpoint = %q", op.endpoint)
	}
}

func TestNewProvider_OpenAI_CustomEndpoint(t *testing.T) {
	p, err := NewProvider("openai", "key", "model", "https://custom.api.com/v1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op := p.(*OpenAIProvider)
	if op.endpoint != "https://custom.api.com/v1" {
		t.Errorf("custom endpoint = %q", op.endpoint)
	}
}

func TestNewProvider_Ollama(t *testing.T) {
	p, err := NewProvider("ollama", "", "llama3", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op, ok := p.(*OllamaProvider)
	if !ok {
		t.Fatal("expected OllamaProvider")
	}
	if op.endpoint != "http://localhost:11434" {
		t.Errorf("default endpoint = %q", op.endpoint)
	}
}

func TestNewProvider_GPUStack_DefaultEndpoint(t *testing.T) {
	p, err := NewProvider("gpustack", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op, ok := p.(*OpenAIProvider)
	if !ok {
		t.Fatal("expected OpenAIProvider (gpustack reuses OpenAI-compatible API)")
	}
	if op.endpoint != "http://localhost/v1" {
		t.Errorf("default endpoint = %q, want %q", op.endpoint, "http://localhost/v1")
	}
}

func TestNewProvider_GPUStack_CustomEndpoint(t *testing.T) {
	p, err := NewProvider("gpustack", "key", "model", "http://192.168.1.100/v1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op := p.(*OpenAIProvider)
	if op.endpoint != "http://192.168.1.100/v1" {
		t.Errorf("custom endpoint = %q, want %q", op.endpoint, "http://192.168.1.100/v1")
	}
}

func TestNewProvider_GPUStack_DefaultTimeout(t *testing.T) {
	p, err := NewProvider("gpustack", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op := p.(*OpenAIProvider)
	if op.client.Timeout.Seconds() != 300 {
		t.Errorf("expected 300s default timeout for gpustack, got %v", op.client.Timeout)
	}
}

func TestNewProvider_Unsupported(t *testing.T) {
	_, err := NewProvider("google", "key", "model", "", 0)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewProvider_CustomTimeout(t *testing.T) {
	// Verify custom timeout is applied (non-zero timeoutSec)
	p, err := NewProvider("openai", "key", "model", "", 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op := p.(*OpenAIProvider)
	if op.client.Timeout.Seconds() != 60 {
		t.Errorf("expected 60s timeout, got %v", op.client.Timeout)
	}
}

func TestNewProvider_DefaultTimeout(t *testing.T) {
	// Verify default timeout when timeoutSec is 0
	p, err := NewProvider("ollama", "", "model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op := p.(*OllamaProvider)
	if op.client.Timeout.Seconds() != 300 {
		t.Errorf("expected 300s default timeout for ollama, got %v", op.client.Timeout)
	}
}

// --- Context Cancellation Test ---

func TestOpenAIProvider_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response — context should cancel first
		<-r.Context().Done()
	}))
	defer server.Close()

	p := &OpenAIProvider{
		apiKey:   "test-key",
		model:    "gpt-test",
		endpoint: server.URL,
		client:   server.Client(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := p.Analyze(ctx, "sys", "usr")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- truncateAPIError Tests ---

func TestTruncateAPIError_Short(t *testing.T) {
	body := []byte(`{"error":"bad request"}`)
	result := truncateAPIError(body)
	if result != `{"error":"bad request"}` {
		t.Errorf("short body should not be truncated: %s", result)
	}
}

func TestTruncateAPIError_Long(t *testing.T) {
	// Create a body longer than 512 bytes
	body := make([]byte, 1024)
	for i := range body {
		body[i] = 'x'
	}
	result := truncateAPIError(body)
	if len(result) > 530 { // 512 + "... (truncated)"
		t.Errorf("long body should be truncated, got len=%d", len(result))
	}
	if !strings.HasSuffix(result, "... (truncated)") {
		t.Error("truncated body should have suffix")
	}
}

func TestTruncateAPIError_Exact512(t *testing.T) {
	body := make([]byte, 512)
	for i := range body {
		body[i] = 'a'
	}
	result := truncateAPIError(body)
	if len(result) != 512 {
		t.Errorf("exactly 512 bytes should not be truncated, got len=%d", len(result))
	}
}
