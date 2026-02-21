package server_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/iyulab/system-coroner/internal/reporter"
	"github.com/iyulab/system-coroner/internal/server"
)

func TestServer_HealthEndpoint(t *testing.T) {
	srv := server.New(nil, "", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServer_ReportEndpoint(t *testing.T) {
	srv := server.New(nil, "<html>test report</html>", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "test report") {
		t.Errorf("expected report content, got: %s", string(body))
	}
}

func TestServer_ReportNotReady(t *testing.T) {
	srv := server.New(nil, "", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestServer_ReEvaluate(t *testing.T) {
	callCount := 0
	mockReEval := func(ctx context.Context, analystContext string) (*reporter.ReportData, error) {
		callCount++
		if analystContext != "rclone is a legitimate backup tool" {
			t.Errorf("expected context 'rclone is a legitimate backup tool', got %q", analystContext)
		}
		return &reporter.ReportData{Hostname: "testhost"}, nil
	}

	srv := server.New(nil, "<html>original</html>", mockReEval)
	srv.SetRenderFunc(func(data *reporter.ReportData) (string, error) {
		return "<html>re-evaluated</html>", nil
	})

	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	body := strings.NewReader(`{"context":"rclone is a legitimate backup tool"}`)
	resp, err := http.Post("http://"+addr+"/re-evaluate", "application/json", body)
	if err != nil {
		t.Fatalf("POST /re-evaluate: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if callCount != 1 {
		t.Errorf("expected reEvaluate called once, got %d", callCount)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "re-evaluated") {
		t.Errorf("expected new HTML in response, got: %s", string(respBody))
	}
}

func TestServer_ReEvaluateNoReEvalFunc(t *testing.T) {
	srv := server.New(nil, "<html>original</html>", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	body := strings.NewReader(`{"context":"test"}`)
	resp, err := http.Post("http://"+addr+"/re-evaluate", "application/json", body)
	if err != nil {
		t.Fatalf("POST /re-evaluate: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestServer_ReEvaluateEmptyContext(t *testing.T) {
	srv := server.New(nil, "<html>original</html>", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	body := strings.NewReader(`{"context":""}`)
	resp, err := http.Post("http://"+addr+"/re-evaluate", "application/json", body)
	if err != nil {
		t.Fatalf("POST /re-evaluate: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestServer_ReEvaluateMethodNotAllowed(t *testing.T) {
	srv := server.New(nil, "<html>original</html>", nil)
	addr, err := srv.Start(context.Background(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp, err := http.Get("http://" + addr + "/re-evaluate")
	if err != nil {
		t.Fatalf("GET /re-evaluate: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
