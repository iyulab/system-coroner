package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/iyulab/system-coroner/internal/reporter"
)

// ReEvaluateFunc is called with analyst context and returns new ReportData.
type ReEvaluateFunc func(ctx context.Context, analystContext string) (*reporter.ReportData, error)

// RenderFunc renders ReportData to HTML string.
type RenderFunc func(data *reporter.ReportData) (string, error)

// Server is a local HTTP server that serves the report and handles re-evaluation.
type Server struct {
	mu         sync.RWMutex
	reportHTML string         // cached HTML of current report
	reEvaluate ReEvaluateFunc // callback to re-run analysis
	renderFn   RenderFunc     // callback to render ReportData to HTML
	httpServer *http.Server
}

// New creates a Server. reportData and reEvaluate may be set after creation.
func New(data *reporter.ReportData, html string, reEval ReEvaluateFunc) *Server {
	return &Server{
		reportHTML: html,
		reEvaluate: reEval,
	}
}

// Start begins listening on the given port (0 = OS-assigned). Returns "host:port".
func (s *Server) Start(ctx context.Context, port int) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/re-evaluate", s.handleReEvaluate)
	mux.HandleFunc("/", s.handleReport)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	s.httpServer = &http.Server{Handler: mux}
	go s.httpServer.Serve(ln) //nolint:errcheck

	return ln.Addr().String(), nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	html := s.reportHTML
	s.mu.RUnlock()

	if html == "" {
		http.Error(w, "report not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

type reEvaluateRequest struct {
	Context string `json:"context"`
}

func (s *Server) handleReEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req reEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Context == "" {
		http.Error(w, "context is required", http.StatusBadRequest)
		return
	}
	if s.reEvaluate == nil {
		http.Error(w, "re-evaluation not configured", http.StatusServiceUnavailable)
		return
	}

	newData, err := s.reEvaluate(r.Context(), req.Context)
	if err != nil {
		http.Error(w, fmt.Sprintf("re-evaluation failed: %v", err), http.StatusInternalServerError)
		return
	}

	if s.renderFn == nil {
		http.Error(w, "render function not configured", http.StatusInternalServerError)
		return
	}

	html, err := s.renderFn(newData)
	if err != nil {
		http.Error(w, fmt.Sprintf("render failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.UpdateReport(html)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// UpdateReport sets the current report HTML (thread-safe).
func (s *Server) UpdateReport(html string) {
	s.mu.Lock()
	s.reportHTML = html
	s.mu.Unlock()
}

// SetRenderFunc sets the function used to render ReportData to HTML.
func (s *Server) SetRenderFunc(fn RenderFunc) {
	s.renderFn = fn
}
