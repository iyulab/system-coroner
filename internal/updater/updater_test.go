package updater_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iyulab/system-coroner/internal/updater"
)

// fakeRelease builds a minimal GitHub releases/latest JSON response.
func fakeRelease(tag string, assets []string) []byte {
	type asset struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}
	type release struct {
		TagName string  `json:"tag_name"`
		Assets  []asset `json:"assets"`
	}
	r := release{TagName: tag}
	for _, name := range assets {
		r.Assets = append(r.Assets, asset{
			Name:               name,
			BrowserDownloadURL: "http://example.com/" + name,
		})
	}
	b, _ := json.Marshal(r)
	return b
}

func TestCheckLatest_NewerAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fakeRelease("v0.2.0", []string{
			"coroner-linux-amd64",
			"coroner-windows-amd64.exe",
		}))
	}))
	defer srv.Close()

	info, err := updater.CheckLatest("v0.1.0", srv.URL+"/latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HasUpdate {
		t.Error("expected HasUpdate=true")
	}
	if info.LatestVersion != "v0.2.0" {
		t.Errorf("LatestVersion = %q, want v0.2.0", info.LatestVersion)
	}
}

func TestCheckLatest_AlreadyLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fakeRelease("v0.2.0", nil))
	}))
	defer srv.Close()

	info, err := updater.CheckLatest("v0.2.0", srv.URL+"/latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.HasUpdate {
		t.Error("expected HasUpdate=false when already on latest")
	}
}

func TestCheckLatest_DevVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fakeRelease("v0.2.0", nil))
	}))
	defer srv.Close()

	info, err := updater.CheckLatest("dev", srv.URL+"/latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HasUpdate {
		t.Error("dev build should always report update available")
	}
}

func TestAssetName(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{"linux", "amd64", "coroner-linux-amd64"},
		{"linux", "arm64", "coroner-linux-arm64"},
		{"darwin", "amd64", "coroner-darwin-amd64"},
		{"darwin", "arm64", "coroner-darwin-arm64"},
		{"windows", "amd64", "coroner-windows-amd64.exe"},
	}
	for _, tt := range tests {
		got := updater.AssetName(tt.goos, tt.goarch)
		if got != tt.want {
			t.Errorf("AssetName(%q,%q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

func TestSelfReplace_BasicRoundtrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip in-place replace test on Windows CI")
	}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "coroner")
	if err := os.WriteFile(exePath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	newPath := filepath.Join(dir, "coroner.new")
	if err := os.WriteFile(newPath, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := updater.SelfReplace(exePath, newPath); err != nil {
		t.Fatalf("SelfReplace: %v", err)
	}

	got, _ := os.ReadFile(exePath)
	if string(got) != "new" {
		t.Errorf("exe content = %q, want new", got)
	}
}
