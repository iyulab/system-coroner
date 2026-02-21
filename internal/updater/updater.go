// Package updater handles self-update logic for the coroner binary.
package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const defaultAPIURL = "https://api.github.com/repos/iyulab/system-coroner/releases/latest"

// UpdateInfo holds the result of a version check.
type UpdateInfo struct {
	HasUpdate      bool
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckLatest queries the GitHub API and returns update info.
// apiURL defaults to the official GitHub releases endpoint when empty.
func CheckLatest(currentVersion, apiURL string) (*UpdateInfo, error) {
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	resp, err := http.Get(apiURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("updater: fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("updater: GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("updater: parse response: %w", err)
	}

	info := &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  release.TagName,
	}

	info.HasUpdate = isNewer(currentVersion, release.TagName)

	if info.HasUpdate {
		target := AssetName(runtime.GOOS, runtime.GOARCH)
		for _, a := range release.Assets {
			if a.Name == target {
				info.DownloadURL = a.BrowserDownloadURL
				break
			}
		}
	}

	return info, nil
}

// AssetName returns the expected release asset filename for the given OS/arch.
func AssetName(goos, goarch string) string {
	name := "coroner-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// SelfReplace atomically replaces exePath with newBinary.
// On Linux/macOS it uses os.Rename (atomic on same filesystem).
// On Windows it renames the current exe to .bak first.
func SelfReplace(exePath, newBinary string) error {
	if err := os.Chmod(newBinary, 0o755); err != nil {
		return fmt.Errorf("updater: chmod new binary: %w", err)
	}

	if runtime.GOOS == "windows" {
		bakPath := exePath + ".bak"
		_ = os.Remove(bakPath)
		if err := os.Rename(exePath, bakPath); err != nil {
			return fmt.Errorf("updater: rename current exe: %w", err)
		}
	}

	if err := os.Rename(newBinary, exePath); err != nil {
		return fmt.Errorf("updater: replace exe: %w", err)
	}
	return nil
}

// Download fetches url and writes the content to destPath.
func Download(url, destPath string) error {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("updater: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("updater: download returned %d", resp.StatusCode)
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("updater: create dest file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("updater: write download: %w", err)
	}
	return nil
}

// isNewer returns true if latest > current (semver comparison).
// A "dev" current version is always considered older.
func isNewer(current, latest string) bool {
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")
	if current == "dev" || current == "" || current == "none" {
		return latest != ""
	}
	return semverLess(current, latest)
}

// semverLess returns true if a < b using major.minor.patch comparison.
func semverLess(a, b string) bool {
	pa := splitSemver(a)
	pb := splitSemver(b)
	for i := range 3 {
		if pa[i] < pb[i] {
			return true
		}
		if pa[i] > pb[i] {
			return false
		}
	}
	return false
}

func splitSemver(v string) [3]int {
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
