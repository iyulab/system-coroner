// Package browser provides cross-platform browser opening.
package browser

import (
	"os/exec"
	"runtime"
)

// Open opens the given URL in the system default browser.
// Errors are silently ignored — this is best-effort.
func Open(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux + others
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
