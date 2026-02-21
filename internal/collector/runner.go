package collector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/iyulab/system-coroner/internal/platform"
)

// RunCheck executes a single check script and returns the result.
func RunCheck(ctx context.Context, check platform.Check, scriptContent []byte) Result {
	start := time.Now()
	result := Result{
		CheckID:     check.ID,
		CollectedAt: start.UTC(),
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, check.Timeout)
	defer cancel()

	cmd, cleanup, err := buildCommand(ctx, check, scriptContent)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		result.Error = fmt.Errorf("build command: %w", err)
		result.ExitCode = -1
		result.Duration = time.Since(start)
		result.FailureKind = FailureUnknown
		return result
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.Bytes()
	result.Stderr = stderr.Bytes()

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		result.Error = fmt.Errorf("timeout after %s", check.Timeout)
		result.FailureKind = FailureTimeout
		return result
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Error = fmt.Errorf("exec: %w", err)
		classifyFailure(&result)
		return result
	}

	result.ExitCode = 0
	result.FailureKind = FailureNone
	return result
}

// classifyFailure sets FailureKind based on exit code and stderr content.
func classifyFailure(result *Result) {
	if result.TimedOut {
		result.FailureKind = FailureTimeout
		return
	}
	if result.Error == nil {
		result.FailureKind = FailureNone
		return
	}
	// Interpreter itself not found (e.g., powershell.exe / bash missing)
	if errors.Is(result.Error, exec.ErrNotFound) {
		result.FailureKind = FailureNotFound
		return
	}
	switch result.ExitCode {
	case 5: // Windows: ERROR_ACCESS_DENIED
		result.FailureKind = FailurePermission
	case 126: // POSIX: cannot execute (permission denied)
		result.FailureKind = FailurePermission
	case 127: // POSIX: command not found
		result.FailureKind = FailureNotFound
	case 9009: // Windows: command not recognized (interpreter not in PATH)
		result.FailureKind = FailureNotFound
	case -1: // OS-level exec failure, not a script exit code
		result.FailureKind = FailureUnknown
	default:
		if result.ExitCode > 0 {
			// Inspect stderr for access-denied patterns
			stderr := strings.ToLower(string(result.Stderr))
			if strings.Contains(stderr, "access denied") ||
				strings.Contains(stderr, "access is denied") ||
				strings.Contains(stderr, "permission denied") {
				result.FailureKind = FailurePermission
			} else {
				result.FailureKind = FailureScriptError
			}
		} else {
			result.FailureKind = FailureUnknown
		}
	}
}

// buildCommand creates the appropriate os/exec.Cmd for the current platform.
// Returns the command, a cleanup function (may be nil), and an error.
func buildCommand(ctx context.Context, check platform.Check, scriptContent []byte) (*exec.Cmd, func(), error) {
	switch runtime.GOOS {
	case "windows":
		return buildPowerShellCommand(ctx, scriptContent)
	case "linux", "darwin":
		return buildBashCommand(ctx, scriptContent)
	default:
		return nil, nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// buildPowerShellCommand creates a PowerShell command using a temp file.
// Falls back to -EncodedCommand if temp file creation fails.
// This avoids Windows Defender ASR blocking Base64-encoded commands containing
// WMI/process keywords.
func buildPowerShellCommand(ctx context.Context, scriptContent []byte) (*exec.Cmd, func(), error) {
	// Try temp file approach first (avoids Defender ASR blocking)
	tmpFile, err := os.CreateTemp("", "coroner-*.ps1")
	if err != nil {
		// fallback: -EncodedCommand 방식
		encoded := encodeForPowerShell(string(scriptContent))
		cmd := exec.CommandContext(ctx,
			"powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-EncodedCommand", encoded,
		)
		return cmd, func() {}, nil
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(scriptContent); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		// fallback: -EncodedCommand 방식
		encoded := encodeForPowerShell(string(scriptContent))
		cmd := exec.CommandContext(ctx,
			"powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-EncodedCommand", encoded,
		)
		return cmd, func() {}, nil
	}
	tmpFile.Close()

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", tmpPath,
	)
	return cmd, func() { os.Remove(tmpPath) }, nil
}

// buildBashCommand creates a Bash command that reads the script from stdin.
func buildBashCommand(ctx context.Context, scriptContent []byte) (*exec.Cmd, func(), error) {
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = bytes.NewReader(scriptContent)
	return cmd, func() {}, nil
}

// encodeForPowerShell converts a UTF-8 string to UTF-16LE Base64 for -EncodedCommand.
func encodeForPowerShell(script string) string {
	runes := utf16.Encode([]rune(script))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
