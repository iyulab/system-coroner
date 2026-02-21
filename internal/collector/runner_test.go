package collector

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/iyulab/system-coroner/internal/platform"
)

func TestEncodeForPowerShell(t *testing.T) {
	encoded := encodeForPowerShell("Write-Output 'hello'")
	if encoded == "" {
		t.Fatal("encoded string should not be empty")
	}
	// Verify it's valid base64
	if len(encoded)%4 != 0 {
		t.Errorf("encoded string length %d is not multiple of 4", len(encoded))
	}
}

func TestRunCheck_SimpleScript(t *testing.T) {
	// PowerShell cold start can take 3-15s on Windows; use generous timeout
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}

	if runtime.GOOS == "windows" {
		// Test with PowerShell
		check := platform.Check{
			ID:           "test_check",
			Timeout:      timeout,
			OutputFormat: "json",
		}
		script := []byte(`Write-Output '{"check":"test","items":[]}'`)
		result := RunCheck(context.Background(), check, script)
		if result.ExitCode != 0 {
			t.Errorf("exit code = %d, want 0; stderr: %s; error: %v", result.ExitCode, result.Stderr, result.Error)
		}
		if len(result.Stdout) == 0 {
			t.Error("stdout should not be empty")
		}
		if result.CheckID != "test_check" {
			t.Errorf("CheckID = %q, want %q", result.CheckID, "test_check")
		}
	} else {
		// Test with Bash
		check := platform.Check{
			ID:           "test_check",
			Timeout:      timeout,
			OutputFormat: "json",
		}
		script := []byte(`echo '{"check":"test","items":[]}'`)
		result := RunCheck(context.Background(), check, script)
		if result.ExitCode != 0 {
			t.Errorf("exit code = %d, want 0; stderr: %s; error: %v", result.ExitCode, result.Stderr, result.Error)
		}
		if len(result.Stdout) == 0 {
			t.Error("stdout should not be empty")
		}
	}
}

func TestRunCheck_Timeout(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Start-Sleep -Seconds 30; Write-Output '{}'`)
	} else {
		script = []byte(`sleep 30; echo '{}'`)
	}

	check := platform.Check{
		ID:      "timeout_check",
		Timeout: 1 * time.Second,
	}

	result := RunCheck(context.Background(), check, script)
	if !result.TimedOut {
		t.Error("expected TimedOut=true")
	}
	if result.Error == nil {
		t.Error("expected non-nil error for timeout")
	}
}

func TestRunCheck_ExitError(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Write-Output '{"error":"test"}'; exit 1`)
	} else {
		script = []byte(`echo '{"error":"test"}'; exit 1`)
	}

	// PowerShell cold start can take 3-15s on Windows
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}
	check := platform.Check{
		ID:      "error_check",
		Timeout: timeout,
	}

	result := RunCheck(context.Background(), check, script)
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code")
	}
	// Should still have partial output (evidence-first)
	if len(result.Stdout) == 0 {
		t.Error("stdout should contain partial output even on error")
	}
}

func TestRunCheck_Duration(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Write-Output 'ok'`)
	} else {
		script = []byte(`echo 'ok'`)
	}

	// PowerShell cold start can take 3-15s on Windows
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}
	check := platform.Check{
		ID:      "duration_check",
		Timeout: timeout,
	}

	result := RunCheck(context.Background(), check, script)
	if result.Duration == 0 {
		t.Error("duration should be non-zero")
	}
	if result.CollectedAt.IsZero() {
		t.Error("CollectedAt should be set")
	}
}

func TestRunCheck_ContextCancellation(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Start-Sleep -Seconds 30`)
	} else {
		script = []byte(`sleep 30`)
	}

	check := platform.Check{
		ID:      "cancel_check",
		Timeout: 60 * time.Second, // Long timeout so context cancel fires first
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	result := RunCheck(ctx, check, script)
	if result.Error == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestRunCheck_EmptyStdout(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`# no output`)
	} else {
		script = []byte(`# no output`)
	}

	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}
	check := platform.Check{
		ID:      "empty_stdout_check",
		Timeout: timeout,
	}

	result := RunCheck(context.Background(), check, script)
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
	if len(result.Stdout) != 0 {
		t.Errorf("expected empty stdout, got %d bytes", len(result.Stdout))
	}
}

func TestRunCheck_StderrOnly(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Write-Error "diagnostic message"`)
	} else {
		script = []byte(`echo "diagnostic message" >&2`)
	}

	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}
	check := platform.Check{
		ID:      "stderr_only_check",
		Timeout: timeout,
	}

	result := RunCheck(context.Background(), check, script)
	// stderr should be captured even when there's no stdout
	if len(result.Stderr) == 0 {
		t.Error("stderr should contain diagnostic output")
	}
}

func TestClassifyFailure_Timeout(t *testing.T) {
	result := Result{
		TimedOut: true,
		ExitCode: -1,
		Error:    fmt.Errorf("timeout after 5s"),
	}
	classifyFailure(&result)
	if result.FailureKind != FailureTimeout {
		t.Errorf("FailureKind = %v, want FailureTimeout", result.FailureKind)
	}
	if result.FailureKind.String() != "timeout" {
		t.Errorf("String() = %q, want %q", result.FailureKind.String(), "timeout")
	}
}

func TestClassifyFailure_None(t *testing.T) {
	result := Result{ExitCode: 0}
	classifyFailure(&result)
	if result.FailureKind != FailureNone {
		t.Errorf("FailureKind = %v, want FailureNone", result.FailureKind)
	}
}

func TestClassifyFailure_PermissionByExitCode(t *testing.T) {
	cases := []struct {
		exitCode int
		want     FailureKind
	}{
		{5, FailurePermission},   // Windows: ERROR_ACCESS_DENIED
		{126, FailurePermission}, // POSIX: cannot execute
		{127, FailureNotFound},   // POSIX: command not found
		{9009, FailureNotFound},  // Windows: not recognized
	}
	for _, tc := range cases {
		result := Result{
			ExitCode: tc.exitCode,
			Error:    fmt.Errorf("exec: exit status %d", tc.exitCode),
		}
		classifyFailure(&result)
		if result.FailureKind != tc.want {
			t.Errorf("exitCode=%d: FailureKind = %v, want %v", tc.exitCode, result.FailureKind, tc.want)
		}
	}
}

func TestClassifyFailure_PermissionByStderr(t *testing.T) {
	for _, pattern := range []string{"access denied", "access is denied", "permission denied"} {
		result := Result{
			ExitCode: 1,
			Error:    fmt.Errorf("exec: exit status 1"),
			Stderr:   []byte("Error: " + pattern),
		}
		classifyFailure(&result)
		if result.FailureKind != FailurePermission {
			t.Errorf("stderr=%q: FailureKind = %v, want FailurePermission", pattern, result.FailureKind)
		}
	}
}

func TestClassifyFailure_ScriptError(t *testing.T) {
	result := Result{
		ExitCode: 1,
		Error:    fmt.Errorf("exec: exit status 1"),
		Stderr:   []byte("some other error"),
	}
	classifyFailure(&result)
	if result.FailureKind != FailureScriptError {
		t.Errorf("FailureKind = %v, want FailureScriptError", result.FailureKind)
	}
	if result.FailureKind.String() != "script_error" {
		t.Errorf("String() = %q, want %q", result.FailureKind.String(), "script_error")
	}
}

func TestClassifyFailure_Unknown(t *testing.T) {
	result := Result{
		ExitCode: -1,
		Error:    fmt.Errorf("exec: some os error"),
	}
	classifyFailure(&result)
	if result.FailureKind != FailureUnknown {
		t.Errorf("FailureKind = %v, want FailureUnknown", result.FailureKind)
	}
}

func TestRunCheck_SuccessHasFailureNone(t *testing.T) {
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Write-Output '{}'`)
	} else {
		script = []byte(`echo '{}'`)
	}
	check := platform.Check{ID: "ok_check", Timeout: timeout}
	result := RunCheck(context.Background(), check, script)
	if result.ExitCode != 0 {
		t.Skipf("script failed (exit %d), skipping FailureNone check", result.ExitCode)
	}
	if result.FailureKind != FailureNone {
		t.Errorf("FailureKind = %v, want FailureNone for success", result.FailureKind)
	}
}

func TestRunCheck_TimeoutHasFailureTimeout(t *testing.T) {
	var script []byte
	if runtime.GOOS == "windows" {
		script = []byte(`Start-Sleep -Seconds 30`)
	} else {
		script = []byte(`sleep 30`)
	}
	check := platform.Check{ID: "timeout_fail_check", Timeout: 1 * time.Second}
	result := RunCheck(context.Background(), check, script)
	if !result.TimedOut {
		t.Skip("expected timeout, got none")
	}
	if result.FailureKind != FailureTimeout {
		t.Errorf("FailureKind = %v, want FailureTimeout", result.FailureKind)
	}
}
