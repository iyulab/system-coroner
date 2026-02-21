// Package scripts provides embedded detection scripts for all platforms.
package scripts

import "embed"

// WindowsScripts contains all Windows PowerShell detection scripts.
//
//go:embed windows/*.ps1
var WindowsScripts embed.FS

// LinuxScripts contains all Linux Bash detection scripts.
//
//go:embed linux/*
var LinuxScripts embed.FS
