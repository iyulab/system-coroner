package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/iyulab/system-coroner/internal/updater"
	"github.com/spf13/cobra"
)

func newUpdateCmd(currentVersion string) *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update to the latest version",
		Long:  "Check for the latest version on GitHub Releases and update automatically.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(currentVersion, checkOnly)
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "check for updates without downloading")
	return cmd
}

func runUpdate(currentVersion string, checkOnly bool) error {
	fmt.Println("Checking for updates...")

	info, err := updater.CheckLatest(currentVersion, "")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	if !info.HasUpdate {
		fmt.Printf("Already up to date (%s)\n", info.CurrentVersion)
		return nil
	}

	fmt.Printf("New version available: %s → %s\n", info.CurrentVersion, info.LatestVersion)

	if checkOnly {
		fmt.Printf("To update, run: coroner update\n")
		return nil
	}

	if info.DownloadURL == "" {
		return fmt.Errorf("update: no binary found for this platform")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("update: could not resolve executable path: %w", err)
	}

	tmpPath := exePath + ".new"
	fmt.Printf("Downloading: %s\n", info.DownloadURL)

	if err := updater.Download(info.DownloadURL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: download failed: %w", err)
	}

	fmt.Printf("Replacing: %s\n", filepath.Base(exePath))
	if err := updater.SelfReplace(exePath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: replace failed (check permissions): %w", err)
	}

	fmt.Printf("Update complete! %s → %s\n", info.CurrentVersion, info.LatestVersion)
	fmt.Println("Restart coroner to apply the update.")
	return nil
}
