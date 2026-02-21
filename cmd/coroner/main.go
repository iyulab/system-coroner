// Package main is the CLI entry point for system-coroner.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/iyulab/system-coroner/internal/config"
	"github.com/iyulab/system-coroner/internal/orchestrator"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "coroner",
		Short: "Automated intrusion artifact detection and LLM-based analysis report generator",
		Long: `system-coroner scans a server for indicators of compromise (IoC),
analyzes them with an LLM, and produces a single report.html.
No agent installation required — one binary, one run.`,
		RunE:          run,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.Flags().StringP("config", "c", "config.toml", "path to config file")
	rootCmd.Flags().Bool("collect-only", false, "collect artifacts without calling the LLM")
	rootCmd.Flags().String("only", "", "run specific checks only (comma-separated)")
	rootCmd.Flags().String("fixture", "", "path to fixture directory (use files instead of collecting)")
	rootCmd.Flags().Bool("skip-collect", false, "skip collection phase (use with --fixture)")
	rootCmd.Flags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.Flags().Bool("no-serve", false, "disable interactive server after analysis (for CI/scripted use)")
	rootCmd.Flags().Int("port", 8742, "port for the interactive server")
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
	rootCmd.AddCommand(newUpdateCmd(version))

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	collectOnly, _ := cmd.Flags().GetBool("collect-only")
	onlyStr, _ := cmd.Flags().GetString("only")
	fixture, _ := cmd.Flags().GetString("fixture")
	skipCollect, _ := cmd.Flags().GetBool("skip-collect")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noServe, _ := cmd.Flags().GetBool("no-serve")
	port, _ := cmd.Flags().GetInt("port")

	// Parse --only flag
	var only []string
	if onlyStr != "" {
		for _, s := range strings.Split(onlyStr, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				only = append(only, s)
			}
		}
	}

	// Validate flag combinations
	if skipCollect && fixture == "" {
		return fmt.Errorf("--skip-collect requires --fixture")
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Create and run orchestrator
	orch := orchestrator.New(cfg, orchestrator.Options{
		CollectOnly: collectOnly,
		Only:        only,
		Fixture:     fixture,
		SkipCollect: skipCollect,
		Verbose:     verbose,
		Version:     fmt.Sprintf("%s (%s)", version, commit),
		Serve:       !noServe,
		ServePort:   port,
	})

	return orch.Run(cmd.Context())
}
