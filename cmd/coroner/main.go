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
		Short: "서버 침입 흔적 자동 탐지 및 LLM 기반 분석 리포트 생성",
		Long: `system-coroner는 서버 전반을 스캔하여 침입 흔적(IoC)을 수집하고,
LLM이 이를 분석한 뒤 단일 report.html을 생성합니다.
에이전트 설치 없이, 한 번의 실행으로.`,
		RunE:          run,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.Flags().StringP("config", "c", "config.toml", "설정 파일 경로")
	rootCmd.Flags().Bool("collect-only", false, "LLM 호출 없이 수집만 실행")
	rootCmd.Flags().String("only", "", "특정 탐지 항목만 실행 (콤마 구분)")
	rootCmd.Flags().String("fixture", "", "픽스처 디렉토리 경로 (수집 대신 파일 사용)")
	rootCmd.Flags().Bool("skip-collect", false, "수집 건너뛰기 (--fixture와 조합)")
	rootCmd.Flags().BoolP("verbose", "v", false, "상세 로그 출력")
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

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
	})

	return orch.Run(cmd.Context())
}
