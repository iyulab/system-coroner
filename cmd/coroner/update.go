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
		Short: "최신 버전으로 업데이트",
		Long:  "GitHub Releases에서 최신 버전을 확인하고 자동으로 업데이트합니다.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(currentVersion, checkOnly)
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "다운로드 없이 최신 버전만 확인")
	return cmd
}

func runUpdate(currentVersion string, checkOnly bool) error {
	fmt.Println("업데이트 확인 중...")

	info, err := updater.CheckLatest(currentVersion, "")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	if !info.HasUpdate {
		fmt.Printf("이미 최신 버전입니다 (%s)\n", info.CurrentVersion)
		return nil
	}

	fmt.Printf("새 버전 발견: %s → %s\n", info.CurrentVersion, info.LatestVersion)

	if checkOnly {
		fmt.Printf("업데이트하려면: coroner update\n")
		return nil
	}

	if info.DownloadURL == "" {
		return fmt.Errorf("update: 이 플랫폼용 바이너리를 찾을 수 없습니다")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("update: 실행 파일 경로 확인 실패: %w", err)
	}

	tmpPath := exePath + ".new"
	fmt.Printf("다운로드 중: %s\n", info.DownloadURL)

	if err := updater.Download(info.DownloadURL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: 다운로드 실패: %w", err)
	}

	fmt.Printf("교체 중: %s\n", filepath.Base(exePath))
	if err := updater.SelfReplace(exePath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: 교체 실패 (권한 확인): %w", err)
	}

	fmt.Printf("업데이트 완료! %s → %s\n", info.CurrentVersion, info.LatestVersion)
	fmt.Println("변경 사항을 적용하려면 coroner를 재시작하세요.")
	return nil
}
