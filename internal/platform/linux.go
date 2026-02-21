package platform

import "time"

// LinuxChecks returns the Linux intrusion detection checks.
func LinuxChecks() []Check {
	return []Check{
		{
			ID:            "c2_connections",
			Name:          "C2 통신 및 역방향 쉘 탐지",
			Description:   "외부 C2 서버 통신, Reverse Shell, 의심 포트 리스닝 탐지",
			Script:        "scripts/linux/c2_connections.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "persistence",
			Name:          "재부팅 후 생존 메커니즘 탐지",
			Description:   "Cron 작업, systemd 비표준 서비스, rc.local을 통한 Persistence 탐지",
			Script:        "scripts/linux/persistence.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "log_tampering",
			Name:          "로그 삭제/변조 흔적 탐지",
			Description:   "로그 파일 크기 이상, 감사 데몬 비활성, 저널 무결성 검증",
			Script:        "scripts/linux/log_tampering.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "account_compromise",
			Name:          "계정 탈취 및 조작 흔적",
			Description:   "UID 0 계정, 비인가 SSH 키, 브루트포스, 최근 계정 파일 변경 탐지",
			Script:        "scripts/linux/account_compromise.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "credential_dump",
			Name:          "크리덴셜 덤프 흔적 탐지",
			Description:   "/etc/shadow 접근 권한, 크리덴셜 도구, 민감 파일 접근 탐지",
			Script:        "scripts/linux/credential_dump.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "fileless_attack",
			Name:          "파일리스 공격 탐지",
			Description:   "삭제된 실행 파일 프로세스, /dev/shm 악용, memfd_create 탐지",
			Script:        "scripts/linux/fileless_attack.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "lolbin_abuse",
			Name:          "GTFOBins 악용 탐지",
			Description:   "curl, wget, python, nc 등 정상 도구의 악의적 사용 탐지",
			Script:        "scripts/linux/lolbin_abuse.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "lateral_movement",
			Name:          "내부 이동 흔적 탐지",
			Description:   "SSH 세션, 원격 로그인, SSH 터널링, 원격 실행 도구 탐지",
			Script:        "scripts/linux/lateral_movement.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "webshell",
			Name:          "웹쉘 탐지",
			Description:   "웹 서버 디렉토리 내 의심 스크립트, 웹쉘 패턴 매칭 탐지",
			Script:        "scripts/linux/webshell.sh",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
	}
}
