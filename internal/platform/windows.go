package platform

import "time"

// WindowsChecks returns the 9 Windows intrusion detection checks.
func WindowsChecks() []Check {
	return []Check{
		{
			ID:            "c2_connections",
			Name:          "C2 통신 및 역방향 쉘 탐지",
			Description:   "외부 C2 서버 통신, Reverse Shell, Beacon 트래픽 탐지",
			Script:        "windows/c2_connections.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "account_compromise",
			Name:          "계정 탈취 및 조작 흔적",
			Description:   "공격자 계정 생성, 권한 상승, 브루트포스 공격 탐지",
			Script:        "windows/account_compromise.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "persistence",
			Name:          "재부팅 후 생존 메커니즘 탐지",
			Description:   "레지스트리 Run 키, 스케줄 작업, 비표준 서비스를 통한 Persistence 탐지",
			Script:        "windows/persistence.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "lolbin_abuse",
			Name:          "Living-off-the-Land 공격 탐지",
			Description:   "certutil, mshta, regsvr32 등 Windows 내장 도구 악용 탐지",
			Script:        "windows/lolbin_abuse.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "fileless_attack",
			Name:          "파일리스 공격 탐지",
			Description:   "WMI 이벤트 구독, PowerShell 스크립트 블록 로깅, 메모리 기반 공격 탐지",
			Script:        "windows/fileless_attack.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
		{
			ID:            "log_tampering",
			Name:          "로그 삭제/변조 흔적 탐지",
			Description:   "Security/System 로그 삭제, 감사 정책 비활성화 탐지",
			Script:        "windows/log_tampering.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "credential_dump",
			Name:          "크리덴셜 덤프 흔적 탐지",
			Description:   "LSASS 접근, SAM 하이브 복사, Mimikatz 흔적 탐지",
			Script:        "windows/credential_dump.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "lateral_movement",
			Name:          "내부 이동 흔적 탐지",
			Description:   "RDP, PsExec, WinRM, Pass-the-Hash를 통한 Lateral Movement 탐지",
			Script:        "windows/lateral_movement.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: true,
		},
		{
			ID:            "webshell",
			Name:          "웹쉘 탐지",
			Description:   "웹 서버 루트 내 신규/변조된 스크립트 파일, IIS 로그 이상 탐지",
			Script:        "windows/webshell.ps1",
			Timeout:       30 * time.Second,
			OutputFormat:  "json",
			RequiresAdmin: false,
		},
	}
}
