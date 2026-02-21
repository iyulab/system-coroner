# Contributing to system-coroner

침입 탐지 스크립트 기여를 특히 환영합니다. Go를 몰라도 PowerShell이나 Bash를 작성할 수 있다면 기여 가능합니다.

---

## 기여 방법

- **침입 탐지 스크립트 추가** — 새로운 공격 패턴 또는 플랫폼 지원
- **버그 수정** — 이슈 먼저 등록 후 논의
- **탐지 품질 개선** — 기존 스크립트의 탐지율 향상, 오탐 감소
- **리포트 개선** — HTML 템플릿 디자인, 새 시각화 추가
- **문서 개선** — 탐지 항목 설명, 공격 시나리오 보완

---

## 침입 탐지 스크립트 추가하기

가장 임팩트 있는 기여 방법입니다.

### 1. 스크립트 작성

```
scripts/windows/your_check.ps1
scripts/linux/your_check.sh
```

**설계 원칙:**
- **"이것이 침입 흔적인가?"** 를 기준으로 수집 항목을 선정합니다
- 보안 설정 점검(패치 여부, 방화벽 규칙 등)은 이 도구의 범위가 아닙니다
- 수집 결과는 LLM이 분석하므로 가능한 한 원본 데이터를 많이 포함하세요
- JSON 출력을 기본으로 합니다

**PowerShell 템플릿:**

```powershell
# scripts/windows/your_check.ps1
#
# 탐지 목표: 공격자가 [무엇]을 한 흔적
# 관련 MITRE: T1xxx
# 필요 권한: Administrator / Standard User
# 예상 실행 시간: ~N초

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

try {
    $result = @{
        collected_at   = (Get-Date -Format "o")
        hostname       = $env:COMPUTERNAME
        check          = "your_check"
        # 수집 데이터를 여기에 추가
        items          = @()
        errors         = @()
    }

    # --- 수집 로직 ---
    # 예: 비정상 외부 연결 탐지
    # $connections = Get-NetTCPConnection | Where-Object { ... }
    # $result.items = $connections | Select-Object ...

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    # 에러가 있어도 부분 결과와 함께 JSON 반환
    @{
        collected_at = (Get-Date -Format "o")
        check        = "your_check"
        error        = $_.Exception.Message
        items        = @()
    } | ConvertTo-Json -Compress
    exit 1
}
```

**Bash 템플릿:**

```bash
#!/bin/bash
# scripts/linux/your_check.sh
#
# 탐지 목표: 공격자가 [무엇]을 한 흔적
# 관련 MITRE: T1xxx
# 필요 권한: root / normal

set -uo pipefail

collected_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname=$(hostname)

items="[]"

# --- 수집 로직 ---

jq -n \
  --arg ts "$collected_at" \
  --arg host "$hostname" \
  --argjson items "$items" \
  '{
    collected_at: $ts,
    hostname: $host,
    check: "your_check",
    items: $items
  }'
```

**출력 요구사항:**
- stdout: 유효한 JSON
- stderr: 진단 메시지 (`.log` 파일에 별도 저장됨)
- exit code: 0 = 성공, 1 = 실패 (부분 결과는 계속 출력)
- 실행 시간: 30초 이내 (서버 부하 고려)
- 수집 실패 시에도 JSON 반환 (에러 필드 포함)

### 2. 탐지 항목 등록

```go
// internal/platform/windows.go

Check{
    ID:           "your_check",
    Name:         "탐지 항목 이름",
    Description:  "공격자가 무엇을 했을 때 탐지되는지 한 줄 설명",
    Script:       "scripts/windows/your_check.ps1",
    Timeout:      30 * time.Second,
    OutputFormat: "json",
    Enabled:      true,
    RequiresAdmin: false,  // 관리자 권한 필요 여부
},
```

### 3. 테스트 픽스처 작성

```
tests/fixtures/windows/your_check_clean.json       # 정상 — 이상 없음
tests/fixtures/windows/your_check_compromised.json  # 침해 — 탐지되어야 할 항목 포함
```

픽스처는 LLM 프롬프트 테스트와 리포트 렌더링 테스트에 사용됩니다.

### 4. CHECKS.md 업데이트

`CHECKS.md`에 새 항목을 추가합니다:
- 탐지 목표
- 수집 항목 목록
- LLM 분석 포인트 (어떤 패턴이 의심스러운가)
- MITRE ATT&CK 매핑

### 5. PR 설명에 포함할 내용

- 어떤 공격 기법을 탐지하는가 (실제 사례나 APT 그룹 TTP 참조 환영)
- `*_compromised.json` 픽스처에서 어떤 항목이 탐지되어야 하는가
- 오탐 가능성이 있는 정상 케이스는 무엇인가
- 필요 권한과 그 이유

---

## 개발 환경 설정

```bash
git clone https://github.com/iyulab/system-coroner
cd system-coroner

go mod download
go build -o coroner ./cmd/coroner
go test ./...
```

### 개발용 실행 옵션

```bash
# LLM 호출 없이 수집만 실행
./coroner --collect-only

# 특정 항목만 실행
./coroner --only c2_connections,log_tampering

# 픽스처 파일로 LLM 분석 및 리포트 테스트
./coroner --fixture tests/fixtures/windows/compromised/ --skip-collect

# 상세 로그 출력
./coroner --verbose

# LLM 타임아웃 설정 (config.toml)
# timeout = 60  # 초 단위, 0 = 프로바이더 기본값
```

---

## 코드 스타일

```bash
gofmt -w .          # 포맷
golangci-lint run   # 린트
go test ./...       # 테스트
```

- 외부 의존성 추가는 반드시 사전 논의 — 바이너리 크기와 공급망 보안 고려
- 공개 함수와 타입에는 doc comment 필수
- 에러는 wrap해서 컨텍스트 보존: `fmt.Errorf("runner: %w", err)`
- panic 사용 금지 (프로덕션 경로)

---

## 커밋 메시지

```
feat(windows): WMI 이벤트 구독 탐지 스크립트 추가
fix(collector): PowerShell 타임아웃 시 부분 결과 보존
docs(checks): lateral_movement 항목 MITRE 매핑 추가
test: c2_connections 픽스처 추가
```

형식: `type(scope): 설명`
타입: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`

---

## 이슈 리포트

다음 내용을 포함해주세요:
- OS 및 버전
- system-coroner 버전 (`coroner --version`)
- 실행 명령
- 전체 출력 / 에러 메시지
- `config.toml` 관련 부분 (API 키 제외)

---

## 라이선스

기여한 코드는 MIT 라이선스로 배포됩니다.