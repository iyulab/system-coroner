# Architecture

## 설계 원칙

1. **증거 우선** — 수집된 원본 데이터는 항상 먼저 디스크에 저장한다. LLM 분석 실패와 무관하게 IoC 증거는 보존된다.
2. **침입 시나리오 중심 분석** — LLM에게 "이것이 정상인가?"를 묻지 않는다. "이것이 침입 흔적인가? 공격자가 무엇을 했는가?"를 묻는다.
3. **절대 중단 없음** — 어떤 수집 항목이 실패해도 나머지를 계속 실행하고 부분 리포트를 생성한다.
4. **단일 바이너리** — 설치 불필요. 실행 파일 하나를 복사해서 실행하면 끝난다.

---

## 전체 구조

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (cobra)                          │
│                    cmd/coroner/main.go                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────▼───────────────┐
          │          Orchestrator         │
          │     internal/orchestrator/    │
          │                               │
          │  1. 수집 (Collect)             │
          │  2. 분석 (Analyze)             │
          │  3. 리포트 (Report)            │
          │  4. 증거 패키지 (Export)        │
          └───┬──────────────────────┬────┘
              │                      │
  ┌───────────▼──────────┐  ┌────────▼────────────┐
  │      Collector        │  │      Analyzer        │
  │  internal/collector/  │  │  internal/analyzer/  │
  │                       │  │                      │
  │ - 스크립트 병렬 실행   │  │ - 전처리 (preprocess)│
  │ - 타임아웃 관리        │  │   · Known-Good 필터  │
  │ - IoC 원본 파일 저장   │  │   · 필드 절삭        │
  │ - 권한 수준 감지       │  │   · 이벤트 집계      │
  │                       │  │ - LLM 클라이언트     │
  │                       │  │ - 침입 시나리오 프롬프트│
  │                       │  │ - 구조화 JSON 파싱   │
  │                       │  │ - 확신도 계산        │
  └───────────┬───────────┘  └────────┬────────────┘
              │                       │
  ┌───────────▼───────────┐  ┌────────▼────────────┐
  │   scripts/windows/    │  │      Reporter        │
  │   scripts/linux/      │  │  internal/reporter/  │
  │                       │  │                      │
  │   *.ps1 (9개)         │  │ - 격리 권고 판단      │
  │   *.sh  (9개)         │  │ - 타임라인 재구성     │
  │   (embed 내장)        │  │ - MITRE 매핑         │
  └───────────────────────┘  │ - report.html 생성   │
                             │ - ZIP 증거 패키지     │
                             └────────┬────────────┘
                                      │
                           ┌──────────▼───────────────────┐
                           │  output/{timestamp}/          │
                           │  ├── *.json (수집 결과 9개)    │
                           │  ├── manifest.json            │
                           │  └── report.html              │
                           │                               │
                           │  output/{timestamp}.zip       │
                           │  └── package_info.json 포함   │
                           │     (SHA-256 해시, 메타데이터) │
                           └──────────────────────────────┘
```

---

## 디렉토리 구조

```
system-coroner/
│
├── cmd/
│   └── coroner/
│       └── main.go                    # CLI 진입점, 플래그 파싱
│
├── internal/
│   ├── config/
│   │   └── config.go                  # config.toml 로드 및 검증
│   │
│   ├── collector/
│   │   ├── collector.go               # 병렬 실행 오케스트레이션
│   │   ├── runner.go                  # os/exec 래퍼, 타임아웃 처리
│   │   ├── result.go                  # 수집 결과 구조체 정의
│   │   └── writer.go                  # IoC 원본 파일 저장
│   │
│   ├── platform/
│   │   ├── platform.go                # OS 감지, 탐지 항목 정의
│   │   ├── windows.go                 # Windows 탐지 항목 목록 (9개)
│   │   └── linux.go                   # Linux 탐지 항목 목록 (9개)
│   │
│   ├── analyzer/
│   │   ├── analyzer.go                # LLM 분석 오케스트레이션 (Two-Phase)
│   │   ├── client.go                  # LLM HTTP 클라이언트 추상화
│   │   ├── preprocess.go              # 전처리: Known-Good 필터, 필드 절삭, 이벤트 집계
│   │   ├── prompt.go                  # 침입 탐지 특화 프롬프트 생성
│   │   ├── response.go                # 구조화 응답 파싱
│   │   └── schema.go                  # Finding, Verdict 등 스키마 + JSON Schema
│   │
│   └── reporter/
│       ├── reporter.go                # html/template 렌더링
│       ├── aggregator.go              # 전체 확신도 및 격리 권고 판단
│       ├── exporter.go                # ZIP 증거 패키지 생성 (SHA-256 해시)
│       └── templates/
│           └── report.html.tmpl       # 셀프컨테인드 HTML 템플릿
│
├── scripts/
│   ├── windows/                       # PowerShell 수집 스크립트 (9개)
│   │   ├── c2_connections.ps1
│   │   ├── account_compromise.ps1
│   │   ├── persistence.ps1
│   │   ├── lolbin_abuse.ps1
│   │   ├── fileless_attack.ps1
│   │   ├── log_tampering.ps1
│   │   ├── credential_dump.ps1
│   │   ├── lateral_movement.ps1
│   │   └── webshell.ps1
│   │
│   └── linux/                         # Bash 수집 스크립트 (9개, python3 미사용)
│       ├── c2_connections.sh
│       ├── account_compromise.sh
│       ├── persistence.sh
│       ├── lolbin_abuse.sh
│       ├── fileless_attack.sh
│       ├── log_tampering.sh
│       ├── credential_dump.sh
│       ├── lateral_movement.sh
│       └── webshell.sh
│
├── tests/
│   └── fixtures/
│       ├── windows/
│       │   ├── clean/                 # 정상 환경 픽스처 (9개)
│       │   └── compromised/           # 침해 환경 픽스처 (9개)
│       └── linux/
│           ├── clean/                 # 정상 환경 픽스처 (9개)
│           └── compromised/           # 침해 환경 픽스처 (9개)
│
├── .gitattributes                     # 줄바꿈 정규화 규칙
├── config.example.toml
├── go.mod
├── Makefile
└── README.md
```

---

## 핵심 설계 결정

### 1. 스크립트 바이너리 내장 (embed)

사용자가 실행 파일 하나만 있으면 동작합니다. 스크립트 파일을 별도 배포하거나 추출할 필요가 없습니다.

```go
//go:embed scripts/windows/*.ps1
var windowsScripts embed.FS

//go:embed scripts/linux/*.sh
var linuxScripts embed.FS
```

### 2. 병렬 수집 (goroutine per check)

모든 탐지 항목이 동시에 실행됩니다. 9개 항목 × 평균 10초 = 90초가 아니라 가장 느린 항목 하나의 시간(~30초)만 소요됩니다.

```
goroutine: c2_connections.ps1      ─┐
goroutine: account_compromise.ps1  ─┤
goroutine: persistence.ps1         ─┤──► ResultChannel ──► Writer
goroutine: lolbin_abuse.ps1        ─┤
goroutine: log_tampering.ps1       ─┘
```

각 goroutine은 개별 타임아웃을 가지며, 타임아웃 초과 시 프로세스를 강제 종료하고 부분 결과를 기록합니다.

### 3. 증거 우선 저장

LLM 분석 전에 반드시 원본 수집 결과를 디스크에 저장합니다. LLM API가 실패해도 원본 증거는 보존됩니다.

```
Script 실행 → stdout 캡처 → 즉시 disk 저장 → LLM 분석
                                    ↑
                            이 단계가 항상 먼저
```

### 4. 침입 특화 LLM 프롬프트

일반적인 "이게 이상한가?"가 아니라 구체적인 침입 시나리오를 가정하고 분석합니다.

```
❌ 일반 프롬프트:
"다음 데이터를 분석하고 보안 문제를 찾아주세요."

✅ 침입 특화 프롬프트:
"당신은 디지털 포렌식 전문가입니다.
다음은 [c2_connections] 수집 결과입니다.
공격자의 C2 통신, Reverse Shell, Beacon 패턴이 있는지 분석하세요.
의심 항목이 있으면 반드시 원본 데이터의 어느 부분인지 구체적으로 지적하세요.
다음 JSON 형식으로만 응답하세요: ..."
```

### 5. 항목별 분석 + 전체 종합

개별 항목 분석과 종합 판단을 분리합니다. 컨텍스트 윈도우 초과를 방지하고, 여러 항목의 조합으로 확신도를 높이는 교차 분석이 가능합니다.

```
c2_connections  → Finding{ risk: "high", confidence: "suspected" }
log_tampering   → Finding{ risk: "critical", confidence: "confirmed" }
account_changes → Finding{ risk: "high", confidence: "likely" }
        │
        └──► Aggregator ──► 교차 분석 ──► 전체 판단
                            "로그 삭제 + C2 의심 + 계정 변경
                             → Confirmed, 즉시 격리 권고"
```

---

## LLM 응답 스키마

스키마 정의: `internal/analyzer/schema.go`

### Phase 1: 항목별 분석 (Finding)

각 탐지 항목에 대해 LLM은 다음 JSON을 반환합니다.

```json
{
  "check": "c2_connections",
  "intrusion_confidence": "likely",
  "risk_level": "high",
  "title": "svchost.exe의 비정상 외부 연결 탐지",
  "attack_scenario": "시스템 프로세스로 위장한 C2 비콘으로 추정",
  "evidence": ["PID 4821 → 185.220.101.45:4444"],
  "ioc": {
    "ips": ["185.220.101.45"],
    "processes": ["C:\\Users\\Public\\svchost.exe"],
    "ports": [4444],
    "hashes": [], "registry_keys": [], "domains": [], "user_accounts": []
  },
  "mitre": ["T1071", "T1036"],
  "immediate_actions": ["PID 4821 프로세스 즉시 종료"],
  "forensic_next_steps": ["메모리 덤프 수집 권고"],
  "reasoning_chain": {
    "observation": "svchost.exe가 비표준 경로에서 실행",
    "baseline": "정상 svchost.exe는 C:\\Windows\\System32에 위치",
    "deviation": "C:\\Users\\Public 경로는 공격자 악용 빈도 높음",
    "context": "외부 IP 4444 포트 연결 → 비콘 패턴",
    "conclusion": "C2 통신 가능성 높음"
  }
}
```

### Phase 2: 전체 종합 (Verdict)

개별 분석 완료 후 교차 분석으로 종합 판단을 생성합니다.

```json
{
  "overall_verdict": {
    "status": "compromised",
    "confidence": "confirmed",
    "recommendation": "즉시 네트워크 격리",
    "summary": "활성 C2 통신 + 로그 삭제 확인"
  },
  "findings": [{ "id": "F-01", "severity": "critical", ... }],
  "timeline": [{ "timestamp": "2026-02-20T21:30:00Z", "event": "...", "kill_chain_phase": "initial_access" }],
  "ioc_list": [{ "type": "ip", "value": "185.220.101.45", "context": "C2 서버" }],
  "data_gaps": ["Sysmon 미설치로 프로세스 인젝션 탐지 제한"]
}
```

---

## 격리 권고 판단 로직

```go
func (a *Aggregator) ShouldIsolate(findings []Finding) IsolationRecommendation {
    // 즉시 격리 조건 (하나라도 해당 시)
    for _, f := range findings {
        if f.IntrusionConfidence == "confirmed" {
            return IsolationRecommendation{
                Isolate: true,
                Urgency: "immediate",
                Reason:  f.Title,
            }
        }
    }

    // 복합 조건 격리 (Likely 2개 이상)
    likelyCount := countByConfidence(findings, "likely")
    if likelyCount >= 2 {
        return IsolationRecommendation{
            Isolate: true,
            Urgency: "urgent",
            Reason:  "복수의 침해 가능성 높은 항목 동시 발견",
        }
    }

    return IsolationRecommendation{ Isolate: false }
}
```

---

## 리포트 구조

`report.html`은 외부 의존성 없는 단일 파일입니다.

```
report.html
│
├── [상단 배너] 격리 권고 여부 (즉시 눈에 띄는 색상)
│
├── [요약] 침해 확신도 + 탐지된 공격 단계 (Kill Chain)
│
├── [타임라인] 공격자 추정 행동 순서
│   └── 이벤트 로그 + 수집 데이터 교차 재구성
│
├── [증거 카드] 탐지 항목별 상세
│   ├── 확신도 / 위험도 배지
│   ├── 공격 시나리오 설명
│   ├── 구체적 증거 (원본 데이터 발췌)
│   ├── MITRE ATT&CK 기법
│   ├── 즉각 조치 체크리스트
│   └── [접기] 원본 수집 데이터 전체
│
├── [IoC 목록] IP, 해시, 프로세스, 레지스트리 키 통합
│
├── [대응 가이드] 우선순위별 조치 항목
│
└── [경영진 요약] (접기/펼치기)
    └── 침해 여부 / 영향 범위 / 현재 상태
```

---

## 에러 처리 전략

| 상황 | 동작 |
|------|------|
| 스크립트 실행 실패 | 에러 기록 후 계속 진행, 리포트에 "수집 실패" 표시 |
| 타임아웃 | 프로세스 종료, 부분 수집 결과 저장, 계속 진행 |
| 권한 부족 | 가능한 항목만 수집, 리포트에 "권한 부족으로 미수집" 명시 |
| LLM API 실패 | 1회 재시도, 실패 시 원본 데이터와 함께 "분석 불가" 표시 |
| LLM JSON 파싱 실패 | 원문 응답 보존, 파싱 실패 플래그 표시 |
| 모든 항목 실패 | 에러 요약 포함한 리포트 생성 — 빈 파일은 절대 없음 |

---

## 증거 패키지 (ZIP Export)

리포트 생성 후 자동으로 `output/{timestamp}.zip` 증거 패키지를 생성합니다.

```
output/2026-02-21T14-00-00.zip
├── 2026-02-21T14-00-00/
│   ├── c2_connections.json
│   ├── account_compromise.json
│   ├── ... (수집 결과 전체)
│   ├── manifest.json
│   ├── report.html
│   └── package_info.json          ← 자동 생성 메타데이터
```

`package_info.json` 구조:
```json
{
  "version": "1.0",
  "hostname": "target-server",
  "os": "linux",
  "created_at": "2026-02-21T14:00:00Z",
  "tool_version": "v0.5.0",
  "files": [
    { "name": "c2_connections.json", "sha256": "a1b2c3...", "size": 4096 }
  ]
}
```

구현: `internal/reporter/exporter.go` — DFIR 증거 보존 원칙 (NIST IR 8387) 준수.

---

## 에러 처리 매트릭스 (ARCH-009)

> **원칙**: "절대 중단 없음" — 어떤 에러도 전체 파이프라인을 중단하지 않는다. 빈 리포트는 절대 없다.

### 수집 단계 에러 (Collector)

`collector.Result.FailureKind`로 분류:

| 에러 유형 | ExitCode | FailureKind | 복구 전략 | 리포트 영향 |
|----------|---------|-------------|---------|------------|
| 타임아웃 | -1 | `timeout` | 수집 중단, 빈 결과 기록 | CollectionFailures에 `timeout` 표시 |
| 권한 거부 (Windows: 5, Linux: 126) | 5 / 126 | `permission_denied` | 계속 진행, 해당 Check 제외 | CollectionFailures에 `permission_denied` 표시 |
| 스크립트 에러 (비-0 종료) | 1–255 | `script_error` | 부분 출력 보존, 계속 진행 | CollectionFailures에 `script_error` 표시 |
| 인터프리터 없음 (Windows: 9009, Linux: 127) | 9009 / 127 | `not_found` | 해당 Check 제외 | CollectionFailures에 `not_found` 표시 |
| embed.FS 스크립트 읽기 실패 | -1 | `unknown` | 빌드 문제로 분류, 계속 진행 | CollectionFailures에 `unknown` 표시 |
| `exec.ErrNotFound` (Go 수준) | -1 | `not_found` | 인터프리터 부재로 분류 | CollectionFailures에 `not_found` 표시 |
| stderr 내 "access denied" 패턴 | 임의 양수 | `permission_denied` | stderr 텍스트로 재분류 | CollectionFailures에 `permission_denied` 표시 |

**분류 구현**: `internal/collector/runner.go` — `classifyFailure(*Result)`

```go
// 분류 우선순위:
// 1. TimedOut == true → FailureTimeout
// 2. errors.Is(err, exec.ErrNotFound) → FailureNotFound
// 3. ExitCode switch (5, 126, 127, 9009) → 플랫폼별 코드
// 4. ExitCode > 0 + stderr 패턴 → FailurePermission or FailureScriptError
// 5. ExitCode == -1 → FailureUnknown
```

### 분석 단계 에러 (Analyzer)

| 에러 유형 | 복구 전략 | 리포트 영향 |
|----------|---------|------------|
| LLM API 에러 (네트워크/인증) | `AnalyzeAll` 계속 진행 (부분 결과 허용) | 해당 Finding 누락, 다른 분석 결과 유지 |
| LLM 응답 JSON 파싱 실패 | `RawFinding`으로 보존 | "Analysis Failures" 섹션에 원본 출력 표시 |
| LLM 응답 필드 검증 실패 (confidence/risk 범위 오류) | `informational`/`none`으로 정규화 | Finding 생성되나 신뢰도 낮게 표시 |
| LLM 전체 실패 (`AnalyzeAll` 오류) | `fmt.Fprintf(stderr, ...)` 후 계속 | 빈 Findings, Verdict 없음 — 원본 수집 데이터는 보존 |

### 리포트 단계 에러 (Reporter/Orchestrator)

| 에러 유형 | 심각도 | 복구 전략 |
|----------|-------|---------|
| 출력 디렉토리 생성 실패 | **Fatal** | 즉시 오류 반환 (디스크 공간/권한 문제) |
| HTML 템플릿 렌더링 실패 | **Fatal** | 즉시 오류 반환 (빌드 시 템플릿 검증으로 방지) |
| 증거 ZIP 생성 실패 | Non-fatal | `stderr` 경고 출력 후 계속 진행 |
| `collection_meta.json` 저장 실패 | Non-fatal | `stderr` 경고, 분석은 계속 |
| `manifest.json` 저장 실패 | Non-fatal | `stderr` 경고, 해시 검증 불가하나 리포트 계속 |

### API 에러 절삭

LLM API 에러 메시지는 2,000자로 절삭 (`internal/analyzer/client.go`):
```go
// 최대 2KB — 인증 오류, Rate Limit 등의 상세 응답 유지
const maxAPIErrorLen = 2000
```

---

## 빌드 및 배포

```makefile
make build-all   # 전 플랫폼 빌드
# → build/coroner-windows-amd64.exe
# → build/coroner-linux-amd64
# → build/coroner-darwin-arm64
# → build/coroner-darwin-amd64

make test        # 단위 테스트
make lint        # golangci-lint
```

GitHub Actions → goreleaser → GitHub Releases 자동화