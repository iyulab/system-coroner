# 🔍 system-coroner

> **해커가 이미 들어왔는가? — 서버 침입 흔적 자동 탐지 및 증거 리포트 생성 도구**

system-coroner는 실행 즉시 서버 전반을 스캔하여 침입 흔적(IoC)을 수집하고, LLM이 이를 분석한 뒤 단일 `report.html`을 생성합니다. 에이전트 설치 없이, 한 번의 실행으로.

---

## 이 도구가 답하는 질문

- 이 서버에 해커가 들어온 흔적이 있는가?
- 지금 이 순간 C2 서버와 통신 중인 프로세스가 있는가?
- 공격자가 계정을 만들거나 권한을 올렸는가?
- 악성코드가 재부팅 후에도 살아남도록 설치되었는가?
- 로그가 지워진 흔적이 있는가?
- 지금 서버를 격리해야 하는가?

**보안 설정 점검이나 취약점 스캔이 목적이 아닙니다. 이미 일어난 침입의 흔적을 찾는 것이 목적입니다.**

---

## 동작 방식

```
실행
 ↓
침입 흔적 수집 스크립트 병렬 실행 (PowerShell / Bash)
 ↓
IoC 원본 보존 → output/{timestamp}/*.json, *.log, *.md
 ↓
LLM이 각 수집 결과를 침입 시나리오 관점에서 분석
 ↓
전체 결과 종합 → 격리 여부 판단 포함
 ↓
report.html 생성 ✅
```

---

## 빠른 시작

```bash
# Windows Server — PowerShell 5.1+, 관리자 권한 권장
.\coroner.exe --config config.toml

# Linux — Bash 4+, root 권장
sudo ./coroner --config config.toml

# 결과
# → output/2026-02-21T14-00-00/report.html  (브라우저 자동 오픈)
# → output/2026-02-21T14-00-00/*.json       (원본 증거 파일 보존)
```

> **관리자/root 권한으로 실행할수록 더 많은 흔적을 탐지합니다.** Windows: Security 이벤트 로그, LSASS 보호 상태. Linux: /etc/shadow 접근, audit 로그, /proc 전체 프로세스 매핑.

### CLI 옵션

```bash
./coroner --config config.toml                          # 전체 실행 (수집 + LLM 분석 + 리포트)
./coroner --collect-only                                # LLM 호출 없이 수집만
./coroner --only c2_connections,log_tampering            # 특정 항목만 실행
./coroner --fixture tests/fixtures/linux/clean/ --skip-collect  # 픽스처로 LLM 분석 테스트
./coroner --verbose                                     # 상세 로그
```

---

## 설치

| 플랫폼 | 파일 |
|--------|------|
| Windows (amd64) | `coroner-windows-amd64.exe` |
| Linux (amd64) | `coroner-linux-amd64` |
| macOS (arm64) | `coroner-darwin-arm64` |

```bash
# 소스 빌드
git clone https://github.com/iyulab/system-coroner
cd system-coroner
go build -o coroner ./cmd/coroner
```

---

## 설정

첫 실행 시: `cp config.example.toml config.toml` 후 API 키를 설정합니다.

```toml
[llm]
provider = "anthropic"           # anthropic | openai | ollama
api_key  = "sk-ant-..."
model    = "claude-opus-4-20250514"
endpoint = ""                    # 로컬 Ollama 사용 시 설정
# timeout = 0                   # HTTP 타임아웃(초), 0 = 프로바이더 기본값

[output]
dir          = "output"
open_browser = true
keep_raw     = true              # IoC 원본 파일 보존 (포렌식 목적으로 항상 true 권장)

[checks]
# 침입 흔적 탐지 항목 — 기본 전체 활성화
c2_connections     = true   # C2 통신 및 역방향 쉘 탐지
lateral_movement   = true   # 내부 이동 흔적
account_compromise = true   # 계정 탈취 및 생성 흔적
persistence        = true   # 재부팅 후 생존 메커니즘
lolbin_abuse       = true   # 합법적 도구를 이용한 공격
fileless_attack    = true   # 파일리스 공격 (WMI, 메모리)
log_tampering      = true   # 로그 삭제/변조 흔적
webshell           = true   # 웹쉘 탐지 (웹서버 존재 시)
credential_dump    = true   # 크리덴셜 덤프 흔적
```

---

## 리포트 구성

### 시스템 관리자 / 보안 담당자 (메인)

**즉시 판단 섹션**
- 🚨 **격리 권고 여부** — 지금 당장 네트워크에서 분리해야 하는가
- **침해 확신도** — Confirmed / Likely / Suspected / Clean
- **탐지된 공격 단계** — MITRE ATT&CK Kill Chain 상 위치

**증거 섹션**
- 발견된 IoC 목록 (IP, 파일 해시, 프로세스, 레지스트리 키)
- 각 증거의 원본 데이터 (접기/펼치기)
- 타임라인 — 공격자 행동 추정 순서
- MITRE ATT&CK 기법 매핑 (T-번호)

**대응 섹션**
- 즉각 조치 항목 (순서 있는 체크리스트)
- 추가 포렌식 수집 권고 항목
- 보존해야 할 증거 목록

### 경영진 요약 (보조, 접기/펼치기)
- 침해 여부 한 줄 결론
- 영향 받은 범위 추정
- 현재 대응 상태

---

## 침해 확신도 기준

| 등급 | 의미 | 예시 |
|------|------|------|
| 🔴 **Confirmed** | 침해 확실 | 활성 C2 연결, 알려진 악성코드 해시, 이벤트 로그 삭제 흔적 |
| 🟠 **Likely** | 침해 가능성 높음 | 의심 프로세스 + 비정상 계정 + 자동실행 등록이 동시에 발견 |
| 🟡 **Suspected** | 추가 조사 필요 | 단독으로는 설명 가능하지만 의심스러운 항목 다수 |
| 🟢 **Clean** | 침입 흔적 미발견 | 수집된 모든 항목이 정상 범위 |

---

## 프라이버시 및 데이터

- 수집 데이터는 설정한 LLM API로만 전송됩니다
- `report.html`과 원본 증거 파일은 로컬에만 저장됩니다
- 로컬 Ollama 설정 시 외부 전송 없이 완전 오프라인 분석 가능합니다
- API 키는 설정 파일 또는 환경변수로만 관리되며 출력 파일에 포함되지 않습니다

---

## 로드맵

- [x] Windows Server — PowerShell 기반 침입 흔적 탐지 (9개 check)
- [x] Linux — Bash 기반 침입 흔적 탐지 (9개 check)
- [ ] macOS 지원
- [ ] 이전 스캔과 차이점 비교 (델타 리포트)
- [ ] YARA 룰 연동
- [ ] VirusTotal API 연동 (파일 해시 자동 조회)
- [x] 증거 패키지 내보내기 (ZIP, chain-of-custody 메타데이터 포함)

---

## 라이선스

MIT License — *Built by [iyulab](https://github.com/iyulab)*