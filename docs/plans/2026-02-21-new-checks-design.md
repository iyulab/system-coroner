# Design: 신규 탐지 Check 5종 + 4단계 점수화 판단 파이프라인

> **작성일**: 2026-02-21
> **최종 업데이트**: 2026-02-21 (4단계 파이프라인 아키텍처 추가, 실제 오탐 사례 반영)
> **상태**: 설계 확정, 구현 미착수
> **관련 리서치**: web search — Magnet Forensics, MITRE ATT&CK, SRUM, Shellbags, AmCache, DFIR best practices

---

## 배경 및 목표

현재 system-coroner는 C2 연결·계정 조작·지속성·LOLBin·필리스·로그 변조·자격증명 덤프·횡적이동·웹쉘 등 **공격 실행 단계**를 잘 탐지한다. 그러나 다음 영역이 완전히 누락되어 있다:

- 공격자가 **내부를 어떻게 정찰**했는지 (Discovery)
- **어떤 파일을 열어봤는지** (File Access / Browsing)
- **어떤 프로그램을 실행**했는지 (Execution evidence, 삭제 후에도)
- **어떤 파일을 다운로드**했는지 (Ingress Tool Transfer)
- **어떤 데이터를 가져갔는지** (Data Exfiltration staging)

이 5가지 영역을 포괄하는 신규 Check를 추가하고, **1차 룰기반 + 2차 LLM** 하이브리드 판단 아키텍처를 도입한다.

---

## 신규 탐지 Check 5종

### Check A: `discovery_recon` — 내부 정찰 흔적

**목표**: "공격자가 시스템/네트워크를 어떻게 파악했나?"
**MITRE**: T1046 (Network Service Scanning), T1082 (System Info Discovery), T1083 (File/Dir Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery)

**Windows 수집 대상**:
- Event 4688에서 정찰 명령 패턴: `net user`, `net group`, `whoami /all`, `nltest /domain_trusts`, `dsquery *`, `arp -a`, `route print`, `ipconfig /all`, `systeminfo`
- BloodHound/SharpHound 실행 흔적 (Event 4688 + 특징적 인수 패턴)
- 내부 포트스캔 패턴: Windows Filtering Platform Event 5156/5158 (짧은 시간 다수 포트 연결 시도)
- SQL Server xp_cmdshell 활성화 시도 (SQL ErrorLog / Event 33205)
- RDP 클라이언트 MRU: `HKCU\Software\Microsoft\Terminal Server Client\Servers` (이 서버에서 다른 서버로 피벗)
- `net use`, `net view` 실행 (네트워크 공유 열거)

**Linux 수집 대상**:
- `bash_history`에서 정찰 명령: `id`, `whoami`, `uname -a`, `cat /etc/passwd`, `ss -tulnp`, `netstat`, `nmap`, `arp -n`
- `/proc` 기반 포트스캔 패턴 (짧은 시간 대량 소켓 생성)
- `find / -perm -4000` (SUID 열거), `find / -name "*.conf"` (설정파일 탐색)

**룰기반 필터 (스크립트 레벨)**:
- 도메인 컨트롤러가 정기적으로 실행하는 LDAP 쿼리 제외
- 알려진 모니터링 에이전트 (SCOM, Nagios, Zabbix) 프로세스 제외

**룰기반 필터 (Go 레벨)**:
- 정상 관리 시간대 + 알려진 관리자 계정 조합은 신뢰도 낮게 (informational)
- BloodHound/SharpHound 특징 패턴은 무조건 SUSPICIOUS → LLM 전달

---

### Check B: `process_execution` — 프로그램 실행 흔적

**목표**: "공격자가 어떤 도구를 실행했나?" (파일 삭제 후에도 아티팩트 남음)
**MITRE**: T1059 (Command and Scripting), T1204 (User Execution), T1218 (System Binary Proxy)

**Windows 수집 대상**:
- **Prefetch 파일** `C:\Windows\Prefetch\*.pf`: 실행파일명, 마지막 8회 실행 시각, 실행 횟수
- **AppCompatCache (Shimcache)**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` — 시스템에 존재했던 실행파일 목록 (삭제 후에도 남음)
- **Amcache.hve** `C:\Windows\AppCompat\Programs\Amcache.hve`: SHA-1 해시 포함 실행파일 메타데이터
- **BAM/DAM** (Background Activity Moderator, Windows 10+): `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*` — 앱별 마지막 실행 UTC 타임스탬프
- **UserAssist**: GUI 앱 실행 횟수 및 마지막 실행 시각

**룰기반 필터 (스크립트 레벨)**:
- `C:\Windows\System32\` 경로 실행파일 중 표준 Windows 프로세스 목록에 있는 것 제외
- `C:\Program Files\Microsoft\` 하위 실행파일 제외

**룰기반 필터 (Go 레벨)**:
- 경로가 `\Temp\`, `\AppData\Local\Temp\`, `\Users\Public\`, `C:\PerfLogs\` → 즉시 SUSPICIOUS
- 경로가 `\Windows\System32\` + 알려진 이름 → SAFE 제외
- 알려진 공격 도구명 (mimikatz, procdump, psexec, cobalt, meterpreter, nmap, masscan, bloodhound) → 즉시 SUSPICIOUS

---

### Check C: `file_access` — 파일 접근 흔적

**목표**: "공격자가 어떤 파일과 폴더를 열어봤나?"
**MITRE**: T1083 (File and Directory Discovery), T1552 (Unsecured Credentials), T1005 (Data from Local System)

**Windows 수집 대상**:
- **Shellbags** (USRCLASS.DAT): `%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat` — Explorer 폴더 브라우징 전체 기록 (삭제된 폴더도 남음)
  - 레지스트리: `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- **Recent Items LNK**: `%AppData%\Microsoft\Windows\Recent\*.lnk` — 최근 열린 파일 경로+타임스탬프
- **Jump Lists**: `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\` — 앱별 최근 파일 목록
- **민감 경로 접근**: Recent Items 중 다음 패턴이 있으면 강조
  - `\SAM`, `\NTDS.dit`, `\SYSTEM`, `\SECURITY` (레지스트리 하이브)
  - `*.pfx`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, `*.kdb`, `*.rdp`
  - `\backup\`, `\Backup\`, `shadow`, `*.bak`
  - `\AppData\Roaming\` 내 브라우저 저장 비밀번호 경로
- **Event 4663** (파일 감사 활성화 시): 민감 파일 직접 접근 감사 로그

**Linux 수집 대상**:
- `/root/.bash_history`, `/home/*/.bash_history` 내 파일 접근 명령 (`cat`, `less`, `vi`, `cp` 등으로 민감 파일 접근)
- `auditd` 활성화 시 `/var/log/audit/audit.log` 내 OPEN/READ 이벤트 (민감 경로)
- Recently accessed files: `find / -atime -1 -type f 2>/dev/null` (제한적으로)

**룰기반 필터 (Go 레벨)**:
- LNK 파일이 `C:\Windows\`, `C:\Program Files\` 경로 → SAFE 제외
- 민감 확장자(`.pfx`, `.key`, `.pem`, `id_rsa`) 또는 민감 경로(`SAM`, `NTDS`, `backup`) → 무조건 SUSPICIOUS

---

### Check D: `file_download` — 파일 다운로드 흔적

**목표**: "공격자가 외부에서 어떤 도구/페이로드를 가져왔나?"
**MITRE**: T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode), T1608 (Stage Capabilities)

**Windows 수집 대상**:
- **Zone.Identifier ADS (Mark of the Web)**: 다운로드된 파일에 붙는 출처 URL
  - 수집 경로: `\Temp\`, `\AppData\Local\Temp\`, `\Downloads\`, `\Desktop\`, `\Public\`
  - PowerShell: `Get-Item -Path <path> -Stream Zone.Identifier` — `ZoneId=3`(Internet), `ZoneId=4`(Restricted) 및 `HostUrl`
- **BITS 전송 이력**: `Get-BitsTransfer -AllUsers` + BITS 작업 큐 레지스트리
- **certutil 다운로드 패턴**: Prefetch에 `CERTUTIL.EXE`가 있고 최근 실행 → 다운로드 의심
- **PowerShell 다운로드 흔적**: `%TEMP%\` 내 최근 생성된 `.ps1`, `.exe`, `.dll`, `.bat` 파일
- **최근 생성 실행파일**: `\Temp\`, `\AppData\`, `\Users\Public\`에 최근 7일 내 생성된 실행파일 목록

**Linux 수집 대상**:
- `bash_history` 내 다운로드 명령: `wget`, `curl -O`, `scp`, `rsync`, `ftp get`
- `/tmp/`, `/dev/shm/`, `/var/tmp/` 내 최근 생성된 실행파일 (`-executable -newer /tmp`)

**룰기반 필터 (Go 레벨)**:
- `HostUrl`이 `microsoft.com`, `windowsupdate.com`, `digicert.com`, `windows.net` → SAFE
- `ZoneId=3` + 실행파일 확장자 + `\Temp\` 경로 조합 → 즉시 SUSPICIOUS
- `ZoneId=3` + 일반 문서 확장자(`.pdf`, `.docx`) → UNCERTAIN (LLM 판단)

---

### Check E: `staging_exfiltration` — 데이터 유출 준비 및 유출 흔적

**목표**: "공격자가 어떤 데이터를 모았고 가져갔나?"
**MITRE**: T1074 (Data Staged), T1560 (Archive Collected Data), T1048 (Exfiltration Over Alt Protocol), T1052 (Exfiltration Over Physical Medium)

**Windows 수집 대상**:
- **SRUM (System Resource Usage Monitor)** `C:\Windows\System32\sru\SRUDB.dat`:
  - 프로세스별 네트워크 bytes_sent/received (최근 60일, 1시간 단위)
  - 비정상적으로 큰 bytes_sent (>100MB) 프로세스 추출
  - 수집 방법: `reg export HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM` (임시 데이터) 또는 ESE DB 파싱
- **USB/외장 스토리지**: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` — 연결된 USB 장치 목록, 첫/마지막 연결 시각
- **아카이브 스테이징**: `\Temp\`, `\AppData\`, `\Users\Public\`에 최근 생성된 `.zip`, `.7z`, `.rar`, `.tar`, `.gz` 파일
- **유출 도구 실행 흔적**: Prefetch/Amcache에서 `rclone.exe`, `WinSCP.exe`, `putty.exe`, `filezilla.exe` 이상 위치 실행
- **Archive 명령 이력**: Event 4688에서 압축 명령: `Compress-Archive`, `7z a`, `rar a`, `winrar`
- **VSS 삭제**: `vssadmin delete shadows` 실행 흔적 (랜섬웨어+유출 공통 지표)
- **민감 파일 복사 명령**: `xcopy /s C:\Users`, `robocopy` + 외부/공유 경로

**Linux 수집 대상**:
- `bash_history` 내 아카이브 생성: `tar czf`, `zip -r`, `7z a` + 민감 경로 포함
- `/tmp/`, `/dev/shm/` 내 최근 생성된 아카이브 파일
- `ss -tnp` 기반 대용량 전송 중인 연결 (bytes 기반)
- USB 마운트 이력 (`/var/log/syslog` 내 USB 이벤트)

**룰기반 필터 (Go 레벨)**:
- 알려진 백업 소프트웨어 프로세스 (Veeam, Windows Server Backup, `wbadmin`) → SAFE
- bytes_sent < 10MB → 필터 제외 (정상 범주)
- bytes_sent > 100MB + 비표준 프로세스 → 즉시 SUSPICIOUS
- `\Temp\` 내 아카이브 + 최근 생성 → SUSPICIOUS

---

## 판단 파이프라인 아키텍처 (4단계)

```
┌─────────────────────────────────────────────────────────────┐
│  Stage 1: 수집                                               │
│  .ps1 / .sh → JSON (디스크 저장, 증거 보존)                  │
│  스크립트 레벨 coarse filter (명백한 안전 항목 제외)          │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Stage 2: 룰 기반 판단 → 점수화                              │
│  preprocess.go: 각 항목에 규칙 적용 → item_score (0–100)    │
│  FilterResult: SAFE(제외) / SUSPICIOUS(+점수) / UNCERTAIN   │
│  check_rule_score = Σ item_scores / 정규화                   │
└──────────────────────┬──────────────────────────────────────┘
                       ↓ SAFE는 여기서 탈락
┌─────────────────────────────────────────────────────────────┐
│  Stage 3: LLM 기반 판단 → 점수화                             │
│  SUSPICIOUS + UNCERTAIN 항목만 LLM에 전달                    │
│  SUSPICIOUS: "규칙 위반 사유" 주석 포함 → 확증 요청           │
│  UNCERTAIN: 컨텍스트 판단 요청                               │
│  LLM 출력: findings + intrusion_confidence → llm_score      │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Stage 4: 확률적 종합 평가                                    │
│  final_score = w_rule×rule_score + w_llm×llm_score          │
│  + cross_check_bonus (복수 check 동시 발견 가중치)            │
│  → 임계값 기반 격리 판정                                      │
└─────────────────────────────────────────────────────────────┘
```

---

### Stage 1: 수집

수집 스크립트(`.ps1`/`.sh`)는 다음 원칙을 따른다:

- **stdout = JSON** — 항상 구조화 JSON 반환, 수집 실패 시에도 `{"error": "..."}` 포함
- **stderr = 진단** — 진행 상황, 권한 오류 등
- **30초 이내 완료** — 타임아웃 초과 시 partial 결과 반환
- **스크립트 레벨 coarse filter** — 명백히 안전한 항목을 스크립트 내부에서 제외하여 JSON 크기 최소화
  - 예: `C:\Windows\System32\svchost.exe`, `C:\Program Files\Microsoft\` 경로의 서명된 MS 바이너리
  - 예: `%AppData%\Microsoft\Windows\Recent\*.lnk` 중 `C:\Windows\` 또는 `C:\Program Files\` 경로

---

### Stage 2: 룰 기반 판단 → 점수화

#### 핵심 설계

```go
// FilterResult: 각 항목에 대한 규칙 적용 결과
type FilterResult int

const (
    FilterSafe       FilterResult = iota // 제외 (토큰 절감, 증거는 디스크 보존)
    FilterUncertain                       // LLM 전달 — 컨텍스트 판단 위임
    FilterSuspicious                      // LLM 전달 + 규칙 위반 사유 주석 첨부
)

// ScoredItem: 규칙 적용 결과와 점수를 가진 항목
type ScoredItem struct {
    Raw    map[string]interface{} // 원본 JSON 항목
    Result FilterResult
    Score  int    // 0–100: 이 항목의 위험 기여도
    Reason string // 규칙 위반 사유 (SUSPICIOUS일 때 LLM 프롬프트에 포함)
}

// FilterRule: 단일 규칙 인터페이스
type FilterRule interface {
    Apply(item map[string]interface{}) (FilterResult, int, string)
    Name() string
}

// CheckRuleScore: 하나의 check에 대한 종합 룰 점수 (0–100)
type CheckRuleScore struct {
    CheckID         string
    Score           int
    SuspiciousCount int
    UncertainCount  int
    Items           []ScoredItem
}
```

#### 점수화 공식

```
item_score:
  SAFE        →  0점  (집계 제외)
  UNCERTAIN   → 20점 (기본)
  SUSPICIOUS  → 40–100점 (규칙 심각도에 따라)

check_rule_score = min(100, Σ(suspicious_item_scores) / normalizer)
normalizer = max(1, total_item_count * 0.1)  // 전체 항목 대비 비율
```

#### 핵심 규칙 목록

| 규칙명 | 대상 Check | 점수 | 조건 |
|--------|-----------|------|------|
| `TempPathExec` | process_execution | 80 | 경로 = `\Temp\`, `\Users\Public\`, `\PerfLogs\` |
| `KnownAttackTool` | process_execution | 100 | 이름 = mimikatz, procdump, meterpreter, bloodhound, cobalt |
| `SensitiveFileLNK` | file_access | 90 | 경로에 SAM, NTDS.dit, .pfx, id_rsa, .kdb 포함 |
| `ZoneId3Executable` | file_download | 85 | ZoneId=3 + 실행파일 확장자 + Temp 경로 |
| `LargeOutboundTransfer` | staging_exfiltration | 70 | bytes_sent > 100MB + 비표준 프로세스 |
| `TempArchive` | staging_exfiltration | 65 | Temp 경로 + .zip/.7z/.rar 최근 생성 |
| `BloodHoundPattern` | discovery_recon | 100 | Event 4688 인수 패턴 매칭 |
| `PortScanPattern` | discovery_recon | 75 | 짧은 시간 내 동일 소스 → 다수 포트 연결 실패 |

#### False Positive 방지 규칙 (실제 오탐 사례 반영)

실제 보고서에서 발생한 오탐 원인을 규칙으로 방지한다:

| 오탐 패턴 | 규칙 처리 | 근거 |
|-----------|-----------|------|
| `signature_status: "error"` | → UNCERTAIN (점수 10), 서명 확인 실패로 처리 | Authenticode 쿼리 실패 ≠ 미서명. 비관리자 권한, 네트워크 격리 등으로 발생 |
| `BingWallpaperDaemon.exe` + Temp 경로 | → SAFE (알려진 앱 화이트리스트) | Microsoft Bing Wallpaper 앱의 정상 언인스톨러 패턴 |
| `claude.exe` + `~/.local/bin/` 경로 | → UNCERTAIN (점수 15) | 개발자 도구 경로, 알려진 앱 목록 확인 후 판단 |
| IObit 관련 태스크 (`SkipUAC`) | → UNCERTAIN (점수 30) | PUP 수준, 악의적 침해 증거 없음 |
| Event 4648, 관리자+개발자 도구 | → UNCERTAIN (점수 20) | 개발 워크스테이션에서 정상 발생 가능 |
| 서버 vs 개발 워크스테이션 컨텍스트 | → 시스템 프롬프트에 `host_type` 포함 | 동일 패턴이라도 컨텍스트에 따라 위험도 상이 |

> **구현 참고**: `signature_status` 필드는 `"valid"` / `"invalid"` / `"error"` 3가지 값을 갖는다. `"error"`는 확인 불가(권한 부족 등)이므로 `"invalid"`(실제 미서명)와 다르게 처리해야 한다.

---

### Stage 3: LLM 기반 판단 → 점수화

#### 필터링 후 LLM 전달

```
룰 결과         LLM 처리
──────────────────────────────────────────────────
SAFE            제외 (프롬프트에 포함하지 않음)
UNCERTAIN       원본 항목 그대로 전달 — 판단 요청
SUSPICIOUS      원본 항목 + reason 필드 추가 — 확증/반증 요청
```

SUSPICIOUS 항목 프롬프트 예시:
```json
{
  "path": "C:\\Users\\attacker\\AppData\\Local\\Temp\\x.exe",
  "rule_flags": ["TempPathExec", "ZoneId3Executable"],
  "rule_note": "Downloaded executable in Temp directory — requires confirmation"
}
```

#### LLM 출력 → 점수 변환

LLM이 반환하는 `intrusion_confidence` 값을 숫자 점수로 변환:

| intrusion_confidence | llm_item_score |
|---------------------|----------------|
| `confirmed`         | 100 |
| `high`              | 80 |
| `medium`            | 55 |
| `low`               | 30 |
| `informational`     | 10 |

```
check_llm_score = weighted_avg(llm_item_scores, weight=item_rule_score)
// 룰 점수가 높은 항목의 LLM 판단에 더 높은 가중치
```

---

### Stage 4: 확률적 종합 평가

#### 최종 점수 공식

```
final_check_score = w_rule × check_rule_score + w_llm × check_llm_score

기본 가중치:
  w_rule = 0.35  (룰은 빠르고 확정적이나 컨텍스트 부족)
  w_llm  = 0.65  (LLM은 컨텍스트 반영, 오류 가능성 존재)
```

#### Cross-Check 상관 보너스

복수의 check가 동시에 높은 점수를 내면 공격 시나리오가 완성되므로 가중치 보정:

```
고위험 check 조합 → bonus 점수 추가:

+20: c2_connections(>60) + credential_dump(>60)        → 자격증명 탈취 + 외부 유출
+20: process_execution(>70) + discovery_recon(>60)     → 도구 반입 + 내부 정찰
+15: file_access(>70) + staging_exfiltration(>60)      → 민감 파일 접근 + 압축/반출
+15: lateral_movement(>50) + discovery_recon(>50)      → 횡적이동 + 정찰
+10: file_download(>70) + lolbin_abuse(>50)            → 도구 반입 + LOLBin 실행
```

#### 최종 판정 임계값

```
system_score = avg(final_check_scores) + cross_check_bonus

판정:
  system_score ≥ 75 → COMPROMISED (격리 권고)
  system_score ≥ 50 → LIKELY_COMPROMISED (즉시 조사)
  system_score ≥ 25 → SUSPICIOUS (모니터링 강화)
  system_score < 25 → CLEAN
```

#### 신뢰도 보정 (컨텍스트)

시스템 컨텍스트에 따라 최종 점수를 보정:

| 컨텍스트 | 보정 | 이유 |
|---------|------|------|
| `host_type: server` (프로덕션 서버) | 기준값 유지 | 서버에서 개발자 도구 활동은 비정상 |
| `host_type: workstation` (개발자 PC) | ×0.7 (30% 감점) | IDE, 개발 도구, 다수 계정 정상 활동 존재 |
| `host_type: dc` (도메인 컨트롤러) | ×1.3 (30% 가중) | DC 침해는 최고 위험, 경계 강화 |
| 컨텍스트 미지정 | ×1.0 | 보수적 기준 적용 |

---

### 체크별 룰 매핑 요약

| Check | SAFE 기준 | SUSPICIOUS 기준 | UNCERTAIN 기준 |
|-------|-----------|-----------------|----------------|
| `process_execution` | System32 + MS 서명 + 알려진 이름 | Temp/Public 경로, 공격도구명 | signature_status=error, 비표준 경로 |
| `file_access` | Windows/ProgramFiles 경로 LNK | 민감 확장자(pfx/key), SAM/NTDS 경로 | 비업무 시간 + 비표준 경로 |
| `file_download` | MS 도메인 HostUrl | ZoneId=3 + Temp + 실행파일 | ZoneId=3 + 일반 문서, BITS 미확인 |
| `staging_exfiltration` | 백업 소프트웨어(Veeam 등), <10MB | >100MB + 비표준 프로세스, Temp 아카이브 | 50–100MB 전송, 외부 전송 도구 |
| `discovery_recon` | DC 정기 쿼리, 모니터링 에이전트 | BloodHound 패턴, 포트스캔 패턴 | 관리자+비업무시간 정찰 명령 |

---

## 기존 탐지 체계와의 관계

```
기존 (공격 실행 단계)          신규 (공격 전/후 단계)
──────────────────────    ─────────────────────────────
c2_connections            discovery_recon   ← 정찰
account_compromise        process_execution ← 도구 실행
persistence               file_access       ← 파일 탐색
lolbin_abuse              file_download     ← 도구 반입
fileless_attack           staging_exfil     ← 데이터 반출
log_tampering
credential_dump
lateral_movement
webshell
```

### 확신도 영향표 (신규)

| Check | 단독 발견 | 복합 발견 |
|-------|-----------|-----------|
| BloodHound/SharpHound 실행 | → Likely | + C2/credential_dump → Confirmed |
| Temp 경로 실행파일 (Zone.Id=3) | → Likely | + lolbin_abuse → Confirmed |
| 민감파일 LNK (SAM, NTDS) | → Likely | + credential_dump → Confirmed |
| SRUM bytes_sent > 500MB | → Suspected | + c2_connections → Confirmed |
| USB 연결 + 임시 아카이브 | → Suspected | + file_access 민감파일 → Likely |
| 포트스캔 패턴 (5156/5158) | → Suspected | + lateral_movement → Likely |

---

## 구현 우선순위

| 순위 | Check | 이유 |
|------|-------|------|
| 1 | `discovery_recon` | 현재 완전 누락, 공격 초기 단서 |
| 2 | `process_execution` | AmCache/Prefetch로 삭제 도구 증명 가능, 고가치 |
| 3 | `staging_exfiltration` | SRUM은 LLM 없이도 강력한 증거 |
| 4 | `file_download` | Zone.Identifier는 수집 간단 |
| 5 | `file_access` | Shellbags는 파싱 복잡, 가장 나중 |

---

## 플랫폼별 구현 계획

각 Check는 4단계로 구현:
1. `scripts/{windows,linux}/{check_id}.{ps1,sh}` — 수집 스크립트
2. `internal/platform/{windows,linux}.go` — Check 구조체 등록
3. `tests/fixtures/{platform}/{clean,compromised}/{check_id}.json` — 픽스처
4. `docs/CHECKS.md` 업데이트 — MITRE 매핑, 분석 포인트

---

## 참고 자료

- [Magnet Forensics: Investigating Data Exfiltration](https://www.magnetforensics.com/blog/investigating-data-exfiltration-key-digital-artifacts-across-windows-linux-and-macos/)
- [ShimCache vs AmCache](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/)
- [SRUM Forensic Analysis](https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/)
- [Shellbags Forensic Analysis](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/)
- [MITRE T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [Unit 42 2026 IR Report](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report)
