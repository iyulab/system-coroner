# 침입 탐지 항목 레퍼런스

system-coroner가 탐지하는 침입 흔적 전체 목록입니다.
각 항목은 **"공격자가 이 서버에서 무엇을 했을 가능성이 있는가"** 를 기준으로 설계되었습니다.

---

## 탐지 항목 맵 (MITRE ATT&CK 기준)

```
초기 침입                   내부 활동                    지속성 확보
─────────────────     ──────────────────────     ──────────────────────
웹쉘 탐지             크리덴셜 덤프 흔적           레지스트리 Persistence
                      Lateral Movement            스케줄 작업 이식
                      LOLBin 남용                 서비스 이식
                                                  WMI 구독 (Fileless)
                      ──────────────────────
                      C2 통신 탐지
                      로그 삭제/변조
                      계정 조작 흔적
```

---

## 구현 상태

| Check ID | 스크립트 | 플랫폼 | MITRE ATT&CK | 상태 |
|----------|---------|--------|--------------|------|
| `c2_connections` | `scripts/windows/c2_connections.ps1` | Windows | T1071.001 (HTTP), T1071.004 (DNS), T1048.003 (Exfil-TLS), T1095 (Non-Std Port), T1573 (Encrypted Channel) | Implemented |
| `account_compromise` | `scripts/windows/account_compromise.ps1` | Windows | T1136.001 (Local Account), T1078.003 (Local Accounts), T1550.002 (Pass-the-Hash), T1110.003 (Password Spraying) | Implemented |
| `persistence` | `scripts/windows/persistence.ps1` | Windows | T1547.001 (Registry Run), T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1546.001 (IFEO Hijack), T1027.010 (Command Obfuscation) | Implemented |
| `lolbin_abuse` | `scripts/windows/lolbin_abuse.ps1` | Windows | T1218.002 (Mshta), T1218.010 (Regsvr32), T1218.011 (Rundll32), T1059.001 (PowerShell), T1059.003 (Cmd), T1105 (Ingress Transfer) | Implemented |
| `fileless_attack` | `scripts/windows/fileless_attack.ps1` | Windows | T1546.003 (WMI Subscription), T1055.002 (PE Injection), T1059.001 (PowerShell SBL), T1620 (Reflective Loading) | Implemented |
| `log_tampering` | `scripts/windows/log_tampering.ps1` | Windows | T1070.001 (Clear Windows Logs), T1562.002 (Disable Win Audit Policy), T1562.006 (Indicator Blocking) | Implemented |
| `credential_dump` | `scripts/windows/credential_dump.ps1` | Windows | T1003.001 (LSASS Memory), T1003.002 (SAM), T1003.003 (NTDS), T1552.002 (Credentials in Registry) | Implemented |
| `lateral_movement` | `scripts/windows/lateral_movement.ps1` | Windows | T1021.001 (RDP), T1021.002 (SMB/WinRM), T1021.006 (WinRM), T1570 (Lateral Tool Transfer), T1135 (Share Discovery) | Implemented |
| `webshell` | `scripts/windows/webshell.ps1` | Windows | T1505.003 (Web Shell), T1190 (Exploit Public App), T1036.005 (Match Legitimate Name) | Implemented |
| `c2_connections` | `scripts/linux/c2_connections.sh` | Linux | T1071.001 (HTTP), T1071.004 (DNS), T1048.003 (Exfil-TLS), T1095 (Non-Std Port), T1090 (Proxy) | Implemented |
| `persistence` | `scripts/linux/persistence.sh` | Linux | T1053.003 (Cron), T1543.002 (Systemd Service), T1037.004 (RC Scripts), T1574.006 (LD_PRELOAD), T1546.004 (.bashrc/.profile) | Implemented |
| `log_tampering` | `scripts/linux/log_tampering.sh` | Linux | T1070.001 (Clear Log Files), T1070.002 (Clear wtmp/btmp), T1562.001 (Disable Auditd) | Implemented |
| `account_compromise` | `scripts/linux/account_compromise.sh` | Linux | T1136.001 (Local Account), T1098.004 (SSH Authorized Keys), T1110.001 (Brute Force) | Implemented |
| `credential_dump` | `scripts/linux/credential_dump.sh` | Linux | T1003.008 (/etc/shadow), T1003.007 (/proc mem), T1552.001 (Credentials in Files) | Implemented |
| `fileless_attack` | `scripts/linux/fileless_attack.sh` | Linux | T1059.004 (Unix Shell), T1620 (Reflective Loading/memfd), T1027.002 (SW Packing) | Implemented |
| `lolbin_abuse` | `scripts/linux/lolbin_abuse.sh` | Linux | T1059.004 (Shell), T1105 (Ingress Transfer), T1218 (System Binary Proxy) | Implemented |
| `lateral_movement` | `scripts/linux/lateral_movement.sh` | Linux | T1021.004 (SSH), T1572 (Protocol Tunneling), T1563.001 (SSH Session Hijack) | Implemented |
| `webshell` | `scripts/linux/webshell.sh` | Linux | T1505.003 (Web Shell), T1190 (Exploit Public App) | Implemented |

테스트 픽스처: `tests/fixtures/{platform}/{clean,compromised}/{check_id}.json` (Windows + Linux 각 9개 × 2)

---

## Windows Server 탐지 항목

---

### `c2_connections` — C2 통신 및 역방향 쉘 탐지

**탐지 목표:** 공격자 서버(C2)와의 통신, Reverse Shell, 비콘(Beacon) 트래픽

**수집 항목:**
- 모든 외부 아웃바운드 연결 (프로세스명 + PID + 원격 IP:Port)
- 비정상적인 포트로의 연결 (4444, 1337, 8080, 9001 등 공격자 선호 포트)
- HTTPS가 아닌 443 연결 (SSL 터널링 위장)
- 정기적으로 동일 외부 IP에 연결하는 프로세스 (비콘 패턴)
- DNS 쿼리 이상 (DGA 도메인, 비정상적으로 긴 서브도메인)

**LLM 분석 포인트:**
- 시스템 프로세스(`svchost.exe`, `lsass.exe`)가 외부와 통신 중인가
- 연결 빈도가 일정한가 (비콘 특징 — 30초, 60초 주기 등)
- 원격 IP가 알려진 클라우드/CDN이 아닌가
- 연결된 프로세스의 실행 경로가 정상인가

**MITRE:** T1071 (Application Layer Protocol), T1048 (Exfiltration Over C2), T1095 (Non-Standard Port)

---

### `account_compromise` — 계정 탈취 및 조작 흔적

**탐지 목표:** 공격자가 계정을 만들었거나, 기존 계정을 탈취했거나, 권한을 올린 흔적

**수집 항목:**
- Event ID 4720 (계정 생성), 4726 (계정 삭제)
- Event ID 4732 (관리자 그룹 추가), 4733 (관리자 그룹 제거)
- Event ID 4648 (명시적 자격증명 사용 — Pass-the-Hash 징후)
- Event ID 4625 (로그인 실패) — 소스 IP별 빈도 분석
- 현재 관리자 그룹 전체 멤버 목록
- 최근 생성된 계정 (생성 시각 포함)
- `$` 접미사 계정 (숨김 계정 패턴)
- 비밀번호 만료 없음 + 관리자 그룹 조합 계정

**LLM 분석 포인트:**
- 업무 시간 외 계정 생성이 있었는가
- 단기간 대량 4625 이벤트 (브루트포스)
- 4648 이벤트가 비정상적인 프로세스에서 발생했는가
- 관리자 그룹에 알 수 없는 계정이 있는가

**MITRE:** T1136 (Create Account), T1078 (Valid Accounts), T1550 (Pass-the-Hash)

---

### `persistence` — 재부팅 후 생존 메커니즘 탐지

**탐지 목표:** 공격자가 서버 재부팅 후에도 다시 실행되도록 설치한 항목

**수집 항목:**

*레지스트리 자동실행 (7개 경로)*
- `HKLM\SOFTWARE\...\Run`, `RunOnce` (64-bit)
- `HKCU\SOFTWARE\...\Run`, `RunOnce` (64-bit)
- `HKLM\SOFTWARE\WOW6432Node\...\Run`, `RunOnce` (32-bit on 64-bit OS — 악성코드 은닉 빈발)
- `HKCU\SOFTWARE\WOW6432Node\...\Run` (32-bit user 자동실행)
- `HKLM\...\Winlogon` (Userinit, Shell 값)
- `HKLM\...\Image File Execution Options` (디버거 하이재킹, T1546.001)
- `HKLM\SYSTEM\CurrentControlSet\Services` (서비스 등록)

*스케줄 작업*
- 모든 등록된 Task 목록 (실행 경로, 트리거, 실행 계정)
- 최근 생성된 Task (생성 시각 기준)
- SYSTEM 권한으로 실행되는 비표준 Task

*서비스*
- 비Microsoft 서비스 전체 목록
- 바이너리 경로가 Temp, AppData, 사용자 폴더인 서비스
- `cmd.exe` 또는 `powershell.exe`를 직접 실행하는 서비스

**LLM 분석 포인트:**
- Temp/AppData 경로 실행 항목 (거의 항상 악성)
- `-EncodedCommand` 또는 Base64 payload를 포함한 PowerShell 명령어 (`base64_detections` 필드)
- WOW64 경로 Run 키 (64-bit 정상 소프트웨어는 거의 사용 안 함)
- 최근 며칠 이내 생성된 항목
- 정상 프로그램처럼 위장한 이름 (오타, 유사 문자, Unicode)

**MITRE:** T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1546.001 (IFEO), T1027.010 (Encoded Commands)

---

### `lolbin_abuse` — Living-off-the-Land 공격 탐지

**탐지 목표:** Windows 내장 도구를 악용한 공격 탐지 (탐지 회피 목적)

공격자는 별도 악성 파일 없이 `powershell.exe`, `certutil.exe`, `mshta.exe` 등 정상 Windows 도구로 공격합니다. 안티바이러스를 우회하면서 악성 행위가 가능합니다.

**수집 항목:**

| 도구 | 공격자 악용 방식 |
|------|-----------------|
| `powershell.exe` | Base64 인코딩 명령, `-EncodedCommand`, `-WindowStyle Hidden` |
| `certutil.exe` | 파일 다운로드 (`-urlcache -split -f`) |
| `mshta.exe` | 원격 HTA 파일 실행 |
| `wscript.exe` / `cscript.exe` | VBScript/JScript 페이로드 실행 |
| `regsvr32.exe` | COM 객체를 통한 원격 코드 실행 (Squiblydoo) |
| `rundll32.exe` | DLL 사이드로딩 |
| `bitsadmin.exe` | 백그라운드 파일 다운로드 |
| `wmic.exe` | 원격 프로세스 실행, 정보 수집 |
| `net.exe` / `net1.exe` | 계정 조작, 공유 폴더 탐색 |

- 이벤트 로그 4688 (프로세스 생성)에서 위 도구의 비정상 인자 탐색
- PowerShell 커맨드라인 길이가 비정상적으로 긴 항목
- 위 도구들이 비정상 부모 프로세스 하에 실행된 경우

**MITRE:** T1218 (System Binary Proxy Execution), T1059 (Command and Scripting Interpreter)

---

### `fileless_attack` — 파일리스 공격 탐지

**탐지 목표:** 디스크에 파일을 남기지 않는 메모리 기반, WMI 기반 공격 탐지

**수집 항목:**

*WMI 영속성*
- WMI 이벤트 구독 (EventFilter + EventConsumer + FilterToConsumerBinding)
- 알려지지 않은 WMI 구독 (공격자 persistence 핵심 기법)

*PowerShell*
- PowerShell 스크립트 블록 로깅 이벤트 (Event ID 4104)
- PowerShell 모듈 로깅 이벤트 (Event ID 4103)
- Base64 디코딩이 필요한 실행 이력

*프로세스 인젝션 징후*
- 메모리에만 존재하는 프로세스 (디스크 이미지 없음)
- 부모 프로세스가 비정상인 시스템 프로세스
- 할당된 메모리 크기가 비정상적으로 큰 프로세스

*레지스트리 기반 페이로드*
- 레지스트리에 저장된 실행 가능 코드 흔적 (긴 바이너리 값)

**MITRE:** T1546.003 (WMI Event Subscription), T1055 (Process Injection), T1059.001 (PowerShell)

---

### `log_tampering` — 로그 삭제/변조 흔적 탐지

**탐지 목표:** 공격자가 흔적을 지우기 위해 로그를 삭제하거나 비활성화한 흔적

로그 삭제는 **침해 확신도를 즉시 Confirmed로 올리는** 가장 강력한 지표 중 하나입니다.

**수집 항목:**
- Event ID 1102 (Security 로그 삭제 — 관리자가 직접 지운 경우)
- Event ID 104 (System 로그 삭제)
- 각 이벤트 로그의 현재 크기 vs 최대 크기 (비정상적으로 작으면 의심)
- 이벤트 로그 서비스 상태 (중지되어 있으면 의심)
- Windows Defender 로그 삭제 또는 비활성화 여부
- 감사 정책 비활성화 흔적 (Event ID 4719)
- 로그 파일의 마지막 수정 시각 비정상 (갭이 생긴 경우)

**LLM 분석 포인트:**
- 1102/104 이벤트가 존재하면 즉시 Confirmed 상향 고려
- 업무 시간 외 로그 삭제
- 로그 삭제 직전/직후 이벤트 패턴 분석

**MITRE:** T1070 (Indicator Removal), T1562 (Impair Defenses)

---

### `credential_dump` — 크리덴셜 덤프 흔적 탐지

**탐지 목표:** 공격자가 비밀번호 해시나 평문 크리덴셜을 추출한 흔적

**수집 항목:**
- LSASS 프로세스에 접근한 프로세스 목록 (Event ID 10 — Sysmon 있을 경우)
- `procdump.exe`, `mimikatz`, `sekurlsa` 관련 이벤트 이력
- SAM, SECURITY, SYSTEM 레지스트리 하이브 접근 이력
- `ntdsutil.exe` 실행 이력 (AD 환경 — NTDS.dit 덤프)
- Volume Shadow Copy 접근 이력 (`vssadmin`, `wbadmin`)
- WDigest 인증 활성화 여부 (활성화 시 평문 비밀번호 메모리 노출)

**LLM 분석 포인트:**
- 비정상 프로세스의 LSASS 접근
- SAM 하이브를 직접 복사하려는 시도
- VSS 삭제 이력 (랜섬웨어 + 크리덴셜 덤프 공통 패턴)

**MITRE:** T1003 (OS Credential Dumping), T1003.001 (LSASS Memory), T1003.002 (SAM)

---

### `lateral_movement` — 내부 이동 흔적 탐지

**탐지 목표:** 공격자가 이 서버에서 다른 서버로, 또는 다른 서버에서 이 서버로 이동한 흔적

**수집 항목:**
- Event ID 4624 Type 3 (네트워크 로그인) — 비정상 소스에서의 접근
- Event ID 4624 Type 10 (RemoteInteractive — RDP) 
- SMB 연결 이력 (비정상 내부 IP 간)
- WinRM / PSRemoting 연결 이력 (Event ID 6 in Microsoft-Windows-WinRM)
- PsExec 사용 흔적 (서비스 이름 `PSEXESVC`, 파이프 `\psexec`)
- `net use` / `net view` 실행 이력 (내부 네트워크 탐색)
- RDP 최근 연결 이력 (`HKCU\...\Terminal Server Client\Servers`)
- 내부 IP 대역으로의 비정상적인 포트 스캔 패턴

**MITRE:** T1021 (Remote Services), T1570 (Lateral Tool Transfer), T1135 (Network Share Discovery)

---

### `webshell` — 웹쉘 탐지

**탐지 목표:** 웹 서버를 통해 심어진 웹쉘 파일 탐지

웹 서버가 설치된 경우에만 실행됩니다 (IIS, Apache, nginx, Tomcat 등 자동 감지).

**수집 항목:**
- 웹 루트 디렉토리 내 최근 수정된 파일 (24h, 7d, 30d 기준)
- `.php`, `.asp`, `.aspx`, `.jsp`, `.cfm` 파일 중 의심 패턴 포함 항목
  - `eval(`, `base64_decode(`, `exec(`, `system(`, `cmd.exe` 포함 파일
- IIS 로그에서 비정상 요청 패턴 (POST to static files, 이상한 User-Agent)
- 웹 디렉토리 내 `.exe`, `.dll`, `.ps1` 파일 (있어서는 안 됨)
- 최근 업로드된 것으로 의심되는 파일 (생성 시각 vs 배포 시각 비교)

**MITRE:** T1505.003 (Web Shell), T1190 (Exploit Public-Facing Application)

---

## 탐지 항목별 침해 확신도 영향

| 항목 | Clean 단독 | 복합 발견 시 |
|------|-----------|-------------|
| C2 활성 연결 | → Confirmed | — |
| 로그 삭제 (1102) | → Confirmed | — |
| 웹쉘 발견 | → Confirmed | — |
| 알 수 없는 WMI 구독 | → Likely | + 계정 조작 → Confirmed |
| 비정상 자동실행 항목 | → Suspected | + LOLBin → Likely |
| 비정상 계정 생성 | → Suspected | + 외부 연결 → Likely |
| 크리덴셜 덤프 도구 흔적 | → Likely | + Lateral → Confirmed |

---

## 향후 추가 예정 (Windows)

- `ransomware_indicators` — 랜섬웨어 활동 패턴 (VSS 삭제, 대량 파일 변경)
- `data_exfiltration` — 대용량 데이터 외부 전송 흔적
- `defense_evasion` — AV/EDR 비활성화, 프로세스 숨김 탐지
- `supply_chain` — 소프트웨어 업데이트를 통한 침투 흔적

## 향후 추가 예정 (Linux)

- `rootkit_indicators` — 숨겨진 프로세스/파일, LD_PRELOAD 조작, 커널 모듈 검증
- `suid_abuse` — SUID 바이너리 조작, capabilities 남용