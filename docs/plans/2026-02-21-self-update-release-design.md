# Design: self-update + GitHub Releases 배포

> **작성일**: 2026-02-21
> **상태**: 설계 확정, 구현 미착수

---

## 목표

1. `coroner update` — 최신 릴리즈를 GitHub Releases에서 받아 자신을 교체
2. `coroner update --check` — 다운로드 없이 최신 버전만 확인
3. GoReleaser + GitHub Actions로 릴리즈 자동화
4. `VERSION` 파일 기반 버전 관리 (`make release`로 태그+릴리즈 트리거)

---

## 섹션 1: 버전 관리 플로우

### VERSION 파일

```
VERSION   ← "0.1.0" 한 줄. 진실의 원천.
```

- `Makefile`의 `VERSION` 변수가 이 파일을 읽음
- `ldflags`로 바이너리에 주입: `-X main.version=$(shell cat VERSION)`
- git 태그와 VERSION 파일이 항상 1:1 대응

### make release

```makefile
release:
    @version=$$(cat VERSION); \
    echo "Releasing v$$version..."; \
    git tag -a "v$$version" -m "Release v$$version"; \
    git push origin "v$$version"
```

실행 흐름:
```
VERSION 파일 수정 (0.1.0 → 0.2.0)
    ↓
git commit -m "chore: bump version to 0.2.0"
    ↓
make release
    ↓
git tag v0.2.0 + git push --tags
    ↓
GitHub Actions (release.yml) 트리거
    ↓
GoReleaser 실행 → GitHub Release 생성 + 바이너리 5종 업로드
```

---

## 섹션 2: GoReleaser 구성

### 파일: `.goreleaser.yaml`

- **아카이브 없음**: 바이너리 직접 배포 (`format: binary`)
- **명명 규칙**: `coroner-{{ .Os }}-{{ .Arch }}` (기존 Makefile과 동일)
- **체크섬**: sha256 자동 생성
- **플랫폼**: windows-amd64, linux-amd64, linux-arm64, darwin-amd64, darwin-arm64

배포 후 다운로드 URL 패턴:
```
https://github.com/iyulab/system-coroner/releases/download/v{version}/coroner-{os}-{arch}
https://github.com/iyulab/system-coroner/releases/download/v{version}/coroner-windows-amd64.exe
```

### 파일: `.github/workflows/release.yml`

트리거: `push: tags: ['v*']`

```
checkout → setup-go → goreleaser/goreleaser-action@v6
```

`GITHUB_TOKEN`만 사용 (추가 시크릿 불필요).

---

## 섹션 3: `coroner update` 서브커맨드

### CLI

```
coroner update           최신 버전으로 자동 업데이트
coroner update --check   다운로드 없이 최신 버전만 확인
```

### 패키지 구조

```
internal/updater/
    updater.go   CheckLatest(), SelfUpdate()
```

`cmd/coroner/update.go` — cobra 서브커맨드 등록

### 업데이트 흐름

```
1. GitHub API GET /repos/iyulab/system-coroner/releases/latest
       → tag_name: "v0.2.0", assets: [...]

2. semver 비교: 현재 version vs tag_name
       → 최신이면 "already up to date" 출력 후 종료

3. runtime.GOOS + runtime.GOARCH로 asset URL 계산
       coroner-linux-amd64
       coroner-darwin-arm64
       coroner-windows-amd64.exe

4. 임시 파일로 다운로드 (os.CreateTemp)

5. 원자적 교체:
       Linux/Mac: os.Rename(tmp, exePath)        ← 원자적
       Windows:   Rename(exe → exe.bak)
                  Rename(tmp → exe)

6. 성공 메시지 + 재시작 안내
```

### Windows .bak 정리

업데이트 시작 시 `<exe>.bak` 파일이 존재하면 먼저 삭제. 이전 업데이트의 잔재 자동 정리.

### 에러 처리

| 상황 | 처리 |
|------|------|
| 네트워크 없음 | 에러 반환, 바이너리 무변경 |
| 권한 없음 | 에러 메시지 + sudo/관리자 안내 |
| 다운로드 중단 | 임시 파일 삭제, 바이너리 무변경 |
| 지원 안 되는 플랫폼 | 에러 메시지 (darwin-386 등) |

---

## 섹션 4: `--check` 전용 흐름

```
GitHub API 호출 → 버전 비교만
→ "최신: v0.2.0 (현재: v0.1.0) — coroner update 로 업데이트하세요"
→ 또는 "이미 최신 버전입니다 (v0.2.0)"
```

---

## 변경 파일 목록

| 파일 | 작업 |
|------|------|
| `VERSION` | 신규 생성 |
| `Makefile` | `VERSION` 변수, `release` 타겟 추가, ldflags 수정 |
| `.goreleaser.yaml` | 신규 생성 |
| `.github/workflows/release.yml` | 신규 생성 |
| `internal/updater/updater.go` | 신규 생성 |
| `cmd/coroner/update.go` | 신규 생성 (cobra 서브커맨드) |
| `cmd/coroner/main.go` | 서브커맨드 등록 |
