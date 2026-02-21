.PHONY: build build-all test test-unit test-integration lint clean fmt vet check release update-sigma

VERSION  := $(shell cat VERSION)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   = -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

build:
	go build $(LDFLAGS) -trimpath -o coroner ./cmd/coroner

build-all:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-windows-amd64.exe ./cmd/coroner
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-linux-amd64 ./cmd/coroner
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -trimpath -o build/coroner-linux-arm64 ./cmd/coroner
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -trimpath -o build/coroner-darwin-arm64 ./cmd/coroner
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-darwin-amd64 ./cmd/coroner

# CI용: OS 명령 실행 없는 빠른 단위 테스트만
test-unit:
	go test ./... -short -count=1

# 로컬용: OS 명령 실행 포함 전체 통합 테스트
test-integration:
	go test ./... -count=1 -v

# 기본 test 타겟은 전체 통합 테스트
test: test-integration

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run

check: vet
	@unformatted=$$(gofmt -l .); \n	if [ -n "$$unformatted" ]; then \n		echo "Unformatted files:"; echo "$$unformatted"; exit 1; \n	fi
	go test ./... -short -count=1

release:
	@version=$$(cat VERSION); \n	echo "Releasing v$$version..."; \n	git tag -a "v$$version" -m "Release v$$version"; \n	git push origin "v$$version"; \n	echo "Tag v$$version pushed. GitHub Actions will build and publish the release."

clean:
	rm -f coroner coroner.exe
	rm -rf build/

# SIG-006: Download and curate latest Sigma rules from SigmaHQ
# Downloads Windows-relevant rules and places them in internal/sigma/rules/
# Requires: curl, python3 (for rule selection script)
update-sigma:
	@echo "Downloading latest Sigma rules from SigmaHQ..."
	@mkdir -p /tmp/sigma-update
	@curl -fsSL "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz" \
		-o /tmp/sigma-update/sigma-master.tar.gz
	@tar -xzf /tmp/sigma-update/sigma-master.tar.gz -C /tmp/sigma-update
	@echo "Selecting Windows-relevant rules..."
	@python3 scripts/update_sigma_rules.py \
		/tmp/sigma-update/sigma-master/rules \
		internal/sigma/rules
	@echo "Cleaning up..."
	@rm -rf /tmp/sigma-update
	@echo "Done. Run 'go build ./...' to embed updated rules."
