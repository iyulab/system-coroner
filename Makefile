.PHONY: build build-all test lint clean fmt vet check

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

build:
	go build $(LDFLAGS) -trimpath -o coroner ./cmd/coroner

build-all:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-windows-amd64.exe ./cmd/coroner
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-linux-amd64 ./cmd/coroner
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -trimpath -o build/coroner-linux-arm64 ./cmd/coroner
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -trimpath -o build/coroner-darwin-arm64 ./cmd/coroner
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -trimpath -o build/coroner-darwin-amd64 ./cmd/coroner

test:
	go test ./... -count=1 -v

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run

# Run all checks: vet, format verification, tests
check: vet
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:"; echo "$$unformatted"; exit 1; \
	fi
	go test ./... -count=1

clean:
	rm -f coroner coroner.exe
	rm -rf build/
