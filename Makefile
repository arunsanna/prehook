VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
BINARY  := prehook

.PHONY: build test lint vet sec clean ci

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./... -count=1 -race

lint: vet
	@command -v golangci-lint >/dev/null 2>&1 || { echo "install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run

vet:
	go vet ./...

sec:
	@command -v govulncheck >/dev/null 2>&1 || { echo "install: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

clean:
	rm -f $(BINARY) coverage.out

ci: test lint sec
