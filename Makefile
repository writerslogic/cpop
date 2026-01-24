# witnessd - Kinetic Proof of Provenance
# Makefile for building, testing, and verification

.PHONY: all build build-reproducible test test-race test-forensics test-tpm \
        test-integration anchor-test bench bench-mmr bench-signer coverage \
        clean install audit verify-self fmt lint tidy security setup \
        docker-up docker-down sbom release-dry-run tools/keystroke-gen help

# Build variables
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Go variables
GO := go
GOFLAGS := -trimpath
CGO := 1

# Binaries
BINDIR := bin
WITNESSD := $(BINDIR)/witnessd
WITNESSCTL := $(BINDIR)/witnessctl

all: lint test build

## Build targets

build: $(WITNESSD) $(WITNESSCTL)
	@echo "Build complete: $(WITNESSD) $(WITNESSCTL)"

$(WITNESSD): cmd/witnessd/*.go internal/**/*.go
	@mkdir -p $(BINDIR)
	CGO_ENABLED=$(CGO) $(GO) build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/witnessd

$(WITNESSCTL): cmd/witnessctl/*.go internal/**/*.go
	@mkdir -p $(BINDIR)
	CGO_ENABLED=$(CGO) $(GO) build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/witnessctl

build-reproducible: ## Build with reproducible output (for verification)
	@mkdir -p $(BINDIR)
	CGO_ENABLED=$(CGO) $(GO) build -trimpath -ldflags="-s -w -buildid=" -o $(WITNESSD) ./cmd/witnessd
	CGO_ENABLED=$(CGO) $(GO) build -trimpath -ldflags="-s -w -buildid=" -o $(WITNESSCTL) ./cmd/witnessctl
	@echo "Checksums:"
	@sha256sum $(WITNESSD) $(WITNESSCTL) 2>/dev/null || shasum -a 256 $(WITNESSD) $(WITNESSCTL)

install: build
	cp $(WITNESSD) /usr/local/bin/
	cp $(WITNESSCTL) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

## Test targets

test:
	$(GO) test -v -short ./...

test-race:
	$(GO) test -race -v ./...

test-forensics: ## Run forensics-specific tests
	$(GO) test -v -race ./internal/forensics/...
	$(GO) test -v -race ./internal/witness/...

test-tpm: ## Run TPM integration tests (requires TPM simulator)
	$(GO) test -v -tags=tpm_integration ./internal/tpm/...

test-integration: docker-up ## Run integration tests with external services
	$(GO) test -v -tags=integration ./...
	$(MAKE) docker-down

anchor-test: ## Test external anchoring (OpenTimestamps, RFC 3161)
	$(GO) test -v -race ./internal/anchors/...

bench:
	$(GO) test -bench=. -benchmem ./...

bench-mmr:
	$(GO) test -bench=. -benchmem ./internal/mmr/...

bench-signer:
	$(GO) test -bench=. -benchmem ./internal/signer/...

coverage:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Audit and verification

audit:
	@echo "=== Git Signature Audit ==="
	git log --show-signature -10 || echo "No signed commits found"

verify-self: build
	@echo "=== Self-Verification ==="
	@if [ -f ~/.witnessd/mmr.db ]; then \
		for f in internal/**/*.go cmd/**/*.go; do \
			echo "Verifying: $$f"; \
			$(WITNESSCTL) verify "$$f" 2>/dev/null || echo "  (not witnessed)"; \
		done \
	else \
		echo "No witness database found. Run witnessd first."; \
	fi

## Code quality

fmt:
	$(GO) fmt ./...
	goimports -w -local witnessd . 2>/dev/null || true
	gofumpt -w . 2>/dev/null || true

lint:
	golangci-lint run --timeout 5m ./... 2>/dev/null || $(GO) vet ./...

vet:
	$(GO) vet ./...

security: ## Run security scanners
	gosec -quiet ./... 2>/dev/null || echo "gosec not installed"
	govulncheck ./... 2>/dev/null || echo "govulncheck not installed"

tidy:
	$(GO) mod tidy

## Development setup

setup: ## Install development dependencies
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/goreleaser/goreleaser@latest
	go install github.com/air-verse/air@latest
	@echo "Installing pre-commit hooks..."
	@command -v pre-commit >/dev/null && pre-commit install || echo "pre-commit not found, skipping hooks"

## Docker targets (for integration testing)

docker-up: ## Start test infrastructure
	docker-compose -f docker-compose.yml up -d
	@echo "Waiting for services..."
	@sleep 5

docker-down: ## Stop test infrastructure
	docker-compose -f docker-compose.yml down -v

## Release targets

sbom: ## Generate Software Bill of Materials
	syft dir:. -o spdx-json=witnessd-sbom.spdx.json
	syft dir:. -o cyclonedx-json=witnessd-sbom.cdx.json
	@echo "SBOM generated: witnessd-sbom.spdx.json, witnessd-sbom.cdx.json"

release-dry-run: ## Test release process
	goreleaser release --snapshot --clean --skip=publish

## Tools

tools/keystroke-gen: ## Build keystroke generator tool
	$(GO) build -o $(BINDIR)/keystroke-gen ./tools/keystroke-gen.go

## Development workflow

dev: fmt tidy test build

run-daemon: build
	$(WITNESSD) -v

status: build
	$(WITNESSCTL) status

## Clean

clean:
	rm -rf $(BINDIR) dist/
	rm -f coverage.out coverage.html
	rm -f *.sbom.json *.spdx.json *.cdx.json

## Help

help:
	@echo "witnessd - Kinetic Proof of Provenance"
	@echo ""
	@echo "Build targets:"
	@echo "  make build              - Build witnessd and witnessctl"
	@echo "  make build-reproducible - Build with reproducible output"
	@echo "  make install            - Install binaries to /usr/local/bin"
	@echo ""
	@echo "Test targets:"
	@echo "  make test               - Run all unit tests"
	@echo "  make test-race          - Run tests with race detector"
	@echo "  make test-forensics     - Run forensics-specific tests"
	@echo "  make test-tpm           - Run TPM integration tests"
	@echo "  make test-integration   - Run full integration tests"
	@echo "  make anchor-test        - Test external timestamping"
	@echo "  make bench              - Run benchmarks"
	@echo "  make coverage           - Generate coverage report"
	@echo ""
	@echo "Audit targets:"
	@echo "  make audit              - Show git signature audit log"
	@echo "  make verify-self        - Verify source code against witness database"
	@echo ""
	@echo "Code quality:"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Run linters"
	@echo "  make security           - Run security scanners"
	@echo "  make setup              - Install development dependencies"
	@echo ""
	@echo "Release:"
	@echo "  make sbom               - Generate Software Bill of Materials"
	@echo "  make release-dry-run    - Test release process"
	@echo ""
	@echo "Utilities:"
	@echo "  make docker-up          - Start test infrastructure"
	@echo "  make docker-down        - Stop test infrastructure"
	@echo "  make status             - Show daemon status"
	@echo "  make clean              - Remove build artifacts"
