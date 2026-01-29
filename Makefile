# witnessd - Kinetic Proof of Provenance
# Makefile for building, testing, and verification

.PHONY: all build test bench clean install audit verify-self fmt lint help

# Build variables
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Binaries
BINDIR := bin
WITNESSD := $(BINDIR)/witnessd
WITNESSCTL := $(BINDIR)/witnessctl

all: build

## Build targets

build: $(WITNESSD) $(WITNESSCTL)
	@echo "Build complete: $(WITNESSD) $(WITNESSCTL)"

$(WITNESSD): cmd/witnessd/*.go internal/**/*.go
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $@ ./cmd/witnessd

$(WITNESSCTL): cmd/witnessctl/*.go internal/**/*.go
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $@ ./cmd/witnessctl

install: build
	cp $(WITNESSD) /usr/local/bin/
	cp $(WITNESSCTL) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

## Test targets

test:
	go test -v ./...

test-race:
	go test -race -v ./...

bench:
	go test -bench=. -benchmem ./...

bench-mmr:
	go test -bench=. -benchmem ./internal/mmr/...

bench-signer:
	go test -bench=. -benchmem ./internal/signer/...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
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
	go fmt ./...
	gofumpt -w . 2>/dev/null || true

lint:
	golangci-lint run ./... 2>/dev/null || go vet ./...

tidy:
	go mod tidy

## Development

dev: fmt tidy test build

run-daemon: build
	$(WITNESSD) -v

status: build
	$(WITNESSCTL) status

## IME targets

.PHONY: ime-macos ime-linux ime-windows ime-android ime-ios

ime-macos:
	@echo "Building macOS IME..."
	$(MAKE) -C cmd/witnessd-ime

ime-linux:
	@echo "Building Linux IBus engine..."
	$(MAKE) -C cmd/witnessd-ibus

ime-windows:
	@echo "Building Windows TSF..."
	@echo "Note: Must be run on Windows with MSVC"
	$(MAKE) -C cmd/witnessd-tsf

ime-android:
	@echo "Building Android IME..."
	cd cmd/witnessd-android && chmod +x build.sh && ./build.sh

ime-ios:
	@echo "Building iOS keyboard extension..."
	cd cmd/witnessd-ios && chmod +x build.sh && ./build.sh

install-ime-macos: ime-macos
	$(MAKE) -C cmd/witnessd-ime install

install-ime-linux: ime-linux
	$(MAKE) -C cmd/witnessd-ibus install

## Clean

clean:
	rm -rf $(BINDIR)
	rm -f coverage.out coverage.html
	$(MAKE) -C cmd/witnessd-ime clean 2>/dev/null || true
	$(MAKE) -C cmd/witnessd-ibus clean 2>/dev/null || true

## Help

help:
	@echo "witnessd - Kinetic Proof of Provenance"
	@echo ""
	@echo "Build targets:"
	@echo "  make build      - Build witnessd and witnessctl"
	@echo "  make install    - Install binaries to /usr/local/bin"
	@echo ""
	@echo "Test targets:"
	@echo "  make test       - Run all tests"
	@echo "  make test-race  - Run tests with race detector"
	@echo "  make bench      - Run benchmarks"
	@echo "  make coverage   - Generate coverage report"
	@echo ""
	@echo "IME targets:"
	@echo "  make ime-macos  - Build macOS Input Method"
	@echo "  make ime-linux  - Build Linux IBus engine"
	@echo "  make ime-windows - Build Windows TSF (Windows only)"
	@echo "  make ime-android - Build Android IME"
	@echo "  make ime-ios    - Build iOS keyboard extension"
	@echo "  make install-ime-macos - Install macOS IME"
	@echo "  make install-ime-linux - Install Linux IBus engine"
	@echo ""
	@echo "Audit targets:"
	@echo "  make audit      - Show git signature audit log"
	@echo "  make verify-self - Verify source code against witness database"
	@echo ""
	@echo "Development:"
	@echo "  make fmt        - Format code"
	@echo "  make lint       - Run linters"
	@echo "  make dev        - Format, tidy, test, build"
	@echo ""
	@echo "Utilities:"
	@echo "  make status     - Show daemon status"
	@echo "  make clean      - Remove build artifacts"
