# witnessd - Kinetic Proof of Provenance
# Makefile for building, testing, and verification

.PHONY: all build test bench clean install install-man uninstall audit verify-self fmt lint validate-schemas help
.PHONY: release release-snapshot sign notarize
.PHONY: witness-app witness-build witness-archive witness-clean

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

install: build install-man
	install -m 755 $(WITNESSD) /usr/local/bin/
	install -m 755 $(WITNESSCTL) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

install-man:
	@mkdir -p /usr/local/share/man/man1
	install -m 644 docs/man/witnessd.1 /usr/local/share/man/man1/
	install -m 644 docs/man/witnessctl.1 /usr/local/share/man/man1/
	@echo "Man pages installed to /usr/local/share/man/man1/"

uninstall:
	rm -f /usr/local/bin/witnessd
	rm -f /usr/local/bin/witnessctl
	rm -f /usr/local/share/man/man1/witnessd.1
	rm -f /usr/local/share/man/man1/witnessctl.1
	@echo "Uninstalled witnessd"

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

validate-schemas:
	go test ./internal/schemavalidation -run TestSchemaValidation

tidy:
	go mod tidy

## Development

dev: fmt tidy test build

run-daemon: build
	$(WITNESSD) -v

status: build
	$(WITNESSCTL) status

## IME targets (desktop platforms only)

.PHONY: ime-macos ime-linux ime-windows

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

install-ime-macos: ime-macos
	$(MAKE) -C cmd/witnessd-ime install

install-ime-linux: ime-linux
	$(MAKE) -C cmd/witnessd-ibus install

## Release targets

release:
	@echo "Creating release with goreleaser..."
	goreleaser release --clean

release-snapshot:
	@echo "Creating snapshot release..."
	goreleaser release --snapshot --clean

release-dry-run:
	@echo "Dry run release..."
	goreleaser release --skip=publish --clean

## macOS signing (requires Apple Developer ID)

sign: build
	@echo "Signing binaries for macOS..."
	@if [ -z "$(APPLE_DEVELOPER_ID)" ]; then \
		echo "Error: APPLE_DEVELOPER_ID environment variable not set"; \
		exit 1; \
	fi
	codesign --force --options runtime --sign "$(APPLE_DEVELOPER_ID)" --timestamp $(WITNESSD)
	codesign --force --options runtime --sign "$(APPLE_DEVELOPER_ID)" --timestamp $(WITNESSCTL)
	@echo "Binaries signed."

notarize: sign
	@echo "Notarizing binaries..."
	@if [ -z "$(APPLE_ISSUER_ID)" ] || [ -z "$(APPLE_KEY_ID)" ]; then \
		echo "Error: APPLE_ISSUER_ID and APPLE_KEY_ID must be set"; \
		exit 1; \
	fi
	@echo "Creating zip for notarization..."
	zip -j witnessd-notarize.zip $(WITNESSD) $(WITNESSCTL)
	xcrun notarytool submit witnessd-notarize.zip \
		--issuer "$(APPLE_ISSUER_ID)" \
		--key-id "$(APPLE_KEY_ID)" \
		--key "$(APPLE_PRIVATE_KEY)" \
		--wait
	rm witnessd-notarize.zip
	@echo "Notarization complete."

## Witness macOS App

witness-app: witness-build
	@echo "Witness.app built successfully!"
	@echo "Location: Witness/build/Build/Products/Release/Witness.app"

witness-build:
	@echo "Building Witness.app..."
	@# First build witnessd for the app bundle (CGO required for keystroke tracking)
	CGO_ENABLED=1 GOOS=darwin go build $(LDFLAGS) -o Witness/Witness/Resources/witnessd ./cmd/witnessd
	@# Build the Xcode project
	xcodebuild -project Witness/Witness.xcodeproj \
		-scheme Witness \
		-configuration Release \
		-derivedDataPath Witness/build \
		build

witness-archive:
	@echo "Archiving Witness.app for distribution..."
	@# Build witnessd universal binary (CGO required)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o Witness/Witness/Resources/witnessd-amd64 ./cmd/witnessd
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o Witness/Witness/Resources/witnessd-arm64 ./cmd/witnessd
	lipo -create -output Witness/Witness/Resources/witnessd \
		Witness/Witness/Resources/witnessd-amd64 \
		Witness/Witness/Resources/witnessd-arm64
	rm Witness/Witness/Resources/witnessd-amd64 Witness/Witness/Resources/witnessd-arm64
	@# Archive for App Store / Notarization
	xcodebuild -project Witness/Witness.xcodeproj \
		-scheme Witness \
		-configuration Release \
		-archivePath Witness/build/Witness.xcarchive \
		archive
	@echo "Archive created: Witness/build/Witness.xcarchive"

witness-clean:
	rm -rf Witness/build
	rm -f Witness/Witness/Resources/witnessd
	rm -f Witness/Witness/Resources/witnessd-amd64
	rm -f Witness/Witness/Resources/witnessd-arm64

## Clean

clean: witness-clean
	rm -rf $(BINDIR)
	rm -f coverage.out coverage.html
	$(MAKE) -C cmd/witnessd-ime clean 2>/dev/null || true
	$(MAKE) -C cmd/witnessd-ibus clean 2>/dev/null || true

## Help

help:
	@echo "witnessd - Kinetic Proof of Provenance"
	@echo ""
	@echo "Build targets:"
	@echo "  make build       - Build witnessd and witnessctl"
	@echo "  make install     - Install binaries and man pages"
	@echo "  make install-man - Install man pages only"
	@echo "  make uninstall   - Remove installed files"
	@echo ""
	@echo "Witness.app (macOS):"
	@echo "  make witness-app     - Build Witness.app for macOS"
	@echo "  make witness-archive - Create archive for App Store submission"
	@echo "  make witness-clean   - Clean Witness.app build artifacts"
	@echo ""
	@echo "Test targets:"
	@echo "  make test        - Run all tests"
	@echo "  make test-race   - Run tests with race detector"
	@echo "  make bench       - Run benchmarks"
	@echo "  make coverage    - Generate coverage report"
	@echo ""
	@echo "Release targets:"
	@echo "  make release          - Create release with goreleaser"
	@echo "  make release-snapshot - Create snapshot release"
	@echo "  make release-dry-run  - Dry run (no publish)"
	@echo "  make sign             - Sign macOS binaries"
	@echo "  make notarize         - Notarize macOS binaries"
	@echo ""
	@echo "IME targets (desktop platforms):"
	@echo "  make ime-macos   - Build macOS Input Method"
	@echo "  make ime-linux   - Build Linux IBus engine"
	@echo "  make ime-windows - Build Windows TSF (Windows only)"
	@echo "  make install-ime-macos - Install macOS IME"
	@echo "  make install-ime-linux - Install Linux IBus engine"
	@echo ""
	@echo "Audit targets:"
	@echo "  make audit       - Show git signature audit log"
	@echo "  make verify-self - Verify source code against witness database"
	@echo ""
	@echo "Development:"
	@echo "  make fmt         - Format code"
	@echo "  make lint        - Run linters"
	@echo "  make dev         - Format, tidy, test, build"
	@echo ""
	@echo "Utilities:"
	@echo "  make status      - Show daemon status"
	@echo "  make clean       - Remove build artifacts"
