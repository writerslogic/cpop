# Makefile for Witnessd IBus Engine (Linux)
#
# Builds and installs the witnessd IBus input method engine.
# Supports both X11 and Wayland environments.

.PHONY: all build clean install uninstall install-user install-system
.PHONY: install-systemd uninstall-systemd install-desktop uninstall-desktop
.PHONY: test test-integration test-coverage run debug fmt vet lint
.PHONY: help status restart logs package

# Binary and paths
BINARY = witnessd-ibus
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Installation directories
PREFIX ?= /usr/local
INSTALL_DIR = $(PREFIX)/bin
SYSTEM_COMPONENT_DIR = /usr/share/ibus/component
USER_COMPONENT_DIR = $(HOME)/.local/share/ibus/component
SYSTEMD_USER_DIR = $(HOME)/.config/systemd/user
DESKTOP_DIR = $(HOME)/.local/share/applications
ICONS_DIR = $(HOME)/.local/share/icons/hicolor/scalable/apps
DATA_DIR = $(HOME)/.local/share/witnessd
CONFIG_DIR = $(HOME)/.config/witnessd
LOG_DIR = $(DATA_DIR)/logs

# Source files
SOURCES = $(wildcard *.go) $(wildcard ../../internal/ime/*.go)

# Default target
all: build

# Build targets
build: $(BINARY)

$(BINARY): $(SOURCES)
	@echo "Building $(BINARY) version $(VERSION)..."
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -o $(BINARY) .

build-debug: $(SOURCES)
	@echo "Building $(BINARY) with debug symbols..."
	go build -gcflags="all=-N -l" $(LDFLAGS) -o $(BINARY) .

# Test targets
test:
	@echo "Running unit tests..."
	go test -v ./...

test-race:
	@echo "Running tests with race detector..."
	go test -race -v ./...

test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Benchmark
bench:
	go test -bench=. -benchmem ./...

# User installation (no sudo required)
install-user: $(BINARY)
	@echo "=== User Installation ==="
	@echo "Installing $(BINARY) to $(HOME)/.local/bin"
	@mkdir -p $(HOME)/.local/bin
	install -m 755 $(BINARY) $(HOME)/.local/bin/$(BINARY)
	@echo ""
	@echo "Installing IBus component to $(USER_COMPONENT_DIR)..."
	@mkdir -p $(USER_COMPONENT_DIR)
	@sed 's|/usr/local/bin|$(HOME)/.local/bin|g' components/witnessd.xml > $(USER_COMPONENT_DIR)/witnessd.xml
	@chmod 644 $(USER_COMPONENT_DIR)/witnessd.xml
	@echo ""
	@echo "Creating data directories..."
	@mkdir -p $(DATA_DIR) $(CONFIG_DIR) $(LOG_DIR)
	@chmod 700 $(DATA_DIR) $(CONFIG_DIR)
	@echo ""
	@echo "Installing systemd user service..."
	@$(MAKE) install-systemd
	@echo ""
	@echo "Installing desktop file..."
	@$(MAKE) install-desktop
	@echo ""
	@echo "Restarting IBus..."
	-ibus restart 2>/dev/null || true
	@echo ""
	@echo "=== Installation Complete ==="
	@echo "Enable Witnessd in:"
	@echo "  - IBus preferences (ibus-setup)"
	@echo "  - GNOME: Settings > Keyboard > Input Sources"
	@echo "  - KDE: System Settings > Input Devices > Input Methods"
	@echo ""
	@echo "Start with: systemctl --user start witnessd-ibus"

# System-wide installation (requires sudo)
install-system: $(BINARY)
	@echo "=== System Installation ==="
	@echo "Installing $(BINARY) to $(INSTALL_DIR)"
	sudo install -m 755 $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo ""
	@echo "Installing IBus component to $(SYSTEM_COMPONENT_DIR)..."
	sudo mkdir -p $(SYSTEM_COMPONENT_DIR)
	sudo install -m 644 components/witnessd.xml $(SYSTEM_COMPONENT_DIR)/witnessd.xml
	@echo ""
	@echo "Creating system data directories..."
	@mkdir -p $(DATA_DIR) $(CONFIG_DIR) $(LOG_DIR)
	@chmod 700 $(DATA_DIR) $(CONFIG_DIR)
	@echo ""
	@echo "Restarting IBus..."
	-ibus restart 2>/dev/null || true
	@echo ""
	@echo "=== Installation Complete ==="
	@echo "Enable Witnessd in IBus preferences or system keyboard settings."

# Default install to user installation
install: install-user

# Uninstall
uninstall: uninstall-systemd uninstall-desktop
	@echo "=== Uninstalling Witnessd IBus Engine ==="
	@echo "Removing user installation..."
	rm -f $(HOME)/.local/bin/$(BINARY)
	rm -f $(USER_COMPONENT_DIR)/witnessd.xml
	@echo ""
	@echo "Removing system installation (if exists)..."
	-sudo rm -f $(INSTALL_DIR)/$(BINARY) 2>/dev/null || true
	-sudo rm -f $(SYSTEM_COMPONENT_DIR)/witnessd.xml 2>/dev/null || true
	@echo ""
	@echo "Restarting IBus..."
	-ibus restart 2>/dev/null || true
	@echo ""
	@echo "Note: Data directory $(DATA_DIR) was preserved."
	@echo "To remove all data: rm -rf $(DATA_DIR) $(CONFIG_DIR)"
	@echo ""
	@echo "=== Uninstallation Complete ==="

# Systemd service management
install-systemd:
	@echo "Installing systemd user service..."
	@mkdir -p $(SYSTEMD_USER_DIR)
	@sed 's|/usr/local/bin|$(HOME)/.local/bin|g' systemd/witnessd-ibus.service > $(SYSTEMD_USER_DIR)/witnessd-ibus.service
	@chmod 644 $(SYSTEMD_USER_DIR)/witnessd-ibus.service
	-systemctl --user daemon-reload 2>/dev/null || true
	@echo "Service installed. Enable with: systemctl --user enable witnessd-ibus"

uninstall-systemd:
	@echo "Removing systemd user service..."
	-systemctl --user stop witnessd-ibus 2>/dev/null || true
	-systemctl --user disable witnessd-ibus 2>/dev/null || true
	rm -f $(SYSTEMD_USER_DIR)/witnessd-ibus.service
	-systemctl --user daemon-reload 2>/dev/null || true

# Desktop file management
install-desktop:
	@echo "Installing desktop files..."
	@mkdir -p $(DESKTOP_DIR)
	@sed 's|/usr/local/bin|$(HOME)/.local/bin|g' desktop/witnessd-ibus-setup.desktop > $(DESKTOP_DIR)/witnessd-ibus-setup.desktop
	@chmod 644 $(DESKTOP_DIR)/witnessd-ibus-setup.desktop
	-update-desktop-database $(DESKTOP_DIR) 2>/dev/null || true

uninstall-desktop:
	@echo "Removing desktop files..."
	rm -f $(DESKTOP_DIR)/witnessd-ibus-setup.desktop
	rm -f $(DESKTOP_DIR)/witnessd.desktop
	-update-desktop-database $(DESKTOP_DIR) 2>/dev/null || true

# Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f coverage.out coverage.html

# Development targets
run: $(BINARY)
	@echo "Running $(BINARY) in foreground..."
	./$(BINARY) --ibus

debug: build-debug
	@echo "Running $(BINARY) with debug logging..."
	./$(BINARY) --ibus --debug

# Code quality
fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./... 2>/dev/null || go vet ./...

# Status and diagnostics
status:
	@echo "=== Witnessd IBus Status ==="
	@echo ""
	@echo "Binary:"
	@which witnessd-ibus 2>/dev/null && echo "  Found: $$(which witnessd-ibus)" || echo "  Not found in PATH"
	@test -f $(HOME)/.local/bin/witnessd-ibus && echo "  User install: $(HOME)/.local/bin/witnessd-ibus" || true
	@test -f $(INSTALL_DIR)/witnessd-ibus && echo "  System install: $(INSTALL_DIR)/witnessd-ibus" || true
	@echo ""
	@echo "IBus Component:"
	@test -f $(USER_COMPONENT_DIR)/witnessd.xml && echo "  User: $(USER_COMPONENT_DIR)/witnessd.xml" || echo "  User: not installed"
	@test -f $(SYSTEM_COMPONENT_DIR)/witnessd.xml && echo "  System: $(SYSTEM_COMPONENT_DIR)/witnessd.xml" || echo "  System: not installed"
	@echo ""
	@echo "Systemd Service:"
	@systemctl --user is-active witnessd-ibus 2>/dev/null && echo "  Status: active" || echo "  Status: inactive"
	@systemctl --user is-enabled witnessd-ibus 2>/dev/null && echo "  Enabled: yes" || echo "  Enabled: no"
	@echo ""
	@echo "IBus Daemon:"
	@pgrep -x ibus-daemon > /dev/null && echo "  Running: yes (PID $$(pgrep -x ibus-daemon))" || echo "  Running: no"
	@echo ""
	@echo "Current Engine:"
	@ibus engine 2>/dev/null || echo "  Cannot query (ibus-daemon not running?)"
	@echo ""
	@echo "Data Directory:"
	@test -d $(DATA_DIR) && echo "  $(DATA_DIR) exists" || echo "  $(DATA_DIR) does not exist"
	@test -d $(DATA_DIR)/evidence && ls -la $(DATA_DIR)/evidence 2>/dev/null | head -5 || true

# Restart IBus
restart:
	@echo "Restarting IBus daemon..."
	ibus restart
	@echo "Done. You may need to re-select the input method."

# View logs
logs:
	@echo "=== Witnessd IBus Logs ==="
	@if command -v journalctl > /dev/null 2>&1; then \
		journalctl --user -u witnessd-ibus -f; \
	else \
		tail -f $(LOG_DIR)/ibus.log 2>/dev/null || echo "No logs found"; \
	fi

# Package for distribution
package: $(BINARY)
	@echo "Creating distribution package..."
	@mkdir -p dist
	@tar czvf dist/witnessd-ibus-$(VERSION)-linux-amd64.tar.gz \
		$(BINARY) \
		components/witnessd.xml \
		systemd/witnessd-ibus.service \
		desktop/*.desktop \
		Makefile \
		README.md 2>/dev/null || true
	@echo "Package created: dist/witnessd-ibus-$(VERSION)-linux-amd64.tar.gz"

# Help
help:
	@echo "Witnessd IBus Engine - Makefile Targets"
	@echo ""
	@echo "Build:"
	@echo "  make build          - Build the IBus engine"
	@echo "  make build-debug    - Build with debug symbols"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Installation:"
	@echo "  make install        - User installation (recommended)"
	@echo "  make install-user   - User installation (no sudo)"
	@echo "  make install-system - System-wide installation (requires sudo)"
	@echo "  make uninstall      - Remove all installations"
	@echo ""
	@echo "Systemd Service:"
	@echo "  make install-systemd   - Install systemd user service"
	@echo "  make uninstall-systemd - Remove systemd user service"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run unit tests"
	@echo "  make test-race      - Run tests with race detector"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-coverage  - Generate coverage report"
	@echo "  make bench          - Run benchmarks"
	@echo ""
	@echo "Development:"
	@echo "  make run            - Run engine in foreground"
	@echo "  make debug          - Run with debug logging"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linters"
	@echo ""
	@echo "Diagnostics:"
	@echo "  make status         - Show installation status"
	@echo "  make restart        - Restart IBus daemon"
	@echo "  make logs           - View engine logs"
	@echo ""
	@echo "Distribution:"
	@echo "  make package        - Create distribution tarball"
	@echo ""
	@echo "Environment Variables:"
	@echo "  PREFIX              - Installation prefix (default: /usr/local)"
