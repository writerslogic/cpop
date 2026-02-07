#!/bin/bash
# build-app.sh - Build witnessd CLI as a universal binary (arm64 + amd64)
# This script builds the Go binary that gets bundled inside Witnessd.app

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
APP_PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESOURCES_DIR="${APP_PROJECT_DIR}/witnessd/Resources"

# Version info from git
VERSION="${VERSION:-$(git -C "$PROJECT_ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

# Build flags
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# Output binary
OUTPUT_BINARY="${RESOURCES_DIR}/witnessd"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for Go
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Found Go version: $GO_VERSION"

    # Check for lipo (should be present on macOS)
    if ! command -v lipo &> /dev/null; then
        log_error "lipo is not available. This script requires macOS."
        exit 1
    fi

    # Ensure resources directory exists
    mkdir -p "$RESOURCES_DIR"
}

build_architecture() {
    local arch=$1
    local output="${RESOURCES_DIR}/witnessd-${arch}"

    log_info "Building witnessd for darwin/${arch}..."

    cd "$PROJECT_ROOT"

    # Build with CGO enabled for keystroke tracking
    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH="$arch" \
    go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$output" \
        ./cmd/witnessd

    if [ ! -f "$output" ]; then
        log_error "Failed to build witnessd for ${arch}"
        exit 1
    fi

    log_info "Built: $output ($(du -h "$output" | cut -f1))"
}

create_universal_binary() {
    log_info "Creating universal binary..."

    local arm64_bin="${RESOURCES_DIR}/witnessd-arm64"
    local amd64_bin="${RESOURCES_DIR}/witnessd-amd64"

    if [ ! -f "$arm64_bin" ] || [ ! -f "$amd64_bin" ]; then
        log_error "Architecture-specific binaries not found"
        exit 1
    fi

    # Create universal binary
    lipo -create \
        -output "$OUTPUT_BINARY" \
        "$arm64_bin" \
        "$amd64_bin"

    # Verify universal binary
    log_info "Verifying universal binary..."
    lipo -info "$OUTPUT_BINARY"

    # Verify architectures
    if ! lipo -info "$OUTPUT_BINARY" | grep -q "arm64"; then
        log_error "Universal binary missing arm64 architecture"
        exit 1
    fi

    if ! lipo -info "$OUTPUT_BINARY" | grep -q "x86_64"; then
        log_error "Universal binary missing x86_64 architecture"
        exit 1
    fi

    # Clean up architecture-specific binaries
    rm -f "$arm64_bin" "$amd64_bin"

    log_info "Universal binary created: $OUTPUT_BINARY ($(du -h "$OUTPUT_BINARY" | cut -f1))"
}

build_single_arch() {
    local arch="${1:-}"

    if [ -z "$arch" ]; then
        # Detect current architecture
        arch=$(uname -m)
        case "$arch" in
            arm64) arch="arm64" ;;
            x86_64) arch="amd64" ;;
            *)
                log_error "Unsupported architecture: $arch"
                exit 1
                ;;
        esac
    fi

    log_info "Building for single architecture: ${arch}"

    cd "$PROJECT_ROOT"

    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH="$arch" \
    go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$OUTPUT_BINARY" \
        ./cmd/witnessd

    log_info "Single-arch binary created: $OUTPUT_BINARY"
}

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build witnessd CLI binary for macOS app bundle"
    echo ""
    echo "Options:"
    echo "  --universal     Build universal binary (arm64 + amd64) [default]"
    echo "  --arm64         Build arm64 only"
    echo "  --amd64         Build amd64 (x86_64) only"
    echo "  --native        Build for current architecture"
    echo "  --clean         Remove existing binary before building"
    echo "  --verify        Verify existing binary"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  VERSION         Override version string"
    echo "  COMMIT          Override commit hash"
    echo "  BUILD_TIME      Override build time"
}

verify_binary() {
    if [ ! -f "$OUTPUT_BINARY" ]; then
        log_error "Binary not found: $OUTPUT_BINARY"
        exit 1
    fi

    log_info "Verifying binary: $OUTPUT_BINARY"

    # Check if it's a valid Mach-O binary
    if ! file "$OUTPUT_BINARY" | grep -q "Mach-O"; then
        log_error "Not a valid Mach-O binary"
        exit 1
    fi

    # Show file info
    file "$OUTPUT_BINARY"

    # Show architecture info
    lipo -info "$OUTPUT_BINARY"

    # Check version
    if "$OUTPUT_BINARY" version 2>/dev/null; then
        log_info "Binary version check passed"
    else
        log_warn "Could not verify binary version"
    fi

    log_info "Verification complete"
}

# Main
main() {
    local mode="universal"
    local clean=false
    local verify_only=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --universal)
                mode="universal"
                shift
                ;;
            --arm64)
                mode="arm64"
                shift
                ;;
            --amd64)
                mode="amd64"
                shift
                ;;
            --native)
                mode="native"
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --verify)
                verify_only=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    if [ "$verify_only" = true ]; then
        verify_binary
        exit 0
    fi

    echo ""
    echo "=========================================="
    echo "  Witnessd CLI Build"
    echo "  Version: ${VERSION}"
    echo "  Mode: ${mode}"
    echo "=========================================="
    echo ""

    check_prerequisites

    if [ "$clean" = true ]; then
        log_info "Cleaning existing binaries..."
        rm -f "${RESOURCES_DIR}/witnessd"*
    fi

    case "$mode" in
        universal)
            build_architecture "arm64"
            build_architecture "amd64"
            create_universal_binary
            ;;
        arm64)
            build_single_arch "arm64"
            ;;
        amd64)
            build_single_arch "amd64"
            ;;
        native)
            build_single_arch ""
            ;;
    esac

    verify_binary

    echo ""
    log_info "Build complete!"
    echo ""
}

main "$@"
