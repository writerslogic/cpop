#!/bin/bash
# witnessd installer
# Usage: curl -sSf https://raw.githubusercontent.com/writerslogic/witnessd/main/install.sh | sh

set -e

REPO="writerslogic/witnessd"
BINARY_NAME="witnessd-cli"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS and architecture
detect_platform() {
    local os arch

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        linux)
            os="unknown-linux-gnu"
            ;;
        darwin)
            os="apple-darwin"
            ;;
        mingw* | msys* | cygwin* | windows*)
            error "Windows detected. Please use the PowerShell installer or download from GitHub releases."
            ;;
        *)
            error "Unsupported operating system: $os"
            ;;
    esac

    case "$arch" in
        x86_64 | amd64)
            arch="x86_64"
            ;;
        aarch64 | arm64)
            arch="aarch64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            ;;
    esac

    echo "${arch}-${os}"
}

# Get the latest release version
get_latest_version() {
    curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install_witnessd() {
    local platform version url archive_name tmp_dir

    info "Detecting platform..."
    platform=$(detect_platform)
    info "Platform: $platform"

    info "Fetching latest version..."
    version=$(get_latest_version)
    if [ -z "$version" ]; then
        error "Could not determine latest version. Check your internet connection."
    fi
    info "Latest version: $version"

    archive_name="witnessd_${version}_${platform}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

    info "Downloading $archive_name..."
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    if ! curl -sSfL -o "${tmp_dir}/${archive_name}" "$url"; then
        error "Failed to download $url"
    fi

    info "Extracting archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        info "Installing to $INSTALL_DIR..."
        mv "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/witnessd"
        chmod +x "${INSTALL_DIR}/witnessd"
    else
        info "Installing to $INSTALL_DIR (requires sudo)..."
        sudo mv "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/witnessd"
        sudo chmod +x "${INSTALL_DIR}/witnessd"
    fi

    info "witnessd installed successfully!"
    echo ""
    echo "To get started:"
    echo "  witnessd init        # Initialize witnessd"
    echo "  witnessd calibrate   # Calibrate VDF for your machine"
    echo "  witnessd --help      # Show all commands"
    echo ""

    # Verify installation
    if command -v witnessd &> /dev/null; then
        info "Installed version: $(witnessd --version)"
    else
        warn "witnessd installed but not in PATH. Add $INSTALL_DIR to your PATH."
    fi
}

# Main
main() {
    echo ""
    echo "  ╦ ╦╦╔╦╗╔╗╔╔═╗╔═╗╔═╗╔╦╗"
    echo "  ║║║║ ║ ║║║║╣ ╚═╗╚═╗ ║║"
    echo "  ╚╩╝╩ ╩ ╝╚╝╚═╝╚═╝╚═╝═╩╝"
    echo "  Cryptographic Authorship Witnessing"
    echo ""

    install_witnessd
}

main "$@"
