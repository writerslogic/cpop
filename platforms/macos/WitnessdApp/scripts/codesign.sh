#!/bin/bash
# codesign.sh - Code sign Witnessd.app and all embedded binaries
# Signs with Developer ID for distribution outside the App Store

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
DERIVED_DATA_PATH="${BUILD_DIR}/DerivedData"
DEFAULT_APP_PATH="${DERIVED_DATA_PATH}/Build/Products/Release/Witnessd.app"

# Signing identity - must be "Developer ID Application" for distribution
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application: David Condrey (U3PZN7P3E5)}"

# Entitlements
ENTITLEMENTS_PATH="${PROJECT_DIR}/witnessd/witnessd.entitlements"
HARDENED_ENTITLEMENTS_PATH="${SCRIPT_DIR}/witnessd-hardened.entitlements"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for codesign
    if ! command -v codesign &> /dev/null; then
        log_error "codesign not found. This script requires macOS."
        exit 1
    fi

    # Check signing identity
    log_info "Checking signing identity: ${SIGNING_IDENTITY}"

    if ! security find-identity -v -p codesigning | grep -q "$SIGNING_IDENTITY"; then
        log_error "Signing identity not found in keychain: $SIGNING_IDENTITY"
        log_info "Available identities:"
        security find-identity -v -p codesigning
        exit 1
    fi

    log_info "Signing identity found in keychain"
}

create_hardened_entitlements() {
    log_step "Creating hardened runtime entitlements..."

    # Create entitlements file with all necessary permissions for witnessd
    cat > "$HARDENED_ENTITLEMENTS_PATH" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- App Sandbox (required for distribution) -->
    <key>com.apple.security.app-sandbox</key>
    <true/>

    <!-- File access -->
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.files.bookmarks.app-scope</key>
    <true/>
    <key>com.apple.security.files.bookmarks.document-scope</key>
    <true/>
    <key>com.apple.security.files.downloads.read-write</key>
    <true/>

    <!-- Accessibility (for keystroke monitoring) -->
    <key>com.apple.security.automation.apple-events</key>
    <true/>

    <!-- Network access for anchoring services -->
    <key>com.apple.security.network.client</key>
    <true/>

    <!-- Keychain access for key storage -->
    <key>com.apple.security.keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.witnessd.app</string>
    </array>

    <!-- Allow JIT compilation (if needed for performance) -->
    <key>com.apple.security.cs.allow-jit</key>
    <false/>

    <!-- Allow unsigned executable memory -->
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <false/>

    <!-- Allow DYLD environment variables (for debugging, disable in production) -->
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <false/>

    <!-- Disable library validation (only if needed for third-party dylibs) -->
    <key>com.apple.security.cs.disable-library-validation</key>
    <false/>

    <!-- Hardened Runtime - disable executable heap -->
    <key>com.apple.security.cs.disable-executable-page-protection</key>
    <false/>

    <!-- Debugger (disable in production) -->
    <key>com.apple.security.cs.debugger</key>
    <false/>
</dict>
</plist>
EOF

    log_info "Created hardened entitlements: $HARDENED_ENTITLEMENTS_PATH"
}

# Create minimal entitlements for the embedded CLI binary
create_cli_entitlements() {
    local cli_entitlements="${SCRIPT_DIR}/witnessd-cli.entitlements"

    cat > "$cli_entitlements" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Inherit sandbox from parent app -->
    <key>com.apple.security.inherit</key>
    <true/>
</dict>
</plist>
EOF

    echo "$cli_entitlements"
}

sign_binary() {
    local binary_path="$1"
    local entitlements="${2:-}"
    local identifier="${3:-}"

    if [ ! -f "$binary_path" ] && [ ! -d "$binary_path" ]; then
        log_warn "Skipping non-existent path: $binary_path"
        return 0
    fi

    local sign_args=(
        --force
        --options runtime
        --timestamp
        --sign "$SIGNING_IDENTITY"
    )

    if [ -n "$entitlements" ] && [ -f "$entitlements" ]; then
        sign_args+=(--entitlements "$entitlements")
    fi

    if [ -n "$identifier" ]; then
        sign_args+=(--identifier "$identifier")
    fi

    log_info "Signing: $binary_path"
    codesign "${sign_args[@]}" "$binary_path"
}

sign_frameworks() {
    local app_path="$1"
    local frameworks_dir="${app_path}/Contents/Frameworks"

    if [ ! -d "$frameworks_dir" ]; then
        log_info "No Frameworks directory found"
        return 0
    fi

    log_step "Signing frameworks..."

    # Sign each framework
    find "$frameworks_dir" -name "*.framework" -type d | while read -r framework; do
        log_info "Signing framework: $(basename "$framework")"

        # Sign all binaries within the framework
        local framework_binary="${framework}/Versions/A/$(basename "${framework%.framework}")"
        if [ -f "$framework_binary" ]; then
            sign_binary "$framework_binary"
        fi

        # Sign the framework bundle itself
        sign_binary "$framework"
    done

    # Sign any dylibs
    find "$frameworks_dir" -name "*.dylib" -type f | while read -r dylib; do
        log_info "Signing dylib: $(basename "$dylib")"
        sign_binary "$dylib"
    done
}

sign_plugins() {
    local app_path="$1"
    local plugins_dir="${app_path}/Contents/PlugIns"

    if [ ! -d "$plugins_dir" ]; then
        log_info "No PlugIns directory found"
        return 0
    fi

    log_step "Signing plugins..."

    find "$plugins_dir" -name "*.appex" -type d | while read -r plugin; do
        log_info "Signing plugin: $(basename "$plugin")"
        sign_binary "$plugin"
    done
}

sign_helpers() {
    local app_path="$1"
    local helpers_dir="${app_path}/Contents/MacOS"

    log_step "Signing helper binaries..."

    # Sign any additional executables in MacOS directory
    find "$helpers_dir" -type f -perm +111 | while read -r binary; do
        local binary_name=$(basename "$binary")
        if [ "$binary_name" != "Witnessd" ] && [ "$binary_name" != "witnessd" ]; then
            log_info "Signing helper: $binary_name"
            sign_binary "$binary"
        fi
    done
}

sign_resources() {
    local app_path="$1"
    local resources_dir="${app_path}/Contents/Resources"
    local cli_entitlements=$(create_cli_entitlements)

    log_step "Signing resource binaries..."

    # Sign the embedded witnessd CLI binary
    local witnessd_binary="${resources_dir}/witnessd"
    if [ -f "$witnessd_binary" ]; then
        log_info "Signing embedded witnessd CLI"
        sign_binary "$witnessd_binary" "$cli_entitlements" "com.witnessd.cli"
    fi

    # Sign any other executables in Resources
    find "$resources_dir" -type f -perm +111 ! -name "witnessd" | while read -r binary; do
        # Skip non-Mach-O files
        if file "$binary" | grep -q "Mach-O"; then
            log_info "Signing resource binary: $(basename "$binary")"
            sign_binary "$binary" "$cli_entitlements"
        fi
    done
}

sign_app() {
    local app_path="$1"

    log_step "Signing main app bundle..."

    # Use the app's entitlements or hardened entitlements
    local entitlements="$ENTITLEMENTS_PATH"
    if [ -f "$HARDENED_ENTITLEMENTS_PATH" ]; then
        entitlements="$HARDENED_ENTITLEMENTS_PATH"
    fi

    # Sign the main executable first
    local main_executable="${app_path}/Contents/MacOS/Witnessd"
    if [ -f "$main_executable" ]; then
        log_info "Signing main executable"
        sign_binary "$main_executable" "$entitlements" "com.witnessd.app"
    fi

    # Sign the entire app bundle (deep sign)
    log_info "Signing app bundle"
    codesign \
        --force \
        --deep \
        --options runtime \
        --timestamp \
        --sign "$SIGNING_IDENTITY" \
        --entitlements "$entitlements" \
        "$app_path"
}

verify_signature() {
    local app_path="$1"

    log_step "Verifying code signature..."

    # Basic verification
    log_info "Running codesign verification..."
    if ! codesign --verify --verbose=2 "$app_path" 2>&1; then
        log_error "Code signature verification failed"
        exit 1
    fi

    # Deep verification
    log_info "Running deep verification..."
    if ! codesign --verify --deep --strict --verbose=2 "$app_path" 2>&1; then
        log_warn "Deep verification had warnings (may be acceptable)"
    fi

    # Gatekeeper check
    log_info "Running Gatekeeper assessment..."
    if spctl --assess --type execute --verbose=2 "$app_path" 2>&1; then
        log_info "Gatekeeper assessment PASSED"
    else
        log_warn "Gatekeeper assessment failed (may need notarization)"
    fi

    # Show signature details
    log_info "Signature details:"
    codesign -dv --verbose=4 "$app_path" 2>&1 | head -30

    log_info "Code signature verification complete"
}

list_identities() {
    log_info "Available signing identities:"
    echo ""
    security find-identity -v -p codesigning
    echo ""
    log_info "Use SIGNING_IDENTITY environment variable or --identity flag to specify"
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Code sign Witnessd.app for distribution"
    echo ""
    echo "Commands:"
    echo "  sign [APP_PATH]   Sign the app bundle (default)"
    echo "  verify [APP_PATH] Verify existing signature"
    echo "  identities        List available signing identities"
    echo ""
    echo "Options:"
    echo "  --identity ID     Signing identity (Developer ID Application: ...)"
    echo "  --app PATH        Path to Witnessd.app"
    echo "  --entitlements    Path to custom entitlements file"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  SIGNING_IDENTITY  Code signing identity"
    echo ""
    echo "Examples:"
    echo "  $0 sign"
    echo "  $0 sign ./build/Witnessd.app"
    echo "  $0 --identity 'Developer ID Application: Your Name' sign"
    echo "  $0 verify ./build/Witnessd.app"
    echo "  $0 identities"
}

# Main
main() {
    local command="sign"
    local app_path="$DEFAULT_APP_PATH"
    local custom_entitlements=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            sign|verify|identities)
                command="$1"
                shift
                # Check if next arg is a path (not starting with -)
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    app_path="$1"
                    shift
                fi
                ;;
            --identity)
                SIGNING_IDENTITY="$2"
                shift 2
                ;;
            --app)
                app_path="$2"
                shift 2
                ;;
            --entitlements)
                custom_entitlements="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                # Check if it's a path
                if [[ -d "$1" || -f "$1" ]]; then
                    app_path="$1"
                    shift
                else
                    log_error "Unknown option: $1"
                    print_usage
                    exit 1
                fi
                ;;
        esac
    done

    case "$command" in
        identities)
            list_identities
            exit 0
            ;;
        verify)
            if [ ! -d "$app_path" ]; then
                log_error "App not found: $app_path"
                exit 1
            fi
            verify_signature "$app_path"
            exit 0
            ;;
        sign)
            ;;
        *)
            log_error "Unknown command: $command"
            print_usage
            exit 1
            ;;
    esac

    echo ""
    echo "=========================================="
    echo "  Witnessd Code Signing"
    echo "  Identity: ${SIGNING_IDENTITY}"
    echo "  App: ${app_path}"
    echo "=========================================="
    echo ""

    if [ ! -d "$app_path" ]; then
        log_error "App not found: $app_path"
        log_info "Build the app first using: ./build-swiftui.sh"
        exit 1
    fi

    check_prerequisites

    # Create hardened entitlements
    if [ -n "$custom_entitlements" ]; then
        HARDENED_ENTITLEMENTS_PATH="$custom_entitlements"
    else
        create_hardened_entitlements
    fi

    # Sign in order: deepest first
    # 1. Frameworks
    sign_frameworks "$app_path"

    # 2. Plugins
    sign_plugins "$app_path"

    # 3. Helper binaries
    sign_helpers "$app_path"

    # 4. Resource binaries (embedded CLI)
    sign_resources "$app_path"

    # 5. Main app bundle
    sign_app "$app_path"

    # 6. Verify
    verify_signature "$app_path"

    echo ""
    log_info "Code signing complete!"
    log_info "App is signed and ready for notarization."
    echo ""
}

main "$@"
