#!/bin/bash
# build-swiftui.sh - Build Witnessd SwiftUI app via xcodebuild
# This script builds the macOS SwiftUI application using Xcode's command-line tools

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_NAME="witnessd"
SCHEME="witnessd"
CONFIGURATION="${CONFIGURATION:-Release}"
BUILD_DIR="${PROJECT_DIR}/build"
DERIVED_DATA_PATH="${BUILD_DIR}/DerivedData"
ARCHIVE_PATH="${BUILD_DIR}/Witnessd.xcarchive"

# macOS deployment target
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-13.0}"

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

    # Check for xcodebuild
    if ! command -v xcodebuild &> /dev/null; then
        log_error "xcodebuild not found. Please install Xcode Command Line Tools."
        log_info "Run: xcode-select --install"
        exit 1
    fi

    # Check Xcode version
    XCODE_VERSION=$(xcodebuild -version | head -1)
    log_info "Found: $XCODE_VERSION"

    # Check for project file
    if [ ! -d "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" ]; then
        log_error "Xcode project not found: ${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj"
        exit 1
    fi

    # Check for witnessd binary in Resources
    if [ ! -f "${PROJECT_DIR}/witnessd/Resources/witnessd" ]; then
        log_warn "witnessd binary not found in Resources. Building it now..."
        "$SCRIPT_DIR/build-app.sh"
    fi

    log_info "Prerequisites check passed"
}

clean_build() {
    log_step "Cleaning previous build..."

    xcodebuild clean \
        -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
        -scheme "$SCHEME" \
        -configuration "$CONFIGURATION" \
        2>/dev/null || true

    rm -rf "$DERIVED_DATA_PATH"
    rm -rf "$ARCHIVE_PATH"

    log_info "Clean complete"
}

build_app() {
    log_step "Building Witnessd.app (${CONFIGURATION})..."

    mkdir -p "$BUILD_DIR"

    # Build the app
    xcodebuild build \
        -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
        -scheme "$SCHEME" \
        -configuration "$CONFIGURATION" \
        -derivedDataPath "$DERIVED_DATA_PATH" \
        MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        CODE_SIGN_IDENTITY="" \
        CODE_SIGNING_REQUIRED=NO \
        CODE_SIGNING_ALLOWED=NO \
        ONLY_ACTIVE_ARCH=NO \
        | xcpretty 2>/dev/null || xcodebuild build \
            -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
            -scheme "$SCHEME" \
            -configuration "$CONFIGURATION" \
            -derivedDataPath "$DERIVED_DATA_PATH" \
            MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
            CODE_SIGN_IDENTITY="" \
            CODE_SIGNING_REQUIRED=NO \
            CODE_SIGNING_ALLOWED=NO \
            ONLY_ACTIVE_ARCH=NO

    local app_path="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/Witnessd.app"

    if [ ! -d "$app_path" ]; then
        log_error "Build failed: Witnessd.app not found at $app_path"
        exit 1
    fi

    log_info "Build successful: $app_path"
    echo "$app_path"
}

build_app_signed() {
    local signing_identity="${1:-}"

    log_step "Building Witnessd.app with signing (${CONFIGURATION})..."

    if [ -z "$signing_identity" ]; then
        log_error "Signing identity required for signed build"
        exit 1
    fi

    mkdir -p "$BUILD_DIR"

    # Build with signing
    xcodebuild build \
        -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
        -scheme "$SCHEME" \
        -configuration "$CONFIGURATION" \
        -derivedDataPath "$DERIVED_DATA_PATH" \
        MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        CODE_SIGN_IDENTITY="$signing_identity" \
        CODE_SIGNING_REQUIRED=YES \
        CODE_SIGNING_ALLOWED=YES \
        OTHER_CODE_SIGN_FLAGS="--options runtime --timestamp" \
        ONLY_ACTIVE_ARCH=NO \
        | xcpretty 2>/dev/null || xcodebuild build \
            -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
            -scheme "$SCHEME" \
            -configuration "$CONFIGURATION" \
            -derivedDataPath "$DERIVED_DATA_PATH" \
            MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
            CODE_SIGN_IDENTITY="$signing_identity" \
            CODE_SIGNING_REQUIRED=YES \
            CODE_SIGNING_ALLOWED=YES \
            OTHER_CODE_SIGN_FLAGS="--options runtime --timestamp" \
            ONLY_ACTIVE_ARCH=NO

    local app_path="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/Witnessd.app"

    if [ ! -d "$app_path" ]; then
        log_error "Build failed: Witnessd.app not found"
        exit 1
    fi

    log_info "Signed build successful: $app_path"
}

create_archive() {
    local signing_identity="${1:-}"

    log_step "Creating Xcode archive..."

    local sign_args=""
    if [ -n "$signing_identity" ]; then
        sign_args="CODE_SIGN_IDENTITY=\"$signing_identity\" OTHER_CODE_SIGN_FLAGS=\"--options runtime --timestamp\""
    else
        sign_args="CODE_SIGN_IDENTITY=\"\" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO"
    fi

    mkdir -p "$BUILD_DIR"

    xcodebuild archive \
        -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
        -scheme "$SCHEME" \
        -configuration "$CONFIGURATION" \
        -archivePath "$ARCHIVE_PATH" \
        MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
        ONLY_ACTIVE_ARCH=NO \
        $sign_args \
        | xcpretty 2>/dev/null || xcodebuild archive \
            -project "${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj" \
            -scheme "$SCHEME" \
            -configuration "$CONFIGURATION" \
            -archivePath "$ARCHIVE_PATH" \
            MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
            ONLY_ACTIVE_ARCH=NO \
            $sign_args

    if [ ! -d "$ARCHIVE_PATH" ]; then
        log_error "Archive failed: $ARCHIVE_PATH not found"
        exit 1
    fi

    log_info "Archive created: $ARCHIVE_PATH"
}

export_app() {
    local export_options_plist="${1:-${SCRIPT_DIR}/export-options.plist}"
    local export_path="${BUILD_DIR}/export"

    log_step "Exporting app from archive..."

    if [ ! -f "$export_options_plist" ]; then
        log_error "Export options plist not found: $export_options_plist"
        exit 1
    fi

    if [ ! -d "$ARCHIVE_PATH" ]; then
        log_error "Archive not found: $ARCHIVE_PATH"
        exit 1
    fi

    rm -rf "$export_path"

    xcodebuild -exportArchive \
        -archivePath "$ARCHIVE_PATH" \
        -exportOptionsPlist "$export_options_plist" \
        -exportPath "$export_path"

    local app_path="${export_path}/Witnessd.app"

    if [ ! -d "$app_path" ]; then
        log_error "Export failed: Witnessd.app not found in $export_path"
        exit 1
    fi

    log_info "Exported: $app_path"
}

verify_build() {
    local app_path="${1:-${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/Witnessd.app}"

    log_step "Verifying build..."

    if [ ! -d "$app_path" ]; then
        log_error "App not found: $app_path"
        exit 1
    fi

    # Check Info.plist
    if [ ! -f "${app_path}/Contents/Info.plist" ]; then
        log_error "Info.plist not found in app bundle"
        exit 1
    fi

    local bundle_id=$(defaults read "${app_path}/Contents/Info" CFBundleIdentifier 2>/dev/null || echo "unknown")
    local version=$(defaults read "${app_path}/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "unknown")
    local build=$(defaults read "${app_path}/Contents/Info" CFBundleVersion 2>/dev/null || echo "unknown")

    log_info "Bundle ID: $bundle_id"
    log_info "Version: $version ($build)"

    # Check for witnessd binary inside app
    local witnessd_path="${app_path}/Contents/Resources/witnessd"
    if [ -f "$witnessd_path" ]; then
        log_info "Embedded witnessd binary found"
        file "$witnessd_path"
    else
        log_warn "witnessd binary not found in Resources"
    fi

    # Check code signature (if signed)
    if codesign -dv "$app_path" 2>/dev/null; then
        log_info "Code signature info:"
        codesign -dv --verbose=2 "$app_path" 2>&1 | head -20
    else
        log_info "App is not code signed (expected for dev builds)"
    fi

    # Check app size
    local app_size=$(du -sh "$app_path" | cut -f1)
    log_info "App size: $app_size"

    log_info "Verification complete"
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Build Witnessd SwiftUI macOS application"
    echo ""
    echo "Commands:"
    echo "  build             Build the app (default)"
    echo "  build-signed      Build with code signing"
    echo "  archive           Create Xcode archive"
    echo "  export            Export from archive"
    echo "  clean             Clean build artifacts"
    echo "  verify            Verify built app"
    echo ""
    echo "Options:"
    echo "  --configuration   Build configuration (Debug/Release) [default: Release]"
    echo "  --identity        Code signing identity (Developer ID Application: ...)"
    echo "  --export-plist    Path to export options plist"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  CONFIGURATION           Build configuration"
    echo "  MACOS_DEPLOYMENT_TARGET Minimum macOS version [default: 13.0]"
    echo "  SIGNING_IDENTITY        Code signing identity"
    echo ""
    echo "Examples:"
    echo "  $0 build                     # Build unsigned app for testing"
    echo "  $0 build-signed --identity 'Developer ID Application: Your Name'"
    echo "  $0 archive                   # Create archive for distribution"
    echo "  $0 clean && $0 build         # Clean build"
}

# Main
main() {
    local command="build"
    local signing_identity="${SIGNING_IDENTITY:-}"
    local export_plist=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            build|build-signed|archive|export|clean|verify)
                command="$1"
                shift
                ;;
            --configuration)
                CONFIGURATION="$2"
                shift 2
                ;;
            --identity)
                signing_identity="$2"
                shift 2
                ;;
            --export-plist)
                export_plist="$2"
                shift 2
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

    echo ""
    echo "=========================================="
    echo "  Witnessd SwiftUI Build"
    echo "  Configuration: ${CONFIGURATION}"
    echo "  Command: ${command}"
    echo "=========================================="
    echo ""

    case "$command" in
        build)
            check_prerequisites
            build_app
            verify_build
            ;;
        build-signed)
            check_prerequisites
            if [ -z "$signing_identity" ]; then
                log_error "Signing identity required. Use --identity or set SIGNING_IDENTITY"
                exit 1
            fi
            build_app_signed "$signing_identity"
            verify_build
            ;;
        archive)
            check_prerequisites
            create_archive "$signing_identity"
            ;;
        export)
            if [ -n "$export_plist" ]; then
                export_app "$export_plist"
            else
                log_error "Export options plist required. Use --export-plist"
                exit 1
            fi
            ;;
        clean)
            clean_build
            ;;
        verify)
            verify_build
            ;;
        *)
            log_error "Unknown command: $command"
            print_usage
            exit 1
            ;;
    esac

    echo ""
    log_info "Done!"
    echo ""
}

main "$@"
