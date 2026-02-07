#!/bin/bash
# notarize.sh - Submit Witnessd.app to Apple's notarization service
# Handles submission, waiting for completion, and stapling the ticket

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
DERIVED_DATA_PATH="${BUILD_DIR}/DerivedData"
DEFAULT_APP_PATH="${DERIVED_DATA_PATH}/Build/Products/Release/Witnessd.app"

# Notarization credentials
# Method 1: Keychain profile (recommended)
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-notarytool}"

# Method 2: API Key (for CI/CD)
APPLE_KEY_ID="${APPLE_KEY_ID:-}"
APPLE_ISSUER_ID="${APPLE_ISSUER_ID:-}"
APPLE_PRIVATE_KEY="${APPLE_PRIVATE_KEY:-}"      # Path to .p8 file or contents
APPLE_PRIVATE_KEY_PATH="${APPLE_PRIVATE_KEY_PATH:-}"  # Explicit path to .p8 file

# Method 3: Apple ID (legacy, not recommended)
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"

# Bundle identifier
BUNDLE_ID="${BUNDLE_ID:-com.witnessd.app}"

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

    # Check for notarytool
    if ! command -v xcrun &> /dev/null; then
        log_error "xcrun not found. This script requires Xcode Command Line Tools."
        exit 1
    fi

    # Check notarytool availability
    if ! xcrun notarytool --version &> /dev/null; then
        log_error "notarytool not found. Requires Xcode 13 or later."
        exit 1
    fi

    local notarytool_version=$(xcrun notarytool --version 2>&1 | head -1)
    log_info "Found: $notarytool_version"

    # Check for stapler
    if ! xcrun stapler --version &> /dev/null; then
        log_error "stapler not found."
        exit 1
    fi
}

detect_auth_method() {
    # Priority: API Key > Keychain Profile > Apple ID

    if [ -n "$APPLE_KEY_ID" ] && [ -n "$APPLE_ISSUER_ID" ]; then
        if [ -n "$APPLE_PRIVATE_KEY_PATH" ] && [ -f "$APPLE_PRIVATE_KEY_PATH" ]; then
            log_info "Using API Key authentication (path)"
            echo "apikey"
            return
        elif [ -n "$APPLE_PRIVATE_KEY" ]; then
            log_info "Using API Key authentication (inline)"
            echo "apikey-inline"
            return
        fi
    fi

    # Check if keychain profile exists
    if xcrun notarytool info --keychain-profile "$NOTARYTOOL_PROFILE" dummy 2>&1 | grep -q "Could not find"; then
        # Profile doesn't exist, but command works - check if it's configured
        :
    fi

    # Try keychain profile
    log_info "Using keychain profile authentication: $NOTARYTOOL_PROFILE"
    echo "keychain"
}

get_auth_args() {
    local auth_method=$(detect_auth_method)
    local args=""

    case "$auth_method" in
        apikey)
            args="--key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$APPLE_PRIVATE_KEY_PATH\""
            ;;
        apikey-inline)
            # Write key to temp file
            local temp_key=$(mktemp)
            echo "$APPLE_PRIVATE_KEY" > "$temp_key"
            args="--key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$temp_key\""
            ;;
        keychain)
            args="--keychain-profile \"$NOTARYTOOL_PROFILE\""
            ;;
        appleid)
            args="--apple-id \"$APPLE_ID\" --team-id \"$APPLE_TEAM_ID\" --password \"$APPLE_APP_SPECIFIC_PASSWORD\""
            ;;
        *)
            log_error "No valid authentication method configured"
            log_info "Configure one of:"
            log_info "  1. APPLE_KEY_ID + APPLE_ISSUER_ID + APPLE_PRIVATE_KEY_PATH (API Key - recommended for CI)"
            log_info "  2. NOTARYTOOL_PROFILE (Keychain profile - recommended for local dev)"
            log_info "  3. APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD (Apple ID)"
            exit 1
            ;;
    esac

    echo "$args"
}

create_zip_for_notarization() {
    local app_path="$1"
    local zip_path="${2:-${BUILD_DIR}/Witnessd-notarize.zip}"

    log_step "Creating ZIP archive for notarization..."

    # Remove old zip if exists
    rm -f "$zip_path"

    # Create zip with ditto (preserves extended attributes and resource forks)
    ditto -c -k --keepParent "$app_path" "$zip_path"

    if [ ! -f "$zip_path" ]; then
        log_error "Failed to create ZIP archive"
        exit 1
    fi

    local zip_size=$(du -h "$zip_path" | cut -f1)
    log_info "Created: $zip_path ($zip_size)"

    echo "$zip_path"
}

submit_for_notarization() {
    local zip_path="$1"
    local auth_method=$(detect_auth_method)

    log_step "Submitting to Apple notarization service..."

    local submit_cmd="xcrun notarytool submit \"$zip_path\""

    case "$auth_method" in
        apikey)
            submit_cmd+=" --key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$APPLE_PRIVATE_KEY_PATH\""
            ;;
        apikey-inline)
            # Write key to temp file
            local temp_key=$(mktemp)
            echo "$APPLE_PRIVATE_KEY" > "$temp_key"
            chmod 600 "$temp_key"
            submit_cmd+=" --key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$temp_key\""
            ;;
        keychain)
            submit_cmd+=" --keychain-profile \"$NOTARYTOOL_PROFILE\""
            ;;
    esac

    submit_cmd+=" --wait --timeout 30m"

    log_info "Running: xcrun notarytool submit ... --wait"

    # Execute and capture output
    local output
    if output=$(eval "$submit_cmd" 2>&1); then
        log_info "Notarization completed successfully"
        echo "$output"

        # Extract submission ID for logs
        local submission_id=$(echo "$output" | grep -E "^\s*id:" | head -1 | awk '{print $2}')
        if [ -n "$submission_id" ]; then
            log_info "Submission ID: $submission_id"

            # Fetch and save log
            fetch_notarization_log "$submission_id"
        fi

        return 0
    else
        log_error "Notarization failed"
        echo "$output"

        # Try to extract submission ID for logs
        local submission_id=$(echo "$output" | grep -E "^\s*id:" | head -1 | awk '{print $2}')
        if [ -n "$submission_id" ]; then
            log_info "Fetching failure log for submission: $submission_id"
            fetch_notarization_log "$submission_id"
        fi

        return 1
    fi
}

fetch_notarization_log() {
    local submission_id="$1"
    local log_path="${BUILD_DIR}/notarization-log-${submission_id}.json"
    local auth_method=$(detect_auth_method)

    log_step "Fetching notarization log..."

    local log_cmd="xcrun notarytool log \"$submission_id\""

    case "$auth_method" in
        apikey)
            log_cmd+=" --key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$APPLE_PRIVATE_KEY_PATH\""
            ;;
        keychain)
            log_cmd+=" --keychain-profile \"$NOTARYTOOL_PROFILE\""
            ;;
    esac

    log_cmd+=" \"$log_path\""

    if eval "$log_cmd" 2>/dev/null; then
        log_info "Notarization log saved: $log_path"

        # Parse and display issues
        if command -v jq &> /dev/null && [ -f "$log_path" ]; then
            local issues=$(jq -r '.issues[]? | "  - \(.severity): \(.message)"' "$log_path" 2>/dev/null)
            if [ -n "$issues" ]; then
                log_warn "Issues found:"
                echo "$issues"
            fi
        fi
    else
        log_warn "Could not fetch notarization log"
    fi
}

staple_app() {
    local app_path="$1"

    log_step "Stapling notarization ticket to app..."

    if xcrun stapler staple "$app_path"; then
        log_info "Ticket stapled successfully"
    else
        log_error "Failed to staple ticket"
        exit 1
    fi
}

verify_notarization() {
    local app_path="$1"

    log_step "Verifying notarization..."

    # Check stapler status
    log_info "Checking stapler status..."
    if xcrun stapler validate "$app_path"; then
        log_info "Stapler validation PASSED"
    else
        log_warn "Stapler validation failed"
    fi

    # Gatekeeper assessment
    log_info "Running Gatekeeper assessment..."
    if spctl --assess --type execute --verbose=2 "$app_path" 2>&1; then
        log_info "Gatekeeper assessment PASSED"
    else
        log_warn "Gatekeeper assessment had warnings"
    fi

    # Check for notarization ticket
    log_info "Checking notarization ticket..."
    spctl -a -vv "$app_path" 2>&1 || true

    log_info "Notarization verification complete"
}

staple_dmg() {
    local dmg_path="$1"

    log_step "Stapling notarization ticket to DMG..."

    if xcrun stapler staple "$dmg_path"; then
        log_info "Ticket stapled to DMG successfully"
    else
        log_error "Failed to staple ticket to DMG"
        exit 1
    fi
}

notarize_dmg() {
    local dmg_path="$1"

    log_step "Notarizing DMG..."

    local auth_method=$(detect_auth_method)
    local submit_cmd="xcrun notarytool submit \"$dmg_path\""

    case "$auth_method" in
        apikey)
            submit_cmd+=" --key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$APPLE_PRIVATE_KEY_PATH\""
            ;;
        keychain)
            submit_cmd+=" --keychain-profile \"$NOTARYTOOL_PROFILE\""
            ;;
    esac

    submit_cmd+=" --wait --timeout 30m"

    log_info "Submitting DMG to notarization service..."

    if eval "$submit_cmd"; then
        log_info "DMG notarization successful"
        staple_dmg "$dmg_path"
    else
        log_error "DMG notarization failed"
        exit 1
    fi
}

setup_keychain_profile() {
    local profile_name="${1:-notarytool}"

    log_step "Setting up keychain profile: $profile_name"

    echo ""
    log_info "This will store your Apple notarization credentials in the keychain."
    log_info "You'll need:"
    log_info "  - Apple Developer Team ID"
    log_info "  - App Store Connect API Key ID"
    log_info "  - App Store Connect API Issuer ID"
    log_info "  - Private key file (.p8)"
    echo ""

    xcrun notarytool store-credentials "$profile_name"

    log_info "Keychain profile created: $profile_name"
    log_info "Set NOTARYTOOL_PROFILE=$profile_name to use this profile"
}

check_history() {
    log_step "Checking notarization history..."

    local auth_method=$(detect_auth_method)
    local history_cmd="xcrun notarytool history"

    case "$auth_method" in
        apikey)
            history_cmd+=" --key-id \"$APPLE_KEY_ID\" --issuer \"$APPLE_ISSUER_ID\" --key \"$APPLE_PRIVATE_KEY_PATH\""
            ;;
        keychain)
            history_cmd+=" --keychain-profile \"$NOTARYTOOL_PROFILE\""
            ;;
    esac

    eval "$history_cmd" | head -20
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Submit Witnessd.app to Apple notarization service"
    echo ""
    echo "Commands:"
    echo "  notarize [APP_PATH]  Notarize the app (default)"
    echo "  notarize-dmg [DMG]   Notarize a DMG file"
    echo "  staple [APP_PATH]    Staple ticket to already notarized app"
    echo "  verify [APP_PATH]    Verify notarization status"
    echo "  history              Show notarization history"
    echo "  setup-profile        Create keychain credential profile"
    echo ""
    echo "Options:"
    echo "  --app PATH           Path to Witnessd.app"
    echo "  --profile NAME       Keychain profile name [default: notarytool]"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Authentication (choose one):"
    echo ""
    echo "  1. Keychain Profile (recommended for local development):"
    echo "     NOTARYTOOL_PROFILE=profilename"
    echo ""
    echo "  2. API Key (recommended for CI/CD):"
    echo "     APPLE_KEY_ID=your-key-id"
    echo "     APPLE_ISSUER_ID=your-issuer-id"
    echo "     APPLE_PRIVATE_KEY_PATH=/path/to/AuthKey_XXX.p8"
    echo ""
    echo "Examples:"
    echo "  $0 notarize ./build/Witnessd.app"
    echo "  $0 notarize-dmg ./build/Witnessd-1.0.dmg"
    echo "  $0 setup-profile                    # Interactive setup"
    echo "  $0 verify ./build/Witnessd.app"
    echo ""
    echo "CI/CD Example:"
    echo "  APPLE_KEY_ID=\$KEY_ID APPLE_ISSUER_ID=\$ISSUER APPLE_PRIVATE_KEY_PATH=key.p8 \\"
    echo "    $0 notarize ./build/Witnessd.app"
}

# Main
main() {
    local command="notarize"
    local app_path="$DEFAULT_APP_PATH"
    local dmg_path=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            notarize|staple|verify|history|setup-profile)
                command="$1"
                shift
                # Check if next arg is a path
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    app_path="$1"
                    shift
                fi
                ;;
            notarize-dmg)
                command="notarize-dmg"
                shift
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    dmg_path="$1"
                    shift
                fi
                ;;
            --app)
                app_path="$2"
                shift 2
                ;;
            --profile)
                NOTARYTOOL_PROFILE="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                if [[ -d "$1" || -f "$1" ]]; then
                    if [[ "$1" == *.dmg ]]; then
                        dmg_path="$1"
                    else
                        app_path="$1"
                    fi
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
        setup-profile)
            setup_keychain_profile "$NOTARYTOOL_PROFILE"
            exit 0
            ;;
        history)
            check_prerequisites
            check_history
            exit 0
            ;;
    esac

    echo ""
    echo "=========================================="
    echo "  Witnessd Notarization"
    echo "  Command: ${command}"
    echo "=========================================="
    echo ""

    check_prerequisites

    case "$command" in
        notarize)
            if [ ! -d "$app_path" ]; then
                log_error "App not found: $app_path"
                exit 1
            fi

            # Verify it's signed first
            if ! codesign --verify "$app_path" 2>/dev/null; then
                log_error "App is not properly signed. Run codesign.sh first."
                exit 1
            fi

            local zip_path=$(create_zip_for_notarization "$app_path")
            submit_for_notarization "$zip_path"
            staple_app "$app_path"
            verify_notarization "$app_path"

            # Clean up zip
            rm -f "$zip_path"
            ;;

        notarize-dmg)
            if [ -z "$dmg_path" ] || [ ! -f "$dmg_path" ]; then
                log_error "DMG not found: $dmg_path"
                exit 1
            fi

            notarize_dmg "$dmg_path"

            # Verify
            log_info "Verifying DMG notarization..."
            spctl -a -vv --type install "$dmg_path" 2>&1 || true
            ;;

        staple)
            if [ ! -d "$app_path" ]; then
                log_error "App not found: $app_path"
                exit 1
            fi
            staple_app "$app_path"
            ;;

        verify)
            if [ ! -d "$app_path" ]; then
                log_error "App not found: $app_path"
                exit 1
            fi
            verify_notarization "$app_path"
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
