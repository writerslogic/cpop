#!/bin/bash
# Build script for Witnessd Android IME
#
# Prerequisites:
# - Go with gomobile: go install golang.org/x/mobile/cmd/gomobile@latest
# - Android SDK with NDK
# - Gradle (or use the wrapper)
#
# Usage:
#   ./build.sh          # Build debug APK
#   ./build.sh release  # Build release APK
#   ./build.sh install  # Build and install to device

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AAR_OUTPUT="$SCRIPT_DIR/app/libs/witnessd.aar"

echo "=== Witnessd Android Build ==="
echo ""

# Check prerequisites
check_prereqs() {
    if ! command -v go &> /dev/null; then
        echo "Error: Go is not installed"
        exit 1
    fi

    if ! command -v gomobile &> /dev/null; then
        echo "Error: gomobile is not installed"
        echo "Install with: go install golang.org/x/mobile/cmd/gomobile@latest"
        exit 1
    fi

    if [ -z "$ANDROID_HOME" ]; then
        echo "Warning: ANDROID_HOME not set"
        # Try common locations
        if [ -d "$HOME/Android/Sdk" ]; then
            export ANDROID_HOME="$HOME/Android/Sdk"
        elif [ -d "$HOME/Library/Android/sdk" ]; then
            export ANDROID_HOME="$HOME/Library/Android/sdk"
        else
            echo "Error: Could not find Android SDK"
            exit 1
        fi
    fi
    echo "Using Android SDK: $ANDROID_HOME"
}

# Build Go library as AAR
build_aar() {
    echo ""
    echo "Building Go library as AAR..."
    mkdir -p "$(dirname "$AAR_OUTPUT")"

    cd "$PROJECT_ROOT"
    gomobile bind -target=android -androidapi 24 -o "$AAR_OUTPUT" ./internal/ime

    echo "AAR created: $AAR_OUTPUT"
}

# Build APK
build_apk() {
    local BUILD_TYPE="${1:-debug}"

    echo ""
    echo "Building $BUILD_TYPE APK..."

    cd "$SCRIPT_DIR"

    if [ -f "./gradlew" ]; then
        ./gradlew "assemble${BUILD_TYPE^}"
    else
        gradle "assemble${BUILD_TYPE^}"
    fi

    APK_PATH="$SCRIPT_DIR/app/build/outputs/apk/$BUILD_TYPE/app-$BUILD_TYPE.apk"
    if [ -f "$APK_PATH" ]; then
        echo "APK created: $APK_PATH"
    fi
}

# Install to device
install_apk() {
    echo ""
    echo "Installing to connected device..."

    cd "$SCRIPT_DIR"

    if [ -f "./gradlew" ]; then
        ./gradlew installDebug
    else
        gradle installDebug
    fi

    echo ""
    echo "Installation complete."
    echo "Enable Witnessd in Settings > System > Languages & input > On-screen keyboard"
}

# Main
check_prereqs

case "${1:-}" in
    release)
        build_aar
        build_apk release
        ;;
    install)
        build_aar
        build_apk debug
        install_apk
        ;;
    aar)
        build_aar
        ;;
    apk)
        build_apk debug
        ;;
    clean)
        echo "Cleaning..."
        rm -f "$AAR_OUTPUT"
        cd "$SCRIPT_DIR" && (./gradlew clean 2>/dev/null || gradle clean 2>/dev/null || true)
        echo "Clean complete."
        ;;
    *)
        build_aar
        build_apk debug
        ;;
esac

echo ""
echo "Done."
