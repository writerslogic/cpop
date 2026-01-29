#!/bin/bash
# Build script for Witnessd iOS Keyboard Extension
#
# Prerequisites:
# - macOS with Xcode installed
# - Go with gomobile: go install golang.org/x/mobile/cmd/gomobile@latest
# - Valid iOS development signing identity
#
# Usage:
#   ./build.sh              # Build for simulator
#   ./build.sh device       # Build for device
#   ./build.sh archive      # Create archive for distribution

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FRAMEWORK_OUTPUT="$SCRIPT_DIR/Witnessd.xcframework"
XCODE_PROJECT="$SCRIPT_DIR/Witnessd.xcodeproj"

echo "=== Witnessd iOS Build ==="
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

    if ! command -v xcodebuild &> /dev/null; then
        echo "Error: Xcode is not installed"
        exit 1
    fi

    echo "Xcode version: $(xcodebuild -version | head -1)"
}

# Build Go library as xcframework
build_framework() {
    echo ""
    echo "Building Go library as xcframework..."

    cd "$PROJECT_ROOT"

    # Initialize gomobile if needed
    gomobile init 2>/dev/null || true

    # Build xcframework
    gomobile bind -target=ios -o "$FRAMEWORK_OUTPUT" ./internal/ime

    echo "Framework created: $FRAMEWORK_OUTPUT"
}

# Generate Xcode project if it doesn't exist
generate_project() {
    if [ ! -d "$XCODE_PROJECT" ]; then
        echo ""
        echo "Generating Xcode project..."

        mkdir -p "$XCODE_PROJECT/project.xcworkspace"

        # Create project.pbxproj
        cat > "$XCODE_PROJECT/project.pbxproj" << 'PBXPROJ'
// !$*UTF8*$!
{
    archiveVersion = 1;
    classes = { };
    objectVersion = 55;
    rootObject = 00000000000000000000000000000001;
    objects = {
        00000000000000000000000000000001 = {
            isa = PBXProject;
            buildConfigurationList = 00000000000000000000000000000002;
            compatibilityVersion = "Xcode 13.0";
            developmentRegion = en;
            hasScannedForEncodings = 0;
            knownRegions = (en, Base);
            mainGroup = 00000000000000000000000000000003;
            productRefGroup = 00000000000000000000000000000004;
            projectDirPath = "";
            projectRoot = "";
            targets = (00000000000000000000000000000010);
        };
    };
}
PBXPROJ

        echo "Note: Xcode project generated. Open in Xcode to complete configuration."
    fi
}

# Build for simulator
build_simulator() {
    echo ""
    echo "Building for iOS Simulator..."

    if [ ! -d "$XCODE_PROJECT" ]; then
        echo "Error: Xcode project not found. Run './build.sh setup' first."
        exit 1
    fi

    xcodebuild \
        -project "$XCODE_PROJECT" \
        -scheme "WitnessdKeyboard" \
        -sdk iphonesimulator \
        -configuration Debug \
        build

    echo "Simulator build complete."
}

# Build for device
build_device() {
    echo ""
    echo "Building for iOS Device..."

    if [ ! -d "$XCODE_PROJECT" ]; then
        echo "Error: Xcode project not found. Run './build.sh setup' first."
        exit 1
    fi

    xcodebuild \
        -project "$XCODE_PROJECT" \
        -scheme "WitnessdKeyboard" \
        -sdk iphoneos \
        -configuration Release \
        build

    echo "Device build complete."
}

# Create archive for App Store
build_archive() {
    echo ""
    echo "Creating archive..."

    ARCHIVE_PATH="$SCRIPT_DIR/build/Witnessd.xcarchive"

    xcodebuild \
        -project "$XCODE_PROJECT" \
        -scheme "WitnessdKeyboard" \
        -sdk iphoneos \
        -configuration Release \
        -archivePath "$ARCHIVE_PATH" \
        archive

    echo "Archive created: $ARCHIVE_PATH"
}

# Print setup instructions
print_setup() {
    echo ""
    echo "=== iOS Keyboard Extension Setup ==="
    echo ""
    echo "1. Open Xcode and create a new project:"
    echo "   - File > New > Project"
    echo "   - Choose 'App' template"
    echo "   - Name it 'Witnessd'"
    echo ""
    echo "2. Add a Keyboard Extension target:"
    echo "   - File > New > Target"
    echo "   - Choose 'Custom Keyboard Extension'"
    echo "   - Name it 'WitnessdKeyboard'"
    echo ""
    echo "3. Add the Witnessd.xcframework:"
    echo "   - Drag $FRAMEWORK_OUTPUT into the project"
    echo "   - Add to both the app and keyboard extension targets"
    echo ""
    echo "4. Replace the generated KeyboardViewController.swift:"
    echo "   - Copy content from $SCRIPT_DIR/WitnessdKeyboard/KeyboardViewController.swift"
    echo ""
    echo "5. Configure signing:"
    echo "   - Select your development team in project settings"
    echo "   - Enable 'Keyboard' capability for the extension"
    echo ""
    echo "6. Build and run on a device or simulator"
    echo ""
}

# Main
check_prereqs

case "${1:-}" in
    setup)
        build_framework
        print_setup
        ;;
    device)
        build_framework
        build_device
        ;;
    archive)
        build_framework
        build_archive
        ;;
    framework)
        build_framework
        ;;
    clean)
        echo "Cleaning..."
        rm -rf "$FRAMEWORK_OUTPUT"
        rm -rf "$SCRIPT_DIR/build"
        echo "Clean complete."
        ;;
    help)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  setup      Build framework and print Xcode setup instructions"
        echo "  device     Build for iOS device"
        echo "  archive    Create archive for App Store"
        echo "  framework  Build xcframework only"
        echo "  clean      Remove build artifacts"
        echo "  help       Show this help"
        ;;
    *)
        build_framework
        print_setup
        ;;
esac

echo ""
echo "Done."
