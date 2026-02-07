#!/bin/bash
# Build the Go static library for WitnessdIME
# This script is called by Xcode as a Run Script build phase

set -e

# Navigate to the witnessd root (4 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WITNESSD_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
IME_GO_DIR="$WITNESSD_ROOT/cmd/witnessd-ime"

# Output directory (passed by Xcode or use default)
OUTPUT_DIR="${BUILT_PRODUCTS_DIR:-$SCRIPT_DIR/../build}"
mkdir -p "$OUTPUT_DIR"

# Architecture handling for Universal Binary
if [ -n "$ARCHS" ]; then
    # Called from Xcode with specific architectures
    ARCH_FLAGS=""
    for ARCH in $ARCHS; do
        case $ARCH in
            arm64)
                GOARCH="arm64"
                ;;
            x86_64)
                GOARCH="amd64"
                ;;
            *)
                echo "Unknown architecture: $ARCH"
                exit 1
                ;;
        esac

        echo "Building Go library for $ARCH ($GOARCH)..."

        ARCH_OUTPUT="$OUTPUT_DIR/libwitnessd_$ARCH.a"

        cd "$IME_GO_DIR"
        CGO_ENABLED=1 GOOS=darwin GOARCH=$GOARCH \
            go build -buildmode=c-archive \
            -o "$ARCH_OUTPUT" \
            ./

        ARCH_FLAGS="$ARCH_FLAGS $ARCH_OUTPUT"
    done

    # Create universal binary if multiple architectures
    if [ $(echo $ARCHS | wc -w) -gt 1 ]; then
        echo "Creating universal binary..."
        lipo -create $ARCH_FLAGS -output "$OUTPUT_DIR/libwitnessd.a"
    else
        cp $ARCH_OUTPUT "$OUTPUT_DIR/libwitnessd.a"
    fi
else
    # Called standalone - build for current architecture
    echo "Building Go library for current architecture..."

    cd "$IME_GO_DIR"
    CGO_ENABLED=1 go build -buildmode=c-archive \
        -o "$OUTPUT_DIR/libwitnessd.a" \
        ./
fi

# Copy header to output directory
cp "$IME_GO_DIR/build/libwitnessd.h" "$OUTPUT_DIR/" 2>/dev/null || \
    cp "$OUTPUT_DIR/libwitnessd.h" "$OUTPUT_DIR/libwitnessd.h" 2>/dev/null || true

echo "Go library built successfully: $OUTPUT_DIR/libwitnessd.a"
