#!/bin/bash
# Build AppImage for witnessd
# Usage: ./build-appimage.sh [version] [arch]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/appimage"
VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "1.0.0")}"
ARCH="${2:-x86_64}"

echo "=== Building AppImage for witnessd v${VERSION} (${ARCH}) ==="

# Check dependencies
for cmd in go git; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "Error: ${cmd} is required but not installed."
        exit 1
    fi
done

# Clean and create build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Download linuxdeploy if not present
LINUXDEPLOY="${BUILD_DIR}/linuxdeploy-${ARCH}.AppImage"
if [[ ! -f "${LINUXDEPLOY}" ]]; then
    echo "Downloading linuxdeploy..."
    curl -L -o "${LINUXDEPLOY}" \
        "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${ARCH}.AppImage"
    chmod +x "${LINUXDEPLOY}"
fi

# Create AppDir structure
APPDIR="${BUILD_DIR}/AppDir"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${APPDIR}/usr/share/metainfo"
mkdir -p "${APPDIR}/usr/share/man/man1"
mkdir -p "${APPDIR}/usr/share/doc/witnessd"

# Build binaries
echo "Building binaries..."
cd "${PROJECT_ROOT}"

COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# Set GOARCH based on target
case "${ARCH}" in
    x86_64)
        GOARCH="amd64"
        ;;
    aarch64|arm64)
        GOARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

export CGO_ENABLED=0
export GOOS=linux
export GOARCH="${GOARCH}"

go build -trimpath -ldflags="${LDFLAGS}" -o "${APPDIR}/usr/bin/witnessd" ./cmd/witnessd
go build -trimpath -ldflags="${LDFLAGS}" -o "${APPDIR}/usr/bin/witnessctl" ./cmd/witnessctl
go build -trimpath -ldflags="${LDFLAGS}" -o "${APPDIR}/usr/bin/witnessd-ibus" ./cmd/witnessd-ibus

# Copy resources
echo "Copying resources..."

# Desktop file
cp "${PROJECT_ROOT}/platforms/linux/appimage/witnessd.desktop" "${APPDIR}/usr/share/applications/"
cp "${PROJECT_ROOT}/platforms/linux/appimage/witnessd.desktop" "${APPDIR}/"

# AppData/MetaInfo
cp "${PROJECT_ROOT}/platforms/linux/appimage/witnessd.appdata.xml" "${APPDIR}/usr/share/metainfo/"

# Icons
cp "${PROJECT_ROOT}/platforms/linux/appimage/icons/witnessd.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/"

# Convert SVG to PNG for icon (if ImageMagick is available)
if command -v convert &>/dev/null; then
    convert -background none -resize 256x256 \
        "${PROJECT_ROOT}/platforms/linux/appimage/icons/witnessd.svg" \
        "${APPDIR}/usr/share/icons/hicolor/256x256/apps/witnessd.png"
else
    echo "Warning: ImageMagick not found, skipping PNG icon generation"
fi

# Copy main icon for AppImage
cp "${PROJECT_ROOT}/platforms/linux/appimage/icons/witnessd.svg" "${APPDIR}/witnessd.svg"

# Man pages
if [[ -d "${PROJECT_ROOT}/docs/man" ]]; then
    cp "${PROJECT_ROOT}/docs/man/"*.1 "${APPDIR}/usr/share/man/man1/" 2>/dev/null || true
fi

# Documentation
cp "${PROJECT_ROOT}/LICENSE" "${APPDIR}/usr/share/doc/witnessd/"
cp "${PROJECT_ROOT}/README.md" "${APPDIR}/usr/share/doc/witnessd/"

# AppRun script
cp "${PROJECT_ROOT}/platforms/linux/appimage/AppRun" "${APPDIR}/"
chmod +x "${APPDIR}/AppRun"

# Create the AppImage
echo "Creating AppImage..."
cd "${BUILD_DIR}"

export OUTPUT="witnessd-${VERSION}-${ARCH}.AppImage"
export VERSION="${VERSION}"

"${LINUXDEPLOY}" --appdir "${APPDIR}" --output appimage

# Move to final location
mkdir -p "${PROJECT_ROOT}/build"
mv "${OUTPUT}" "${PROJECT_ROOT}/build/"

# Create update information file (for AppImageUpdate)
echo "gh-releases-zsync|writerslogic|witnessd|latest|witnessd-*${ARCH}.AppImage.zsync" \
    > "${PROJECT_ROOT}/build/${OUTPUT%.AppImage}.zsync"

echo ""
echo "=== Build complete ==="
echo "AppImage created: ${PROJECT_ROOT}/build/${OUTPUT}"
ls -la "${PROJECT_ROOT}/build/"*AppImage* 2>/dev/null || echo "No AppImage files found"
