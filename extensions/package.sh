#!/bin/bash
# Package CPoE browser extensions for store submission
#
# Builds three zip packages from the shared source in
# apps/cpoe_cli/browser-extension/:
#   - extensions/dist/writerslogic-chrome.zip   (Chrome Web Store)
#   - extensions/dist/writerslogic-firefox.zip  (Firefox Add-ons / AMO)
#   - extensions/dist/writerslogic-edge.zip     (Edge Add-ons)
#
# Usage: ./extensions/package.sh [--version X.Y.Z]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${REPO_ROOT}/apps/cpoe_cli/browser-extension"
DIST="${REPO_ROOT}/extensions/dist"
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Validate version format if provided
if [ -n "${VERSION}" ] && ! echo "${VERSION}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Error: Version must be semver (e.g., 1.0.0), got: ${VERSION}"
  exit 1
fi

copy_shared() {
  local dest="$1"
  for f in "${SRC}"/*.{js,html,css}; do
    [ -f "$f" ] && cp "$f" "${dest}/$(basename "$f")"
  done
  cp -r "${SRC}/icons" "${dest}/icons"
}

patch_version() {
  local manifest="$1"
  if [ -n "${VERSION}" ]; then
    sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION}\"/" "${manifest}"
    rm -f "${manifest}.bak"
  fi
}

# Package a single browser extension.
# Usage: package_browser <name> <manifest_source>
package_browser() {
  local name="$1"
  local manifest_src="$2"
  local dir="${DIST}/${name}"

  echo "Packaging ${name} extension..."
  mkdir -p "${dir}"
  copy_shared "${dir}"
  cp "${manifest_src}" "${dir}/manifest.json"
  patch_version "${dir}/manifest.json"
  (cd "${dir}" && zip -r -q "${DIST}/cpoe-${name}.zip" .)
  echo "  -> cpoe-${name}.zip"
}

# Clean previous builds
rm -rf "${DIST}"
mkdir -p "${DIST}"

echo "=== Packaging CPoE Browser Extensions ==="
echo "Source: ${SRC}"
echo "Output: ${DIST}"
if [ -n "${VERSION}" ]; then
  echo "Version override: ${VERSION}"
fi
echo ""

package_browser "chrome"  "${SRC}/manifest.json"
package_browser "firefox" "${SRC}/manifest-firefox.json"
package_browser "edge"    "${SRC}/manifest.json"

echo ""
echo "Done. Packages ready in ${DIST}/"
echo ""
echo "  writerslogic-chrome.zip   -> Chrome Web Store"
echo "  writerslogic-firefox.zip  -> Firefox Add-ons (addons.mozilla.org)"
echo "  writerslogic-edge.zip     -> Edge Add-ons (partner.microsoft.com)"
echo ""
echo "See extensions/README.md for publishing instructions."
