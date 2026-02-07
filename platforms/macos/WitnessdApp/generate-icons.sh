#!/bin/bash
# Generate app icons for Witnessd from SVG source
# Requires: librsvg (brew install librsvg)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SVG_SOURCE="$SCRIPT_DIR/icon.svg"
ICONSET_DIR="$SCRIPT_DIR/witnessd/Assets.xcassets/AppIcon.appiconset"

if [ ! -f "$SVG_SOURCE" ]; then
    echo "Error: icon.svg not found at $SVG_SOURCE"
    exit 1
fi

if ! command -v rsvg-convert &> /dev/null; then
    echo "Error: rsvg-convert not found. Install with: brew install librsvg"
    exit 1
fi

echo "Generating app icons from $SVG_SOURCE"
echo "Output directory: $ICONSET_DIR"
echo ""

# macOS app icon sizes (size@scale = actual pixels)
# 16x16 @1x = 16px, @2x = 32px
# 32x32 @1x = 32px, @2x = 64px
# 128x128 @1x = 128px, @2x = 256px
# 256x256 @1x = 256px, @2x = 512px
# 512x512 @1x = 512px, @2x = 1024px

declare -a SIZES=(
    "16:1:icon_16x16.png"
    "32:2:icon_16x16@2x.png"
    "32:1:icon_32x32.png"
    "64:2:icon_32x32@2x.png"
    "128:1:icon_128x128.png"
    "256:2:icon_128x128@2x.png"
    "256:1:icon_256x256.png"
    "512:2:icon_256x256@2x.png"
    "512:1:icon_512x512.png"
    "1024:2:icon_512x512@2x.png"
)

for entry in "${SIZES[@]}"; do
    IFS=':' read -r pixels scale filename <<< "$entry"
    echo "  Generating $filename (${pixels}x${pixels}px)"
    rsvg-convert -w "$pixels" -h "$pixels" "$SVG_SOURCE" -o "$ICONSET_DIR/$filename"
done

echo ""
echo "Done! Generated $(ls -1 "$ICONSET_DIR"/*.png 2>/dev/null | wc -l | tr -d ' ') icon files."

# Update Contents.json to reference the new files
cat > "$ICONSET_DIR/Contents.json" << 'EOF'
{
  "images" : [
    {
      "filename" : "icon_16x16.png",
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "16x16"
    },
    {
      "filename" : "icon_16x16@2x.png",
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "16x16"
    },
    {
      "filename" : "icon_32x32.png",
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "32x32"
    },
    {
      "filename" : "icon_32x32@2x.png",
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "32x32"
    },
    {
      "filename" : "icon_128x128.png",
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "128x128"
    },
    {
      "filename" : "icon_128x128@2x.png",
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "128x128"
    },
    {
      "filename" : "icon_256x256.png",
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "256x256"
    },
    {
      "filename" : "icon_256x256@2x.png",
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "256x256"
    },
    {
      "filename" : "icon_512x512.png",
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "512x512"
    },
    {
      "filename" : "icon_512x512@2x.png",
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "512x512"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
EOF

echo "Updated Contents.json"
