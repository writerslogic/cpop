#!/bin/bash
# Generate placeholder extension icons using ImageMagick
# Replace these with proper branded icons before release

for size in 16 32 48 128; do
  convert -size ${size}x${size} xc:'#1a1a2e' \
    -fill '#4fc3f7' -draw "roundrectangle 1,1 $((size-2)),$((size-2)) $((size/8)),$((size/8))" \
    -fill '#e0e0e0' -gravity center -pointsize $((size/2)) -annotate 0 'W' \
    "icon-${size}.png" 2>/dev/null || \
  # Fallback: create simple 1x1 pixel PNG if ImageMagick isn't available
  printf '\x89PNG\r\n\x1a\n' > "icon-${size}.png"
done

echo "Icons generated (or placeholders created)"
