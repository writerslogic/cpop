#!/bin/bash
# Generate app icons for Witness
# Requires: sf-symbols-plugin or manual creation in Xcode

# This script provides instructions for creating app icons
# The actual icon generation should be done in Xcode using SF Symbols

echo "App Icon Generation for Witness"
echo "================================"
echo ""
echo "To create the app icon:"
echo ""
echo "1. Open Xcode and select the Witness project"
echo "2. Navigate to Assets.xcassets > AppIcon"
echo "3. For each size slot, create an icon using:"
echo "   - SF Symbol: eye.circle.fill"
echo "   - Gradient: Blue (#007AFF) to Purple (#AF52DE)"
echo "   - Background: White or transparent"
echo ""
echo "Required sizes:"
echo "  - 16x16 @1x, @2x"
echo "  - 32x32 @1x, @2x"
echo "  - 128x128 @1x, @2x"
echo "  - 256x256 @1x, @2x"
echo "  - 512x512 @1x, @2x"
echo ""
echo "Alternatively, use an online tool like:"
echo "  - https://appicon.co (for generating all sizes from one image)"
echo "  - https://makeappicon.com"
echo ""
echo "Design guidelines:"
echo "  - Use the eye.circle.fill SF Symbol as the base"
echo "  - Apply a blue-to-purple gradient"
echo "  - Ensure good contrast on both light and dark backgrounds"
echo "  - The icon should be recognizable at 16x16 pixels"
