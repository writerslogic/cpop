# Windows Store Visual Asset Requirements

This document specifies all visual assets required for Microsoft Store submission.

## Required Assets

### Square44x44Logo (App Icon)
The primary application icon used in taskbar, Start menu, and app lists.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 44x44 | Square44x44Logo.scale-100.png |
| scale-125 | 55x55 | Square44x44Logo.scale-125.png |
| scale-150 | 66x66 | Square44x44Logo.scale-150.png |
| scale-200 | 88x88 | Square44x44Logo.scale-200.png |
| scale-400 | 176x176 | Square44x44Logo.scale-400.png |
| targetsize-16 | 16x16 | Square44x44Logo.targetsize-16.png |
| targetsize-24 | 24x24 | Square44x44Logo.targetsize-24.png |
| targetsize-32 | 32x32 | Square44x44Logo.targetsize-32.png |
| targetsize-48 | 48x48 | Square44x44Logo.targetsize-48.png |
| targetsize-256 | 256x256 | Square44x44Logo.targetsize-256.png |
| altform-unplated_targetsize-16 | 16x16 | Square44x44Logo.altform-unplated_targetsize-16.png |
| altform-unplated_targetsize-32 | 32x32 | Square44x44Logo.altform-unplated_targetsize-32.png |
| altform-unplated_targetsize-48 | 48x48 | Square44x44Logo.altform-unplated_targetsize-48.png |
| altform-unplated_targetsize-256 | 256x256 | Square44x44Logo.altform-unplated_targetsize-256.png |

### Square71x71Logo (Small Tile)
Small Start menu tile.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 71x71 | Square71x71Logo.scale-100.png |
| scale-125 | 89x89 | Square71x71Logo.scale-125.png |
| scale-150 | 107x107 | Square71x71Logo.scale-150.png |
| scale-200 | 142x142 | Square71x71Logo.scale-200.png |
| scale-400 | 284x284 | Square71x71Logo.scale-400.png |

### Square150x150Logo (Medium Tile)
Medium Start menu tile.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 150x150 | Square150x150Logo.scale-100.png |
| scale-125 | 188x188 | Square150x150Logo.scale-125.png |
| scale-150 | 225x225 | Square150x150Logo.scale-150.png |
| scale-200 | 300x300 | Square150x150Logo.scale-200.png |
| scale-400 | 600x600 | Square150x150Logo.scale-400.png |

### Wide310x150Logo (Wide Tile)
Wide Start menu tile.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 310x150 | Wide310x150Logo.scale-100.png |
| scale-125 | 388x188 | Wide310x150Logo.scale-125.png |
| scale-150 | 465x225 | Wide310x150Logo.scale-150.png |
| scale-200 | 620x300 | Wide310x150Logo.scale-200.png |
| scale-400 | 1240x600 | Wide310x150Logo.scale-400.png |

### Square310x310Logo (Large Tile)
Large Start menu tile.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 310x310 | Square310x310Logo.scale-100.png |
| scale-125 | 388x388 | Square310x310Logo.scale-125.png |
| scale-150 | 465x465 | Square310x310Logo.scale-150.png |
| scale-200 | 620x620 | Square310x310Logo.scale-200.png |
| scale-400 | 1240x1240 | Square310x310Logo.scale-400.png |

### StoreLogo
Icon displayed in Microsoft Store.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 50x50 | StoreLogo.scale-100.png |
| scale-125 | 63x63 | StoreLogo.scale-125.png |
| scale-150 | 75x75 | StoreLogo.scale-150.png |
| scale-200 | 100x100 | StoreLogo.scale-200.png |
| scale-400 | 200x200 | StoreLogo.scale-400.png |

### SplashScreen
Shown during app launch.

| Variant | Size | Filename |
|---------|------|----------|
| scale-100 | 620x300 | SplashScreen.scale-100.png |
| scale-125 | 775x375 | SplashScreen.scale-125.png |
| scale-150 | 930x450 | SplashScreen.scale-150.png |
| scale-200 | 1240x600 | SplashScreen.scale-200.png |
| scale-400 | 2480x1200 | SplashScreen.scale-400.png |

## Store Listing Assets (Required for Submission)

These are submitted through Partner Center, not included in the MSIX:

### Screenshots (Required)
- **Minimum**: 1 screenshot
- **Recommended**: 4-10 screenshots
- **Sizes**: 1366x768, 1920x1080, or 2560x1440 (16:9 ratio)
- **Format**: PNG or JPG

### Promotional Images (Optional but Recommended)

| Type | Size | Purpose |
|------|------|---------|
| Hero Image | 1920x1080 | Store feature banner |
| Promotional Poster | 1080x1080 | Square promotional |
| Small Tile | 358x358 | Store tile |
| Trailer | 1920x1080 (video) | App demo video |

## Design Guidelines

### Brand Colors
- **Primary Background**: #1a1a2e (dark navy)
- **Accent**: #e94560 (coral red)
- **Secondary**: #16213e (darker blue)
- **Text**: #ffffff (white)

### Icon Design
- Use simple, recognizable iconography
- Ensure legibility at small sizes (16x16)
- Include transparency where appropriate
- Test on both light and dark backgrounds

### Tile Content
- Square tiles: Icon only, centered
- Wide tile: Icon + app name
- Large tile: Icon + app name + tagline

### Splash Screen
- Center the logo
- Use brand background color
- Keep text minimal
- Ensure fast loading perception

## Generating Assets

### Using the Script
```powershell
# Generate placeholder assets
.\generate-assets.ps1

# Generate from SVG source
.\generate-assets.ps1 -SourceSvg .\witnessd-icon.svg

# Generate from PNG source (high-res master)
.\generate-assets.ps1 -SourcePng .\witnessd-icon-1024.png

# Specify output directory
.\generate-assets.ps1 -SourceSvg .\icon.svg -OutputDir .\output
```

### Manual Creation
For production assets, we recommend:
1. Create master artwork at 1024x1024 minimum
2. Use vector (SVG) format for scaling
3. Export each size individually for quality
4. Test on multiple DPI displays
5. Verify on light and dark Windows themes

## Validation

Before submission, validate assets using:
```powershell
# Run Windows App Cert Kit
.\scripts\validate-msix.ps1

# Manual checks:
# - All required sizes present
# - Correct color depth (32-bit ARGB)
# - No compression artifacts at small sizes
# - Proper transparency handling
```

## Resources

- [Microsoft Store tile and icon assets](https://docs.microsoft.com/en-us/windows/apps/design/style/app-icons-and-logos)
- [MSIX packaging visual assets](https://docs.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-manual-conversion)
- [Windows asset generator tools](https://docs.microsoft.com/en-us/windows/apps/design/style/iconography/app-icon-construction)
