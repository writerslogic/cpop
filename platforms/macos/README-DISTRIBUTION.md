# Witnessd macOS Distribution Guide

This document describes the complete process for building, signing, notarizing, and distributing Witnessd for macOS as a DMG installer.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Build Scripts](#build-scripts)
4. [Quick Start](#quick-start)
5. [Detailed Build Process](#detailed-build-process)
6. [Code Signing](#code-signing)
7. [Notarization](#notarization)
8. [DMG Creation](#dmg-creation)
9. [CI/CD Integration](#cicd-integration)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)

## Overview

The Witnessd macOS distribution pipeline consists of:

1. **Go CLI Binary** - Universal binary (arm64 + x86_64) embedded in the app
2. **SwiftUI Application** - Native macOS menu bar app
3. **Code Signing** - Developer ID signing for distribution outside App Store
4. **Notarization** - Apple's verification service for Gatekeeper
5. **DMG Packaging** - Professional installer with background image

### Distribution Method

Witnessd is distributed as a **Developer ID** signed application (outside the Mac App Store). This allows:
- Direct download from website/GitHub
- No App Store review process
- Full system access capabilities
- Hardened runtime with specific entitlements

## Prerequisites

### Required Software

```bash
# Xcode Command Line Tools
xcode-select --install

# Go 1.21+
brew install go

# For DMG background image generation
brew install librsvg

# Optional: create-dmg tool for enhanced DMG creation
brew install create-dmg
```

### Required Credentials

You need an Apple Developer account ($99/year) with the following:

| Credential | Description | Where to Get |
|------------|-------------|--------------|
| Developer ID Application Certificate | Code signing identity | Apple Developer Portal > Certificates |
| Developer ID Installer Certificate | For pkg signing (optional) | Apple Developer Portal > Certificates |
| App Store Connect API Key | Notarization authentication | App Store Connect > Users > API Keys |
| Team ID | Your 10-character team identifier | Apple Developer Portal > Membership |

### Setting Up Code Signing

1. **Create Certificate** in Apple Developer Portal:
   - Go to Certificates, Identifiers & Profiles
   - Create new certificate: "Developer ID Application"
   - Download and install in Keychain

2. **Export Certificate** for CI/CD:
   ```bash
   # Export from Keychain as .p12 file
   security export -k login.keychain -t identities -f pkcs12 -o certificate.p12 -P "your-password"

   # Convert to base64 for GitHub secrets
   base64 -i certificate.p12 | pbcopy
   ```

3. **Create App Store Connect API Key**:
   - Go to App Store Connect > Users and Access > Keys
   - Create new key with "Developer" role
   - Download the .p8 file (only available once!)
   - Note the Key ID and Issuer ID

### Environment Variables

```bash
# Code Signing
export SIGNING_IDENTITY="Developer ID Application: Your Name (TEAM_ID)"
export APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAM_ID)"

# Notarization (API Key method - recommended)
export APPLE_KEY_ID="XXXXXXXXXX"           # 10-character Key ID
export APPLE_ISSUER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # UUID
export APPLE_PRIVATE_KEY_PATH="/path/to/AuthKey_XXXXXXXXXX.p8"

# Or use keychain profile (local development)
export NOTARYTOOL_PROFILE="notarytool"
```

## Build Scripts

All build scripts are located in `platforms/macos/WitnessdApp/scripts/`:

| Script | Purpose |
|--------|---------|
| `build-app.sh` | Build witnessd CLI as universal binary |
| `build-swiftui.sh` | Build SwiftUI app via xcodebuild |
| `codesign.sh` | Code sign app with Developer ID |
| `notarize.sh` | Submit to Apple notarization |
| `create-dmg.sh` | Create DMG installer |

## Quick Start

### Development Build (Unsigned)

```bash
# From repository root
make dmg-dev
```

This creates an unsigned DMG for local testing.

### Release Build (Signed + Notarized)

```bash
# Ensure signing credentials are configured
make dmg-release
```

### Using Scripts Directly

```bash
cd platforms/macos/WitnessdApp/scripts

# 1. Build CLI binary
./build-app.sh --universal

# 2. Build SwiftUI app
./build-swiftui.sh build

# 3. Sign the app
./codesign.sh sign

# 4. Notarize
./notarize.sh notarize

# 5. Create DMG
./create-dmg.sh release
```

## Detailed Build Process

### 1. Build Go CLI Binary

```bash
./build-app.sh [OPTIONS]

Options:
  --universal    Build universal binary (arm64 + amd64) [default]
  --arm64        Build arm64 only
  --amd64        Build x86_64 only
  --native       Build for current architecture
  --clean        Remove existing binaries first
  --verify       Verify existing binary

Environment:
  VERSION        Override version string
  COMMIT         Override commit hash
```

The binary is placed in `witnessd/Resources/witnessd`.

### 2. Build SwiftUI App

```bash
./build-swiftui.sh [COMMAND] [OPTIONS]

Commands:
  build          Build unsigned app [default]
  build-signed   Build with code signing
  archive        Create Xcode archive
  clean          Clean build artifacts
  verify         Verify built app

Options:
  --configuration   Debug or Release [default: Release]
  --identity        Code signing identity
```

Output: `build/DerivedData/Build/Products/Release/Witnessd.app`

### 3. Code Sign

```bash
./codesign.sh [COMMAND] [OPTIONS]

Commands:
  sign [APP_PATH]   Sign the app [default]
  verify [APP_PATH] Verify signature
  identities        List signing identities

Options:
  --identity        Signing identity
  --entitlements    Custom entitlements file
```

Signing order:
1. Frameworks (if any)
2. Plugins (if any)
3. Helper binaries
4. Embedded CLI (`witnessd`)
5. Main app bundle

### 4. Notarize

```bash
./notarize.sh [COMMAND] [OPTIONS]

Commands:
  notarize [APP_PATH]   Notarize app [default]
  notarize-dmg [DMG]    Notarize DMG file
  staple [APP_PATH]     Staple ticket
  verify [APP_PATH]     Verify notarization
  setup-profile         Create keychain profile
  history               Show notarization history

Authentication (choose one):
  1. Keychain Profile (local development):
     NOTARYTOOL_PROFILE=profilename

  2. API Key (CI/CD):
     APPLE_KEY_ID + APPLE_ISSUER_ID + APPLE_PRIVATE_KEY_PATH
```

#### Setting Up Keychain Profile (Recommended for Local Development)

```bash
./notarize.sh setup-profile

# Follow prompts to enter:
# - Team ID
# - API Key ID
# - API Issuer ID
# - Path to .p8 private key
```

### 5. Create DMG

```bash
./create-dmg.sh [COMMAND] [OPTIONS]

Commands:
  create [APP_PATH]   Create DMG [default]
  dev [APP_PATH]      Unsigned DMG for testing
  release [APP_PATH]  Signed + notarized DMG
  verify [DMG_PATH]   Verify existing DMG
  clean               Remove artifacts

Options:
  --version           Version string
  --output            Output path
  --no-sign           Skip signing
  --no-notarize       Skip notarization
```

## Code Signing

### Signing Identity

The signing identity must be a "Developer ID Application" certificate:

```
Developer ID Application: Your Name (TEAM_ID)
```

List available identities:
```bash
security find-identity -v -p codesigning
```

### Entitlements

The app uses hardened runtime with these entitlements:

| Entitlement | Purpose |
|-------------|---------|
| `com.apple.security.app-sandbox` | App sandboxing |
| `com.apple.security.files.user-selected.read-write` | File access via dialogs |
| `com.apple.security.files.bookmarks.app-scope` | Persistent file access |
| `com.apple.security.network.client` | Network for anchoring |
| `com.apple.security.automation.apple-events` | AppleScript support |

See `scripts/witnessd-hardened.entitlements` for full list.

### Verification

```bash
# Verify signature
codesign --verify --deep --strict --verbose=2 Witnessd.app

# Gatekeeper assessment
spctl --assess --type execute --verbose=2 Witnessd.app

# Show signature details
codesign -dv --verbose=4 Witnessd.app
```

## Notarization

### Process Overview

1. Create ZIP of signed app
2. Submit to Apple's notary service
3. Wait for processing (typically 2-15 minutes)
4. Staple the notarization ticket to the app
5. Verify stapling

### Notarization Logs

Logs are saved to `build/notarization-log-{submission-id}.json`.

View issues:
```bash
jq '.issues[]' build/notarization-log-*.json
```

### Common Notarization Issues

| Issue | Solution |
|-------|----------|
| Invalid signature | Re-sign with hardened runtime |
| Missing entitlements | Add required entitlements |
| Unsigned binaries | Sign all binaries in bundle |
| Network timeout | Retry submission |

## DMG Creation

### DMG Features

- Custom background image (1x and 2x for Retina)
- Positioned icons (App and Applications folder)
- Application symlink for drag-and-drop install
- Optional license agreement (EULA)
- Code signature on DMG itself
- SHA256 checksum generation

### Customizing Background

Edit the SVG template in `create-dmg.sh` or place custom images:

```
dmg-resources/
  background.png      # 660x400 pixels
  background@2x.png   # 1320x800 pixels
  license.txt         # Optional EULA
```

### DMG Window Layout

```
+------------------------------------------+
|              Witnessd                     |
|      Kinetic Proof of Provenance         |
|                                          |
|    [Witnessd.app]  -->  [Applications]   |
|                                          |
|      Drag to Applications to install     |
+------------------------------------------+
```

## CI/CD Integration

### GitHub Actions Secrets

Configure these secrets in your repository:

| Secret | Description |
|--------|-------------|
| `APPLE_CERTIFICATE` | Base64-encoded .p12 certificate |
| `APPLE_CERTIFICATE_PASSWORD` | Certificate password |
| `KEYCHAIN_PASSWORD` | Temporary keychain password |
| `APPLE_DEVELOPER_ID` | Full signing identity string |
| `APPLE_KEY_ID` | App Store Connect API Key ID |
| `APPLE_ISSUER_ID` | App Store Connect Issuer ID |
| `APPLE_PRIVATE_KEY` | Contents of .p8 private key file |

### Workflow Trigger

The workflow triggers on:
- Push to tags matching `v*`
- Manual workflow dispatch

```yaml
# .github/workflows/macos-dmg.yml
on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to build'
        required: false
```

### Manual Release

```bash
# Create and push tag
git tag v1.0.0
git push origin v1.0.0
```

Or trigger manually via GitHub Actions UI.

## Troubleshooting

### Build Errors

**"Go not found"**
```bash
brew install go
# Or ensure go is in PATH
export PATH=$PATH:/usr/local/go/bin
```

**"xcodebuild failed"**
```bash
# Accept Xcode license
sudo xcodebuild -license accept

# Ensure correct Xcode is selected
sudo xcode-select -s /Applications/Xcode.app
```

### Signing Errors

**"No signing identity found"**
```bash
# List identities
security find-identity -v -p codesigning

# Check certificate is valid
security find-certificate -a -c "Developer ID"
```

**"Resource fork, Finder information, or similar detritus"**
```bash
# Remove extended attributes
xattr -cr Witnessd.app
```

### Notarization Errors

**"Invalid signature"**
- Ensure hardened runtime is enabled
- Sign with timestamp: `--timestamp`
- Check entitlements are valid

**"The software is not signed"**
```bash
# Re-sign with options runtime
codesign --force --options runtime --timestamp --sign "IDENTITY" Witnessd.app
```

**"API authentication failed"**
```bash
# Verify API key
xcrun notarytool info --keychain-profile notarytool dummy-id
```

### DMG Errors

**"hdiutil: create failed"**
```bash
# Free up disk space
df -h

# Use smaller image
hdiutil create -size 100m ...
```

## Security Considerations

### Credential Storage

- Never commit credentials to git
- Use GitHub Secrets for CI/CD
- Rotate API keys periodically
- Use keychain for local development

### Hardened Runtime

Witnessd uses hardened runtime with minimal entitlements:
- No JIT compilation
- No unsigned memory execution
- No DYLD environment variables
- Library validation enabled

### Supply Chain Security

- All binaries are code signed
- Notarization provides malware scanning
- SHA256 checksums published with releases
- SLSA provenance generated in CI

## Makefile Targets

```bash
# Build unsigned app
make witnessd-app

# Build and sign
make witnessd-app-sign

# Build, sign, and notarize
make witnessd-app-notarize

# Create unsigned DMG (development)
make dmg-dev

# Create release DMG (signed + notarized)
make dmg-release

# Verify signatures
make verify-signature
make dmg-verify

# Clean build artifacts
make dmg-clean

# List signing identities
make list-signing-identities
```

## File Structure

```
platforms/macos/
├── WitnessdApp/
│   ├── witnessd/               # SwiftUI source
│   │   ├── Resources/
│   │   │   └── witnessd        # Embedded CLI binary
│   │   ├── witnessd.entitlements
│   │   └── *.swift
│   ├── witnessd.xcodeproj/
│   ├── scripts/
│   │   ├── build-app.sh
│   │   ├── build-swiftui.sh
│   │   ├── codesign.sh
│   │   ├── notarize.sh
│   │   ├── create-dmg.sh
│   │   ├── witnessd-hardened.entitlements
│   │   └── export-options.plist
│   ├── dmg-resources/          # Generated
│   │   ├── background.svg
│   │   ├── background.png
│   │   ├── background@2x.png
│   │   └── license.txt
│   └── build/                  # Build output
│       ├── DerivedData/
│       ├── Witnessd-1.0.dmg
│       └── Witnessd-1.0.sha256
└── README-DISTRIBUTION.md      # This file
```

## Support

For issues with the build system:
- Check existing GitHub issues
- Review build logs
- Consult Apple's developer documentation

For code signing issues:
- [Apple Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [Notarizing macOS Software](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
