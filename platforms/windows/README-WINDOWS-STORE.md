# Witnessd - Microsoft Store Distribution Guide

This document provides complete instructions for building, packaging, and submitting Witnessd to the Microsoft Store.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Build Process](#build-process)
4. [MSIX Package Structure](#msix-package-structure)
5. [Code Signing](#code-signing)
6. [Store Submission](#store-submission)
7. [CI/CD Integration](#cicd-integration)
8. [Troubleshooting](#troubleshooting)

## Overview

Witnessd is distributed on Windows via MSIX packages, which provide:
- Modern Windows installation experience
- Automatic updates
- Clean uninstallation
- Sandboxed execution with declared capabilities
- Microsoft Store distribution

### Package Contents

The MSIX package includes:
- `witnessd.exe` - Main daemon/CLI application
- `witnessctl.exe` - Control utility
- `witnessd-tsf.dll` - Text Services Framework provider for keystroke timing
- Visual assets for Windows Start menu and taskbar

## Prerequisites

### Development Environment

1. **Windows 10/11** (version 1809 or later)
2. **Go 1.21+** ([download](https://golang.org/dl/))
3. **Windows SDK 10.0.19041+** ([download](https://developer.microsoft.com/windows/downloads/windows-sdk/))
4. **Visual Studio Build Tools** with C++ workload (for TSF DLL)

### For Store Submission

5. **Microsoft Partner Center account** ([register](https://partner.microsoft.com/dashboard))
6. **Code signing certificate** (EV certificate recommended for Store)

### Installation

```powershell
# Install Windows SDK via winget
winget install Microsoft.WindowsSDK

# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools
# Then add C++ workload via Visual Studio Installer

# Verify Go installation
go version
```

## Build Process

### Quick Start

```powershell
cd platforms/windows

# 1. Build binaries
.\scripts\build-binaries.ps1 -Architecture x64 -Version 1.0.0

# 2. Generate visual assets (or provide your own)
.\assets\generate-assets.ps1 -SourceSvg ..\icon.svg

# 3. Create MSIX package
.\scripts\create-msix.ps1 -Version 1.0.0.0

# 4. Validate package
.\scripts\validate-msix.ps1

# 5. Sign package (optional for testing, required for distribution)
.\scripts\sign-msix.ps1 -CertificatePath cert.pfx

# 6. Test installation
.\scripts\test-msix.ps1
```

### Building Binaries

```powershell
# Build for x64 only
.\scripts\build-binaries.ps1 -Architecture x64

# Build for ARM64
.\scripts\build-binaries.ps1 -Architecture arm64

# Build for both architectures
.\scripts\build-binaries.ps1 -Architecture both

# Release build with version
.\scripts\build-binaries.ps1 -Architecture both -Version 1.0.0 -Configuration Release
```

Output binaries are placed in `build/windows_x64/` and `build/windows_arm64/`.

### Building TSF DLL

The TSF DLL requires:
1. Visual Studio Build Tools with C++ workload
2. CGO enabled (requires GCC or MSVC)

```powershell
# The build script handles TSF automatically
.\scripts\build-binaries.ps1

# Skip TSF if you don't need keystroke timing
.\scripts\build-binaries.ps1 -SkipTSF
```

### Generating Visual Assets

```powershell
# Generate placeholder assets (for testing)
.\assets\generate-assets.ps1

# Generate from SVG source
.\assets\generate-assets.ps1 -SourceSvg .\icon.svg

# Generate from high-res PNG
.\assets\generate-assets.ps1 -SourcePng .\icon-1024.png
```

See `assets/ASSET-REQUIREMENTS.md` for complete specifications.

## MSIX Package Structure

### AppxManifest.xml

The manifest (`msix/AppxManifest.xml`) declares:

```xml
<!-- Package Identity -->
<Identity
  Name="WritersLogic.Witnessd"
  Publisher="CN=Writers Logic LLC, ..."
  Version="1.0.0.0"
  ProcessorArchitecture="x64" />

<!-- Applications -->
<Application Id="Witnessd" Executable="witnessd.exe" ...>
  <!-- Visual elements, extensions, etc. -->
</Application>

<!-- Capabilities (restricted) -->
<Capabilities>
  <rescap:Capability Name="broadFileSystemAccess" />
  <rescap:Capability Name="inputForegroundObservation" />
  <rescap:Capability Name="runFullTrust" />
</Capabilities>

<!-- TSF COM Registration -->
<com:Extension Category="windows.comServer">
  <com:ComServer>
    <com:SurrogateServer DisplayName="Witnessd TSF Provider">
      <com:Class Id="A1B2C3D4-E5F6-7890-ABCD-EF1234567890" .../>
    </com:SurrogateServer>
  </com:ComServer>
</com:Extension>
```

### Required Capabilities

| Capability | Purpose | Justification |
|------------|---------|---------------|
| `runFullTrust` | Desktop app functionality | Required for file system and system access |
| `broadFileSystemAccess` | Access any file | Users may have documents anywhere |
| `inputForegroundObservation` | Keystroke timing | Privacy-preserving biometrics |
| `inputObservation` | Background timing | For active tracking sessions |

### TSF Registration

The TSF provider is registered via the manifest (not regsvr32):

1. COM class registration via `com:Extension`
2. CLSID: `{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}`
3. Threading model: Apartment
4. Activation: On-demand by Windows TSF

## Code Signing

### For Testing (Self-Signed)

```powershell
# Create self-signed certificate
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=Witnessd Test" `
    -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears(1)

# Export to PFX
$password = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath test-cert.pfx -Password $password

# Sign package
.\scripts\sign-msix.ps1 -CertificatePath test-cert.pfx -Password $password
```

### For Production (EV Certificate)

1. Purchase an EV code signing certificate from:
   - DigiCert
   - Sectigo
   - GlobalSign

2. The certificate subject must match the manifest Publisher:
   ```
   CN=Writers Logic LLC, O=Writers Logic LLC, L=San Francisco, S=California, C=US
   ```

3. Sign with timestamp for long-term validity:
   ```powershell
   .\scripts\sign-msix.ps1 `
       -CertificatePath ev-cert.pfx `
       -TimestampServer "http://timestamp.digicert.com"
   ```

### For Microsoft Store

**Important**: Packages submitted to Microsoft Store do NOT need to be pre-signed. Microsoft signs packages during ingestion.

## Store Submission

### 1. Create App in Partner Center

1. Go to [Partner Center](https://partner.microsoft.com/dashboard)
2. Navigate to Apps and games > New product > MSIX or PWA app
3. Reserve the name "Witnessd"
4. Note your App ID for configuration

### 2. Prepare Store Listing

Edit `store/store-listing.json` with:
- Description and features
- Screenshots (1366x768, 1920x1080, or 2560x1440)
- Keywords and categories
- Privacy policy URL
- Support contact

### 3. Complete Age Rating

Review `store/age-rating-questionnaire.md` and complete the IARC questionnaire in Partner Center.

### 4. Submit Package

#### Manual Submission

1. Create the MSIX bundle:
   ```powershell
   .\scripts\create-msix.ps1 -Bundle -Version 1.0.0.0
   ```

2. Upload `build/msix/Witnessd_1.0.0.0.msixbundle` to Partner Center

3. Complete submission checklist

#### Automated Submission (StoreBroker)

```powershell
# Install StoreBroker
Install-Module -Name StoreBroker -Force

# Configure credentials
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = ConvertTo-SecureString "your-secret" -AsPlainText -Force

# Authenticate
$cred = New-Object PSCredential($clientId, $clientSecret)
Set-StoreBrokerAuthentication -TenantId $tenantId -Credential $cred

# Submit
New-ApplicationSubmission -AppId "your-app-id" -PackagePath "build/msix/*.msixupload"
```

### 5. Certification Process

Microsoft reviews submissions for:
- Technical compliance (WACK tests)
- Content policy compliance
- Privacy policy requirements
- Restricted capability justifications

**Expected timeline**: 1-3 business days

### 6. Restricted Capabilities Approval

The following capabilities require additional justification:
- `broadFileSystemAccess`
- `inputForegroundObservation`
- `inputObservation`

Prepare detailed justification explaining:
1. Why the capability is needed
2. How user privacy is protected
3. What data is collected and stored

## CI/CD Integration

### GitHub Actions

The workflow `.github/workflows/windows-msix.yml` provides:

- Automatic builds on push/PR
- Multi-architecture support (x64, ARM64)
- Visual asset generation
- MSIX package creation
- Signing (with secrets)
- Validation
- Release publishing

#### Required Secrets

| Secret | Description |
|--------|-------------|
| `WINDOWS_SIGNING_CERT_PFX` | Base64-encoded PFX certificate |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Certificate password |
| `PARTNER_CENTER_TENANT_ID` | Azure AD tenant ID |
| `PARTNER_CENTER_CLIENT_ID` | App registration client ID |
| `PARTNER_CENTER_CLIENT_SECRET` | App registration secret |
| `PARTNER_CENTER_APP_ID` | Store app ID |

#### Trigger Release

```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

The workflow will:
1. Build binaries for all architectures
2. Generate assets
3. Create MSIX packages
4. Sign packages
5. Validate with WACK
6. Upload to GitHub Release
7. Optionally submit to Store

### Local CI Simulation

```powershell
# Run full build pipeline locally
.\scripts\build-binaries.ps1 -Architecture both
.\assets\generate-assets.ps1
.\scripts\create-msix.ps1 -Bundle
.\scripts\validate-msix.ps1
.\scripts\test-msix.ps1
```

## Troubleshooting

### Build Issues

**"Go not found"**
```powershell
# Install Go via winget
winget install GoLang.Go

# Or download from https://golang.org/dl/
```

**"MSVC not found"**
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Add C++ workload via Visual Studio Installer
```

**"Windows SDK not found"**
```powershell
# Install Windows SDK
winget install Microsoft.WindowsSDK
```

### Package Issues

**"Package validation failed"**
```powershell
# Run detailed validation
.\scripts\validate-msix.ps1 -Verbose

# Check manifest syntax
[xml]$manifest = Get-Content "msix/AppxManifest.xml"
```

**"Missing assets"**
```powershell
# Regenerate assets
.\assets\generate-assets.ps1 -Force

# List required assets
Get-Content assets\ASSET-REQUIREMENTS.md
```

### Installation Issues

**"Package is unsigned"**
- For testing: Enable Developer Mode in Windows Settings
- For distribution: Sign with a valid certificate

**"Publisher mismatch"**
- Ensure certificate subject matches manifest Publisher exactly
- Check for whitespace or encoding differences

**"Capabilities denied"**
- User must approve capability prompts
- Check Windows Settings > Privacy for capability permissions

### TSF Issues

**"TSF DLL not loading"**
- Verify COM registration in manifest
- Check Event Viewer for COM errors
- Ensure DLL dependencies are satisfied

**"Keystroke timing not working"**
- Verify `inputObservation` capability is approved
- Check if antivirus is blocking the DLL
- Run as Administrator for testing

## Resources

- [MSIX Documentation](https://docs.microsoft.com/windows/msix/)
- [Partner Center Documentation](https://docs.microsoft.com/windows/uwp/publish/)
- [StoreBroker Module](https://github.com/Microsoft/StoreBroker)
- [Windows App Certification Kit](https://docs.microsoft.com/windows/uwp/debug-test-perf/windows-app-certification-kit)
- [TSF Documentation](https://docs.microsoft.com/windows/win32/tsf/text-services-framework)

## Support

For issues with:
- **Build process**: Open an issue on GitHub
- **Store submission**: Contact Microsoft Partner Center support
- **Capabilities approval**: File a support request in Partner Center
