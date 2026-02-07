# Witnessd Windows Installer

This directory contains the WiX Toolset v4 installer for distributing Witnessd on Windows outside the Microsoft Store.

## Overview

The Windows installer provides:

- **MSI Package**: Enterprise-ready Windows Installer package
- **EXE Bootstrapper** (optional): User-friendly setup wizard with prerequisites
- **Silent Installation**: Full support for unattended deployment
- **Code Signing**: Authenticode signing for trust verification
- **Enterprise Features**: Group Policy, SCCM/Intune support

## Quick Start

### Prerequisites

1. **Windows 10/11** (64-bit)
2. **WiX Toolset v4**: Install via .NET tool
   ```powershell
   dotnet tool install -g wix
   wix extension add -g WixToolset.UI.wixext
   wix extension add -g WixToolset.Util.wixext
   ```
3. **Go 1.22+**: For building binaries
4. **Visual Studio 2022** (optional): For building TSF DLL

### Build the Installer

```powershell
# Navigate to installer directory
cd platforms\windows\installer

# Build with default settings
.\build-installer.ps1

# Build with signing
.\build-installer.ps1 -Sign -CertificateThumbprint "YOUR_CERT_THUMBPRINT"

# Build EXE bootstrapper
.\build-installer.ps1 -CreateBundle
```

### Test the Installer

```powershell
# Run full install/verify/uninstall cycle
.\test-installer.ps1 -MsiPath .\build\installer\witnessd-1.0.0-x64.msi

# Keep installed for manual testing
.\test-installer.ps1 -MsiPath .\witnessd.msi -KeepInstalled
```

## Installation Components

### Feature Tree

| Feature | Description | Default |
|---------|-------------|---------|
| **Core** | Essential witnessd daemon and witnessctl CLI | Required |
| **Service** | Install as Windows service with auto-start | Enabled |
| **TSF** | Text Services Framework input method | Enabled |
| **Shell Integration** | PATH, shortcuts, context menu | Enabled |

### Directory Structure

After installation (default: `C:\Program Files\Witnessd`):

```
Witnessd\
├── bin\
│   ├── witnessd.exe      # Main daemon
│   ├── witnessctl.exe    # CLI tool
│   └── witnessd-tsf.dll  # TSF input method (optional)
├── config\
│   ├── config.json.template
│   └── attestation.template.json
├── data\                 # Runtime data
├── logs\                 # Log files
├── LICENSE
└── README.md
```

User data is stored in: `%LOCALAPPDATA%\Witnessd\`

## Installation Methods

### Interactive Installation

Double-click the MSI file or run:

```powershell
msiexec /i witnessd-1.0.0-x64.msi
```

### Silent Installation

```powershell
# Full installation (all components)
msiexec /i witnessd-1.0.0-x64.msi /quiet /norestart

# Minimal installation (no service, no TSF)
msiexec /i witnessd-1.0.0-x64.msi /quiet INSTALLSERVICE=0 INSTALLTSF=0

# Custom installation directory
msiexec /i witnessd-1.0.0-x64.msi /quiet INSTALLFOLDER="D:\Tools\Witnessd"
```

### MSI Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `INSTALLSERVICE` | 0, 1 | 1 | Install as Windows service |
| `ADDTOPATH` | 0, 1 | 1 | Add to system PATH |
| `INSTALLSHORTCUTS` | 0, 1 | 1 | Create Start Menu shortcuts |
| `INSTALLCONTEXTMENU` | 0, 1 | 1 | Add Explorer context menu |
| `INSTALLTSF` | 0, 1 | 1 | Install TSF input method |
| `SERVICEACCOUNT` | String | LocalSystem | Service account |

### Logging

Enable installation logging:

```powershell
msiexec /i witnessd.msi /l*v install.log
```

## Windows Service

### Service Details

- **Name**: `witnessd`
- **Display Name**: Witnessd Daemon
- **Start Type**: Automatic (Delayed Start)
- **Account**: LocalSystem (configurable)
- **Recovery**: Restart on failure (60s delay)

### Service Management

```powershell
# Check status
sc query witnessd

# Start service
sc start witnessd

# Stop service
sc stop witnessd

# Configure start type
sc config witnessd start=auto
sc config witnessd start=demand
```

### Service Logs

Logs are written to: `%PROGRAMDATA%\Witnessd\logs\`

## TSF Input Method

The Text Services Framework (TSF) component enables system-wide keystroke witnessing.

### Registration

The TSF DLL is registered automatically during installation:
- COM server registration in `HKLM\Software\Classes\CLSID`
- TSF profile registration in `HKLM\Software\Microsoft\CTF\TIP`

### Manual Registration

```powershell
# Register
regsvr32 "C:\Program Files\Witnessd\bin\witnessd-tsf.dll"

# Unregister
regsvr32 /u "C:\Program Files\Witnessd\bin\witnessd-tsf.dll"
```

## Enterprise Deployment

### SCCM/ConfigMgr Deployment

1. Import the MSI as an Application
2. Set detection method: Registry key `HKLM\Software\WritersLogic\Witnessd`
3. Set install command: `msiexec /i witnessd.msi /quiet /norestart`
4. Set uninstall command: `msiexec /x {ProductCode} /quiet /norestart`

### Intune Deployment

1. Upload MSI as Windows app (MSI line-of-business)
2. Configure silent install: `/quiet /norestart`
3. Set detection rules: File exists `C:\Program Files\Witnessd\bin\witnessd.exe`

### Group Policy Deployment

1. Copy MSI to network share accessible by target computers
2. Create GPO: Computer Configuration > Policies > Software Settings > Software Installation
3. Add new package, select MSI, choose "Assigned"
4. Link GPO to target OU

### MSI Transforms (.mst)

Create transforms for custom configurations:

```powershell
# Using Orca (Windows SDK)
# Or WiX:
wix msi transform -t custom.mst witnessd.msi
```

Common transform settings:
- Disable service: `INSTALLSERVICE=0`
- Custom install path: `INSTALLFOLDER=D:\Apps\Witnessd`
- Disable TSF: `INSTALLTSF=0`

## Code Signing

### Sign Binaries and Installer

```powershell
# Sign all files
.\sign-installer.ps1 -InputPath .\build -CertificateThumbprint "ABC123..."

# Sign with PFX file
$pwd = Read-Host -AsSecureString "Certificate password"
.\sign-installer.ps1 -InputPath .\build\installer\witnessd.msi `
    -CertificateFile code-signing.pfx `
    -CertificatePassword $pwd
```

### Certificate Requirements

For public distribution, use an **Extended Validation (EV)** code signing certificate:

1. EV certificates provide instant reputation on Windows SmartScreen
2. Standard certificates require building reputation over time
3. Hardware token required for EV certificates

Recommended Certificate Authorities:
- DigiCert
- Sectigo
- GlobalSign

### Timestamp Servers

| Provider | URL |
|----------|-----|
| DigiCert | http://timestamp.digicert.com |
| Sectigo | http://timestamp.sectigo.com |
| GlobalSign | http://timestamp.globalsign.com |
| SSL.com | http://ts.ssl.com |

## Upgrading

### Major Upgrade

The installer uses WiX MajorUpgrade, which:
1. Detects previous versions
2. Uninstalls old version
3. Installs new version
4. Preserves user configuration

```powershell
# Upgrade silently
msiexec /i witnessd-2.0.0-x64.msi /quiet /norestart
```

### Configuration Migration

User configuration in `%LOCALAPPDATA%\Witnessd\` is preserved during upgrades.

If configuration schema changes between versions, the installer will migrate settings automatically.

## Uninstallation

### Interactive Uninstall

Via Settings > Apps > Witnessd > Uninstall

Or via Control Panel > Programs and Features

### Silent Uninstall

```powershell
# Using product code
msiexec /x {PRODUCT-CODE-GUID} /quiet /norestart

# Find product code
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Witnessd*" }
```

### Clean Uninstall

To remove all user data:

```powershell
# Uninstall with data cleanup
msiexec /x {PRODUCT-CODE} /quiet CLEANUSERDATA=1
```

Or manually:
```powershell
rmdir /s /q "%LOCALAPPDATA%\Witnessd"
rmdir /s /q "%PROGRAMDATA%\Witnessd"
```

## Troubleshooting

### Installation Fails

1. Check Windows Event Viewer > Application log
2. Enable verbose logging: `msiexec /i witnessd.msi /l*v install.log`
3. Common issues:
   - **Error 1925**: Insufficient privileges (run as Administrator)
   - **Error 1603**: Generic failure (check log for details)
   - **Error 1722**: Custom action failure (check witnessd init)

### Service Won't Start

1. Check Event Viewer > System log for service errors
2. Verify service account permissions
3. Check `%PROGRAMDATA%\Witnessd\logs\` for daemon logs
4. Try manual start: `sc start witnessd`

### TSF Not Working

1. Verify registration: `reg query "HKLM\Software\Classes\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"`
2. Re-register DLL: `regsvr32 "C:\Program Files\Witnessd\bin\witnessd-tsf.dll"`
3. Restart the application using TSF
4. Check `%LOCALAPPDATA%\Witnessd\logs\tsf.log`

### PATH Not Updated

1. Log out and back in (or restart)
2. Verify: `echo %PATH%`
3. Manual fix:
   ```powershell
   [Environment]::SetEnvironmentVariable(
       "PATH",
       $env:PATH + ";C:\Program Files\Witnessd\bin",
       "Machine"
   )
   ```

## Building from Source

### Full Build

```powershell
# Clone repository
git clone https://github.com/writerslogic/witnessd
cd witnessd

# Build installer
cd platforms\windows\installer
.\build-installer.ps1 -Configuration Release -Architecture x64
```

### Build Components Separately

```powershell
# Build Go binaries only
.\build-installer.ps1 -SkipTSFBuild

# Build TSF only (requires Visual Studio)
.\build-installer.ps1 -SkipGoBuild

# Use existing binaries
.\build-installer.ps1 -SkipGoBuild -SkipTSFBuild
```

### CI/CD

The GitHub Actions workflow `.github/workflows/windows-installer.yml` automatically:

1. Builds Go binaries for x64 and arm64
2. Builds TSF DLL
3. Creates MSI installer
4. Signs binaries (when secrets are configured)
5. Runs installer tests
6. Uploads to GitHub Releases

Required secrets for signing:
- `WINDOWS_CODE_SIGNING_CERT`: Base64-encoded PFX
- `WINDOWS_CODE_SIGNING_PASSWORD`: PFX password
- `WINDOWS_CODE_SIGNING_THUMBPRINT`: Certificate thumbprint

## File Reference

| File | Description |
|------|-------------|
| `Product.wxs` | Main product definition, upgrade code, properties |
| `Features.wxs` | Feature tree, component groups, service definition |
| `Files.wxs` | File inventory, registry keys, directories |
| `UI.wxs` | Custom UI dialogs, wizard flow |
| `CustomActions.wxs` | Installation actions (init, calibrate, TSF) |
| `build-installer.ps1` | Main build script |
| `sign-installer.ps1` | Code signing script |
| `test-installer.ps1` | Automated installer tests |
| `resources/` | Installer resources (config templates, license) |

## Support

- Documentation: https://github.com/writerslogic/witnessd
- Issues: https://github.com/writerslogic/witnessd/issues
- Discussions: https://github.com/writerslogic/witnessd/discussions

## License

See [LICENSE](../../../LICENSE) for details.

Patent Pending: USPTO Application No. 19/460,364
