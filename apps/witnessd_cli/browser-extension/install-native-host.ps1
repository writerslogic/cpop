# Install Witnessd Native Messaging Host on Windows
#
# This script:
# 1. Copies the native messaging host binary to %LOCALAPPDATA%\Witnessd\
# 2. Registers the native messaging manifest via Registry for Chrome, Firefox, and/or Edge
#
# Usage: .\install-native-host.ps1 [-Chrome] [-Firefox] [-Edge] [-All]

param(
    [switch]$Chrome,
    [switch]$Firefox,
    [switch]$Edge,
    [switch]$All,
    [switch]$Both  # Legacy alias for -All
)

$ErrorActionPreference = "Stop"

$HostBinary = "witnessd-native-messaging-host.exe"
$HostName = "com.writerslogic.witnessd"
$InstallDir = Join-Path $env:LOCALAPPDATA "Witnessd"

# Find binary
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinaryPath = $null

$candidates = @(
    (Join-Path (Split-Path $ScriptDir) "target\release\$HostBinary"),
    (Join-Path (Split-Path $ScriptDir) "target\debug\$HostBinary")
)

foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
        $BinaryPath = $candidate
        break
    }
}

if (-not $BinaryPath) {
    Write-Error "Cannot find $HostBinary. Build it first: cargo build --release --bin witnessd-native-messaging-host"
    exit 1
}

# Default to all
if (-not $Chrome -and -not $Firefox -and -not $Edge -and -not $All -and -not $Both) {
    $All = $true
}
if ($All -or $Both) {
    $Chrome = $true
    $Firefox = $true
    $Edge = $true
}

Write-Host "=== Witnessd Native Messaging Host Installer ===" -ForegroundColor Cyan
Write-Host ""

# Install binary
Write-Host "Installing $HostBinary to $InstallDir..."
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $BinaryPath (Join-Path $InstallDir $HostBinary) -Force
$InstalledBinary = Join-Path $InstallDir $HostBinary
Write-Host "  Installed: $InstalledBinary" -ForegroundColor Green

# Generate manifest
$ManifestDir = Join-Path $InstallDir "native-manifests"
New-Item -ItemType Directory -Path $ManifestDir -Force | Out-Null

function Install-ChromeHost {
    $manifest = @{
        name = $HostName
        description = "Witnessd Native Messaging Host"
        path = $InstalledBinary
        type = "stdio"
        allowed_origins = @("chrome-extension://EXTENSION_ID_HERE/")
    }

    $manifestPath = Join-Path $ManifestDir "chrome-$HostName.json"
    $manifest | ConvertTo-Json | Set-Content $manifestPath

    # Register in Windows Registry
    $regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $manifestPath

    Write-Host "  Chrome manifest: $manifestPath" -ForegroundColor Green
    Write-Host "  Chrome registry: $regPath" -ForegroundColor Green
    Write-Host "  NOTE: Replace EXTENSION_ID_HERE in $manifestPath with your extension ID" -ForegroundColor Yellow
}

function Install-FirefoxHost {
    $manifest = @{
        name = $HostName
        description = "Witnessd Native Messaging Host"
        path = $InstalledBinary
        type = "stdio"
        allowed_extensions = @("witnessd@writerslogic.com")
    }

    $manifestPath = Join-Path $ManifestDir "firefox-$HostName.json"
    $manifest | ConvertTo-Json | Set-Content $manifestPath

    # Register in Windows Registry
    $regPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $manifestPath

    Write-Host "  Firefox manifest: $manifestPath" -ForegroundColor Green
    Write-Host "  Firefox registry: $regPath" -ForegroundColor Green
}

function Install-EdgeHost {
    $manifest = @{
        name = $HostName
        description = "Witnessd Native Messaging Host"
        path = $InstalledBinary
        type = "stdio"
        allowed_origins = @("chrome-extension://EXTENSION_ID_HERE/")
    }

    $manifestPath = Join-Path $ManifestDir "edge-$HostName.json"
    $manifest | ConvertTo-Json | Set-Content $manifestPath

    # Register in Windows Registry
    $regPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $manifestPath

    Write-Host "  Edge manifest: $manifestPath" -ForegroundColor Green
    Write-Host "  Edge registry: $regPath" -ForegroundColor Green
    Write-Host "  NOTE: Replace EXTENSION_ID_HERE in $manifestPath with your extension ID" -ForegroundColor Yellow
}

if ($Chrome) {
    Write-Host ""
    Write-Host "Registering Chrome native messaging host..."
    Install-ChromeHost
}

if ($Firefox) {
    Write-Host ""
    Write-Host "Registering Firefox native messaging host..."
    Install-FirefoxHost
}

if ($Edge) {
    Write-Host ""
    Write-Host "Registering Edge native messaging host..."
    Install-EdgeHost
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Load the browser extension in developer mode"
Write-Host "  2. Copy the extension ID from chrome://extensions or edge://extensions"
Write-Host "  3. Update the Chrome/Edge manifests with your extension ID"
