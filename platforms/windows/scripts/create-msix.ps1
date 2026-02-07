# create-msix.ps1
# Create MSIX package for Witnessd
#
# Creates a properly structured MSIX package from built binaries and assets.
# The package can be signed separately or installed for testing.
#
# Usage:
#   .\create-msix.ps1                      # Create unsigned package
#   .\create-msix.ps1 -Architecture x64    # Specific architecture
#   .\create-msix.ps1 -Version 1.2.3       # Specific version
#   .\create-msix.ps1 -Bundle              # Create MSIX bundle for multiple architectures

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",

    [Parameter(Mandatory=$false)]
    [string]$Version = "1.0.0.0",

    [Parameter(Mandatory=$false)]
    [string]$Publisher = "CN=Writers Logic LLC, O=Writers Logic LLC, L=San Francisco, S=California, C=US",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory=$false)]
    [string]$BuildDir = "",

    [Parameter(Mandatory=$false)]
    [switch]$Bundle = $false,

    [Parameter(Mandatory=$false)]
    [switch]$SkipAssetValidation = $false
)

$ErrorActionPreference = "Stop"

# Get paths
$ScriptDir = $PSScriptRoot
$PlatformDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$RepoRoot = (Resolve-Path (Join-Path $PlatformDir "..\..")).Path

# Default directories
if (-not $BuildDir) {
    $BuildDir = Join-Path $RepoRoot "build"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $BuildDir "msix"
}

# MSIX tools
$MakeAppx = ""
$MakePri = ""

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Find-WindowsSDKTools {
    # Try to find makeappx.exe from Windows SDK
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64"
    )

    foreach ($pattern in $sdkPaths) {
        $paths = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach ($path in $paths) {
            $makeAppx = Join-Path $path.FullName "makeappx.exe"
            if (Test-Path $makeAppx) {
                return @{
                    MakeAppx = $makeAppx
                    MakePri = Join-Path $path.FullName "makepri.exe"
                    SignTool = Join-Path $path.FullName "signtool.exe"
                }
            }
        }
    }

    throw "Windows SDK tools not found. Install Windows 10 SDK."
}

function Test-RequiredFiles {
    param([string]$Arch)

    $binDir = Join-Path $BuildDir "windows_$Arch"
    $assetsDir = Join-Path $PlatformDir "assets"
    $msixDir = Join-Path $PlatformDir "msix"

    $required = @{
        "witnessd.exe" = Join-Path $binDir "witnessd.exe"
        "witnessctl.exe" = Join-Path $binDir "witnessctl.exe"
        "AppxManifest.xml" = Join-Path $msixDir "AppxManifest.xml"
    }

    $missing = @()
    foreach ($name in $required.Keys) {
        if (-not (Test-Path $required[$name])) {
            $missing += "$name ($($required[$name]))"
        }
    }

    if ($missing.Count -gt 0) {
        Write-Error "Missing required files:`n$($missing -join "`n")"
        exit 1
    }

    # Check assets (warning only if skip flag set)
    $requiredAssets = @(
        "Square44x44Logo.scale-100.png",
        "Square150x150Logo.scale-100.png",
        "StoreLogo.scale-100.png"
    )

    foreach ($asset in $requiredAssets) {
        $assetPath = Join-Path $assetsDir $asset
        if (-not (Test-Path $assetPath)) {
            if ($SkipAssetValidation) {
                Write-Warning "Missing asset: $asset (continuing anyway)"
            } else {
                Write-Error "Missing asset: $asset`nRun .\assets\generate-assets.ps1 to create assets"
                exit 1
            }
        }
    }
}

function Update-ManifestVersion {
    param(
        [string]$ManifestPath,
        [string]$OutputPath,
        [string]$Version,
        [string]$Publisher,
        [string]$Architecture
    )

    [xml]$manifest = Get-Content $ManifestPath

    # Update Identity
    $ns = @{
        "default" = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    }

    $identity = $manifest.Package.Identity
    $identity.Version = $Version
    $identity.Publisher = $Publisher
    $identity.ProcessorArchitecture = $Architecture

    $manifest.Save($OutputPath)
    Write-Host "  Updated manifest: Version=$Version, Arch=$Architecture"
}

function New-ResourcesPri {
    param(
        [string]$PackageDir,
        [string]$ConfigPath
    )

    if (-not (Test-Path $MakePri)) {
        Write-Warning "makepri.exe not found, skipping PRI generation"
        return
    }

    $priPath = Join-Path $PackageDir "resources.pri"

    # Generate PRI config if not exists
    if (-not (Test-Path $ConfigPath)) {
        & $MakePri createconfig /cf $ConfigPath /dq en-US /o
    }

    # Create PRI file
    Push-Location $PackageDir
    try {
        & $MakePri new /pr . /cf $ConfigPath /of $priPath /o
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Created resources.pri" -ForegroundColor Green
        } else {
            Write-Warning "PRI generation failed (non-fatal)"
        }
    } finally {
        Pop-Location
    }
}

function New-MSIXPackage {
    param(
        [string]$Arch,
        [string]$Version
    )

    $archName = if ($Arch -eq "x64") { "amd64" } else { $Arch }
    $binDir = Join-Path $BuildDir "windows_$Arch"
    $assetsDir = Join-Path $PlatformDir "assets"
    $msixSourceDir = Join-Path $PlatformDir "msix"
    $packageDir = Join-Path $OutputDir "package_$Arch"
    $packageAssetsDir = Join-Path $packageDir "Assets"

    # Create clean package directory
    if (Test-Path $packageDir) {
        Remove-Item -Recurse -Force $packageDir
    }
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    New-Item -ItemType Directory -Path $packageAssetsDir -Force | Out-Null

    Write-Host "Staging package for $Arch..."

    # Copy executables
    Copy-Item (Join-Path $binDir "witnessd.exe") $packageDir -Force
    Copy-Item (Join-Path $binDir "witnessctl.exe") $packageDir -Force

    # Copy TSF DLL if exists
    $tsfDll = Join-Path $binDir "witnessd-tsf.dll"
    if (Test-Path $tsfDll) {
        Copy-Item $tsfDll $packageDir -Force
        Write-Host "  Included: witnessd-tsf.dll"
    }

    # Copy and update manifest
    $manifestSource = Join-Path $msixSourceDir "AppxManifest.xml"
    $manifestDest = Join-Path $packageDir "AppxManifest.xml"
    Update-ManifestVersion -ManifestPath $manifestSource -OutputPath $manifestDest `
        -Version $Version -Publisher $Publisher -Architecture $Arch

    # Copy assets
    $assetFiles = Get-ChildItem $assetsDir -Filter "*.png" -ErrorAction SilentlyContinue
    foreach ($file in $assetFiles) {
        Copy-Item $file.FullName $packageAssetsDir -Force
    }
    Write-Host "  Copied $($assetFiles.Count) asset files"

    # Generate resources.pri
    $priConfig = Join-Path $msixSourceDir "priconfig.xml"
    New-ResourcesPri -PackageDir $packageDir -ConfigPath $priConfig

    # Create MSIX package
    $msixPath = Join-Path $OutputDir "Witnessd_${Version}_${Arch}.msix"

    Write-Host "Creating MSIX package..."

    & $MakeAppx pack /d $packageDir /p $msixPath /o

    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe failed"
    }

    $fileInfo = Get-Item $msixPath
    Write-Host "  Created: $msixPath ($([Math]::Round($fileInfo.Length / 1MB, 2)) MB)" -ForegroundColor Green

    return $msixPath
}

function New-MSIXBundle {
    param(
        [string[]]$PackagePaths,
        [string]$Version
    )

    $bundlePath = Join-Path $OutputDir "Witnessd_${Version}.msixbundle"
    $bundleDir = Join-Path $OutputDir "bundle_staging"

    # Create staging directory
    if (Test-Path $bundleDir) {
        Remove-Item -Recurse -Force $bundleDir
    }
    New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

    # Copy packages to staging
    foreach ($pkg in $PackagePaths) {
        Copy-Item $pkg $bundleDir -Force
    }

    Write-Host "Creating MSIX bundle..."

    & $MakeAppx bundle /d $bundleDir /p $bundlePath /o

    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe bundle failed"
    }

    $fileInfo = Get-Item $bundlePath
    Write-Host "  Created: $bundlePath ($([Math]::Round($fileInfo.Length / 1MB, 2)) MB)" -ForegroundColor Green

    # Cleanup staging
    Remove-Item -Recurse -Force $bundleDir

    return $bundlePath
}

# Main execution
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " Witnessd MSIX Package Creator" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Version:      $Version"
Write-Host "Architecture: $Architecture"
Write-Host "Publisher:    $Publisher"
Write-Host "Output:       $OutputDir"
Write-Host ""

# Find SDK tools
Write-Step "Locating Windows SDK tools"
$tools = Find-WindowsSDKTools
$MakeAppx = $tools.MakeAppx
$MakePri = $tools.MakePri
Write-Host "  makeappx.exe: $MakeAppx"
Write-Host "  makepri.exe:  $MakePri"

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$createdPackages = @()

if ($Bundle) {
    # Build for both architectures
    Write-Step "Creating packages for bundle"

    foreach ($arch in @("x64", "arm64")) {
        Write-Step "Processing $arch"
        Test-RequiredFiles -Arch $arch
        $pkg = New-MSIXPackage -Arch $arch -Version $Version
        $createdPackages += $pkg
    }

    Write-Step "Creating MSIX bundle"
    $bundlePath = New-MSIXBundle -PackagePaths $createdPackages -Version $Version
    $createdPackages += $bundlePath
} else {
    # Single architecture
    Write-Step "Validating files"
    Test-RequiredFiles -Arch $Architecture

    Write-Step "Creating MSIX package"
    $pkg = New-MSIXPackage -Arch $Architecture -Version $Version
    $createdPackages += $pkg
}

Write-Step "Summary"
Write-Host ""
Write-Host "Created packages:" -ForegroundColor Green
foreach ($pkg in $createdPackages) {
    $fileInfo = Get-Item $pkg
    Write-Host "  $($fileInfo.Name) - $([Math]::Round($fileInfo.Length / 1MB, 2)) MB"
}

Write-Host ""
Write-Host "Package created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Sign the package: .\scripts\sign-msix.ps1 -CertificatePath <pfx>"
Write-Host "  2. Validate: .\scripts\validate-msix.ps1"
Write-Host "  3. Test installation: Add-AppxPackage -Path <msix>"
Write-Host ""
Write-Host "For Store submission, use the bundle: Witnessd_${Version}.msixbundle"
