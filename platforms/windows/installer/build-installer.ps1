<#
.SYNOPSIS
    Build Witnessd Windows Installer (MSI/EXE)

.DESCRIPTION
    This script builds the Witnessd Windows installer using WiX Toolset v4.
    It compiles Go binaries, builds the TSF DLL, and creates the MSI package.
    Optionally wraps the MSI in a bootstrapper EXE for better user experience.

.PARAMETER Configuration
    Build configuration: Debug or Release (default: Release)

.PARAMETER Architecture
    Target architecture: x64 or arm64 (default: x64)

.PARAMETER Version
    Product version (e.g., 1.0.0). If not specified, uses git describe.

.PARAMETER OutputDir
    Output directory for built installer (default: .\build\installer)

.PARAMETER SkipGoBuild
    Skip building Go binaries (use existing binaries)

.PARAMETER SkipTSFBuild
    Skip building TSF DLL (use existing DLL)

.PARAMETER CreateBundle
    Create EXE bootstrapper bundle instead of standalone MSI

.PARAMETER Sign
    Sign the installer and binaries (requires signtool and certificate)

.PARAMETER CertificateThumbprint
    Certificate thumbprint for code signing

.PARAMETER TimestampServer
    Timestamp server URL (default: http://timestamp.digicert.com)

.EXAMPLE
    .\build-installer.ps1 -Configuration Release -Architecture x64

.EXAMPLE
    .\build-installer.ps1 -Sign -CertificateThumbprint "ABC123..."

.EXAMPLE
    .\build-installer.ps1 -CreateBundle -Version "1.2.3"
#>

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",

    [string]$Version,

    [string]$OutputDir = ".\build\installer",

    [switch]$SkipGoBuild,

    [switch]$SkipTSFBuild,

    [switch]$CreateBundle,

    [switch]$Sign,

    [string]$CertificateThumbprint,

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Script paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..\..\..")
$InstallerDir = $ScriptDir
$BuildDir = Join-Path $OutputDir "bin"
$WixObjDir = Join-Path $OutputDir "wixobj"

# Version handling
if (-not $Version) {
    Push-Location $RepoRoot
    try {
        $Version = (git describe --tags --always 2>$null) -replace '^v', ''
        if (-not $Version) { $Version = "0.0.1-dev" }
    } finally {
        Pop-Location
    }
}

# Parse version for MSI (must be X.X.X.X format)
$VersionParts = $Version -split '[-+]'
$MsiVersion = $VersionParts[0]
if (($MsiVersion -split '\.').Count -lt 3) {
    $MsiVersion = "$MsiVersion.0"
}
if (($MsiVersion -split '\.').Count -lt 4) {
    $MsiVersion = "$MsiVersion.0"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Witnessd Windows Installer Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration: $Configuration"
Write-Host "Architecture:  $Architecture"
Write-Host "Version:       $Version"
Write-Host "MSI Version:   $MsiVersion"
Write-Host "Output:        $OutputDir"
Write-Host ""

# Create output directories
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
New-Item -ItemType Directory -Path $WixObjDir -Force | Out-Null

# ============================================================================
# Step 1: Build Go Binaries
# ============================================================================

if (-not $SkipGoBuild) {
    Write-Host "Building Go binaries..." -ForegroundColor Yellow

    $GoArch = if ($Architecture -eq "x64") { "amd64" } else { "arm64" }
    $env:GOOS = "windows"
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = "0"

    $LdFlags = "-s -w -X main.Version=$Version -X main.Commit=$(git rev-parse --short HEAD 2>$null) -X main.BuildTime=$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"

    # Build witnessd
    Write-Host "  Building witnessd.exe..." -ForegroundColor Gray
    Push-Location $RepoRoot
    try {
        go build -ldflags $LdFlags -o "$BuildDir\witnessd.exe" ./cmd/witnessd
        if ($LASTEXITCODE -ne 0) { throw "Failed to build witnessd.exe" }
    } finally {
        Pop-Location
    }

    # Build witnessctl
    Write-Host "  Building witnessctl.exe..." -ForegroundColor Gray
    Push-Location $RepoRoot
    try {
        go build -ldflags $LdFlags -o "$BuildDir\witnessctl.exe" ./cmd/witnessctl
        if ($LASTEXITCODE -ne 0) { throw "Failed to build witnessctl.exe" }
    } finally {
        Pop-Location
    }

    Write-Host "  Go binaries built successfully." -ForegroundColor Green
} else {
    Write-Host "Skipping Go build (using existing binaries)" -ForegroundColor Yellow
}

# ============================================================================
# Step 2: Build TSF DLL
# ============================================================================

if (-not $SkipTSFBuild) {
    Write-Host "Building TSF DLL..." -ForegroundColor Yellow

    $TSFDir = Join-Path $RepoRoot "cmd\witnessd-tsf"

    # Check for Visual Studio
    $VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $VsWhere) {
        $VsPath = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($VsPath) {
            $VcVarsAll = Join-Path $VsPath "VC\Auxiliary\Build\vcvarsall.bat"
            $VcArch = if ($Architecture -eq "x64") { "x64" } else { "arm64" }

            Write-Host "  Using Visual Studio: $VsPath" -ForegroundColor Gray

            # Build Go archive
            Write-Host "  Building Go archive..." -ForegroundColor Gray
            Push-Location $TSFDir
            try {
                $env:CGO_ENABLED = "1"
                go build -buildmode=c-archive -o "$BuildDir\witnessd.a" .
                if ($LASTEXITCODE -ne 0) { throw "Failed to build Go archive" }
            } finally {
                Pop-Location
            }

            # Build C++ DLL
            Write-Host "  Building C++ DLL..." -ForegroundColor Gray
            $CppFiles = Join-Path $TSFDir "tsf\*.cpp"
            $BuildCmd = @"
call "$VcVarsAll" $VcArch
cl /EHsc /LD /O2 /DNDEBUG "$CppFiles" "$BuildDir\witnessd.a" /Fe"$BuildDir\witnessd-tsf.dll" /link /DEF:"$(Join-Path $TSFDir 'tsf\witnessd_tsf.def')" ole32.lib oleaut32.lib advapi32.lib
"@
            $BuildCmd | Out-File -FilePath "$env:TEMP\build_tsf.cmd" -Encoding ascii
            cmd /c "$env:TEMP\build_tsf.cmd"
            if ($LASTEXITCODE -ne 0) { throw "Failed to build TSF DLL" }

            Write-Host "  TSF DLL built successfully." -ForegroundColor Green
        } else {
            Write-Warning "Visual Studio with C++ tools not found. Skipping TSF DLL build."
        }
    } else {
        Write-Warning "Visual Studio not found. Skipping TSF DLL build."
    }
} else {
    Write-Host "Skipping TSF build (using existing DLL)" -ForegroundColor Yellow
}

# ============================================================================
# Step 3: Code Signing (Optional)
# ============================================================================

if ($Sign) {
    Write-Host "Signing binaries..." -ForegroundColor Yellow

    if (-not $CertificateThumbprint) {
        throw "Certificate thumbprint required for signing. Use -CertificateThumbprint parameter."
    }

    $SignTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $SignTool) {
        # Try to find signtool in Windows SDK
        $SdkPaths = @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
            "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
        )
        foreach ($Path in $SdkPaths) {
            $Found = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
            if ($Found) {
                $SignTool = $Found.FullName
                break
            }
        }
    }

    if (-not $SignTool) {
        throw "signtool.exe not found. Install Windows SDK or add signtool to PATH."
    }

    $FilesToSign = @(
        "$BuildDir\witnessd.exe",
        "$BuildDir\witnessctl.exe"
    )
    if (Test-Path "$BuildDir\witnessd-tsf.dll") {
        $FilesToSign += "$BuildDir\witnessd-tsf.dll"
    }

    foreach ($File in $FilesToSign) {
        if (Test-Path $File) {
            Write-Host "  Signing $([System.IO.Path]::GetFileName($File))..." -ForegroundColor Gray
            & $SignTool sign /sha1 $CertificateThumbprint /tr $TimestampServer /td sha256 /fd sha256 /v $File
            if ($LASTEXITCODE -ne 0) { throw "Failed to sign $File" }
        }
    }

    Write-Host "  Binaries signed successfully." -ForegroundColor Green
}

# ============================================================================
# Step 4: Build WiX Installer
# ============================================================================

Write-Host "Building WiX installer..." -ForegroundColor Yellow

# Check for WiX Toolset
$WixCmd = Get-Command wix -ErrorAction SilentlyContinue
if (-not $WixCmd) {
    # Try dotnet tool
    $WixCmd = "dotnet wix"
    $TestWix = & dotnet tool list -g | Select-String "wix"
    if (-not $TestWix) {
        throw "WiX Toolset not found. Install with: dotnet tool install -g wix"
    }
}

# Copy resources
Write-Host "  Copying resources..." -ForegroundColor Gray
Copy-Item -Path "$InstallerDir\resources\*" -Destination $BuildDir -Recurse -Force

# Copy license and readme
if (Test-Path "$RepoRoot\LICENSE") {
    Copy-Item -Path "$RepoRoot\LICENSE" -Destination $BuildDir -Force
}
if (Test-Path "$RepoRoot\README.md") {
    Copy-Item -Path "$RepoRoot\README.md" -Destination $BuildDir -Force
}

# Build MSI
Write-Host "  Compiling WiX sources..." -ForegroundColor Gray

$WixSources = @(
    "$InstallerDir\Product.wxs",
    "$InstallerDir\Features.wxs",
    "$InstallerDir\Files.wxs",
    "$InstallerDir\UI.wxs",
    "$InstallerDir\CustomActions.wxs"
)

$WixDefines = @(
    "-d", "BuildDir=$BuildDir",
    "-d", "SourceDir=$RepoRoot",
    "-d", "ResourcesDir=$BuildDir",
    "-d", "ProductVersion=$MsiVersion"
)

$MsiOutput = "$OutputDir\witnessd-$Version-$Architecture.msi"

# WiX v4 build command
$WixArgs = @(
    "build",
    "-arch", $Architecture,
    "-o", $MsiOutput
) + $WixDefines + $WixSources

Write-Host "  Running: wix $($WixArgs -join ' ')" -ForegroundColor Gray

if ($WixCmd -is [string]) {
    Invoke-Expression "$WixCmd $($WixArgs -join ' ')"
} else {
    & $WixCmd $WixArgs
}

if ($LASTEXITCODE -ne 0) { throw "WiX build failed" }

Write-Host "  MSI built: $MsiOutput" -ForegroundColor Green

# ============================================================================
# Step 5: Sign MSI (Optional)
# ============================================================================

if ($Sign) {
    Write-Host "Signing MSI..." -ForegroundColor Yellow
    & $SignTool sign /sha1 $CertificateThumbprint /tr $TimestampServer /td sha256 /fd sha256 /v $MsiOutput
    if ($LASTEXITCODE -ne 0) { throw "Failed to sign MSI" }
    Write-Host "  MSI signed successfully." -ForegroundColor Green
}

# ============================================================================
# Step 6: Create Bootstrapper Bundle (Optional)
# ============================================================================

if ($CreateBundle) {
    Write-Host "Creating bootstrapper bundle..." -ForegroundColor Yellow

    $BundleWxs = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle Name="Witnessd"
          Version="$MsiVersion"
          Manufacturer="Writers Logic"
          UpgradeCode="A1B2C3D4-E5F6-7890-ABCD-000000000002"
          IconSourceFile="$BuildDir\witnessd.ico"
          SplashScreenSourceFile="$BuildDir\splash.bmp">

    <BootstrapperApplication>
      <bal:WixStandardBootstrapperApplication
        LicenseFile="$BuildDir\license.rtf"
        Theme="hyperlinkLicense"
        LogoFile="$BuildDir\logo.png" />
    </BootstrapperApplication>

    <Chain>
      <!-- Prerequisites -->
      <PackageGroupRef Id="NetFx48Redist" />

      <!-- Witnessd MSI -->
      <MsiPackage Id="WitnessdMsi"
                  SourceFile="$MsiOutput"
                  Vital="yes" />
    </Chain>
  </Bundle>
</Wix>
"@

    $BundleWxsPath = "$WixObjDir\Bundle.wxs"
    $BundleWxs | Out-File -FilePath $BundleWxsPath -Encoding utf8

    $BundleOutput = "$OutputDir\witnessd-$Version-$Architecture-setup.exe"

    $BundleArgs = @(
        "build",
        "-arch", $Architecture,
        "-ext", "WixToolset.Bal.wixext",
        "-ext", "WixToolset.NetFx.wixext",
        "-o", $BundleOutput,
        $BundleWxsPath
    )

    if ($WixCmd -is [string]) {
        Invoke-Expression "$WixCmd $($BundleArgs -join ' ')"
    } else {
        & $WixCmd $BundleArgs
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Bundle creation failed (this is optional)"
    } else {
        Write-Host "  Bundle built: $BundleOutput" -ForegroundColor Green

        if ($Sign) {
            Write-Host "Signing bundle..." -ForegroundColor Yellow
            & $SignTool sign /sha1 $CertificateThumbprint /tr $TimestampServer /td sha256 /fd sha256 /v $BundleOutput
            if ($LASTEXITCODE -ne 0) { Write-Warning "Failed to sign bundle" }
        }
    }
}

# ============================================================================
# Summary
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:"
Write-Host "  MSI: $MsiOutput" -ForegroundColor Green

if ($CreateBundle -and (Test-Path $BundleOutput)) {
    Write-Host "  EXE: $BundleOutput" -ForegroundColor Green
}

Write-Host ""
Write-Host "Installation:"
Write-Host "  msiexec /i `"$MsiOutput`"" -ForegroundColor Yellow
Write-Host ""
Write-Host "Silent installation:"
Write-Host "  msiexec /i `"$MsiOutput`" /quiet /norestart" -ForegroundColor Yellow
Write-Host ""
