# build-binaries.ps1
# Build Go binaries for Windows MSIX packaging
#
# Builds:
# - witnessd.exe (main daemon/CLI)
# - witnessctl.exe (control utility)
# - witnessd-tsf.dll (Text Services Framework provider)
#
# Usage:
#   .\build-binaries.ps1                    # Build for current architecture
#   .\build-binaries.ps1 -Architecture x64  # Build for x64 only
#   .\build-binaries.ps1 -Architecture arm64 -Configuration Release

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "arm64", "both")]
    [string]$Architecture = "x64",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory=$false)]
    [string]$Version = "1.0.0",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipTSF = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Clean = $false
)

$ErrorActionPreference = "Stop"

# Get repository root (4 levels up from this script)
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..\")).Path
$ProjectRoot = $RepoRoot

# Default output directory
if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "build"
}

# Build metadata
$BuildTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$Commit = ""
try {
    $Commit = (git -C $RepoRoot rev-parse --short HEAD 2>$null)
    if (-not $Commit) { $Commit = "unknown" }
} catch {
    $Commit = "unknown"
}

# Go ldflags for version info
$LdFlags = "-s -w -X main.Version=$Version -X main.BuildTime=$BuildTime -X main.Commit=$Commit"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-GoInstalled {
    try {
        $null = & go version
        return $true
    } catch {
        return $false
    }
}

function Test-MSVCInstalled {
    # Check for Visual Studio Build Tools
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -property installationPath 2>$null
        return $null -ne $vsPath
    }
    return $false
}

function Get-VSDevEnv {
    param([string]$Arch)

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWhere)) {
        throw "Visual Studio not found"
    }

    $vsPath = & $vsWhere -latest -property installationPath
    $vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"

    if (-not (Test-Path $vcvarsPath)) {
        throw "vcvarsall.bat not found at $vcvarsPath"
    }

    # Get the environment after running vcvarsall
    $archArg = if ($Arch -eq "arm64") { "arm64" } else { "x64" }
    $envOutput = cmd /c "`"$vcvarsPath`" $archArg >nul 2>&1 && set"

    $env = @{}
    foreach ($line in $envOutput) {
        if ($line -match "^([^=]+)=(.*)$") {
            $env[$matches[1]] = $matches[2]
        }
    }
    return $env
}

function Build-GoBinary {
    param(
        [string]$Name,
        [string]$Package,
        [string]$GoArch,
        [string]$OutDir
    )

    $outPath = Join-Path $OutDir "$Name.exe"
    Write-Host "Building $Name for windows/$GoArch..."

    $env:GOOS = "windows"
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = "0"

    Push-Location $ProjectRoot
    try {
        & go build -trimpath -ldflags "$LdFlags" -o $outPath $Package

        if ($LASTEXITCODE -ne 0) {
            throw "Go build failed for $Name"
        }

        $fileInfo = Get-Item $outPath
        Write-Host "  Created: $outPath ($([Math]::Round($fileInfo.Length / 1MB, 2)) MB)" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

function Build-TSFLibrary {
    param(
        [string]$GoArch,
        [string]$OutDir
    )

    Write-Host "Building TSF library for windows/$GoArch..."

    # Step 1: Build Go code as C archive
    $archiveDir = Join-Path $OutDir "tsf_build"
    New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null

    $archivePath = Join-Path $archiveDir "witnessd.a"
    $headerPath = Join-Path $archiveDir "witnessd.h"

    $env:GOOS = "windows"
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = "1"

    # Set appropriate C compiler for cross-compilation
    if ($GoArch -eq "arm64" -and $env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
        $env:CC = "aarch64-w64-mingw32-gcc"
    }

    Push-Location $ProjectRoot
    try {
        & go build -buildmode=c-archive -trimpath -o $archivePath ./cmd/witnessd-tsf

        if ($LASTEXITCODE -ne 0) {
            throw "Go c-archive build failed for TSF"
        }

        Write-Host "  Created Go archive: $archivePath" -ForegroundColor Green
    } finally {
        Pop-Location
    }

    # Step 2: Compile C++ TSF implementation with MSVC
    if (Test-MSVCInstalled) {
        $vsArch = if ($GoArch -eq "arm64") { "arm64" } else { "x64" }

        Write-Host "  Compiling TSF C++ code with MSVC ($vsArch)..."

        $tsfSourceDir = Join-Path $ProjectRoot "cmd\witnessd-tsf\tsf"
        $dllPath = Join-Path $OutDir "witnessd-tsf.dll"

        # Get Visual Studio environment
        $vsEnv = Get-VSDevEnv -Arch $vsArch

        # Save current environment
        $savedEnv = @{}
        foreach ($key in $vsEnv.Keys) {
            $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key)
            [Environment]::SetEnvironmentVariable($key, $vsEnv[$key])
        }

        try {
            # Compile with cl.exe
            $clArgs = @(
                "/nologo",
                "/EHsc",
                "/LD",
                "/MD",
                "/O2",
                "/DNDEBUG",
                "/I$archiveDir",
                "$tsfSourceDir\witnessd_tsf.cpp",
                $archivePath,
                "kernel32.lib",
                "user32.lib",
                "ole32.lib",
                "oleaut32.lib",
                "advapi32.lib",
                "shlwapi.lib",
                "/link",
                "/DLL",
                "/OUT:$dllPath"
            )

            & cl.exe @clArgs

            if ($LASTEXITCODE -ne 0) {
                throw "MSVC compilation failed for TSF DLL"
            }

            $fileInfo = Get-Item $dllPath
            Write-Host "  Created: $dllPath ($([Math]::Round($fileInfo.Length / 1KB, 2)) KB)" -ForegroundColor Green
        } finally {
            # Restore environment
            foreach ($key in $savedEnv.Keys) {
                [Environment]::SetEnvironmentVariable($key, $savedEnv[$key])
            }
        }
    } else {
        Write-Warning "Visual Studio not found. TSF DLL requires MSVC to build."
        Write-Warning "Install Visual Studio Build Tools with C++ workload."
    }
}

# Main build process
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " Witnessd Windows Build" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Version:       $Version"
Write-Host "Configuration: $Configuration"
Write-Host "Architecture:  $Architecture"
Write-Host "Output:        $OutputDir"
Write-Host "Commit:        $Commit"
Write-Host ""

# Verify Go is installed
if (-not (Test-GoInstalled)) {
    Write-Error "Go is not installed or not in PATH"
    exit 1
}

$goVersion = (& go version)
Write-Host "Go: $goVersion"

# Clean if requested
if ($Clean -and (Test-Path $OutputDir)) {
    Write-Step "Cleaning build directory"
    Remove-Item -Recurse -Force $OutputDir
}

# Determine architectures to build
$archList = @()
switch ($Architecture) {
    "x64" { $archList = @(@{ Name = "x64"; GoArch = "amd64" }) }
    "arm64" { $archList = @(@{ Name = "arm64"; GoArch = "arm64" }) }
    "both" { $archList = @(
        @{ Name = "x64"; GoArch = "amd64" },
        @{ Name = "arm64"; GoArch = "arm64" }
    )}
}

foreach ($arch in $archList) {
    $archOutDir = Join-Path $OutputDir "windows_$($arch.Name)"
    New-Item -ItemType Directory -Path $archOutDir -Force | Out-Null

    Write-Step "Building for Windows $($arch.Name)"

    # Build main executables
    Build-GoBinary -Name "witnessd" -Package "./cmd/witnessd" -GoArch $arch.GoArch -OutDir $archOutDir
    Build-GoBinary -Name "witnessctl" -Package "./cmd/witnessctl" -GoArch $arch.GoArch -OutDir $archOutDir

    # Build TSF DLL (requires CGO and MSVC)
    if (-not $SkipTSF) {
        Build-TSFLibrary -GoArch $arch.GoArch -OutDir $archOutDir
    } else {
        Write-Host "Skipping TSF DLL build" -ForegroundColor Yellow
    }
}

Write-Step "Build Summary"

foreach ($arch in $archList) {
    $archOutDir = Join-Path $OutputDir "windows_$($arch.Name)"
    Write-Host ""
    Write-Host "$($arch.Name):" -ForegroundColor Cyan

    Get-ChildItem $archOutDir -File | ForEach-Object {
        $size = if ($_.Length -ge 1MB) {
            "$([Math]::Round($_.Length / 1MB, 2)) MB"
        } else {
            "$([Math]::Round($_.Length / 1KB, 2)) KB"
        }
        Write-Host "  $($_.Name) - $size"
    }
}

Write-Host ""
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Generate visual assets: .\assets\generate-assets.ps1"
Write-Host "  2. Create MSIX package: .\scripts\create-msix.ps1"
Write-Host "  3. Sign the package: .\scripts\sign-msix.ps1"
