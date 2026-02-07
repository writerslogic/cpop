<#
.SYNOPSIS
    Sign Witnessd Windows binaries and installer

.DESCRIPTION
    This script signs all Witnessd executables, DLLs, and installers using
    Authenticode code signing. Supports both certificate file and Windows
    Certificate Store based signing.

.PARAMETER InputPath
    Path to file or directory to sign. If directory, signs all EXE, DLL, and MSI files.

.PARAMETER CertificateFile
    Path to PFX certificate file for signing

.PARAMETER CertificatePassword
    Password for PFX certificate file

.PARAMETER CertificateThumbprint
    Thumbprint of certificate in Windows Certificate Store

.PARAMETER TimestampServer
    Timestamp server URL (default: http://timestamp.digicert.com)

.PARAMETER HashAlgorithm
    Hash algorithm for signature (default: sha256)

.PARAMETER Verbose
    Show detailed signing information

.EXAMPLE
    .\sign-installer.ps1 -InputPath .\build\installer -CertificateThumbprint "ABC123..."

.EXAMPLE
    .\sign-installer.ps1 -InputPath .\build\installer\witnessd.msi -CertificateFile cert.pfx -CertificatePassword $pwd

.EXAMPLE
    .\sign-installer.ps1 -InputPath .\build -CertificateThumbprint "ABC123..." -TimestampServer "http://ts.ssl.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$CertificateFile,

    [SecureString]$CertificatePassword,

    [string]$CertificateThumbprint,

    [string]$TimestampServer = "http://timestamp.digicert.com",

    [ValidateSet("sha256", "sha384", "sha512")]
    [string]$HashAlgorithm = "sha256"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Find SignTool
# ============================================================================

function Find-SignTool {
    # Check PATH
    $SignTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($SignTool) { return $SignTool.Source }

    # Check Windows SDK paths
    $SdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x64\signtool.exe"
    )

    foreach ($Pattern in $SdkPaths) {
        $Found = Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue |
            Sort-Object { [Version]($_.FullName -replace '.*\\(\d+\.\d+\.\d+\.\d+)\\.*', '$1') } -Descending |
            Select-Object -First 1
        if ($Found) { return $Found.FullName }
    }

    throw "signtool.exe not found. Please install Windows SDK or add signtool to PATH."
}

# ============================================================================
# Validate Parameters
# ============================================================================

if (-not $CertificateFile -and -not $CertificateThumbprint) {
    throw "Either -CertificateFile or -CertificateThumbprint must be specified."
}

if ($CertificateFile -and -not (Test-Path $CertificateFile)) {
    throw "Certificate file not found: $CertificateFile"
}

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}

$SignToolPath = Find-SignTool
Write-Host "Using signtool: $SignToolPath" -ForegroundColor Cyan

# ============================================================================
# Collect Files to Sign
# ============================================================================

$FilesToSign = @()

if (Test-Path $InputPath -PathType Leaf) {
    $FilesToSign += Get-Item $InputPath
} else {
    $Extensions = @("*.exe", "*.dll", "*.msi", "*.msix", "*.appx")
    foreach ($Ext in $Extensions) {
        $FilesToSign += Get-ChildItem -Path $InputPath -Filter $Ext -Recurse
    }
}

if ($FilesToSign.Count -eq 0) {
    Write-Warning "No signable files found in: $InputPath"
    exit 0
}

Write-Host ""
Write-Host "Files to sign: $($FilesToSign.Count)" -ForegroundColor Cyan
$FilesToSign | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Write-Host ""

# ============================================================================
# Build SignTool Arguments
# ============================================================================

$SignArgs = @("sign")

if ($CertificateThumbprint) {
    $SignArgs += @("/sha1", $CertificateThumbprint)
} elseif ($CertificateFile) {
    $SignArgs += @("/f", $CertificateFile)
    if ($CertificatePassword) {
        $Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
        try {
            $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
            $SignArgs += @("/p", $PlainPassword)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
        }
    }
}

# Timestamp
$SignArgs += @("/tr", $TimestampServer, "/td", $HashAlgorithm)

# File digest algorithm
$SignArgs += @("/fd", $HashAlgorithm)

# Description
$SignArgs += @("/d", "Witnessd - Cryptographic Authorship Witnessing")
$SignArgs += @("/du", "https://github.com/writerslogic/witnessd")

# Verbose
$SignArgs += "/v"

# ============================================================================
# Sign Files
# ============================================================================

$Succeeded = 0
$Failed = 0

foreach ($File in $FilesToSign) {
    Write-Host "Signing: $($File.Name)..." -ForegroundColor Yellow -NoNewline

    $FileArgs = $SignArgs + @($File.FullName)

    try {
        $Output = & $SignToolPath @FileArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host " OK" -ForegroundColor Green
            $Succeeded++
        } else {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host $Output -ForegroundColor Red
            $Failed++
        }
    } catch {
        Write-Host " ERROR" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        $Failed++
    }
}

# ============================================================================
# Verify Signatures
# ============================================================================

Write-Host ""
Write-Host "Verifying signatures..." -ForegroundColor Cyan

foreach ($File in $FilesToSign) {
    $VerifyOutput = & $SignToolPath verify /pa /v $File.FullName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  $($File.Name): " -NoNewline
        Write-Host "VALID" -ForegroundColor Green
    } else {
        Write-Host "  $($File.Name): " -NoNewline
        Write-Host "INVALID" -ForegroundColor Red
    }
}

# ============================================================================
# Summary
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Signing Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total files: $($FilesToSign.Count)"
Write-Host "  Succeeded:   $Succeeded" -ForegroundColor Green
Write-Host "  Failed:      $Failed" -ForegroundColor $(if ($Failed -gt 0) { "Red" } else { "Gray" })
Write-Host ""

if ($Failed -gt 0) {
    Write-Warning "Some files failed to sign!"
    exit 1
}

Write-Host "All files signed successfully!" -ForegroundColor Green
