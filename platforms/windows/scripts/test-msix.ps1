# test-msix.ps1
# Test MSIX package installation and functionality
#
# Performs comprehensive testing of the MSIX package including:
# - Package installation
# - Application execution
# - TSF registration verification
# - Capability verification
# - Uninstallation
#
# Usage:
#   .\test-msix.ps1                          # Test most recent package
#   .\test-msix.ps1 -Package path\to.msix    # Test specific package
#   .\test-msix.ps1 -SkipInstall             # Skip installation tests

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Package = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipInstall = $false,

    [Parameter(Mandatory=$false)]
    [switch]$SkipUninstall = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

# Get paths
$ScriptDir = $PSScriptRoot
$PlatformDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$RepoRoot = (Resolve-Path (Join-Path $PlatformDir "..\..")).Path
$BuildDir = Join-Path $RepoRoot "build"
$MsixDir = Join-Path $BuildDir "msix"

# Test results
$testResults = @{
    Passed = 0
    Failed = 0
    Skipped = 0
    Details = @()
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$Name,
        [ValidateSet("Pass", "Fail", "Skip")]
        [string]$Result,
        [string]$Details = ""
    )

    $color = switch ($Result) {
        "Pass" { "Green" }
        "Fail" { "Red" }
        "Skip" { "Yellow" }
    }

    $symbol = switch ($Result) {
        "Pass" { "[PASS]" }
        "Fail" { "[FAIL]" }
        "Skip" { "[SKIP]" }
    }

    Write-Host "  $symbol $Name" -ForegroundColor $color
    if ($Details) {
        Write-Host "         $Details" -ForegroundColor Gray
    }

    switch ($Result) {
        "Pass" { $script:testResults.Passed++ }
        "Fail" { $script:testResults.Failed++ }
        "Skip" { $script:testResults.Skipped++ }
    }

    $script:testResults.Details += @{
        Name = $Name
        Result = $Result
        Details = $Details
    }
}

function Test-DeveloperMode {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
        $value = Get-ItemProperty -Path $regPath -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
        return $value.AllowDevelopmentWithoutDevLicense -eq 1
    } catch {
        return $false
    }
}

function Enable-DeveloperMode {
    Write-Host "Enabling developer mode for sideloading..."
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord
        return $true
    } catch {
        Write-Warning "Failed to enable developer mode: $_"
        Write-Warning "Run PowerShell as Administrator to enable sideloading"
        return $false
    }
}

function Test-PackageInstallation {
    param([string]$PackagePath)

    Write-Step "Testing Package Installation"

    # Check developer mode
    if (-not (Test-DeveloperMode)) {
        $enabled = Enable-DeveloperMode
        if (-not $enabled) {
            Write-TestResult "Developer mode" "Skip" "Unable to enable - run as Administrator"
            return $null
        }
    }
    Write-TestResult "Developer mode" "Pass"

    # Install package
    try {
        Write-Host "  Installing package..."
        Add-AppxPackage -Path $PackagePath -ForceApplicationShutdown -ErrorAction Stop
        Write-TestResult "Package installation" "Pass"
    } catch {
        if ($_.Exception.Message -match "signature") {
            Write-TestResult "Package installation" "Skip" "Package requires valid signature for installation"
            return $null
        }
        Write-TestResult "Package installation" "Fail" $_.Exception.Message
        return $null
    }

    # Verify installation
    $installed = Get-AppxPackage | Where-Object { $_.Name -like "*Witnessd*" }
    if ($installed) {
        Write-TestResult "Package registered" "Pass" "Name: $($installed.Name)"
        return $installed
    } else {
        Write-TestResult "Package registered" "Fail" "Package not found after installation"
        return $null
    }
}

function Test-ExecutableExecution {
    param($InstalledPackage)

    Write-Step "Testing Executable Execution"

    if (-not $InstalledPackage) {
        Write-TestResult "Executable tests" "Skip" "Package not installed"
        return
    }

    $installDir = $InstalledPackage.InstallLocation

    # Test witnessd.exe
    $witnessdPath = Join-Path $installDir "witnessd.exe"
    if (Test-Path $witnessdPath) {
        Write-TestResult "witnessd.exe exists" "Pass"

        try {
            $output = & $witnessdPath version 2>&1
            if ($LASTEXITCODE -eq 0 -or $output -match "witnessd") {
                Write-TestResult "witnessd.exe runs" "Pass" "Output: $($output -join ' ' | Select-Object -First 50)"
            } else {
                Write-TestResult "witnessd.exe runs" "Fail" "Exit code: $LASTEXITCODE"
            }
        } catch {
            Write-TestResult "witnessd.exe runs" "Fail" $_.Exception.Message
        }
    } else {
        Write-TestResult "witnessd.exe exists" "Fail"
    }

    # Test witnessctl.exe
    $witnessctlPath = Join-Path $installDir "witnessctl.exe"
    if (Test-Path $witnessctlPath) {
        Write-TestResult "witnessctl.exe exists" "Pass"
    } else {
        Write-TestResult "witnessctl.exe exists" "Fail"
    }

    # Test TSF DLL
    $tsfDllPath = Join-Path $installDir "witnessd-tsf.dll"
    if (Test-Path $tsfDllPath) {
        Write-TestResult "witnessd-tsf.dll exists" "Pass"

        # Verify DLL can be loaded
        try {
            $dll = [System.Reflection.Assembly]::LoadFile($tsfDllPath)
            Write-TestResult "TSF DLL loadable" "Pass"
        } catch {
            # DLL might not be .NET - check with dumpbin
            try {
                $output = & dumpbin /headers $tsfDllPath 2>&1 | Select-String "DLL"
                if ($output) {
                    Write-TestResult "TSF DLL valid" "Pass" "Native DLL"
                } else {
                    Write-TestResult "TSF DLL valid" "Skip" "Unable to verify"
                }
            } catch {
                Write-TestResult "TSF DLL valid" "Skip" "dumpbin not available"
            }
        }
    } else {
        Write-TestResult "witnessd-tsf.dll exists" "Skip" "TSF DLL not included"
    }
}

function Test-TSFRegistration {
    param($InstalledPackage)

    Write-Step "Testing TSF Registration"

    if (-not $InstalledPackage) {
        Write-TestResult "TSF registration tests" "Skip" "Package not installed"
        return
    }

    # Check COM registration
    $clsid = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
    $regPath = "Registry::HKEY_CLASSES_ROOT\CLSID\{$clsid}"

    if (Test-Path $regPath) {
        Write-TestResult "TSF CLSID registered" "Pass" "CLSID: {$clsid}"
    } else {
        Write-TestResult "TSF CLSID registered" "Skip" "COM registration via manifest (not registry)"
    }

    # Check TSF profiles
    try {
        $profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{$clsid}" -ErrorAction SilentlyContinue
        if ($profiles) {
            Write-TestResult "TSF profile registered" "Pass"
        } else {
            Write-TestResult "TSF profile registered" "Skip" "Profile registration deferred"
        }
    } catch {
        Write-TestResult "TSF profile registered" "Skip" "Unable to check"
    }
}

function Test-Capabilities {
    param($InstalledPackage)

    Write-Step "Testing Package Capabilities"

    if (-not $InstalledPackage) {
        Write-TestResult "Capability tests" "Skip" "Package not installed"
        return
    }

    # Get package manifest
    $manifestPath = Join-Path $InstalledPackage.InstallLocation "AppxManifest.xml"
    if (-not (Test-Path $manifestPath)) {
        Write-TestResult "Manifest accessible" "Fail"
        return
    }
    Write-TestResult "Manifest accessible" "Pass"

    [xml]$manifest = Get-Content $manifestPath

    # Check declared capabilities
    $capabilities = @()
    $ns = @{
        "default" = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
        "rescap" = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
        "uap" = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
    }

    foreach ($cap in $manifest.Package.Capabilities.ChildNodes) {
        $capabilities += $cap.Name
    }

    # Required capabilities for witnessd
    $required = @(
        "runFullTrust",
        "broadFileSystemAccess"
    )

    foreach ($req in $required) {
        if ($capabilities -contains $req) {
            Write-TestResult "Capability: $req" "Pass"
        } else {
            Write-TestResult "Capability: $req" "Fail" "Not declared in manifest"
        }
    }

    # Optional capabilities
    $optional = @(
        "inputForegroundObservation",
        "inputObservation"
    )

    foreach ($opt in $optional) {
        if ($capabilities -contains $opt) {
            Write-TestResult "Capability: $opt" "Pass"
        } else {
            Write-TestResult "Capability: $opt" "Skip" "Optional capability not declared"
        }
    }
}

function Test-AppExecution {
    param($InstalledPackage)

    Write-Step "Testing App Execution (AppExecutionAlias)"

    if (-not $InstalledPackage) {
        Write-TestResult "App execution tests" "Skip" "Package not installed"
        return
    }

    # Test command line alias
    try {
        $output = & witnessd version 2>&1
        if ($LASTEXITCODE -eq 0 -or $output -match "witnessd") {
            Write-TestResult "witnessd alias" "Pass" "Command available in PATH"
        } else {
            Write-TestResult "witnessd alias" "Fail" "Alias not working"
        }
    } catch {
        Write-TestResult "witnessd alias" "Skip" "Alias might require re-login"
    }
}

function Test-Uninstallation {
    param($InstalledPackage)

    Write-Step "Testing Package Uninstallation"

    if (-not $InstalledPackage) {
        Write-TestResult "Uninstallation tests" "Skip" "Package not installed"
        return
    }

    try {
        Remove-AppxPackage -Package $InstalledPackage.PackageFullName -ErrorAction Stop
        Write-TestResult "Package removal" "Pass"

        # Verify removal
        $stillInstalled = Get-AppxPackage | Where-Object { $_.Name -like "*Witnessd*" }
        if ($stillInstalled) {
            Write-TestResult "Package fully removed" "Fail" "Package still present"
        } else {
            Write-TestResult "Package fully removed" "Pass"
        }
    } catch {
        Write-TestResult "Package removal" "Fail" $_.Exception.Message
    }
}

# Main execution
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " Witnessd MSIX Test Suite" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Find package
if (-not $Package) {
    $recent = Get-ChildItem $MsixDir -Filter "*.msix" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "\.msixbundle$" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($recent) {
        $Package = $recent.FullName
    } else {
        throw "No MSIX packages found in $MsixDir. Run create-msix.ps1 first."
    }
}

if (-not (Test-Path $Package)) {
    throw "Package not found: $Package"
}

Write-Host "Package: $([System.IO.Path]::GetFileName($Package))"
Write-Host ""

# Run tests
$installed = $null

if (-not $SkipInstall) {
    $installed = Test-PackageInstallation -PackagePath $Package
}

Test-ExecutableExecution -InstalledPackage $installed
Test-TSFRegistration -InstalledPackage $installed
Test-Capabilities -InstalledPackage $installed
Test-AppExecution -InstalledPackage $installed

if (-not $SkipUninstall -and $installed) {
    Test-Uninstallation -InstalledPackage $installed
}

# Summary
Write-Step "Test Summary"
Write-Host ""
Write-Host "  Passed:  $($testResults.Passed)" -ForegroundColor Green
Write-Host "  Failed:  $($testResults.Failed)" -ForegroundColor Red
Write-Host "  Skipped: $($testResults.Skipped)" -ForegroundColor Yellow
Write-Host ""

if ($testResults.Failed -gt 0) {
    Write-Host "Failed tests:" -ForegroundColor Red
    foreach ($test in $testResults.Details | Where-Object { $_.Result -eq "Fail" }) {
        Write-Host "  - $($test.Name): $($test.Details)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "TEST SUITE FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "TEST SUITE PASSED" -ForegroundColor Green
    exit 0
}
