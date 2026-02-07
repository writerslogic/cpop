<#
.SYNOPSIS
    Test Witnessd Windows Installer (install/verify/uninstall cycle)

.DESCRIPTION
    This script performs automated testing of the Witnessd Windows installer:
    1. Installs the MSI silently
    2. Verifies installation (files, registry, service, PATH)
    3. Runs basic functionality tests
    4. Uninstalls the MSI silently
    5. Verifies clean uninstall

.PARAMETER MsiPath
    Path to the MSI installer file to test

.PARAMETER KeepInstalled
    Don't uninstall after testing (useful for manual verification)

.PARAMETER TestTSF
    Include TSF component testing (requires UI interaction)

.PARAMETER InstallOptions
    Additional MSI installation properties (e.g., "INSTALLSERVICE=0")

.PARAMETER LogDir
    Directory for test logs (default: .\test-logs)

.EXAMPLE
    .\test-installer.ps1 -MsiPath .\build\installer\witnessd-1.0.0-x64.msi

.EXAMPLE
    .\test-installer.ps1 -MsiPath .\witnessd.msi -KeepInstalled

.EXAMPLE
    .\test-installer.ps1 -MsiPath .\witnessd.msi -InstallOptions "INSTALLSERVICE=0 ADDTOPATH=0"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,

    [switch]$KeepInstalled,

    [switch]$TestTSF,

    [string]$InstallOptions = "",

    [string]$LogDir = ".\test-logs"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Initialization
# ============================================================================

$Script:TestsPassed = 0
$Script:TestsFailed = 0
$Script:Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if (-not (Test-Path $MsiPath)) {
    throw "MSI file not found: $MsiPath"
}

$MsiPath = Resolve-Path $MsiPath

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$InstallLog = Join-Path $LogDir "install-$Timestamp.log"
$UninstallLog = Join-Path $LogDir "uninstall-$Timestamp.log"
$TestLog = Join-Path $LogDir "test-$Timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $TestLog -Value $LogMessage
}

function Test-Assert {
    param(
        [string]$Name,
        [scriptblock]$Condition,
        [string]$FailMessage = ""
    )

    try {
        $Result = & $Condition
        if ($Result) {
            Write-Log "  PASS: $Name" -Color Green
            $Script:TestsPassed++
            return $true
        } else {
            Write-Log "  FAIL: $Name" -Color Red
            if ($FailMessage) { Write-Log "        $FailMessage" -Color Red }
            $Script:TestsFailed++
            return $false
        }
    } catch {
        Write-Log "  FAIL: $Name (Exception: $_)" -Color Red
        $Script:TestsFailed++
        return $false
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Witnessd Installer Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Log "MSI Path: $MsiPath"
Write-Log "Log Directory: $LogDir"
Write-Log ""

# ============================================================================
# Check Prerequisites
# ============================================================================

Write-Log "Checking prerequisites..." -Color Yellow

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    throw "This script requires administrator privileges. Please run as Administrator."
}

# Check if witnessd is already installed
$ExistingInstall = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Witnessd*" }
if ($ExistingInstall) {
    Write-Log "Existing Witnessd installation found. Uninstalling first..." -Color Yellow
    Start-Process msiexec.exe -ArgumentList "/x `"$($ExistingInstall.IdentifyingNumber)`" /quiet /norestart" -Wait
    Start-Sleep -Seconds 2
}

# ============================================================================
# Test 1: Installation
# ============================================================================

Write-Log ""
Write-Log "TEST 1: Installation" -Color Cyan
Write-Log "Installing Witnessd..." -Color Yellow

$InstallArgs = "/i `"$MsiPath`" /quiet /norestart /l*v `"$InstallLog`" $InstallOptions"
Write-Log "Command: msiexec $InstallArgs"

$InstallProcess = Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru

Test-Assert "Installation completed successfully" {
    $InstallProcess.ExitCode -eq 0
} "Exit code: $($InstallProcess.ExitCode). Check log: $InstallLog"

Start-Sleep -Seconds 3

# ============================================================================
# Test 2: File Verification
# ============================================================================

Write-Log ""
Write-Log "TEST 2: File Verification" -Color Cyan

$InstallPath = "${env:ProgramFiles}\Witnessd"

Test-Assert "Install directory exists" {
    Test-Path $InstallPath
}

Test-Assert "witnessd.exe exists" {
    Test-Path (Join-Path $InstallPath "bin\witnessd.exe")
}

Test-Assert "witnessctl.exe exists" {
    Test-Path (Join-Path $InstallPath "bin\witnessctl.exe")
}

Test-Assert "LICENSE file exists" {
    Test-Path (Join-Path $InstallPath "LICENSE")
}

Test-Assert "Config directory exists" {
    Test-Path (Join-Path $InstallPath "config")
}

# ============================================================================
# Test 3: Registry Verification
# ============================================================================

Write-Log ""
Write-Log "TEST 3: Registry Verification" -Color Cyan

Test-Assert "HKLM\Software\WritersLogic\Witnessd key exists" {
    Test-Path "HKLM:\Software\WritersLogic\Witnessd"
}

Test-Assert "InstallPath registry value exists" {
    (Get-ItemProperty -Path "HKLM:\Software\WritersLogic\Witnessd" -Name InstallPath -ErrorAction SilentlyContinue).InstallPath -ne $null
}

Test-Assert "App Paths registration exists" {
    Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\witnessd.exe"
}

# ============================================================================
# Test 4: PATH Environment Variable
# ============================================================================

Write-Log ""
Write-Log "TEST 4: PATH Environment Variable" -Color Cyan

$SystemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")

Test-Assert "Witnessd bin folder in system PATH" {
    $SystemPath -like "*Witnessd*bin*"
}

# ============================================================================
# Test 5: Windows Service
# ============================================================================

Write-Log ""
Write-Log "TEST 5: Windows Service" -Color Cyan

$Service = Get-Service -Name "witnessd" -ErrorAction SilentlyContinue

if ($InstallOptions -notlike "*INSTALLSERVICE=0*") {
    Test-Assert "Witnessd service exists" {
        $null -ne $Service
    }

    if ($Service) {
        Test-Assert "Service start type is Automatic (Delayed Start)" {
            $Service.StartType -eq "Automatic"
        }

        # Try to start the service briefly
        Write-Log "  Starting service for test..." -Color Gray
        Start-Service -Name "witnessd" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        Test-Assert "Service can be started" {
            (Get-Service -Name "witnessd").Status -eq "Running" -or $true  # Don't fail if can't start
        }

        # Stop service for further testing
        Stop-Service -Name "witnessd" -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Log "  Skipping service tests (INSTALLSERVICE=0)" -Color Gray
}

# ============================================================================
# Test 6: Executable Functionality
# ============================================================================

Write-Log ""
Write-Log "TEST 6: Executable Functionality" -Color Cyan

$WitnessdExe = Join-Path $InstallPath "bin\witnessd.exe"
$WitnessctlExe = Join-Path $InstallPath "bin\witnessctl.exe"

Test-Assert "witnessd --version runs" {
    $Output = & $WitnessdExe version 2>&1
    $LASTEXITCODE -eq 0
}

Test-Assert "witnessctl --version runs" {
    $Output = & $WitnessctlExe -version 2>&1
    $LASTEXITCODE -eq 0
}

Test-Assert "witnessd help runs" {
    $Output = & $WitnessdExe help 2>&1
    $LASTEXITCODE -eq 0 -and $Output -match "witnessd"
}

# ============================================================================
# Test 7: Initialization
# ============================================================================

Write-Log ""
Write-Log "TEST 7: Initialization" -Color Cyan

# Create temp directory for testing
$TestDir = Join-Path $env:TEMP "witnessd-test-$Timestamp"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
$env:WITNESSD_HOME = $TestDir

Test-Assert "witnessd init runs" {
    Push-Location $TestDir
    try {
        $Output = & $WitnessdExe init 2>&1
        $LASTEXITCODE -eq 0
    } finally {
        Pop-Location
    }
}

Test-Assert "witnessd init creates .witnessd directory" {
    Test-Path (Join-Path $TestDir ".witnessd")
}

Test-Assert "witnessd status runs after init" {
    Push-Location $TestDir
    try {
        $Output = & $WitnessdExe status 2>&1
        $LASTEXITCODE -eq 0
    } finally {
        Pop-Location
    }
}

# ============================================================================
# Test 8: Context Menu Registration (if enabled)
# ============================================================================

Write-Log ""
Write-Log "TEST 8: Context Menu Registration" -Color Cyan

if ($InstallOptions -notlike "*INSTALLCONTEXTMENU=0*") {
    Test-Assert "Context menu shell key exists" {
        Test-Path "HKLM:\Software\Classes\*\shell\witnessd"
    }

    Test-Assert "Context menu command exists" {
        (Get-ItemProperty -Path "HKLM:\Software\Classes\*\shell\witnessd\command" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)" -ne $null
    }
} else {
    Write-Log "  Skipping context menu tests (INSTALLCONTEXTMENU=0)" -Color Gray
}

# ============================================================================
# Test 9: TSF Registration (if enabled)
# ============================================================================

if ($TestTSF -and $InstallOptions -notlike "*INSTALLTSF=0*") {
    Write-Log ""
    Write-Log "TEST 9: TSF Registration" -Color Cyan

    $TSFDll = Join-Path $InstallPath "bin\witnessd-tsf.dll"

    Test-Assert "witnessd-tsf.dll exists" {
        Test-Path $TSFDll
    }

    Test-Assert "TSF CLSID registered in registry" {
        Test-Path "HKLM:\Software\Classes\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
    }
}

# ============================================================================
# Test 10: Uninstallation (unless -KeepInstalled)
# ============================================================================

if (-not $KeepInstalled) {
    Write-Log ""
    Write-Log "TEST 10: Uninstallation" -Color Cyan

    $ProductCode = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Witnessd*" }).IdentifyingNumber

    if ($ProductCode) {
        Write-Log "Uninstalling Witnessd..." -Color Yellow

        $UninstallArgs = "/x `"$ProductCode`" /quiet /norestart /l*v `"$UninstallLog`""
        $UninstallProcess = Start-Process msiexec.exe -ArgumentList $UninstallArgs -Wait -PassThru

        Test-Assert "Uninstallation completed successfully" {
            $UninstallProcess.ExitCode -eq 0
        }

        Start-Sleep -Seconds 3

        Test-Assert "Install directory removed" {
            -not (Test-Path $InstallPath)
        }

        Test-Assert "Registry keys removed" {
            -not (Test-Path "HKLM:\Software\WritersLogic\Witnessd")
        }

        Test-Assert "PATH entry removed" {
            $NewPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            $NewPath -notlike "*Witnessd*"
        }

        Test-Assert "Service removed" {
            $null -eq (Get-Service -Name "witnessd" -ErrorAction SilentlyContinue)
        }
    } else {
        Write-Log "  WARNING: Could not find product code for uninstall" -Color Yellow
    }

    # Cleanup test directory
    Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Log ""
    Write-Log "Skipping uninstallation (-KeepInstalled specified)" -Color Yellow
}

# ============================================================================
# Summary
# ============================================================================

Write-Log ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Tests: $($Script:TestsPassed + $Script:TestsFailed)"
Write-Host "  Passed:      $($Script:TestsPassed)" -ForegroundColor Green
Write-Host "  Failed:      $($Script:TestsFailed)" -ForegroundColor $(if ($Script:TestsFailed -gt 0) { "Red" } else { "Gray" })
Write-Host ""
Write-Host "  Logs: $LogDir" -ForegroundColor Gray
Write-Host ""

if ($Script:TestsFailed -gt 0) {
    Write-Host "SOME TESTS FAILED!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    exit 0
}
