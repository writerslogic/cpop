# validate-msix.ps1
# Validate MSIX package using Windows App Certification Kit (WACK)
#
# Runs comprehensive validation including:
# - Package structure validation
# - Manifest validation
# - Binary analysis
# - Security checks
# - API compatibility
#
# Usage:
#   .\validate-msix.ps1                         # Validate most recent package
#   .\validate-msix.ps1 -Package path\to.msix   # Validate specific package
#   .\validate-msix.ps1 -SkipWACK              # Skip WACK (quick validation only)

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Package = "",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipWACK = $false,

    [Parameter(Mandatory=$false)]
    [switch]$Interactive = $false
)

$ErrorActionPreference = "Stop"

# Get paths
$ScriptDir = $PSScriptRoot
$PlatformDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$RepoRoot = (Resolve-Path (Join-Path $PlatformDir "..\..")).Path
$BuildDir = Join-Path $RepoRoot "build"
$MsixDir = Join-Path $BuildDir "msix"

if (-not $OutputDir) {
    $OutputDir = Join-Path $MsixDir "validation"
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Details = "")

    if ($Passed) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
    }
    if ($Details) {
        Write-Host "         $Details" -ForegroundColor Gray
    }
}

function Find-WindowsSDKTools {
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
                    SignTool = Join-Path $path.FullName "signtool.exe"
                }
            }
        }
    }

    return $null
}

function Find-WACK {
    # Windows App Certification Kit locations
    $wackPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\App Certification Kit\appcert.exe",
        "${env:ProgramFiles}\Windows Kits\10\App Certification Kit\appcert.exe"
    )

    foreach ($path in $wackPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

function Test-PackageStructure {
    param([string]$PackagePath)

    Write-Step "Validating package structure"

    $tempDir = Join-Path $env:TEMP "msix_validate_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    $results = @{
        Passed = $true
        Errors = @()
    }

    try {
        # Unpack package
        $tools = Find-WindowsSDKTools
        if ($tools) {
            & $tools.MakeAppx unpack /p $PackagePath /d $tempDir /o 2>&1 | Out-Null
        } else {
            # Fallback to zip extraction
            Rename-Item $PackagePath "$PackagePath.zip"
            Expand-Archive "$PackagePath.zip" -DestinationPath $tempDir -Force
            Rename-Item "$PackagePath.zip" $PackagePath
        }

        # Check manifest
        $manifestPath = Join-Path $tempDir "AppxManifest.xml"
        $hasManifest = Test-Path $manifestPath
        Write-Check "AppxManifest.xml exists" $hasManifest

        if (-not $hasManifest) {
            $results.Passed = $false
            $results.Errors += "Missing AppxManifest.xml"
        } else {
            # Validate manifest XML
            try {
                [xml]$manifest = Get-Content $manifestPath
                Write-Check "Manifest XML valid" $true

                # Check required elements
                $identity = $manifest.Package.Identity
                $hasIdentity = $null -ne $identity.Name -and $null -ne $identity.Publisher -and $null -ne $identity.Version
                Write-Check "Package identity complete" $hasIdentity "Name=$($identity.Name), Version=$($identity.Version)"

                # Check applications
                $apps = $manifest.Package.Applications.Application
                $hasApps = $null -ne $apps
                Write-Check "Applications defined" $hasApps

                if ($hasApps) {
                    foreach ($app in $apps) {
                        $hasExe = $null -ne $app.Executable
                        $exePath = Join-Path $tempDir $app.Executable
                        $exeExists = Test-Path $exePath
                        Write-Check "Application executable: $($app.Executable)" $exeExists
                        if (-not $exeExists) {
                            $results.Passed = $false
                            $results.Errors += "Missing executable: $($app.Executable)"
                        }
                    }
                }

                # Check capabilities
                $caps = $manifest.Package.Capabilities
                if ($caps) {
                    Write-Host "  Declared capabilities:" -ForegroundColor Gray
                    foreach ($cap in $caps.ChildNodes) {
                        Write-Host "    - $($cap.Name)" -ForegroundColor Gray
                    }
                }
            } catch {
                Write-Check "Manifest XML valid" $false $_.Exception.Message
                $results.Passed = $false
                $results.Errors += "Invalid manifest XML: $($_.Exception.Message)"
            }
        }

        # Check assets
        $assetsDir = Join-Path $tempDir "Assets"
        if (Test-Path $assetsDir) {
            $assetCount = (Get-ChildItem $assetsDir -Filter "*.png" -Recurse).Count
            Write-Check "Visual assets present" ($assetCount -gt 0) "$assetCount PNG files"
        } else {
            Write-Check "Visual assets present" $false "Assets directory missing"
            $results.Errors += "Missing Assets directory"
        }

    } finally {
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }

    return $results
}

function Test-PackageSignature {
    param([string]$PackagePath)

    Write-Step "Validating signature"

    $results = @{
        Passed = $true
        IsSigned = $false
        SignerName = ""
        Timestamp = $null
    }

    $tools = Find-WindowsSDKTools
    if (-not $tools) {
        Write-Check "Signature validation" $false "signtool.exe not found"
        return $results
    }

    $output = & $tools.SignTool verify /pa /v $PackagePath 2>&1

    if ($LASTEXITCODE -eq 0) {
        $results.IsSigned = $true

        # Parse signer info
        foreach ($line in $output) {
            if ($line -match "Issued to: (.+)") {
                $results.SignerName = $matches[1]
            }
            if ($line -match "Timestamp: (.+)") {
                $results.Timestamp = $matches[1]
            }
        }

        Write-Check "Package signed" $true "Signer: $($results.SignerName)"
        if ($results.Timestamp) {
            Write-Check "Timestamp present" $true $results.Timestamp
        }
    } else {
        Write-Check "Package signed" $false "Package is unsigned"
        Write-Host "         Note: Unsigned packages can still be submitted to Store" -ForegroundColor Gray
    }

    return $results
}

function Test-WithWACK {
    param([string]$PackagePath, [string]$ReportPath)

    Write-Step "Running Windows App Certification Kit"

    $wack = Find-WACK
    if (-not $wack) {
        Write-Host "  Windows App Certification Kit not found" -ForegroundColor Yellow
        Write-Host "  Install from: https://developer.microsoft.com/windows/downloads/windows-sdk/" -ForegroundColor Gray
        return $null
    }

    Write-Host "  This may take several minutes..."

    # WACK command for desktop bridge apps
    $wackArgs = @(
        "test",
        "-appxpackagepath", $PackagePath,
        "-reportoutputpath", $ReportPath
    )

    if (-not $Interactive) {
        $wackArgs += "-testid"
        $wackArgs += "38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76"
    }

    $process = Start-Process -FilePath $wack -ArgumentList $wackArgs -Wait -PassThru -NoNewWindow

    $results = @{
        ExitCode = $process.ExitCode
        ReportPath = $ReportPath
        Passed = $false
        FailedTests = @()
    }

    if (Test-Path $ReportPath) {
        try {
            [xml]$report = Get-Content $ReportPath
            $results.Passed = $report.REPORT.OVERALL_RESULT -eq "PASS"

            # Find failed tests
            foreach ($test in $report.REPORT.REQUIREMENTS.REQUIREMENT) {
                if ($test.RESULT -eq "FAIL") {
                    $results.FailedTests += $test.TITLE
                }
            }
        } catch {
            Write-Warning "Could not parse WACK report"
        }
    }

    if ($results.Passed) {
        Write-Check "WACK validation" $true
    } else {
        Write-Check "WACK validation" $false

        if ($results.FailedTests.Count -gt 0) {
            Write-Host "  Failed tests:" -ForegroundColor Red
            foreach ($test in $results.FailedTests) {
                Write-Host "    - $test" -ForegroundColor Red
            }
        }
    }

    Write-Host "  Full report: $ReportPath" -ForegroundColor Gray

    return $results
}

function Test-StoreReadiness {
    param(
        [hashtable]$StructureResults,
        [hashtable]$SignatureResults,
        [hashtable]$WACKResults
    )

    Write-Step "Store Submission Readiness"

    $ready = $true
    $warnings = @()

    # Structure must pass
    if (-not $StructureResults.Passed) {
        Write-Check "Package structure" $false
        $ready = $false
    } else {
        Write-Check "Package structure" $true
    }

    # Signature not required for Store (Microsoft signs)
    if ($SignatureResults.IsSigned) {
        Write-Check "Code signing" $true "(optional for Store)"
    } else {
        Write-Host "  [INFO] Package unsigned - OK for Store submission" -ForegroundColor Yellow
        $warnings += "Package is unsigned. Microsoft will sign during Store ingestion."
    }

    # WACK must pass for Store
    if ($WACKResults) {
        if ($WACKResults.Passed) {
            Write-Check "WACK certification" $true
        } else {
            Write-Check "WACK certification" $false
            $ready = $false
        }
    } else {
        Write-Host "  [SKIP] WACK certification not run" -ForegroundColor Yellow
        $warnings += "Run WACK validation before Store submission"
    }

    return @{
        Ready = $ready
        Warnings = $warnings
    }
}

# Main execution
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " Witnessd MSIX Validation" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Find package
if (-not $Package) {
    $recent = Get-ChildItem $MsixDir -Filter "*.msix*" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "\.msixupload$" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($recent) {
        $Package = $recent.FullName
    } else {
        throw "No packages found in $MsixDir. Run create-msix.ps1 first."
    }
}

if (-not (Test-Path $Package)) {
    throw "Package not found: $Package"
}

$packageName = [System.IO.Path]::GetFileName($Package)
Write-Host "Package: $packageName"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Run validations
$structureResults = Test-PackageStructure -PackagePath $Package
$signatureResults = Test-PackageSignature -PackagePath $Package

$wackResults = $null
if (-not $SkipWACK) {
    $wackReportPath = Join-Path $OutputDir "wack_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    $wackResults = Test-WithWACK -PackagePath $Package -ReportPath $wackReportPath
}

# Store readiness check
$readiness = Test-StoreReadiness -StructureResults $structureResults `
    -SignatureResults $signatureResults -WACKResults $wackResults

# Summary
Write-Step "Validation Summary"

$overallPass = $structureResults.Passed -and ($wackResults -eq $null -or $wackResults.Passed)

if ($overallPass) {
    Write-Host ""
    Write-Host "Validation PASSED" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Validation FAILED" -ForegroundColor Red

    if ($structureResults.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors:" -ForegroundColor Red
        foreach ($err in $structureResults.Errors) {
            Write-Host "  - $err" -ForegroundColor Red
        }
    }
}

if ($readiness.Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($warn in $readiness.Warnings) {
        Write-Host "  - $warn" -ForegroundColor Yellow
    }
}

Write-Host ""
if ($readiness.Ready) {
    Write-Host "Package is READY for Microsoft Store submission" -ForegroundColor Green
} else {
    Write-Host "Package is NOT READY for Microsoft Store submission" -ForegroundColor Red
}

Write-Host ""
Write-Host "Validation reports saved to: $OutputDir"

# Return exit code
if ($overallPass) {
    exit 0
} else {
    exit 1
}
