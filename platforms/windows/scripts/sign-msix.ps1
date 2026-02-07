# sign-msix.ps1
# Sign MSIX package with Authenticode certificate
#
# Signs MSIX/MSIXBUNDLE packages for distribution.
# For Microsoft Store, packages are signed by Microsoft during submission.
# For sideloading, you need your own code signing certificate.
#
# Usage:
#   .\sign-msix.ps1 -CertificatePath cert.pfx -Password <password>
#   .\sign-msix.ps1 -CertificateThumbprint <thumbprint>  # From cert store
#   .\sign-msix.ps1 -Package path\to\package.msix

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Package = "",

    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "",

    [Parameter(Mandatory=$false)]
    [SecureString]$Password,

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint = "",

    [Parameter(Mandatory=$false)]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter(Mandatory=$false)]
    [ValidateSet("SHA256", "SHA384", "SHA512")]
    [string]$HashAlgorithm = "SHA256",

    [Parameter(Mandatory=$false)]
    [switch]$SignAll = $false
)

$ErrorActionPreference = "Stop"

# Get paths
$ScriptDir = $PSScriptRoot
$PlatformDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$RepoRoot = (Resolve-Path (Join-Path $PlatformDir "..\..")).Path
$BuildDir = Join-Path $RepoRoot "build"
$MsixDir = Join-Path $BuildDir "msix"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Find-SignTool {
    # Try to find signtool.exe from Windows SDK
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64"
    )

    foreach ($pattern in $sdkPaths) {
        $paths = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach ($path in $paths) {
            $signTool = Join-Path $path.FullName "signtool.exe"
            if (Test-Path $signTool) {
                return $signTool
            }
        }
    }

    throw "signtool.exe not found. Install Windows 10 SDK."
}

function Get-PackagePublisher {
    param([string]$PackagePath)

    # Extract manifest from MSIX to get publisher
    $tempDir = Join-Path $env:TEMP "msix_extract_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        # Use makeappx to unpack just the manifest
        $makeAppx = (Find-WindowsSDKTools).MakeAppx
        & $makeAppx unpack /p $PackagePath /d $tempDir /o 2>$null

        $manifestPath = Join-Path $tempDir "AppxManifest.xml"
        if (Test-Path $manifestPath) {
            [xml]$manifest = Get-Content $manifestPath
            return $manifest.Package.Identity.Publisher
        }
    } finally {
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }

    return $null
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

    throw "Windows SDK tools not found"
}

function Test-CertificateMatch {
    param(
        [string]$CertSubject,
        [string]$PackagePublisher
    )

    # Normalize for comparison
    $certNorm = $CertSubject -replace '\s+', ' '
    $pkgNorm = $PackagePublisher -replace '\s+', ' '

    return $certNorm -eq $pkgNorm
}

function Sign-Package {
    param(
        [string]$PackagePath,
        [string]$SignToolPath,
        [string]$CertPath,
        [SecureString]$CertPassword,
        [string]$Thumbprint,
        [string]$Timestamp,
        [string]$Hash
    )

    $fileName = [System.IO.Path]::GetFileName($PackagePath)
    Write-Host "Signing $fileName..."

    $signArgs = @("sign")

    if ($CertPath) {
        # Sign with PFX file
        $signArgs += "/f"
        $signArgs += $CertPath

        if ($CertPassword) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPassword)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $signArgs += "/p"
            $signArgs += $plainPassword
        }
    } elseif ($Thumbprint) {
        # Sign with certificate from store
        $signArgs += "/sha1"
        $signArgs += $Thumbprint
    } else {
        throw "No certificate specified"
    }

    # Add common options
    $signArgs += "/fd"
    $signArgs += $Hash
    $signArgs += "/tr"
    $signArgs += $Timestamp
    $signArgs += "/td"
    $signArgs += $Hash
    $signArgs += "/v"
    $signArgs += $PackagePath

    & $SignToolPath @signArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Signing failed for $fileName"
    }

    Write-Host "  Signed successfully" -ForegroundColor Green
}

function Verify-Signature {
    param(
        [string]$PackagePath,
        [string]$SignToolPath
    )

    $fileName = [System.IO.Path]::GetFileName($PackagePath)
    Write-Host "Verifying $fileName..."

    & $SignToolPath verify /pa /v $PackagePath 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Signature valid" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  Signature invalid or missing" -ForegroundColor Yellow
        return $false
    }
}

# Main execution
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " Witnessd MSIX Signing Tool" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Find signtool
Write-Step "Locating signing tools"
$SignTool = Find-SignTool
Write-Host "  signtool.exe: $SignTool"

# Determine packages to sign
$packagesToSign = @()

if ($Package) {
    if (-not (Test-Path $Package)) {
        throw "Package not found: $Package"
    }
    $packagesToSign += $Package
} elseif ($SignAll) {
    # Find all MSIX/MSIXBUNDLE files in build directory
    $packagesToSign += Get-ChildItem $MsixDir -Filter "*.msix" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
    $packagesToSign += Get-ChildItem $MsixDir -Filter "*.msixbundle" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
} else {
    # Look for most recent package
    $recent = Get-ChildItem $MsixDir -Filter "*.msix*" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($recent) {
        $packagesToSign += $recent.FullName
    } else {
        throw "No packages found in $MsixDir"
    }
}

if ($packagesToSign.Count -eq 0) {
    throw "No packages to sign"
}

Write-Host ""
Write-Host "Packages to sign:"
foreach ($pkg in $packagesToSign) {
    Write-Host "  $([System.IO.Path]::GetFileName($pkg))"
}

# Validate certificate
Write-Step "Validating certificate"

if ($CertificatePath) {
    if (-not (Test-Path $CertificatePath)) {
        throw "Certificate file not found: $CertificatePath"
    }

    # If no password provided, prompt
    if (-not $Password) {
        $Password = Read-Host "Enter certificate password" -AsSecureString
    }

    # Load certificate to get subject
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $Password)
    $certSubject = $cert.Subject
    Write-Host "  Certificate Subject: $certSubject"
    Write-Host "  Valid From: $($cert.NotBefore)"
    Write-Host "  Valid To: $($cert.NotAfter)"

    if ($cert.NotAfter -lt (Get-Date)) {
        Write-Warning "Certificate has expired!"
    }
} elseif ($CertificateThumbprint) {
    # Find certificate in store
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
    }

    if (-not $cert) {
        throw "Certificate with thumbprint $CertificateThumbprint not found in certificate store"
    }

    $certSubject = $cert.Subject
    Write-Host "  Certificate Subject: $certSubject"
    Write-Host "  Thumbprint: $($cert.Thumbprint)"
} else {
    Write-Host "No certificate specified." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "For sideloading, you need a code signing certificate."
    Write-Host "Options:"
    Write-Host "  1. Create a self-signed certificate for testing:"
    Write-Host "     New-SelfSignedCertificate -Type CodeSigningCert -Subject `"CN=Test`" -CertStoreLocation Cert:\CurrentUser\My"
    Write-Host ""
    Write-Host "  2. Export and use a PFX file:"
    Write-Host "     .\sign-msix.ps1 -CertificatePath cert.pfx"
    Write-Host ""
    Write-Host "  3. Use a certificate from the store:"
    Write-Host "     .\sign-msix.ps1 -CertificateThumbprint <thumbprint>"
    Write-Host ""
    Write-Host "For Microsoft Store submission, packages are signed by Microsoft."
    Write-Host "No signing is required before upload."
    exit 0
}

# Sign packages
Write-Step "Signing packages"

foreach ($pkg in $packagesToSign) {
    Sign-Package -PackagePath $pkg -SignToolPath $SignTool `
        -CertPath $CertificatePath -CertPassword $Password `
        -Thumbprint $CertificateThumbprint `
        -Timestamp $TimestampServer -Hash $HashAlgorithm
}

# Verify signatures
Write-Step "Verifying signatures"

$allValid = $true
foreach ($pkg in $packagesToSign) {
    if (-not (Verify-Signature -PackagePath $pkg -SignToolPath $SignTool)) {
        $allValid = $false
    }
}

Write-Step "Summary"

if ($allValid) {
    Write-Host ""
    Write-Host "All packages signed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Signed packages:"
    foreach ($pkg in $packagesToSign) {
        $fileInfo = Get-Item $pkg
        Write-Host "  $($fileInfo.Name)"
    }
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Validate: .\scripts\validate-msix.ps1"
    Write-Host "  2. Test: Add-AppxPackage -Path <msix>"
    Write-Host "  3. Distribute or submit to Store"
} else {
    Write-Error "Some packages failed signature verification"
    exit 1
}
