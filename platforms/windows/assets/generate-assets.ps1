# generate-assets.ps1
# Generate all required visual assets for Windows MSIX packaging
# Requires: ImageMagick (magick) or System.Drawing for PNG generation
#
# Usage: .\generate-assets.ps1 -SourceSvg .\icon.svg

param(
    [Parameter(Mandatory=$false)]
    [string]$SourceSvg = "icon.svg",

    [Parameter(Mandatory=$false)]
    [string]$SourcePng = "",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".",

    [Parameter(Mandatory=$false)]
    [switch]$UseMagick = $false
)

$ErrorActionPreference = "Stop"

# Asset specifications for MSIX
# Format: Name, BaseSize, Scales[]
$assetSpecs = @{
    "Square44x44Logo" = @{
        BaseSize = 44
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @(16, 24, 32, 48, 256)
        AltFormUnplated = @(16, 32, 48, 256)
    }
    "Square71x71Logo" = @{
        BaseSize = 71
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
    "Square150x150Logo" = @{
        BaseSize = 150
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
    "Wide310x150Logo" = @{
        BaseSize = @(310, 150)
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
    "Square310x310Logo" = @{
        BaseSize = 310
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
    "StoreLogo" = @{
        BaseSize = 50
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
    "SplashScreen" = @{
        BaseSize = @(620, 300)
        Scales = @(100, 125, 150, 200, 400)
        TargetSizes = @()
        AltFormUnplated = @()
    }
}

# Colors
$BackgroundColor = "#1a1a2e"
$ForegroundColor = "#e94560"
$AccentColor = "#16213e"

function Test-ImageMagick {
    try {
        $null = & magick -version
        return $true
    } catch {
        return $false
    }
}

function Test-Inkscape {
    try {
        $null = & inkscape --version
        return $true
    } catch {
        return $false
    }
}

function New-PlaceholderPng {
    param(
        [int]$Width,
        [int]$Height,
        [string]$OutputPath,
        [string]$Text = "W"
    )

    if (Test-ImageMagick) {
        $size = "${Width}x${Height}"
        $fontSize = [Math]::Min($Width, $Height) * 0.6

        & magick -size $size `
            -define png:color-type=6 `
            xc:"$BackgroundColor" `
            -fill "$ForegroundColor" `
            -font "Arial-Bold" `
            -pointsize $fontSize `
            -gravity center `
            -annotate 0 "$Text" `
            -alpha on `
            $OutputPath

        Write-Host "Created: $OutputPath ($size)"
    } else {
        # Fallback: Create minimal PNG using .NET
        Add-Type -AssemblyName System.Drawing

        $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

        # Background
        $bgColor = [System.Drawing.ColorTranslator]::FromHtml($BackgroundColor)
        $graphics.Clear($bgColor)

        # Draw text
        $fgColor = [System.Drawing.ColorTranslator]::FromHtml($ForegroundColor)
        $brush = New-Object System.Drawing.SolidBrush($fgColor)
        $fontSize = [Math]::Min($Width, $Height) * 0.5
        $font = New-Object System.Drawing.Font("Arial", $fontSize, [System.Drawing.FontStyle]::Bold)

        $stringFormat = New-Object System.Drawing.StringFormat
        $stringFormat.Alignment = [System.Drawing.StringAlignment]::Center
        $stringFormat.LineAlignment = [System.Drawing.StringAlignment]::Center

        $rect = New-Object System.Drawing.RectangleF(0, 0, $Width, $Height)
        $graphics.DrawString($Text, $font, $brush, $rect, $stringFormat)

        $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bitmap.Dispose()

        Write-Host "Created (fallback): $OutputPath (${Width}x${Height})"
    }
}

function Convert-SvgToPng {
    param(
        [string]$SvgPath,
        [int]$Width,
        [int]$Height,
        [string]$OutputPath
    )

    if (Test-Inkscape) {
        & inkscape --export-type=png --export-filename=$OutputPath --export-width=$Width --export-height=$Height $SvgPath
        Write-Host "Converted: $OutputPath (${Width}x${Height})"
    } elseif (Test-ImageMagick) {
        & magick convert -background none -resize "${Width}x${Height}" $SvgPath $OutputPath
        Write-Host "Converted: $OutputPath (${Width}x${Height})"
    } else {
        Write-Warning "No SVG converter available, creating placeholder"
        New-PlaceholderPng -Width $Width -Height $Height -OutputPath $OutputPath
    }
}

# Create output directory if needed
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Generating Windows MSIX visual assets..."
Write-Host ""

# Check for source image
$hasSource = $false
if ($SourcePng -and (Test-Path $SourcePng)) {
    $hasSource = $true
    $sourceType = "png"
    Write-Host "Using source PNG: $SourcePng"
} elseif ($SourceSvg -and (Test-Path $SourceSvg)) {
    $hasSource = $true
    $sourceType = "svg"
    Write-Host "Using source SVG: $SourceSvg"
} else {
    Write-Host "No source image found, generating placeholders"
    Write-Host "Create icon.svg or icon.png for proper branding"
}

Write-Host ""

foreach ($assetName in $assetSpecs.Keys) {
    $spec = $assetSpecs[$assetName]

    $baseWidth = if ($spec.BaseSize -is [array]) { $spec.BaseSize[0] } else { $spec.BaseSize }
    $baseHeight = if ($spec.BaseSize -is [array]) { $spec.BaseSize[1] } else { $spec.BaseSize }

    # Generate scaled versions
    foreach ($scale in $spec.Scales) {
        $width = [Math]::Round($baseWidth * $scale / 100)
        $height = [Math]::Round($baseHeight * $scale / 100)
        $outputPath = Join-Path $OutputDir "$assetName.scale-$scale.png"

        if ($hasSource -and $sourceType -eq "svg") {
            Convert-SvgToPng -SvgPath $SourceSvg -Width $width -Height $height -OutputPath $outputPath
        } elseif ($hasSource -and $sourceType -eq "png") {
            if (Test-ImageMagick) {
                & magick convert $SourcePng -resize "${width}x${height}" $outputPath
                Write-Host "Resized: $outputPath (${width}x${height})"
            } else {
                New-PlaceholderPng -Width $width -Height $height -OutputPath $outputPath
            }
        } else {
            New-PlaceholderPng -Width $width -Height $height -OutputPath $outputPath
        }
    }

    # Generate target size versions (for Square44x44Logo)
    foreach ($targetSize in $spec.TargetSizes) {
        $outputPath = Join-Path $OutputDir "$assetName.targetsize-$targetSize.png"

        if ($hasSource -and $sourceType -eq "svg") {
            Convert-SvgToPng -SvgPath $SourceSvg -Width $targetSize -Height $targetSize -OutputPath $outputPath
        } elseif ($hasSource -and $sourceType -eq "png") {
            if (Test-ImageMagick) {
                & magick convert $SourcePng -resize "${targetSize}x${targetSize}" $outputPath
                Write-Host "Resized: $outputPath (${targetSize}x${targetSize})"
            } else {
                New-PlaceholderPng -Width $targetSize -Height $targetSize -OutputPath $outputPath
            }
        } else {
            New-PlaceholderPng -Width $targetSize -Height $targetSize -OutputPath $outputPath
        }
    }

    # Generate altform-unplated versions (no background padding)
    foreach ($targetSize in $spec.AltFormUnplated) {
        $outputPath = Join-Path $OutputDir "$assetName.altform-unplated_targetsize-$targetSize.png"

        if ($hasSource -and $sourceType -eq "svg") {
            Convert-SvgToPng -SvgPath $SourceSvg -Width $targetSize -Height $targetSize -OutputPath $outputPath
        } elseif ($hasSource -and $sourceType -eq "png") {
            if (Test-ImageMagick) {
                & magick convert $SourcePng -resize "${targetSize}x${targetSize}" -background none $outputPath
                Write-Host "Resized (unplated): $outputPath (${targetSize}x${targetSize})"
            } else {
                New-PlaceholderPng -Width $targetSize -Height $targetSize -OutputPath $outputPath
            }
        } else {
            New-PlaceholderPng -Width $targetSize -Height $targetSize -OutputPath $outputPath
        }
    }
}

# Generate the main logo reference files (without scale suffix for manifest references)
$mainAssets = @(
    @{ Name = "Square44x44Logo"; Size = 44 },
    @{ Name = "Square71x71Logo"; Size = 71 },
    @{ Name = "Square150x150Logo"; Size = 150 },
    @{ Name = "StoreLogo"; Size = 50 }
)

foreach ($asset in $mainAssets) {
    $outputPath = Join-Path $OutputDir "$($asset.Name).png"
    $scalePath = Join-Path $OutputDir "$($asset.Name).scale-100.png"
    if (Test-Path $scalePath) {
        Copy-Item $scalePath $outputPath -Force
        Write-Host "Created reference: $outputPath"
    }
}

# Special handling for Wide310x150Logo
$wideScalePath = Join-Path $OutputDir "Wide310x150Logo.scale-100.png"
$widePath = Join-Path $OutputDir "Wide310x150Logo.png"
if (Test-Path $wideScalePath) {
    Copy-Item $wideScalePath $widePath -Force
    Write-Host "Created reference: $widePath"
}

# Special handling for Square310x310Logo
$largeScalePath = Join-Path $OutputDir "Square310x310Logo.scale-100.png"
$largePath = Join-Path $OutputDir "Square310x310Logo.png"
if (Test-Path $largeScalePath) {
    Copy-Item $largeScalePath $largePath -Force
    Write-Host "Created reference: $largePath"
}

# Special handling for SplashScreen
$splashScalePath = Join-Path $OutputDir "SplashScreen.scale-100.png"
$splashPath = Join-Path $OutputDir "SplashScreen.png"
if (Test-Path $splashScalePath) {
    Copy-Item $splashScalePath $splashPath -Force
    Write-Host "Created reference: $splashPath"
}

Write-Host ""
Write-Host "Asset generation complete!"
Write-Host ""
Write-Host "Generated files:"
Get-ChildItem $OutputDir -Filter "*.png" | ForEach-Object {
    $size = [System.Drawing.Image]::FromFile($_.FullName)
    Write-Host "  $($_.Name) - $($size.Width)x$($size.Height)"
    $size.Dispose()
} 2>$null

Write-Host ""
Write-Host "For production, replace these with properly designed assets."
