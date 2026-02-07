# Windows Installer Icons

This directory should contain the following icon resources for the Windows installer:

## Required Files

### witnessd.ico
Windows application icon in ICO format. Should contain the following sizes:
- 16x16 (16-bit and 32-bit)
- 32x32 (16-bit and 32-bit)
- 48x48 (32-bit)
- 256x256 (32-bit, PNG compressed)

### Optional Files for EXE Bootstrapper

### logo.png
Logo image for the installer wizard (approximately 75x75 pixels)

### splash.bmp
Splash screen bitmap (approximately 480x480 pixels)

### banner.bmp
Banner for installer dialogs (approximately 493x58 pixels)

### dialog.bmp
Background for welcome/finish dialogs (approximately 493x312 pixels)

## Creating Icons

From the existing SVG icon:

```bash
# Using ImageMagick
convert icon.svg -define icon:auto-resize=256,128,64,48,32,16 witnessd.ico

# Using librsvg + ImageMagick
rsvg-convert -w 256 -h 256 icon.svg | convert - -define icon:auto-resize=256,128,64,48,32,16 witnessd.ico
```

Or use a tool like:
- ICO Convert: https://icoconvert.com/
- GIMP with ICO export plugin
- Inkscape (export to PNG, then convert)

## Note

The installer will still build without these files but will use default Windows icons.
For production releases, custom branded icons should be provided.
