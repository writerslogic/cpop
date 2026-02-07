# WitnessdIME - Mac App Store Version

This is the Mac App Store compatible version of Witnessd that uses the Input Method Kit (IMK) framework instead of CGEventTap for keystroke monitoring.

## How It Works

Unlike the standard Witnessd app which requires Accessibility permissions to monitor keystrokes globally, this version works as an **Input Method**. Users explicitly select "Witnessd" from their keyboard input sources, giving consent for keystroke monitoring through the standard macOS input method mechanism.

### Advantages
- **App Store Compatible**: No special permissions required
- **User Consent Built-in**: Users explicitly enable the input method
- **Sandboxed**: Runs in the App Sandbox for enhanced security

### Limitations
- Only monitors keystrokes when Witnessd is the active input method
- User must remember to switch to Witnessd input method when writing
- Does not monitor keystrokes in password fields or secure input contexts

## Building

### Prerequisites

1. **Xcode 15+** installed
2. **Go 1.21+** installed
3. **Apple Developer Account** (for code signing and App Store submission)

### Build Steps

1. Open the project in Xcode:
   ```bash
   open WitnessdIME.xcodeproj
   ```

2. Configure your Development Team:
   - Select the WitnessdIME target
   - Go to Signing & Capabilities
   - Select your team from the dropdown

3. Build the project:
   - Press Cmd+B or Product > Build
   - The Go library is built automatically via a Run Script build phase

### Manual Go Library Build

If you need to build the Go library separately:

```bash
./scripts/build-go-library.sh
```

## Installation (Development)

For testing during development:

```bash
# Build the app
xcodebuild -project WitnessdIME.xcodeproj -scheme WitnessdIME -configuration Debug

# Copy to Input Methods folder
cp -R build/Debug/WitnessdIME.app ~/Library/Input\ Methods/

# Log out and back in, or restart your Mac
```

Then enable the input method:
1. Open System Settings > Keyboard > Input Sources
2. Click the + button
3. Find "Witnessd" under English
4. Add it to your input sources

## App Store Submission

### Preparation Checklist

- [ ] Update `DEVELOPMENT_TEAM` in project settings
- [ ] Set `CODE_SIGN_IDENTITY` to "Apple Distribution"
- [ ] Create App Store Connect record
- [ ] Prepare screenshots and metadata
- [ ] Write privacy policy explaining keystroke usage

### Archive and Upload

1. In Xcode: Product > Archive
2. In the Organizer: Distribute App > App Store Connect
3. Follow the upload wizard

### Privacy Policy Requirements

Your App Store listing must include a privacy policy that explains:

- The app monitors keystrokes to create authorship evidence
- Keystroke timing data is stored locally
- No keystroke content is transmitted to servers
- Evidence files can be exported by the user
- Data can be deleted by removing the app

## Architecture

```
WitnessdIME/
├── WitnessdIME.xcodeproj/     # Xcode project
├── WitnessdIME/
│   ├── objc/
│   │   ├── main.m                    # App entry point
│   │   ├── WitnessdInputController.h # IMK controller header
│   │   └── WitnessdInputController.m # IMK controller implementation
│   ├── Assets.xcassets/              # App icons
│   ├── Info.plist                    # App configuration
│   └── WitnessdIME.entitlements      # Sandbox entitlements
└── scripts/
    └── build-go-library.sh           # Builds Go static library
```

The Objective-C code interfaces with the Go engine via cgo. The Go library is built as a static archive (`libwitnessd.a`) and linked into the final executable.

## Comparison with Standard Witnessd

| Feature | Standard (CGEventTap) | IME Version |
|---------|----------------------|-------------|
| Distribution | Notarized DMG | Mac App Store |
| Permissions | Accessibility | None (user selects IME) |
| Scope | All applications | When IME is active |
| Setup | Grant Accessibility | Add input source |
| Sandboxed | No | Yes |

## Troubleshooting

### Build Fails: "libwitnessd.a not found"
The Go library isn't being built. Check:
- Go is installed and in PATH
- The witnessd Go module is accessible at `../../../../cmd/witnessd-ime`

### Input Method Not Appearing
After installing to ~/Library/Input Methods/:
- Log out and log back in
- Or run: `killall -HUP SystemUIServer`

### Keystrokes Not Being Recorded
- Ensure Witnessd is the active input method (check menu bar)
- Secure input fields (passwords) are never monitored
- Some apps may use custom text input that bypasses IMK
