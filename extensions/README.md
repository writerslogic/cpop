# CPoE Browser Extensions — Publishing Guide

This directory contains packaging and publishing instructions for the CPoE browser extensions. All extensions share a common codebase in `apps/cpoe_cli/browser-extension/` and are packaged into browser-specific zip files for store submission.

## Architecture

Each extension operates in two modes:

- **Full mode** — Native messaging host installed; full cryptographic witnessing with VDF proofs, behavioral fingerprinting, keystroke jitter binding, and WAR blocks.
- **Hash-chain mode** (degraded) — No native host; the extension builds a local SHA-256 hash chain in `chrome.storage.local` for tamper-evident content snapshots. No keystroke capture, no VDF proofs — just content hashes.

Safari is bundled with the macOS app and published through the Mac App Store (not a standalone extension).

## Building Packages

```sh
# From the repository root:
./extensions/package.sh

# With a specific version:
./extensions/package.sh --version 1.0.0
```

This creates:
```
extensions/dist/
├── writerslogic-chrome.zip    # Chrome Web Store
├── writerslogic-firefox.zip   # Firefox Add-ons (AMO)
├── writerslogic-edge.zip      # Edge Add-ons
├── chrome/                # Unpacked Chrome extension (for testing)
├── firefox/               # Unpacked Firefox extension (for testing)
└── edge/                  # Unpacked Edge extension (for testing)
```

## Testing Before Submission

### Chrome / Edge
1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable "Developer mode"
3. Click "Load unpacked" and select `extensions/dist/chrome/` (or `edge/`)
4. Open a supported site (Google Docs, Overleaf, Medium, Notion)
5. Click the extension icon — verify mode badge shows "Hash-Chain" (amber) or "Full" (green if native host is installed)
6. Start witnessing, make edits, verify checkpoint count increments
7. In hash-chain mode: click "Export Hash Chain" and verify the JSON contains valid prev-hash linkage

### Firefox
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `extensions/dist/firefox/manifest.json`
4. Same testing steps as Chrome

### Safari
1. Build the macOS app in Xcode (scheme "Witness")
2. Safari → Settings → Advanced → "Show features for web developers"
3. Develop → Allow Unsigned Extensions (resets each Safari restart)
4. Safari → Settings → Extensions → Enable "CPoE"
5. Test on supported sites

---

## Publishing: Chrome Web Store

### Prerequisites
- [Chrome Web Store Developer account](https://chrome.google.com/webstore/devconsole/) ($5 one-time registration fee)
- Store listing assets (see [Assets Required](#assets-required) below)

### Steps
1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/)
2. Click **New Item**
3. Upload `extensions/dist/writerslogic-chrome.zip`
4. Fill in the store listing:
   - **Name:** CPoE
   - **Summary:** Cryptographic proof-of-process evidence for browser-based writing
   - **Description:** (see [Store Description](#store-description) below)
   - **Category:** Productivity
   - **Language:** English
5. Upload screenshots and promotional images
6. Set **Visibility:** Public
7. Under Privacy:
   - **Single purpose:** "Creates cryptographic evidence of the document authorship process"
   - **Permissions justification:**
     - `nativeMessaging` — Communicates with the local CPoE daemon for full cryptographic witnessing
     - `activeTab` — Reads document content on the currently active tab to create content checkpoints
     - `storage` — Stores extension settings and hash-chain data locally
   - **Host permissions justification:** "Monitors document content on supported writing platforms (Google Docs, Overleaf, Medium, Notion) to create cryptographic authorship evidence"
   - **Data use disclosures:** Does not sell data, does not use data for unrelated purposes, does not use data for creditworthiness. Collects "website content" for core functionality.
8. Submit for review

### Post-Publish: Native Host Registration
Once published, copy the extension ID from the Chrome Web Store listing (32-character string), then update the native messaging manifest:
```sh
./apps/cpoe_cli/browser-extension/install-native-host.sh --chrome --extension-id YOUR_CHROME_EXTENSION_ID
```

---

## Publishing: Firefox Add-ons (AMO)

### Prerequisites
- [Firefox Add-on Developer account](https://addons.mozilla.org/en-US/developers/) (free)

### Steps
1. Go to [Firefox Add-on Developer Hub](https://addons.mozilla.org/en-US/developers/)
2. Click **Submit a New Add-on**
3. Choose **On this site** (listed on AMO)
4. Upload `extensions/dist/writerslogic-firefox.zip`
5. AMO will validate the manifest. The extension ID `cpoe@writerslogic.com` is declared in `browser_specific_settings.gecko.id`.
6. Fill in the listing:
   - **Name:** CPoE
   - **Summary:** Cryptographic proof-of-process evidence for browser-based writing
   - **Description:** (see [Store Description](#store-description) below)
   - **Categories:** Privacy & Security, Productivity
   - **License:** GPL-3.0
   - **Homepage:** https://writerslogic.com
7. **Source code submission:** AMO may request source code for review since the extension uses no build step — upload the entire `apps/cpoe_cli/browser-extension/` directory as a zip, or link to the public repository.
8. Upload screenshots
9. Submit for review

### Post-Publish: Native Host Registration
The Firefox extension ID is fixed (`cpoe@writerslogic.com`), so the native manifest works immediately:
```sh
./apps/cpoe_cli/browser-extension/install-native-host.sh --firefox
```

---

## Publishing: Edge Add-ons

### Prerequisites
- [Microsoft Partner Center account](https://partner.microsoft.com/en-us/dashboard/microsoftedge/overview) (free, requires Microsoft account)

### Steps
1. Go to [Microsoft Partner Center — Edge Add-ons](https://partner.microsoft.com/en-us/dashboard/microsoftedge/overview)
2. Click **Create new extension**
3. Upload `extensions/dist/writerslogic-edge.zip`
4. Fill in the listing:
   - **Name:** CPoE
   - **Short description:** Cryptographic proof-of-process evidence for browser-based writing
   - **Description:** (see [Store Description](#store-description) below)
   - **Category:** Productivity
   - **Privacy policy URL:** https://writerslogic.com/privacy
   - **Website URL:** https://writerslogic.com
5. Upload screenshots and promotional images
6. Under **Availability:** Make available in all markets
7. Submit for review

### Post-Publish: Native Host Registration
Copy the extension ID from the Edge Add-ons dashboard, then:
```sh
./apps/cpoe_cli/browser-extension/install-native-host.sh --edge --extension-id YOUR_EDGE_EXTENSION_ID
```

---

## Publishing: Safari (via Mac App Store)

Safari extensions are distributed as part of the macOS app bundle, not as standalone store listings.

### Steps
1. Build the macOS app in Xcode with the "Witness" scheme
2. Archive: Product → Archive
3. Distribute via App Store Connect
4. The Safari extension is automatically included in the app bundle
5. Users enable it via Safari → Settings → Extensions

### Notes
- Bundle ID: `com.writerslogic.witnessd`
- Apple ID: `6758287298`
- Team ID: `U3PZN7P3E5`
- The Safari extension uses FFI to call the Rust engine directly (no native messaging host needed)
- When FFI is unavailable (CI builds), it falls back to App Group JSON storage
- No hash-chain degraded mode — Safari always has the engine available via the app bundle

---

## Assets Required

### All Stores
| Asset | Dimensions | Format |
|-------|-----------|--------|
| Extension icon | 128x128 | PNG (already at `icons/icon-128.png`) |

### Chrome Web Store
| Asset | Dimensions | Format |
|-------|-----------|--------|
| Store icon | 128x128 | PNG |
| Small promo tile | 440x280 | PNG or JPEG |
| Screenshots (1-5) | 1280x800 or 640x400 | PNG or JPEG |
| Marquee promo tile (optional) | 1400x560 | PNG or JPEG |

### Firefox Add-ons
| Asset | Dimensions | Format |
|-------|-----------|--------|
| Extension icon | 128x128 | PNG |
| Screenshots (1+) | Any reasonable size | PNG or JPEG |

### Edge Add-ons
| Asset | Dimensions | Format |
|-------|-----------|--------|
| Store icon | 300x300 | PNG |
| Screenshots (1-10) | 1280x800 or 640x400 | PNG or JPEG |
| Small promo tile (optional) | 440x280 | PNG |

---

## Store Description

Use this description (adapt length per store):

> **CPoE** creates cryptographic evidence of your writing process. As you write in Google Docs, Overleaf, Medium, or Notion, CPoE silently builds proof that a human authored the content — not AI.
>
> **How it works:**
> - Content checkpoints are hashed and chained together, creating a tamper-evident record of your document's evolution
> - When the CPoE native host is installed, the extension captures full cryptographic evidence: VDF time proofs, behavioral fingerprinting, and keystroke timing jitter
> - Without the native host, the extension runs in hash-chain mode: a lightweight SHA-256 chain that proves your document grew incrementally over time
>
> **Privacy first:**
> - No document content leaves your machine — only cryptographic hashes
> - No accounts required
> - No telemetry, no analytics, no tracking
> - All evidence stays local unless you explicitly export it
>
> **Supported editors:** Google Docs, Overleaf, Medium, Notion
>
> **For full witnessing:** Install the CPoE desktop app and native messaging host from https://writerslogic.com

---

## Native Messaging Host

The native host is optional. Without it, extensions run in degraded hash-chain mode. To install:

**macOS / Linux:**
```sh
# Build the native messaging host
cargo build --release --bin writerslogic-native-messaging-host

# Install for all browsers
./apps/cpoe_cli/browser-extension/install-native-host.sh --all

# Or specific browsers with known extension IDs
./apps/cpoe_cli/browser-extension/install-native-host.sh \
  --chrome --extension-id CHROME_ID \
  --edge --extension-id EDGE_ID \
  --firefox
```

**Windows (PowerShell):**
```powershell
# Build
cargo build --release --bin writerslogic-native-messaging-host

# Install for all browsers
.\apps\cpoe_cli\browser-extension\install-native-host.ps1 -All

# Or specific browsers
.\apps\cpoe_cli\browser-extension\install-native-host.ps1 -Chrome -ExtensionId CHROME_ID
```

---

## Extension IDs

| Browser | ID Type | Value |
|---------|---------|-------|
| Chrome | Extension ID | *(assigned after first upload to Chrome Web Store)* |
| Firefox | Add-on ID | `cpoe@writerslogic.com` |
| Edge | Extension ID | *(assigned after first upload to Edge Add-ons)* |
| Safari | Bundle ID | `com.writerslogic.witnessd.WitnessdSafariExtension` |

After publishing to Chrome and Edge, update this table and the native messaging manifests with the assigned IDs.

---

## Versioning

All extensions share the same version number, declared in their respective `manifest.json` files. To bump:

```sh
# Package with a new version
./extensions/package.sh --version 1.1.0
```

Or manually edit:
- `apps/cpoe_cli/browser-extension/manifest.json` (Chrome/Edge)
- `apps/cpoe_cli/browser-extension/manifest-firefox.json` (Firefox)
- `apps/cpoe_macos/CPoESafariExtension/Resources/manifest.json` (Safari)
