# Publishing WritersProof Browser Extensions

## Prerequisites

- Run `./build.sh` to generate ZIP packages in `dist/`
- Prepare a 1280x800 screenshot of the extension popup in action
- Prepare a 440x280 promotional tile image
- Have the privacy policy URL ready (writerslogic.com/privacy)

---

## Chrome Web Store

### Account Setup (one-time)
1. Go to https://chrome.google.com/webstore/devconsole
2. Pay the $5 one-time developer registration fee
3. Verify your identity

### Submission
1. Click **New Item** in the developer dashboard
2. Upload `dist/writersproof-chrome-v1.0.0.zip`
3. Fill in the listing:
   - **Name**: WritersProof
   - **Summary**: Build cryptographic authorship attestations as you write. Prove creative control over your work.
   - **Description**: WritersProof witnesses your creative process in Google Docs, Overleaf, Medium, Notion, and 40+ writing platforms. It captures typing rhythm and content evolution to build a cryptographic attestation that you exercised creative control over your work. Your content is never uploaded — only SHA-256 hashes are recorded. Works standalone in the browser or with the WritersProof desktop app for hardware-backed attestation.
   - **Category**: Productivity
   - **Language**: English
4. Upload assets:
   - At least 1 screenshot (1280x800 or 640x400)
   - Small tile (440x280)
   - Icon is pulled from the extension package
5. Privacy:
   - **Single purpose**: Authorship attestation for documents
   - **Permissions justification**:
     - `nativeMessaging`: Communicate with WritersProof desktop app for hardware-backed attestation
     - `activeTab`: Access current tab to detect supported writing platforms
     - `scripting`: Inject content script on supported sites to capture typing rhythm
     - `storage`: Store session state and user preferences locally
   - **Host permissions**: Required to monitor editing activity on supported writing platforms (Google Docs, Overleaf, Medium, Notion, etc.)
   - **Data usage disclosure**: No data sold to third parties. No data used for advertising. Content hashes (SHA-256) stored locally only. Keystroke timing intervals (not keystrokes themselves) used for authorship attestation.
   - **Privacy policy URL**: https://writerslogic.com/privacy
6. Click **Submit for Review**
7. Review typically takes 1-3 business days

### Post-Publish
- Note the extension ID (e.g., `abcdefghijklmnop`)
- Update `native-manifests/chrome/com.writerslogic.witnessd.json` with the production extension ID in `allowed_origins`

---

## Microsoft Edge Add-ons

### Account Setup (one-time)
1. Go to https://partner.microsoft.com/en-us/dashboard/microsoftedge
2. Sign in with a Microsoft account
3. Register as a developer (free)

### Submission
1. Click **Create new extension**
2. Upload `dist/writersproof-edge-v1.0.0.zip`
3. Fill in the listing (same content as Chrome):
   - **Name**: WritersProof
   - **Summary**: Build cryptographic authorship attestations as you write.
   - **Description**: (same as Chrome)
   - **Category**: Productivity
4. Upload the same screenshots and promotional images
5. Privacy:
   - **Privacy policy URL**: https://writerslogic.com/privacy
   - **Permissions**: Same justifications as Chrome
6. Click **Publish**
7. Review typically takes 1-2 business days

### Notes
- Edge uses the same Manifest V3 format as Chrome
- The same ZIP package works for both (identical manifest.json)
- Edge may flag the `nativeMessaging` permission for extra review

---

## Firefox Add-ons (AMO)

### Account Setup (one-time)
1. Go to https://addons.mozilla.org/en-US/developers/
2. Create a Firefox account or sign in
3. Accept the developer agreement

### Submission
1. Click **Submit a New Add-on**
2. Choose **On this site** (listed on AMO)
3. Upload `dist/writersproof-firefox-v1.0.0.zip`
4. AMO runs automated validation. Fix any issues before proceeding.
5. **Source code**: AMO may request source code for review since the extension uses complex crypto (ECDH, AES-GCM). Prepare a source ZIP of the entire `cpoe_browser_extension/` directory.
6. Fill in the listing:
   - **Name**: WritersProof
   - **Summary**: Build cryptographic authorship attestations as you write.
   - **Description**: (same as Chrome)
   - **Category**: Privacy & Security
   - **Tags**: authorship, writing, privacy, cryptography
7. Upload screenshots (same as Chrome)
8. **Notes to reviewer**:
   ```
   This extension witnesses the user's creative writing process by capturing
   content hashes (SHA-256) and typing rhythm timing. No plaintext content
   is ever transmitted or stored by the extension. The extension communicates
   with an optional desktop app via Chrome Native Messaging protocol for
   hardware-backed attestation. In standalone mode (no desktop app), all
   evidence is stored locally in IndexedDB.

   The secure-channel.js file implements P-256 ECDH key exchange and
   AES-256-GCM encryption for the native messaging channel. This is
   standard Web Crypto API usage, not custom crypto.
   ```
9. Click **Submit Version**
10. Review typically takes 1-5 business days (longer for extensions with crypto)

### Post-Publish
- AMO assigns an add-on ID (different from the `gecko.id` in manifest)
- Update `manifest-firefox.json` with the AMO-assigned ID
- Update `native-manifests/firefox/com.writerslogic.witnessd.json` with the production `allowed_extensions`

---

## After Publishing All Three

1. **Update native messaging manifests** with production extension IDs:
   ```
   native-manifests/chrome/com.writerslogic.witnessd.json   → allowed_origins
   native-manifests/edge/com.writerslogic.witnessd.json     → allowed_origins  
   native-manifests/firefox/com.writerslogic.witnessd.json  → allowed_extensions
   ```

2. **Update install-native-host.sh** with the production extension IDs

3. **Update the desktop app** to include the native messaging manifest installation in its installer/first-run flow

4. **Test end-to-end** on each browser:
   - Install extension from store
   - Install desktop app
   - Run native messaging host installer
   - Open Google Docs, start editing
   - Verify extension popup shows "Connected" status
   - Verify checkpoints are created
   - Verify version history appears in desktop app

5. **Set up automated updates**: bump `version` in both manifest files, re-run `./build.sh`, upload new ZIPs to each store

---

## Version Bumping

To release a new version:
1. Update `version` in `manifest.json` and `manifest-firefox.json`
2. Run `./build.sh`
3. Upload new ZIPs to each store dashboard
4. Chrome and Edge auto-update within 24-48 hours
5. Firefox auto-updates within a few hours after review approval
