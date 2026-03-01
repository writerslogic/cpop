# GUI Guide

Witnessd provides native applications for macOS and Windows, offering a visual interface for managing your creative process evidence.

## macOS Application

The macOS app is designed to stay out of your way while providing continuous protection.

### Main Features

- **Menu Bar Integration**: Quick access to start/stop tracking and view recent activity.
- **Visual History**: Browse your checkpoints on a timeline.
- **One-Click Export**: Easily generate evidence packets for any project.
- **Smart Tracking**: Automatically detects when you are writing and suggests checkpoints.
- **Accessibility Integration**: Uses macOS accessibility features for secure, privacy-preserving keystroke dynamics tracking.

### Installation

1. Download the latest `Witnessd.dmg`.
2. Drag to **Applications**.
3. Launch and grant the requested **Accessibility permissions** (required for keystroke evidence).

---

## Windows Application

The Windows version provides a similar experience tailored for the Windows desktop.

### Main Features

- **System Tray Icon**: Monitor status and control tracking from the taskbar.
- **Dashboard**: A comprehensive view of all your witnessed documents.
- **TPM Integration**: Leverages your computer's TPM 2.0 (if available) for hardware-backed identity attestation.
- **Explorer Integration**: Right-click any file to create a quick checkpoint.

---

## Common Features

### Tracking
Both apps support background activity tracking. This captures the "rhythm" of your writing ([[Glossary#IKI|jitter and timing]]) without ever recording the content of what you type. This provides [[Evidence Format#Verification Tiers|"Tier 2"]] evidence of authentic human authorship.

### History View
The history view shows you:
- When checkpoints were created.
- How much the document grew between points.
- The cryptographic "health" of your evidence chain.

### Evidence Export
When you're ready to share your proof, use the **Export** button. You can choose to include or exclude the document's content in the packet.

---

*For command-line usage, see the **[[CLI Reference]]**.*
