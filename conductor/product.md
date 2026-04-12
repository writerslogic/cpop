# Initial Concept

CPoE: Cryptographic authorship witnessing for writers and creators. A cryptographic engine and CLI that produces independently verifiable, tamper-evident process evidence.

# Product Definition

## Overview
**CPoE (Cryptographic Proof-of-Process)** is a cryptographic engine and ecosystem that produces independently verifiable, tamper-evident evidence of document authorship. It ensures that a document was created through an actual writing process, constrained by "cryptographic causality locks" and behavioral attestation.

## Initial Concept
CPoE implements the draft-condrey-rats-pop IETF protocol specification to convert unsubstantiated doubt about authorship into testable claims across independent trust boundaries.

## Target Users
- **Writers & Journalists:** Proving the authenticity and timeline of their work.
- **Academic Researchers:** Providing evidence of the research and drafting process.
- **Legal Professionals:** Creating tamper-evident records of document evolution.
- **Developers:** Witnessing the authorship of source code.

## Key Goals
1. **Independent Verification:** Evidence can be verified by anyone without requiring a central authority or proprietary software.
2. **Privacy First:** All witnessing and keystroke capture occur entirely on the local machine.
3. **Tamper-Evident:** Any modification to the document or the recorded process breaks the cryptographic chain.
4. **Behavioral Attestation:** Using jitter seals and timing entropy to ensure a human-driven process.

## Core Ecosystem
- **cpoe-engine:** The native cryptographic engine and platform capture layer.
- **cpoe-protocol:** The wire format and RFC-compliant types.
- **cpoe-jitter:** Hardware timing entropy primitives.
- **cpoe_cli:** The primary user interface for desktop and server environments.
- **Integrations:** Support for macOS, Windows, Atlassian Confluence, and Google Workspace.
