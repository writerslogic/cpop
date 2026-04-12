# Specification: Core Session Management and Evidence Export

## Goal
Implement the core logic for managing a cryptographic witnessing session, including session initialization, real-time monitoring, and exporting evidence packets (.cpoe).

## Requirements
- Session Lifecycle: Start, Pause, Resume, Stop.
- Cryptographic State: Manage the ratcheting key hierarchy during a session.
- Platform Monitoring: Interface with platform-specific event capture layers (CGEventTap, etc.).
- Evidence Export: Serialize the session state and captured timing metrics into COSE/CBOR format.

## Invariants
- No raw keystrokes may be stored.
- All evidence must be verifiable against the IETF protocol spec.
- Session state must be persisted across application restarts.
