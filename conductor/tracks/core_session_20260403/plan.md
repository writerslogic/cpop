# Implementation Plan: Core Session Management and Evidence Export

## Phase 1: Session Lifecycle and Persistence
- [ ] Task: Define the `Session` struct and storage schema in `cpoe-engine`.
    - [ ] Write unit tests for session serialization/deserialization.
    - [ ] Implement `Session` with `tokio::fs` persistence.
- [ ] Task: Implement session control methods (Start, Stop, Pause, Resume).
    - [ ] Write integration tests for session lifecycle transitions.
    - [ ] Implement `SessionManager` in `cpoe-engine`.
- [ ] Task: Conductor - User Manual Verification 'Session Lifecycle and Persistence' (Protocol in workflow.md)

## Phase 2: Cryptographic State and Ratcheting
- [ ] Task: Integrate `keyhierarchy` with active session state.
    - [ ] Write unit tests for session key ratcheting.
    - [ ] Implement secure key storage and derivation in `cpoe-engine`.
- [ ] Task: Conductor - User Manual Verification 'Cryptographic State and Ratcheting' (Protocol in workflow.md)

## Phase 3: Evidence Export (COSE/CBOR)
- [ ] Task: Implement evidence serialization logic using `cpoe-protocol`.
    - [ ] Write unit tests for .cpoe packet serialization (CBOR/COSE).
    - [ ] Implement `export_evidence` in `cpoe-engine`.
- [ ] Task: Conductor - User Manual Verification 'Evidence Export (COSE/CBOR)' (Protocol in workflow.md)
