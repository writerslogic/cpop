# Security Policy

[![Security](https://github.com/writerslogic/physjitter/actions/workflows/security.yml/badge.svg)](https://github.com/writerslogic/physjitter/actions/workflows/security.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

This document outlines the security policy for the `physjitter` crate, including vulnerability reporting, threat model, security considerations, and secure usage guidelines.

---

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [Security Models](#security-models)
- [Secure Usage Guidelines](#secure-usage-guidelines)
- [Known Limitations](#known-limitations)
- [Dependency Security](#dependency-security)
- [Cryptographic Implementations](#cryptographic-implementations)
- [Secure Development Practices](#secure-development-practices)
- [SLSA Compliance](#slsa-compliance)
- [Security Audits](#security-audits)
- [Security Updates](#security-updates)
- [Security Hall of Fame](#security-hall-of-fame)

---

## Supported Versions

| Version | Supported          | Notes                          |
| ------- | ------------------ | ------------------------------ |
| 0.1.x   | :white_check_mark: | Current stable release         |
| < 0.1   | :x:                | Pre-release, not supported     |

We support the latest minor version with security patches. Critical vulnerabilities may receive backports to earlier versions at maintainer discretion.

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**:warning: Please do NOT report security vulnerabilities through public GitHub issues.**

Report vulnerabilities via one of the following methods (in order of preference):

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the [Security tab](https://github.com/writerslogic/physjitter/security/advisories)
   - Click "Report a vulnerability"
   - This enables private discussion and coordinated disclosure

2. **Email**
   - Send details to: `security@writerslogic.com`
   - Use our PGP key for sensitive reports (key ID below)

### PGP Key

For encrypted communications:

```
Key ID: [To be added]
Fingerprint: [To be added]
```

Key available at: https://writerslogic.com/.well-known/security.txt

### What to Include

Please provide as much of the following as possible:

| Information | Description |
|-------------|-------------|
| **Vulnerability type** | e.g., timing attack, information disclosure, cryptographic weakness |
| **Affected component** | Module, function, or feature affected |
| **Attack vector** | How the vulnerability can be exploited |
| **Source location** | File path, line numbers, commit/tag |
| **Reproduction steps** | Step-by-step instructions to reproduce |
| **PoC/Exploit** | Proof-of-concept code if available |
| **Impact assessment** | Severity and potential consequences |
| **Suggested fix** | If you have recommendations |

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Initial acknowledgment | Within 48 hours |
| Preliminary assessment | Within 7 days |
| Status updates | Every 14 days |
| Resolution target | Within 90 days (complexity dependent) |

### Our Commitment

- We will acknowledge receipt within 48 hours
- We will keep you informed throughout the process
- We will work with you to understand and validate the issue
- We will credit you in the security advisory (unless you prefer anonymity)
- We will not pursue legal action against good-faith researchers

### CVE Policy

For confirmed vulnerabilities:
- We request CVE IDs through GitHub Security Advisories
- CVEs are published after a fix is available
- Coordinated disclosure date is agreed upon with the reporter

---

## Threat Model

### Scope

`physjitter` is designed to provide proof-of-process through timing jitter. It is **NOT**:

- A replacement for traditional authentication
- A source of cryptographically secure random numbers
- A digital signature scheme
- Suitable for high-stakes security decisions without additional verification

### Actors

| Actor | Capabilities | Goal |
|-------|--------------|------|
| **Legitimate User** | Access to application, typing content | Generate valid proof-of-process |
| **Attacker (Remote)** | Network access, can observe/replay | Forge evidence, bypass detection |
| **Attacker (Local)** | Access to same machine | Extract secrets, manipulate timing |
| **Attacker (Privileged)** | Root/admin access | Full system control, VM manipulation |

### Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| Session secret | High | Memory protection, key derivation |
| Evidence chain | Medium | Integrity via chain hash |
| Jitter timing | Low | Statistical validation |
| Entropy samples | Medium | Hardware binding |

### Attack Vectors

#### 1. Replay Attacks

**Threat**: Attacker captures and replays valid evidence chains.

**Mitigations**:
- Evidence chains include timestamps
- `PhysJitter` includes hardware-bound entropy
- Application should bind evidence to session context

**Residual Risk**: Pure jitter mode without timestamps could be replayed.

#### 2. Timing Side Channels

**Threat**: Secret extraction through timing analysis.

**Mitigations**:
- HMAC computation uses constant-time primitives from `hmac` crate
- Jitter delays are within human typing range (500-3000μs)
- Statistical model validates timing distribution

**Residual Risk**: Sophisticated attackers with many samples may extract partial information.

#### 3. Secret Compromise

**Threat**: Session secret extracted from memory.

**Mitigations**:
- Secrets should use proper key derivation (HKDF, Argon2)
- Application should use memory-locking where available
- Session secrets should be rotated periodically

**Residual Risk**: Local privileged attacker can extract secrets from memory.

#### 4. Virtualization Detection Bypass

**Threat**: Attacker provides fake hardware entropy in VM.

**Mitigations**:
- `HybridEngine` detects low entropy and falls back to pure mode
- Evidence records include mode indicator (Phys vs Pure)
- Applications can require minimum `phys_ratio()` threshold

**Residual Risk**: Sophisticated VM can simulate hardware entropy.

#### 5. Statistical Model Evasion

**Threat**: Attacker crafts timing that passes human validation.

**Mitigations**:
- Model trained on 136M real keystrokes
- Multiple anomaly detection methods
- Configurable sensitivity thresholds

**Residual Risk**: Determined attacker may evade detection with sufficient effort.

---

## Security Models

### Economic Security (PureJitter)

**Principle**: Security relies on the economic cost of reproducing input sequences.

| Property | Value |
|----------|-------|
| Assumption | Attacker cannot retype content identically |
| Strength | Deterministic, portable, fast |
| Weakness | Secret compromise defeats security |

**Appropriate for**:
- Virtualized environments
- WebAssembly targets
- Low-stakes verification

### Physics Security (PhysJitter)

**Principle**: Hardware entropy provides non-reproducible binding.

| Property | Value |
|----------|-------|
| Assumption | Hardware timing cannot be perfectly simulated |
| Strength | Device-bound, tamper-evident |
| Weakness | Requires physical hardware access |

**Appropriate for**:
- Native desktop applications
- High-stakes verification
- When hardware is trusted

### Hybrid Security (HybridEngine)

**Principle**: Use best available security, record which mode was used.

| Property | Value |
|----------|-------|
| Behavior | Attempts physics, falls back to pure |
| Evidence | Records mode for each sample |
| Recommendation | **Use this in production** |

---

## Secure Usage Guidelines

### Key Management

```rust
// ❌ BAD: Hardcoded secret
let secret = [0u8; 32];

// ✅ GOOD: Derive from secure source
use sha2::{Sha256, Digest};
let user_key = get_secure_key(); // From password KDF, HSM, etc.
let mut hasher = Sha256::new();
hasher.update(user_key);
hasher.update(b"physjitter-session-v1");
let secret: [u8; 32] = hasher.finalize().into();
```

### Session Configuration

```rust
use physjitter::{HybridEngine, Session};

// Production configuration
let engine = HybridEngine::builder()
    .min_entropy_bits(8)        // Require meaningful entropy
    .jitter_range(500, 3000)    // Human typing range
    .build();

let mut session = Session::with_engine(secret, engine);
```

### Evidence Validation

```rust
// Always validate evidence before trusting
let result = session.validate();

// Check both human detection AND physics ratio
if result.is_human && session.evidence().phys_ratio() >= 0.8 {
    // High confidence: human + hardware bound
} else if result.is_human {
    // Medium confidence: human but economic security only
} else {
    // Reject: failed human detection
}
```

### Chain Integrity Verification

Evidence chains are automatically keyed with the session secret for tamper detection:

```rust
// Session automatically creates keyed evidence chain
let session = Session::new(secret);

// After collecting evidence, verify integrity
if !session.evidence().verify_integrity(&secret) {
    // Chain has been tampered with!
    panic!("Evidence chain integrity check failed");
}
```

### Memory Protection

Session secrets are automatically zeroized when the session is dropped:

```rust
use physjitter::Session;

{
    let session = Session::new(secret);
    // ... use session ...
} // Secret automatically cleared from memory here

// Manual zeroization is no longer needed for Session
```

### Environment Considerations

| Environment | Recommendation |
|-------------|----------------|
| Native Linux/macOS/Windows | Use `HybridEngine` with `hardware` feature |
| Docker/containers | Use `HybridEngine`, expect `Pure` mode |
| VMs (VMware, VirtualBox) | Use `HybridEngine`, expect `Pure` mode |
| WebAssembly | Use `PureJitter` only |
| SGX/TEE | Not currently supported |

---

## Known Limitations

### 1. Virtualization Detection

Hardware entropy detection may be unreliable in:
- Nested virtualization
- Paravirtualized environments
- Some cloud instances (inconsistent TSC)

**Mitigation**: Always check `phys_ratio()` and set appropriate thresholds.

### 2. Timing Resolution

Timing measurements depend on:
- OS scheduler precision
- CPU frequency scaling
- System load

**Mitigation**: Model validation accounts for expected variance.

### 3. Timing Side Channels

Jitter delays could theoretically leak information about:
- Secret values (through HMAC computation time)
- Input content (through correlation analysis)

**Mitigation**: Uses constant-time HMAC; jitter range masks exact values.

### 4. Single-Device Binding

Evidence is not cryptographically bound to a specific device beyond hardware entropy.

**Mitigation**: Application should add device attestation if required.

---

## Dependency Security

### Supply Chain Measures

| Measure | Implementation |
|---------|----------------|
| Dependency audit | `cargo-audit` in CI |
| License compliance | `cargo-deny` checks |
| Lockfile integrity | `Cargo.lock` committed |
| Automated updates | Dependabot enabled |
| SLSA provenance | Level 3 attestation |

### Dependency Tree

```
physjitter
├── hmac 0.12 (RustCrypto)
├── sha2 0.10 (RustCrypto)
├── subtle 2.5 (RustCrypto) - constant-time operations
├── zeroize 1.7 (RustCrypto) - secure memory clearing
├── serde 1.0
├── serde_json 1.0
├── thiserror 2.0
├── getrandom 0.3
└── rand 0.8 (optional)
```

All cryptographic dependencies are from the [RustCrypto](https://github.com/RustCrypto) project, which undergoes regular security audits.

---

## Cryptographic Implementations

| Primitive | Crate | Version | Usage | Notes |
|-----------|-------|---------|-------|-------|
| HMAC-SHA256 | `hmac` + `sha2` | 0.12 / 0.10 | Jitter computation, chain MAC | Constant-time, domain-separated |
| SHA-256 | `sha2` | 0.10 | Entropy mixing, unkeyed hashing | Standard |
| CSPRNG | `getrandom` | 0.3 | Entropy seeding | OS-provided |
| Constant-time eq | `subtle` | 2.5 | Evidence verification | Timing attack mitigation |
| Secret cleanup | `zeroize` | 1.7 | Session secret management | Secure memory clearing |

### Domain Separation

All HMAC operations use context-specific prefixes to prevent key reuse vulnerabilities:

| Context | Prefix |
|---------|--------|
| Jitter computation | `b"physjitter/v1/jitter"` |
| Chain MAC | `b"physjitter/v1/chain"` |

### Keyed Evidence Chains

Evidence chains can be bound to session secrets via HMAC:

```rust
// Create keyed chain (tamper-evident)
let chain = EvidenceChain::with_secret(session_secret);

// Verify integrity
if !chain.verify_integrity(&session_secret) {
    // Chain has been tampered with
}
```

**We do NOT implement custom cryptographic primitives.**

---

## Secure Development Practices

### Code Quality

- [x] All changes require code review
- [x] CI enforces formatting (`rustfmt`)
- [x] CI enforces linting (`clippy` with `-D warnings`)
- [x] No `unsafe` code in main crate (zero `unsafe` blocks)
- [x] MSRV policy enforced

### Security Testing

| Tool | Purpose | Frequency |
|------|---------|-----------|
| `cargo-audit` | Known vulnerability detection | Every PR, weekly |
| `cargo-deny` | License and dependency policy | Every PR |
| Semgrep | Static analysis (SAST) | Every PR |
| CodeQL | Advanced static analysis | Every PR |
| Fuzzing | Input validation | Periodic |

### CI Security

- Minimal permissions (read-only where possible)
- Dependabot for automated updates
- Signed commits encouraged
- Protected branches on main

---

## SLSA Compliance

This project follows [SLSA](https://slsa.dev) (Supply-chain Levels for Software Artifacts) guidelines:

| Level | Requirement | Status |
|-------|-------------|--------|
| 1 | Build process documented | ✅ |
| 2 | Hosted build, signed provenance | ✅ |
| 3 | Hardened build, non-falsifiable provenance | ✅ |

### Verifying Releases

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download release artifact and provenance
curl -LO https://github.com/writerslogic/physjitter/releases/download/v0.1.0/physjitter-0.1.0.crate
curl -LO https://github.com/writerslogic/physjitter/releases/download/v0.1.0/multiple.intoto.jsonl

# Verify
slsa-verifier verify-artifact physjitter-0.1.0.crate \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/writerslogic/physjitter \
  --source-tag v0.1.0
```

---

## Security Audits

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| — | — | — | No formal audit yet |

We welcome security audits. If you're interested in auditing this crate, please contact us.

### Self-Assessment

- [x] Memory safety (safe Rust only)
- [x] Dependency audit (no known vulnerabilities)
- [x] Cryptographic review (uses audited RustCrypto crates)
- [x] Threat model documented
- [ ] Formal verification (not applicable)
- [ ] Third-party audit (planned)

---

## Security Updates

Security updates are released as:

| Channel | Description |
|---------|-------------|
| Patch releases | Backward-compatible fixes (0.1.x → 0.1.y) |
| Security advisories | GitHub Security Advisories |
| Changelog | `CHANGELOG.md` entries marked `[Security]` |
| RustSec | Advisory database entry |

### Receiving Notifications

1. **Watch this repository** with "Security alerts" enabled
2. **Enable Dependabot alerts** in your projects
3. **Monitor RustSec advisories** via `cargo-audit`

---

## Security Hall of Fame

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities:

| Researcher | Date | Issue |
|------------|------|-------|
| — | — | No reports yet |

*Want to be listed here? Report a valid security issue!*

---

## Contact

- **Security issues**: security@writerslogic.com
- **GitHub Security Advisories**: [Report here](https://github.com/writerslogic/physjitter/security/advisories)
- **General questions**: [GitHub Discussions](https://github.com/writerslogic/physjitter/discussions)

---

*Last updated: 2025-02*
