# Contributing to physjitter

Thank you for your interest in contributing to physjitter! This document provides guidelines and instructions for contributing to this cryptographic library.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Architecture Overview](#architecture-overview)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Review Process](#review-process)
- [Release Process](#release-process)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.70.0+ | MSRV enforced in CI |
| Git | 2.34+ | Commit signing recommended |
| cargo-audit | Latest | Security auditing |
| cargo-deny | Latest | Dependency policy |

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/writerslogic/physjitter.git
cd physjitter

# Verify the build
cargo build --all-features

# Run the test suite
cargo test --all-features

# Run lints
cargo clippy --all-features -- -D warnings

# Check formatting
cargo fmt --check

# Run security audit
cargo audit
```

### Recommended Tools

```bash
# Install recommended tools
cargo install cargo-audit cargo-deny cargo-watch cargo-tarpaulin

# Watch mode for development
cargo watch -x "test --all-features"

# Generate coverage report
cargo tarpaulin --all-features --out Html
```

---

## Architecture Overview

Understanding the architecture helps you contribute effectively.

### Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                           lib.rs                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Session, HybridEngine, Error, PhysHash, Jitter             ││
│  └───────────────────────────┬─────────────────────────────────┘│
│                              │                                   │
│  ┌───────────┬───────────────┼───────────────┬─────────────────┐│
│  │           │               │               │                 ││
│  ▼           ▼               ▼               ▼                 ▼│
│ traits.rs  pure.rs       phys.rs       evidence.rs        model.rs
│  │           │               │               │                 │ │
│  │ Entropy   │ PureJitter    │ PhysJitter    │ Evidence       │ │
│  │ Source    │               │               │ EvidenceChain  │ │
│  │           │               │               │                 │ │
│  │ Jitter    │               │               │                 │ │
│  │ Engine    │               │               │                 │ │
│  └───────────┴───────────────┴───────────────┴─────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `EntropySource` | `traits.rs` | Trait for entropy collection |
| `JitterEngine` | `traits.rs` | Trait for jitter computation |
| `PureJitter` | `pure.rs` | HMAC-based economic security engine |
| `PhysJitter` | `phys.rs` | Hardware entropy-based engine |
| `HybridEngine` | `lib.rs` | Composite engine with auto-fallback |
| `Session` | `lib.rs` | High-level session manager |
| `Evidence` | `evidence.rs` | Single evidence record (Phys/Pure) |
| `EvidenceChain` | `evidence.rs` | Append-only evidence chain |
| `HumanModel` | `model.rs` | Statistical validation model |

### Data Flow

```
User Input → Session.sample()
                  │
                  ▼
          HybridEngine.sample()
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
  PhysJitter.sample()   (fallback)
       │                     │
       ▼                     ▼
  EntropySource         PureJitter
  .sample()             .compute_jitter()
       │                     │
       ▼                     │
  JitterEngine              │
  .compute_jitter()         │
       │                     │
       └──────────┬──────────┘
                  ▼
            (jitter, Evidence)
                  │
                  ▼
         EvidenceChain.append()
                  │
                  ▼
         Session.validate() → HumanModel
```

### Security Model Decision Tree

```
                  HybridEngine.sample()
                         │
                         ▼
                 ┌───────────────┐
                 │ Try PhysJitter│
                 │    .sample()  │
                 └───────┬───────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         Success                  Error
              │                     │
              ▼                     ▼
    ┌─────────────────┐    ┌─────────────────┐
    │ validate(hash)  │    │ Use PureJitter  │
    │ entropy >= min? │    │   (fallback)    │
    └────────┬────────┘    └────────┬────────┘
             │                      │
       ┌─────┴─────┐                │
       │           │                │
      Yes          No               │
       │           │                │
       ▼           ▼                ▼
  Evidence::    Evidence::    Evidence::
    Phys          Pure          Pure
```

---

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Use the bug report template**: [.github/ISSUE_TEMPLATE/bug_report.yml](.github/ISSUE_TEMPLATE/bug_report.yml)
3. **Include**:
   - Rust version (`rustc --version`)
   - Operating system and architecture
   - Feature flags used
   - Minimal reproduction code
   - Expected vs actual behavior

### Security Vulnerabilities

**Do NOT report security vulnerabilities through public issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Feature Requests

1. **Use the feature request template**: [.github/ISSUE_TEMPLATE/feature_request.yml](.github/ISSUE_TEMPLATE/feature_request.yml)
2. **Consider**:
   - Does it fit the project's scope?
   - What's the proposed API?
   - Are there security implications?
   - Can it be implemented without breaking changes?

### Pull Requests

1. **Fork and create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes** following the coding standards

3. **Write/update tests**:
   ```bash
   cargo test --all-features
   ```

4. **Run all checks**:
   ```bash
   # Lints
   cargo clippy --all-features -- -D warnings

   # Format
   cargo fmt

   # Security audit
   cargo audit

   # MSRV check (if you have 1.70.0 installed)
   cargo +1.70.0 test --all-features
   ```

5. **Commit with clear messages** (see below)

6. **Push and open a PR** against `main`

---

## Development Workflow

### Branch Naming

| Type | Format | Example |
|------|--------|---------|
| Feature | `feature/short-description` | `feature/batch-verification` |
| Bug fix | `fix/issue-or-description` | `fix/entropy-estimation` |
| Documentation | `docs/what-changed` | `docs/api-examples` |
| Refactoring | `refactor/what-changed` | `refactor/evidence-chain` |
| Performance | `perf/what-improved` | `perf/hash-computation` |

### Commit Messages

Write clear, descriptive commit messages:

```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem this commit solves and why this approach
was chosen.

- Bullet points are fine
- Use imperative mood ("Add feature" not "Added feature")

Fixes #123
```

**Good examples:**
```
Add batch verification API for evidence chains

Implement verify_batch() method that validates multiple evidence
records in a single pass, improving performance for large chains.

- Add EvidenceChain::verify_batch() method
- Add benchmarks for batch vs sequential verification
- Update documentation with examples

Fixes #45
```

```
Fix entropy estimation for constant sequences

The previous implementation incorrectly reported non-zero entropy
for sequences with constant deltas. This fix properly calculates
variance of deltas rather than absolute values.

Fixes #78
```

### Commit Signing

We recommend signing commits:

```bash
# Configure SSH signing (recommended)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Or GPG signing
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global commit.gpgsign true
```

### Local Development Loop

```bash
# Watch for changes and run tests
cargo watch -x "test --all-features"

# Run specific test
cargo test test_name -- --nocapture

# Check before committing
cargo fmt && cargo clippy --all-features -- -D warnings && cargo test --all-features
```

---

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` defaults (no custom configuration)
- Fix all `clippy` warnings with `-D warnings`
- This crate uses **zero unsafe code**: `#![forbid(unsafe_code)]`

### Code Organization

```rust
//! Module-level documentation explaining purpose.
//!
//! # Examples
//!
//! ```rust
//! // Example usage
//! ```

use external_crate::Something;
use std::collections::HashMap;

use crate::internal::Module;

// Constants
const MAX_ENTROPY_BITS: u8 = 64;

// Type aliases
type Result<T> = std::result::Result<T, Error>;

// Structs (public first, then private)
/// Documentation for public struct.
pub struct PublicStruct { /* ... */ }

struct PrivateStruct { /* ... */ }

// Implementations
impl PublicStruct {
    // Public methods first
    pub fn new() -> Self { /* ... */ }

    // Private methods after
    fn helper(&self) { /* ... */ }
}

// Trait implementations
impl SomeTrait for PublicStruct { /* ... */ }

// Tests at the bottom
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() { /* ... */ }
}
```

### Documentation

- Document all public items with `///` doc comments
- Include examples in doc comments where appropriate
- Use `#![deny(missing_docs)]` to enforce documentation

```rust
/// Compute jitter delay from secret and inputs.
///
/// # Arguments
///
/// * `secret` - 32-byte session secret
/// * `inputs` - Input data (typically keystroke)
/// * `entropy` - Hardware entropy hash (ignored in pure mode)
///
/// # Returns
///
/// Jitter delay in microseconds, in range `[jmin, jmin + range)`.
///
/// # Examples
///
/// ```rust
/// use physjitter::{PureJitter, JitterEngine};
///
/// let engine = PureJitter::default();
/// let secret = [0u8; 32];
/// let jitter = engine.compute_jitter(&secret, b"input", [0u8; 32]);
/// assert!(jitter >= 500 && jitter < 3000);
/// ```
pub fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter
```

### Error Handling

- Use the crate's `Error` type for fallible operations
- Provide meaningful error messages
- Avoid panics in library code
- Use `expect()` only for truly impossible conditions with explanation

```rust
// Good: Descriptive error
return Err(Error::InsufficientEntropy {
    required: self.min_entropy_bits,
    found: entropy_bits,
});

// Good: Impossible condition with explanation
let mac = HmacSha256::new_from_slice(secret)
    .expect("HMAC accepts any key size");

// Bad: Generic panic
panic!("something went wrong");
```

---

## Testing Guidelines

### Test Organization

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Group related tests with comments
    // --- Basic Functionality ---

    #[test]
    fn test_basic_operation() { /* ... */ }

    // --- Edge Cases ---

    #[test]
    fn test_empty_input() { /* ... */ }

    #[test]
    fn test_maximum_values() { /* ... */ }

    // --- Error Conditions ---

    #[test]
    fn test_insufficient_entropy_error() { /* ... */ }

    // --- Integration ---

    #[test]
    fn test_full_workflow() { /* ... */ }
}
```

### Test Naming

Use descriptive names: `test_<function>_<scenario>_<expected_result>`

```rust
#[test]
fn test_validate_rejects_low_variance_sequence() { /* ... */ }

#[test]
fn test_compute_jitter_is_deterministic_for_same_inputs() { /* ... */ }

#[test]
fn test_evidence_chain_hash_changes_on_append() { /* ... */ }
```

### What to Test

| Category | Examples |
|----------|----------|
| Happy path | Normal inputs produce expected outputs |
| Edge cases | Empty inputs, maximum values, boundaries |
| Error conditions | Invalid inputs produce correct errors |
| Security properties | Timing, determinism, entropy requirements |
| Serialization | Round-trip JSON encoding/decoding |
| Integration | Full workflows across components |

### Running Tests

```bash
# All tests
cargo test --all-features

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture

# Feature combinations
cargo test                          # Default features
cargo test --features hardware      # With hardware
cargo test --all-features           # All features
cargo test --no-default-features    # Minimal

# MSRV verification
cargo +1.70.0 test --all-features
```

---

## Security Considerations

This is a cryptographic library. Extra care is required for all contributions.

### Requirements

| Requirement | Reason |
|-------------|--------|
| No `unsafe` code | Memory safety guarantee |
| Constant-time operations | Prevent timing attacks |
| No secret logging | Prevent information leakage |
| Dependency review | Supply chain security |

### Checklist for Security-Sensitive Changes

- [ ] No new `unsafe` code introduced
- [ ] Constant-time comparisons for secrets
- [ ] No secrets in error messages or logs
- [ ] No timing variations based on secret values
- [ ] New dependencies reviewed for security
- [ ] Cryptographic operations use audited crates

### Cryptographic Changes

Changes to cryptographic code require:

1. Clear explanation of the security rationale
2. Reference to standards or papers if applicable
3. Additional review from maintainers
4. Comprehensive test coverage

---

## Documentation

### Types of Documentation

| Type | Location | Purpose |
|------|----------|---------|
| API docs | `///` comments | Function/struct documentation |
| Module docs | `//!` comments | Module-level overview |
| README | `README.md` | Project overview, quick start |
| Examples | `examples/` | Runnable example programs |
| Architecture | `CONTRIBUTING.md` | Internal design documentation |

### Building Documentation

```bash
# Build and open docs locally
cargo doc --all-features --open

# Build with private items (for development)
cargo doc --all-features --document-private-items --open
```

### Documentation Standards

- Every public item must have documentation
- Include at least one example for complex APIs
- Link to related items with `[`backticks`]`
- Use proper markdown formatting

---

## Review Process

### PR Requirements

1. **CI must pass**: Tests, clippy, format, MSRV
2. **Security checks**: cargo-audit, cargo-deny
3. **Documentation**: New public APIs documented
4. **Tests**: New functionality has test coverage
5. **Changelog**: Notable changes documented

### Review Criteria

| Aspect | Criteria |
|--------|----------|
| Correctness | Does it work as intended? |
| Security | Any security implications? |
| Performance | Any performance impact? |
| API design | Is the API ergonomic and consistent? |
| Documentation | Is it well-documented? |
| Tests | Adequate test coverage? |

### Merge Requirements

- At least one maintainer approval
- All CI checks passing
- No unresolved review comments
- Security-sensitive changes require additional review

---

## Release Process

Releases are handled by maintainers. The process is:

1. Update `Cargo.toml` version
2. Update `CHANGELOG.md`
3. Create git tag: `git tag -s v0.1.x`
4. Push tag to trigger release workflow
5. Verify SLSA provenance attestation
6. Publish to crates.io

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

---

## Getting Help

- **Questions**: Open a [discussion](https://github.com/writerslogic/physjitter/discussions)
- **Bugs**: Open an [issue](https://github.com/writerslogic/physjitter/issues)
- **Security**: See [SECURITY.md](SECURITY.md)

---

Thank you for contributing to physjitter!
