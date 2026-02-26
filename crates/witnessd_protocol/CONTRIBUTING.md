# Contributing to pop-crate

Thank you for your interest in contributing to pop-crate! This document provides guidelines and instructions for contributing to this core Rust implementation of the Proof-of-Process (PoP) Protocol.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Review Process](#review-process)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.70.0+ | MSRV |
| Git | 2.34+ | |

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/writerslogic/pop-crate.git
cd pop-crate

# Verify the build
cargo build --all-features

# Run the test suite
cargo test --all-features
```

---

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates.
2. **Include**:
   - Rust version (`rustc --version`)
   - Operating system and architecture
   - Minimal reproduction code
   - Expected vs actual behavior

### Pull Requests

1. **Fork and create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Make your changes** following the coding standards.
3. **Write/update tests**.
4. **Run all checks**:
   ```bash
   cargo clippy --all-features -- -D warnings
   cargo fmt
   ```
5. **Push and open a PR** against `main`.

---

## Coding Standards

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Use `rustfmt` defaults.
- Fix all `clippy` warnings.
- Favor safe Rust code.

---

## Testing Guidelines

- Every new feature should have corresponding tests.
- Bug fixes should include a regression test.
- Use `cargo test --all-features` to ensure all feature combinations work.

---

## Security Considerations

This is a cryptographic library. Extra care is required for all contributions.
See [SECURITY.md](SECURITY.md) for details on our security policy.

---

## Documentation

- Document all public items with `///` doc comments.
- Include examples in doc comments where appropriate.

---

## Release Process

Releases follow [Semantic Versioning](https://semver.org/).

---

## Getting Help

- **Questions**: Open a GitHub Discussion.
- **Bugs**: Open a GitHub Issue.
- **Security**: See [SECURITY.md](SECURITY.md).
