# Contributing to witnessd

Thank you for your interest in contributing to witnessd! This document provides
guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold this code.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Use issue templates when available
- Include reproduction steps, expected vs actual behavior
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Development Setup

1. **Prerequisites**
   - Go 1.21 or later
   - Make (or Task)
   - Pre-commit (recommended)
   - Docker (for integration tests)

2. **Clone and Setup**
   ```bash
   git clone https://github.com/davidcondrey/witnessd.git
   cd witnessd
   make setup
   ```

3. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

4. **Run Tests**
   ```bash
   make test              # Unit tests
   make test-integration  # Integration tests (requires Docker)
   make test-forensics    # Forensic analysis tests
   ```

### Making Changes

1. **Create a Feature Branch**
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Follow Commit Conventions**
   ```
   feat(scope): add new feature
   fix(scope): fix bug description
   docs(scope): update documentation
   refactor(scope): code refactoring
   test(scope): add or update tests
   ```

3. **Write Tests**
   - Aim for high coverage on new code
   - Include unit and integration tests
   - Test edge cases and error conditions

4. **Run All Checks**
   ```bash
   make lint    # Linters
   make test    # Tests
   make build   # Build verification
   ```

5. **Submit Pull Request**
   - Fill out PR template completely
   - Link related issues
   - Ensure CI passes

### Code Style

- Follow standard Go conventions (`gofmt`, `goimports`)
- Use meaningful names for variables and functions
- Document exported functions and types
- Keep functions focused and reasonably sized

### Cryptographic Code Guidelines

Extra care is required for cryptographic code:

1. **No Custom Primitives:** Use stdlib `crypto/*` or `golang.org/x/crypto`
2. **Document Assumptions:** Security assumptions and threat models
3. **Constant-Time Operations:** Use `subtle.ConstantTimeCompare` for secrets
4. **Review Required:** Crypto changes require security-experienced maintainer review

### Documentation

- Update README.md for user-facing changes
- Update inline docs for API changes
- Add examples for new features
- Keep specs/ in sync with implementation

## Pull Request Process

1. PRs require at least one maintainer approval
2. All CI checks must pass
3. Squash commits when merging
4. Delete branch after merge

## Release Process

Releases are managed by maintainers:
- Semantic versioning (MAJOR.MINOR.PATCH)
- Goreleaser for builds
- SLSA provenance for supply chain security
- SBOM generation for compliance

## Getting Help

- [GitHub Discussions](https://github.com/davidcondrey/witnessd/discussions)
- Documentation in `docs/`
- Test files for usage examples

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
