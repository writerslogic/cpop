## Description

<!-- Brief description of the changes -->

## Related Issues

<!-- Link to related issues: Fixes #123, Relates to #456 -->

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Security fix

## Checklist

### Code Quality
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] No new warnings introduced

### Testing
- [ ] New tests added for changes
- [ ] All existing tests pass (`cargo test --all-features`)
- [ ] Integration tests pass (if applicable)
- [ ] Manual testing performed

### Documentation
- [ ] README updated (if needed)
- [ ] API documentation updated (if needed)
- [ ] CHANGELOG entry added (for user-facing changes)

### Security (for crypto/security changes)
- [ ] No custom cryptographic primitives introduced
- [ ] Constant-time comparisons used for secrets
- [ ] Security implications documented
- [ ] Reviewed by security-experienced maintainer

## Test Evidence

<!-- Paste test output or screenshots -->

```
$ cargo test --all-features
...
```

## Additional Notes

<!-- Any additional context or notes for reviewers -->
