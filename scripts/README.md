# Test Scripts

## Quick Reference

```bash
# Run all automated tests (no manual interaction needed)
cargo test -p cpop_engine --lib                                    # 1025 engine unit tests (~55s)
cargo test -p cpop_engine --test integration_tests --features ffi  # 45+ engine integration tests (~2s)
bash scripts/test_api.sh                                           # 52 API endpoint tests (~10s)

# Run E2E test (launches TextEdit, types keystrokes, verifies anti-forgery)
bash scripts/test_e2e.sh                                           # 20 E2E tests (~30s)

# Run Swift tests (needs Xcode)
xcodebuild test -scheme cpop -destination 'platform=macOS' \
  -only-testing:WritersLogicTests                                  # 2247 Swift unit tests

# Run UI automation tests (needs Accessibility permission)
xcodebuild test -scheme cpop -destination 'platform=macOS' \
  -only-testing:WritersLogicUITests                                # 51 UI tests
```

## What Each Suite Covers

| Suite | What It Proves |
|-------|---------------|
| Engine unit | All 30 Rust modules work in isolation |
| Engine integration | Full pipelines: keystroke→checkpoint→export→verify, security hardness, edge cases |
| API tests | All endpoints exist, auth works (ES256+RS256), CORS, security headers |
| E2E tests | Real cross-process flow: app launch, AppleScript typing rejected (anti-forgery), database integrity, file permissions |
| Swift unit | Service layer, FFI wrappers, status HMAC, data models, cloud sync connectivity |
| UI automation | All navigation paths, dashboard indicators, settings tabs, export form, accessibility |
