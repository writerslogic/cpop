.PHONY: build test run clean release

# Debug build with ad-hoc codesign (macOS only — prevents keychain prompts)
build:
	cargo build
	@if [ "$$(uname)" = "Darwin" ]; then \
		codesign -s - -f target/debug/wld 2>/dev/null && \
		echo "Ad-hoc signed target/debug/wld"; \
	fi

# Run all workspace tests (mock keychain — zero keychain interaction)
test:
	WLD_NO_KEYCHAIN=1 cargo test --workspace

# Build + codesign + run the binary directly (bypasses cargo run rebuild)
run: build
	target/debug/wld $(ARGS)

# Release build (should be properly codesigned separately for distribution)
release:
	cargo build --release

clean:
	cargo clean
