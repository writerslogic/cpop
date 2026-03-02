.PHONY: build test run clean release

# Debug build with ad-hoc codesign (macOS only — prevents keychain prompts)
build:
	cargo build
	@if [ "$$(uname)" = "Darwin" ]; then \
		codesign -s - -f target/debug/witnessd 2>/dev/null && \
		echo "Ad-hoc signed target/debug/witnessd"; \
	fi

# Run all workspace tests (mock keychain — zero keychain interaction)
test:
	WITNESSD_NO_KEYCHAIN=1 cargo test --workspace

# Build + codesign + run the binary directly (bypasses cargo run rebuild)
run: build
	target/debug/witnessd $(ARGS)

# Release build (should be properly codesigned separately for distribution)
release:
	cargo build --release

clean:
	cargo clean
