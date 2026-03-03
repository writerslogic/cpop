<p align="center">
  <img src="assets/logo.png" alt="wld_jitter" width="200">
</p>

<h1 align="center">wld_jitter</h1>

<p align="center">
  <strong>Proof-of-process primitive using timing jitter for human authorship verification</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/wld_jitter"><img src="https://img.shields.io/crates/v/wld_jitter.svg" alt="Crates.io"></a>
  <a href="https://docs.rs/wld_jitter"><img src="https://docs.rs/wld_jitter/badge.svg" alt="Documentation"></a>
  <a href="https://github.com/writerslogic/writerslogic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/MSRV-1.70.0-blue" alt="MSRV">
</p>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Security Models](#security-models)
- [Human Validation](#human-validation)
- [Evidence Chain](#evidence-chain)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Configuration](#configuration)
- [Testing](#testing)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)
- [Comparison with Alternatives](#comparison-with-alternatives)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

`wld_jitter` (formerly `physjitter`) provides cryptographic proof-of-process through timing jitter, enabling verification that content was created through a human typing process rather than generated or pasted. It creates tamper-evident records that serve as evidence of authorship process. It is a core component of the [WritersLogic](https://github.com/writerslogic/writerslogic) monorepo.

### What Problem Does This Solve?

In an era of AI-generated content, proving that text was actually *typed* by a human—keystroke by keystroke—has become valuable. `wld_jitter` addresses this by:

1. **Recording timing evidence** for each input event (keystroke, edit, etc.)
2. **Binding evidence to hardware** when available (physics-based security)
3. **Validating against human patterns** using statistical models from real typing data
4. **Creating verifiable proof chains** that can be independently validated

### Use Cases

| Use Case | Description |
|----------|-------------|
| **Authorship Verification** | Prove a document was typed, not pasted or generated |
| **Academic Integrity** | Evidence that essays were written by the student |
| **Legal Documentation** | Proof of process for contracts and agreements |
| **Content Authenticity** | Distinguish human-written from AI-generated content |
| **Anti-Fraud** | Detect automated form submissions |

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Dual Security Models** | Economic (HMAC-based) and Physics (hardware entropy) |
| **Automatic Fallback** | Uses hardware when available, gracefully degrades in VMs |
| **Human Validation** | Statistical model trained on 136M real keystrokes |
| **Evidence Chain** | Cryptographically-linked, serializable proof records |
| **Zero Unsafe Code (pure mode)** | `#![forbid(unsafe_code)]` by default; `hardware` feature enables minimal `unsafe` for TSC/CNTVCT reads |
| **`no_std` Support** | Works in embedded and WASM environments |
| **SLSA Level 3** | Supply chain security with provenance attestation |
| **Minimal Dependencies** | Only well-audited RustCrypto crates |
| **Cross-Platform** | Linux, macOS, Windows, WebAssembly |

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
wld_jitter = "0.2"
```

Or install with cargo:

```bash
cargo add wld_jitter
```

### Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library support (Session, timing, JSON) | Yes |
| `hardware` | Enable TSC/hardware entropy collection | No |
| `rand` | Enable random secret generation | No |

```toml
# Enable all features
wld_jitter = { version = "0.2", features = ["hardware", "rand"] }

# no_std (embedded/WASM compatible)
wld_jitter = { version = "0.2", default-features = false }
```

### Platform Support

| Platform | Pure Jitter | Hardware Entropy | Notes |
|----------|-------------|------------------|-------|
| Linux x86_64 | Yes | Yes | Full support |
| Linux aarch64 | Yes | Yes | Full support |
| macOS x86_64 | Yes | Yes | Full support |
| macOS aarch64 | Yes | Yes | Full support (Apple Silicon) |
| Windows x86_64 | Yes | Yes | Full support |
| WebAssembly | Yes | No | Pure jitter only (`no_std`) |
| Embedded (`no_std`) | Yes | No | Core functionality only |
| Docker/VMs | Yes | Varies | May fall back to pure jitter |

---

## Quick Start

### Basic Usage

```rust
use wld_jitter::{Session, Error};

fn main() -> Result<(), Error> {
    // Create a session with your secret key
    // IMPORTANT: Use proper key derivation in production!
    let secret = [0u8; 32];
    let mut session = Session::new(secret);

    // Sample jitter for each keystroke/input event
    let keystrokes = ["H", "e", "l", "l", "o", " ", "W", "o", "r", "l", "d"];

    for keystroke in keystrokes {
        // Get jitter delay for this input
        let jitter_us = session.sample(keystroke.as_bytes())?;

        // Apply the jitter delay (creates timing evidence)
        std::thread::sleep(std::time::Duration::from_micros(jitter_us as u64));
    }

    // Validate the session against human typing model
    let result = session.validate();
    println!("Human: {}, Confidence: {:.2}", result.is_human, result.confidence);

    // Export evidence chain for storage/verification
    let evidence_json = session.export_json()?;
    println!("Evidence records: {}", session.evidence().records.len());
    println!("Physics ratio: {:.1}%", session.phys_ratio() * 100.0);

    Ok(())
}
```

### Using the Hybrid Engine Directly

```rust
use wld_jitter::{HybridEngine, Evidence, Error};

fn main() -> Result<(), Error> {
    // Create hybrid engine (auto-selects best entropy source)
    let engine = HybridEngine::default();
    let secret = [42u8; 32];

    // Sample jitter with evidence
    let (jitter, evidence) = engine.sample(&secret, b"keystroke-a")?;

    match &evidence {
        Evidence::Phys { phys_hash, .. } => {
            println!("Hardware entropy captured: {:02x?}...", &phys_hash[..4]);
        }
        Evidence::Pure { .. } => {
            println!("Using HMAC fallback (VM/container detected)");
        }
    }

    println!("Jitter delay: {}μs", jitter);

    Ok(())
}
```

### With Random Secret Generation

```rust
use wld_jitter::Session;

fn main() {
    // Requires "rand" feature
    #[cfg(feature = "rand")]
    {
        let mut session = Session::random();
        // ... use session
    }
}
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
├─────────────────────────────────────────────────────────────────┤
│                          Session                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   Secret    │  │ HybridEngine │  │    EvidenceChain       │ │
│  │  [u8; 32]   │  │              │  │  ┌──────┐ ┌──────┐     │ │
│  └─────────────┘  │  ┌────────┐  │  │  │ Phys │→│ Pure │→... │ │
│                   │  │PhysJit │  │  │  └──────┘ └──────┘     │ │
│                   │  │  ter   │  │  └────────────────────────┘ │
│                   │  └───┬────┘  │                              │
│                   │      │       │  ┌────────────────────────┐ │
│                   │  ┌───▼────┐  │  │     HumanModel         │ │
│                   │  │PureJit │  │  │  (Aalto 136M dataset)  │ │
│                   │  │  ter   │  │  └────────────────────────┘ │
│                   │  └────────┘  │                              │
│                   └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### Core Traits

```rust
/// Source of physical entropy from hardware or environment.
pub trait EntropySource {
    /// Collect entropy sample, mixing with provided inputs.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    /// Validate that a captured hash meets statistical requirements.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Engine that computes jitter delays from entropy.
pub trait JitterEngine {
    /// Compute jitter delay from secret, inputs, and entropy.
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
```

### Module Structure

| Module | Description |
|--------|-------------|
| `lib.rs` | Main entry point, `Session`, `HybridEngine` |
| `traits.rs` | Core traits `EntropySource`, `JitterEngine` |
| `pure.rs` | `PureJitter` - HMAC-based economic security |
| `phys.rs` | `PhysJitter` - Hardware entropy collection |
| `evidence.rs` | `Evidence`, `EvidenceChain` - Proof records |
| `model.rs` | `HumanModel` - Statistical validation |

### Implementations

| Engine | Trait | Security Model | Requirements |
|--------|-------|----------------|--------------|
| [`PureJitter`] | `JitterEngine` | Economic | None |
| [`PhysJitter`] | `EntropySource` + `JitterEngine` | Physics | Hardware access |
| [`HybridEngine`] | (composite) | Both | Auto-detect |

---

## Security Models

### Economic Security (`PureJitter`)

Security relies on the **economic cost** of reproducing the exact input sequence. An attacker would need to retype content character-by-character with identical timing to reproduce the jitter chain.

```rust
use wld_jitter::{PureJitter, JitterEngine};

let engine = PureJitter::new(500, 2500); // jmin=500μs, range=2500μs
let secret = [0u8; 32];
let entropy = [0u8; 32]; // Unused in pure mode

let jitter = engine.compute_jitter(&secret, b"keystroke", entropy);
assert!(jitter >= 500 && jitter < 3000);
```

**Properties:**

| Property | Value |
|----------|-------|
| Deterministic | Yes - same inputs always produce same jitter |
| Portable | Works everywhere (VMs, containers, WASM) |
| Performance | ~200ns per computation |
| Secret dependency | Full - compromise defeats security |

**When to use:**
- Virtualized environments (Docker, VMs, cloud)
- WebAssembly targets
- When hardware entropy is unavailable
- Lower-stakes verification scenarios

### Physics Security (`PhysJitter`)

Security relies on **hardware entropy** that cannot be perfectly simulated. Uses TSC (Time Stamp Counter) and timing variations unique to the physical device.

```rust
use wld_jitter::{PhysJitter, EntropySource, JitterEngine, Error};

fn main() -> Result<(), Error> {
    let phys = PhysJitter::new(8); // Require 8 bits minimum entropy

    // Collect hardware entropy
    let entropy = phys.sample(b"inputs")?;

    // Compute jitter using hardware entropy
    let secret = [42u8; 32];
    let jitter = phys.compute_jitter(&secret, b"inputs", entropy);

    // Verify entropy meets requirements
    assert!(phys.validate(entropy));

    Ok(())
}
```

**Properties:**

| Property | Value |
|----------|-------|
| Deterministic | No - hardware noise provides true randomness |
| Device-bound | Entropy tied to specific hardware |
| Tamper-evident | Replay attacks detectable |
| Requirements | Physical hardware access |

**When to use:**
- Native desktop applications
- High-stakes verification
- When hardware is trusted
- Maximum security requirements

### Hybrid Security (`HybridEngine`) - Recommended

Combines both models: uses physics when available, falls back to pure jitter in virtualized environments. **Evidence records which mode was used.**

```rust
use wld_jitter::{HybridEngine, Evidence, Error};

fn main() -> Result<(), Error> {
    let engine = HybridEngine::default()
        .with_min_entropy(8); // Require 8 bits for physics mode

    let secret = [42u8; 32];
    let (jitter, evidence) = engine.sample(&secret, b"input")?;

    // Check which mode was used
    match &evidence {
        Evidence::Phys { phys_hash, .. } => {
            println!("Hardware entropy: {:02x?}...", &phys_hash[..4]);
        }
        Evidence::Pure { .. } => {
            println!("HMAC fallback (VM/low entropy detected)");
        }
    }

    // Check if physics mode is available
    if engine.phys_available() {
        println!("Hardware entropy source detected");
    }

    Ok(())
}
```

**This is the recommended engine for production use.**

---

## Human Validation

The `HumanModel` validates jitter sequences against statistical patterns derived from the [Aalto 136M keystroke dataset](https://userinterfaces.aalto.fi/136Mkeystrokes/).

### Basic Validation

```rust
use wld_jitter::{Session, HumanModel, Jitter};

fn main() {
    let secret = [0u8; 32];
    let mut session = Session::new(secret);

    // Simulate typing (in real use, this comes from actual keystrokes)
    for i in 0..50 {
        let input = format!("key{}", i);
        let _ = session.sample(input.as_bytes());
    }

    // Validate against human model
    let result = session.validate();

    println!("Is human: {}", result.is_human);
    println!("Confidence: {:.2}", result.confidence);
    println!("Anomalies: {}", result.anomalies.len());

    // Examine statistics
    println!("Mean jitter: {:.2}μs", result.stats.mean);
    println!("Std dev: {:.2}μs", result.stats.std_dev);
    println!("Range: [{}, {}]μs", result.stats.min, result.stats.max);
}
```

### Custom Model Configuration

```rust
use wld_jitter::HumanModel;

// Load default model (based on Aalto dataset)
let model = HumanModel::default();

// Load embedded baseline
let baseline = HumanModel::baseline();

// Or create custom model
let custom = HumanModel {
    iki_min_us: 30_000,       // 30ms minimum IKI
    iki_max_us: 2_000_000,    // 2s maximum IKI
    iki_mean_us: 200_000,     // 200ms mean IKI
    iki_std_us: 80_000,       // 80ms std dev
    jitter_min_us: 500,       // Match engine jmin
    jitter_max_us: 3000,      // Match engine jmin + range
    min_sequence_length: 20,  // Minimum samples for validation
    max_perfect_ratio: 0.05,  // Max 5% identical consecutive values
};
```

### Detected Anomalies

| Anomaly | Description | Indicates |
|---------|-------------|-----------|
| `PerfectTiming` | Too many identical consecutive values | Automation, replay attack |
| `LowVariance` | Unnaturally consistent timing | Scripted input, bot |
| `RepeatingPattern` | Periodic patterns in sequence | Macro, automation |
| `OutOfRange` | Values outside human typing range | Invalid data, tampering |
| `DistributionMismatch` | Statistical distribution anomaly | Non-human origin |

### Interpreting Results

```rust
use wld_jitter::{Session, ValidationResult, AnomalyKind};

fn interpret_validation(result: &ValidationResult) {
    match (result.is_human, result.confidence) {
        (true, c) if c > 0.9 => println!("High confidence human"),
        (true, c) if c > 0.7 => println!("Likely human"),
        (true, _) => println!("Possibly human (low confidence)"),
        (false, _) => {
            println!("Likely automated. Anomalies:");
            for anomaly in &result.anomalies {
                match anomaly.kind {
                    AnomalyKind::PerfectTiming =>
                        println!("  - Perfect timing detected (replay?)"),
                    AnomalyKind::LowVariance =>
                        println!("  - Too consistent (bot?)"),
                    AnomalyKind::RepeatingPattern =>
                        println!("  - Pattern detected (macro?)"),
                    AnomalyKind::OutOfRange =>
                        println!("  - Invalid values (tampering?)"),
                    AnomalyKind::DistributionMismatch =>
                        println!("  - Statistical anomaly"),
                }
            }
        }
    }
}
```

---

## Evidence Chain

Evidence is accumulated in an append-only chain with cryptographic integrity. Each record is hashed into a running chain hash, making tampering detectable.

### Creating and Managing Evidence

```rust
use wld_jitter::{EvidenceChain, Evidence};

fn main() {
    let mut chain = EvidenceChain::new();

    // Append evidence records
    chain.append(Evidence::phys([1u8; 32], 1500));
    chain.append(Evidence::pure(2000));
    chain.append(Evidence::phys([2u8; 32], 1800));

    // Chain statistics
    println!("Total records: {}", chain.records.len());
    println!("Physics records: {}", chain.phys_count());
    println!("Pure records: {}", chain.pure_count());
    println!("Physics ratio: {:.1}%", chain.phys_ratio() * 100.0);

    // Chain integrity hash
    println!("Chain MAC: {:02x?}...", &chain.chain_mac[..8]);
}
```

### Serialization

```rust
use wld_jitter::{EvidenceChain, Evidence};

fn main() -> Result<(), serde_json::Error> {
    let mut chain = EvidenceChain::new();
    chain.append(Evidence::phys([1u8; 32], 1500));
    chain.append(Evidence::pure(2000));

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&chain)?;
    println!("{}", json);

    // Deserialize from JSON
    let restored: EvidenceChain = serde_json::from_str(&json)?;
    assert_eq!(restored.records.len(), 2);

    Ok(())
}
```

### Evidence Format

```json
{
  "version": 1,
  "records": [
    {
      "type": "Phys",
      "phys_hash": [1, 2, 3, "...32 bytes..."],
      "jitter": 1500,
      "timestamp_us": 1706745600000000
    },
    {
      "type": "Pure",
      "jitter": 2000,
      "timestamp_us": 1706745600100000
    }
  ],
  "chain_mac": ["...32 bytes..."]
}
```

### Verification

```rust
use wld_jitter::{EvidenceChain, Evidence, PureJitter, JitterEngine};

fn main() {
    let engine = PureJitter::default();
    let secret = [42u8; 32];
    let inputs: Vec<&[u8]> = vec![b"key1", b"key2", b"key3"];

    // Build chain with known inputs
    let mut chain = EvidenceChain::new();
    for input in &inputs {
        let jitter = engine.compute_jitter(&secret, input, [0u8; 32]);
        chain.append(Evidence::pure(jitter));
    }

    // Verify chain against inputs
    assert!(chain.verify_chain(&secret, &inputs, &engine));

    // Fails with wrong inputs
    let wrong_inputs: Vec<&[u8]> = vec![b"wrong1", b"wrong2", b"wrong3"];
    assert!(!chain.verify_chain(&secret, &wrong_inputs, &engine));
}
```

---

## API Reference

### Types

| Type | Description |
|------|-------------|
| `PhysHash` | `[u8; 32]` - SHA-256 hash output |
| `Jitter` | `u32` - Jitter delay in microseconds |

### Error Types

```rust
pub enum Error {
    /// Insufficient entropy collected from hardware.
    InsufficientEntropy { required: u8, found: u8 },

    /// Hardware entropy source not available.
    HardwareUnavailable { reason: String },

    /// Invalid input provided.
    InvalidInput(String),
}
```

### Key Structs

| Struct | Description |
|--------|-------------|
| `Session` | High-level session manager with evidence tracking |
| `HybridEngine` | Combines physics and pure jitter with fallback |
| `PureJitter` | HMAC-based jitter engine (economic security) |
| `PhysJitter` | Hardware entropy-based engine (physics security) |
| `EvidenceChain` | Append-only chain of evidence records |
| `Evidence` | Single evidence record (Phys or Pure) |
| `HumanModel` | Statistical model for validation |
| `ValidationResult` | Result of human validation |

For complete API documentation, see [docs.rs/wld_jitter](https://docs.rs/wld_jitter).

---

## Performance

Benchmarked on Apple M1 Pro:

| Operation | Time | Throughput |
|-----------|------|------------|
| `PureJitter::compute_jitter` | ~200ns | 5M ops/sec |
| `PhysJitter::sample` | ~10μs | 100K ops/sec |
| `HybridEngine::sample` | ~12μs | 83K ops/sec |
| `HumanModel::validate` (1000 samples) | ~50μs | — |
| `EvidenceChain::append` | ~1μs | 1M ops/sec |
| Evidence JSON serialization | ~5μs | 200K ops/sec |

### Memory Usage

| Component | Memory |
|-----------|--------|
| `Session` | ~500 bytes + evidence |
| `Evidence` record | ~80 bytes |
| `EvidenceChain` (1000 records) | ~80KB |

---

## Configuration

### Session Configuration

```rust
use wld_jitter::{Session, HybridEngine, PhysJitter, PureJitter};

// Default configuration
let session = Session::new([0u8; 32]);

// Custom hybrid engine
let phys = PhysJitter::new(8);  // 8 bits minimum entropy
let pure = PureJitter::new(500, 2500);  // 500-3000μs range
let engine = HybridEngine::new(phys, pure)
    .with_min_entropy(8);

// Note: Session uses default HybridEngine
// For custom engine, use HybridEngine directly
```

### Pure Jitter Configuration

```rust
use wld_jitter::PureJitter;

// Default: 500-3000μs range
let default = PureJitter::default();

// Custom range: 1000-5000μs
let custom = PureJitter::new(1000, 4000);
```

### Physics Jitter Configuration

```rust
use wld_jitter::PhysJitter;

// Default: 0 bits minimum (accept all)
let default = PhysJitter::default();

// Require 8 bits minimum entropy
let strict = PhysJitter::new(8);

// Very strict: 16 bits minimum
let very_strict = PhysJitter::new(16);
```

---

## Testing

### Running Tests

```bash
# All tests
cargo test

# All tests with all features
cargo test --all-features

# Specific test
cargo test test_human_validation

# With output
cargo test -- --nocapture
```

### Running Benchmarks

```bash
cargo bench
```

### Testing Feature Combinations

```bash
# Default features only
cargo test

# Hardware feature
cargo test --features hardware

# All features
cargo test --all-features

# No default features (minimal)
cargo test --no-default-features
```

### Fuzzing

This crate includes fuzzing targets using `cargo-fuzz` to find edge cases and potential bugs:

| Target | Description |
|--------|-------------|
| `fuzz_evidence_json` | JSON deserialization of Evidence and EvidenceChain |
| `fuzz_human_model` | HumanModel validation with arbitrary jitter/IKI values |
| `fuzz_evidence_verify` | Evidence verification and chain integrity |
| `fuzz_jitter_compute` | Jitter computation with various parameters |

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz

# Run a specific fuzz target
cargo +nightly fuzz run fuzz_evidence_json

# Run with a time limit (60 seconds)
cargo +nightly fuzz run fuzz_human_model -- -max_total_time=60

# Run all fuzz targets briefly
for target in fuzz_evidence_json fuzz_human_model fuzz_evidence_verify fuzz_jitter_compute; do
  cargo +nightly fuzz run $target -- -max_total_time=10
done
```

---

## FAQ

### General

**Q: What makes this different from just recording timestamps?**

A: `wld_jitter` combines:
1. Cryptographic binding (HMAC) to a session secret
2. Hardware entropy when available (non-reproducible)
3. Statistical validation against real human typing data
4. Tamper-evident chain hashing

Plain timestamps can be easily forged. `wld_jitter` creates evidence that's cryptographically bound to both the secret and the hardware.

**Q: Can this be fooled by typing very slowly?**

A: The human model has upper bounds (~2 seconds) for inter-key intervals. Extremely slow typing may pass validation but would be impractical for generating significant content. The primary defense is against automation, not against dedicated human efforts to create false evidence.

**Q: Does this prove who typed the content?**

A: No. It proves that *someone* typed the content through a human-like process. Authentication (proving identity) requires separate mechanisms.

### Security

**Q: What if the secret is compromised?**

A: In pure jitter mode, a compromised secret allows an attacker to compute valid jitter values. However:
- They still need to match the exact input sequence
- Physics-bound evidence remains valid (hardware entropy can't be reproduced)
- Timestamps provide additional context

For high-stakes applications, use hardware entropy mode and rotate secrets regularly.

**Q: Is the HMAC computation constant-time?**

A: Yes, we use the `hmac` crate from RustCrypto which provides constant-time operations.

**Q: Can an attacker replay evidence?**

A: Evidence includes timestamps, making replay detectable. Physics-bound evidence includes hardware entropy that varies per capture. Applications should also bind evidence to session context (user ID, document ID, etc.).

### Technical

**Q: Why does physics mode fail in my VM?**

A: VMs often don't provide accurate TSC (Time Stamp Counter) readings. The hybrid engine automatically detects this and falls back to pure jitter mode. Check `evidence.is_phys()` to see which mode was used.

**Q: What's the minimum sequence length for validation?**

A: Default is 20 samples. You can adjust this in `HumanModel::min_sequence_length`. Shorter sequences have higher false positive/negative rates.

**Q: Can I use this in WebAssembly?**

A: Yes, but only pure jitter mode is available (no hardware entropy). Compile without the `hardware` feature.

---

## Troubleshooting

### Common Issues

**"InsufficientEntropy" error:**
```
Error: Insufficient entropy: required 8 bits, found 2
```

This occurs when hardware entropy doesn't meet the minimum threshold. Solutions:
1. Use `HybridEngine` for automatic fallback
2. Lower the entropy requirement: `PhysJitter::new(2)`
3. Check if running in a VM (hardware entropy may be unavailable)

**All evidence is "Pure" even on native hardware:**

Check that:
1. The `hardware` feature is enabled
2. You're not running in a container/VM
3. `engine.phys_available()` returns `true`

**Validation always returns `is_human: false`:**

Check for:
1. Sufficient sequence length (minimum 20 by default)
2. Varied input values (not all identical)
3. Reasonable timing variation

```rust
// Debug validation
let result = session.validate();
for anomaly in &result.anomalies {
    println!("Anomaly: {:?} at {}: {}",
        anomaly.kind, anomaly.position, anomaly.detail);
}
```

**High memory usage with large evidence chains:**

Evidence chains grow linearly. For long sessions:
1. Export and archive evidence periodically
2. Start new sessions for new documents
3. Consider summarizing older evidence

---

## Comparison with Alternatives

| Feature | wld_jitter | Timestamp logging | Behavioral biometrics |
|---------|------------|-------------------|----------------------|
| Hardware binding | Yes | No | Varies |
| Cryptographic proof | Yes | No | No |
| Human validation | Yes | No | Yes |
| Privacy preserving | Yes | No | No |
| Offline verification | Yes | Yes | No |
| No external service | Yes | Yes | No |

---

## Roadmap

### Planned Features

- [ ] WASM-optimized builds
- [ ] Additional statistical models
- [ ] Batch verification API
- [ ] Hardware attestation integration
- [ ] Language-specific typing patterns

See [GitHub Issues](https://github.com/writerslogic/writerslogic/issues) for detailed roadmap.

---

## Related Projects

- [WritersLogic](https://github.com/writerslogic/writerslogic) — Cryptographic authorship witnessing monorepo (parent project)
- [wld_engine](../wld_engine/) — Core cryptographic engine
- [wld_protocol](../wld_protocol/) — Wire protocol and CBOR encoding

---

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) before submitting PRs.

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

## Verification

All releases include SLSA Level 3 provenance attestations:

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download and verify
curl -LO https://github.com/writerslogic/writerslogic/releases/download/v0.2.0/...
slsa-verifier verify-artifact artifact.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/writerslogic/writerslogic
```

---

## License

Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing ([LICENSE](LICENSE)).

---

## Acknowledgments

- [Aalto University](https://userinterfaces.aalto.fi/136Mkeystrokes/) for the 136M keystroke dataset
- The [RustCrypto](https://github.com/RustCrypto) team for cryptographic primitives
- The Rust community for foundational tooling

---

<p align="center">
  <sub>Built with care by <a href="https://writerslogic.com">WritersLogic</a></sub>
</p>
