# wld_jitter

**wld_jitter** (formerly `physjitter`) is the hardware timing entropy foundation for the WritersLogic ecosystem. It provides cryptographic proof-of-process through timing jitter, enabling verification that content was created through a human typing process.

**License:** Apache-2.0
**Path:** [`crates/wld_jitter`](https://github.com/writerslogic/writerslogic/tree/main/crates/wld_jitter)

---

## Key Responsibilities

- **Jitter Computation**: HMAC-based timing jitter bound to session secrets and input
- **Hardware Entropy**: [[Glossary#TSC|TSC]]/CNTVCT sampling for physics-based security when available
- **Human Validation**: Statistical model trained on the Aalto 136M keystroke dataset
- **Evidence Chains**: Append-only cryptographic chain of [[Glossary#Jitter Seal|jitter evidence]] records

## Security Models

### Economic Security (`PureJitter`)

Security relies on the **economic cost** of reproducing the exact input sequence. Works everywhere including VMs, containers, and WebAssembly.

### Physics Security (`PhysJitter`)

Security relies on **hardware entropy** from the CPU's timing variations, which cannot be perfectly simulated or replayed.

### Hybrid Security (`HybridEngine`) -- Recommended

Combines both models: uses physics when available, falls back to pure jitter in virtualized environments. Evidence records which mode was used.

## Architecture

```
wld_jitter/src/
├── lib.rs         Session, HybridEngine, public API
├── traits.rs      EntropySource, JitterEngine traits
├── pure.rs        PureJitter (HMAC-based)
├── phys.rs        PhysJitter (hardware entropy)
├── evidence.rs    Evidence, EvidenceChain
└── model.rs       HumanModel (statistical validation)
```

## Features

| Feature | Description | Default |
|:--------|:------------|:--------|
| `std` | Standard library support | Yes |
| `hardware` | TSC/hardware entropy collection | No |
| `rand` | Random secret generation | No |

## `no_std` Support

The crate supports `no_std` environments (embedded, WASM) when compiled with `default-features = false`. Only pure jitter mode is available without `std`.

## Human Validation

The `HumanModel` validates jitter sequences against statistical patterns from the [Aalto 136M keystroke dataset](https://userinterfaces.aalto.fi/136Mkeystrokes/). Detected anomalies include:

| Anomaly | Indicates |
|:--------|:----------|
| `PerfectTiming` | Automation or replay attack |
| `LowVariance` | Scripted input or bot |
| `RepeatingPattern` | Macro or automation |
| `OutOfRange` | Invalid data or tampering |
| `DistributionMismatch` | Non-human origin |

## Usage

```toml
[dependencies]
wld_jitter = { git = "https://github.com/writerslogic/writerslogic", branch = "main" }
```

## Related Pages

- [[wld_engine]] - Uses wld_jitter for evidence generation
- [[wld_protocol]] - Wire format for jitter evidence
- [[Behavioral Metrics]] - Keystroke dynamics specification
- [[Glossary]] - Key terms (Jitter Seal, IKI, PUF, etc.)
