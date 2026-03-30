[//]: # (SPDX-License-Identifier: Apache-2.0)

<div align="center">

<img alt="cpop-protocol" src="https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/proof-of-process/main/assets/branding/production/dark/png/cpop-protocol.png" width="360">

### Wire format, CBOR/COSE codec, and evidence builder for CPoP

[![crates.io](https://img.shields.io/crates/v/cpop-protocol.svg?style=for-the-badge)](https://crates.io/crates/cpop-protocol)
[![downloads](https://img.shields.io/crates/d/cpop-protocol?style=for-the-badge)](https://crates.io/crates/cpop-protocol)
[![docs.rs](https://img.shields.io/docsrs/cpop-protocol?style=for-the-badge)](https://docs.rs/cpop-protocol)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://github.com/LF-Decentralized-Trust-labs/proof-of-process/blob/main/LICENSE)

Part of the [Cryptographic Proof of Process (CPoP)](https://github.com/LF-Decentralized-Trust-labs/proof-of-process/blob/main/README.md) specification — an [LF Decentralized Trust](https://www.lfdecentralizedtrust.org/) Lab

</div>

---

## Overview

`cpop-protocol` is the reference implementation of the CPoP wire format as
defined in [`draft-condrey-cpop-protocol`](../../draft-condrey-cpop-protocol.md).
It provides the types, codec, and cryptographic logic needed to build and
verify CPoP Evidence Packets and Written Authorship Reports.

## Quick Start

```toml
[dependencies]
cpop-protocol = "0.1"
```

```rust
use cpop_protocol::evidence::{Builder, Verifier};
use cpop_protocol::rfc::DocumentRef;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Create a document reference
let document = DocumentRef::new("doc.txt", b"document content");

// Build evidence
let signing_key = SigningKey::generate(&mut OsRng);
let mut builder = Builder::new(document, Box::new(signing_key)).unwrap();
builder.add_checkpoint(b"first edit").unwrap();
let (packet, raw) = builder.finalize().unwrap();

// Verify evidence
let verifier = Verifier::new(signing_key.verifying_key());
assert!(verifier.verify(&packet, &raw).is_ok());
```

## Modules

| Module | Description |
|--------|-------------|
| `evidence` | `Builder` and `Verifier` — build and verify evidence packets |
| `codec` | CBOR/COSE encoding (RFC 8949, RFC 9052) |
| `crypto` | SHA-256, HMAC, Ed25519 signatures, `EvidenceSigner` trait |
| `rfc` | Wire format types: `EvidencePacket`, `DocumentRef`, CBOR tags |
| `identity` | X.509 certificate generation, CSR, Proof-of-Possession |
| `c2pa` | C2PA manifest builder with CPoP evidence assertions |
| `forensics` | Entropy analysis and transcription verification |
| `baseline` | Behavioral baseline operations |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Standard library support |
| `full` | No | All features enabled |
| `wasm` | No | WebAssembly bindings via wasm-bindgen |
| `apple-secure-enclave` | No | Apple Secure Enclave support |

## Contributing

See [CONTRIBUTING.md](https://github.com/LF-Decentralized-Trust-labs/proof-of-process/blob/main/CONTRIBUTING.md) for DCO sign-off requirements and contribution workflow.

## License

Apache License, Version 2.0. See [LICENSE](https://github.com/LF-Decentralized-Trust-labs/proof-of-process/blob/main/LICENSE).

Part of the [proof-of-process](https://github.com/LF-Decentralized-Trust-labs/proof-of-process) repository.
