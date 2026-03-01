# witnessd_protocol

Core Rust implementation of the Proof-of-Process (PoP) Protocol.

## Overview

Proof-of-Process (PoP) is a protocol currently being socialized in the IETF RATS working group. It provides a mechanism for high-integrity process verification, ensuring that a particular process (human or automated) has occurred as claimed.

This crate serves as the core library for PoP, providing the necessary cryptographic primitives, data structures, and protocol encoding (CBOR/COSE) required for interoperable implementations.

## Features

- **CBOR/COSE Encoding**: Native support for PoP packet serialization following RFC 8949 and RFC 9052.
- **Cryptographic Primitives**: Integration with standard Rust crypto libraries for signatures and hashing.
- **Protocol Models**: Complete implementation of PoP protocol models as defined in the internet-drafts.
- **Hardware Attestation**: Support for hardware-backed evidence collection and verification.
- **X.509 Identity**: Certificate-based identity with Proof-of-Possession verification.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
witnessd_protocol = { git = "https://github.com/writerslogic/witnessd", branch = "main" }
```

## Related Projects

- [witnessd](https://github.com/writerslogic/witnessd): Monorepo containing all witnessd components.
- [witnessd_jitter](../witnessd_jitter): Hardware entropy collection primitive for PoP.
- [witnessd_engine](../witnessd_engine): High-performance cryptographic engine.
- [draft-condrey-rats-pop](https://github.com/writerslogic/draft-condrey-rats-pop): IETF Internet-Draft source.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.
