# SLSA Provenance

This directory contains resources for [SLSA](https://slsa.dev/) (Supply-chain
Levels for Software Artifacts) provenance generation.

## Overview

witnessd releases include SLSA Level 3 provenance, which provides:

- **Build Integrity:** Proof that binaries were built from specific source code
- **Source Integrity:** Verification that source comes from expected repository
- **Build Service:** Attestation that builds occurred on trusted infrastructure

## Verification

### Prerequisites

Install the SLSA verifier:

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

### Verify a Release

```bash
# Download release artifacts
curl -LO https://github.com/davidcondrey/witnessd/releases/download/v0.1.0/witnessd_0.1.0_linux_amd64.tar.gz
curl -LO https://github.com/davidcondrey/witnessd/releases/download/v0.1.0/witnessd_0.1.0_linux_amd64.tar.gz.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact witnessd_0.1.0_linux_amd64.tar.gz \
  --provenance-path witnessd_0.1.0_linux_amd64.tar.gz.intoto.jsonl \
  --source-uri github.com/davidcondrey/witnessd \
  --source-tag v0.1.0
```

### Expected Output

```
Verified signature against tance envelope payload.
Verified entry in log
Verified provenance for artifact witnessd_0.1.0_linux_amd64.tar.gz
  * Repository: github.com/davidcondrey/witnessd
  * Tag: v0.1.0
  * Builder: github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml
  * Build type: https://github.com/slsa-framework/slsa-github-generator/generic@v1
PASSED: Verified SLSA provenance
```

## Provenance Contents

The provenance file (`.intoto.jsonl`) contains:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "witnessd_0.1.0_linux_amd64.tar.gz",
      "digest": { "sha256": "abc123..." }
    }
  ],
  "predicate": {
    "builder": { "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
    "invocation": { ... },
    "buildConfig": { ... },
    "materials": [
      {
        "uri": "git+https://github.com/davidcondrey/witnessd@refs/tags/v0.1.0",
        "digest": { "sha1": "..." }
      }
    ]
  }
}
```

## SLSA Levels

| Level | Description | witnessd Status |
|-------|-------------|-----------------|
| L1 | Documentation of build process | ✅ |
| L2 | Tamper-resistant build service | ✅ |
| L3 | Hardened build platform | ✅ |
| L4 | Two-party review + hermetic builds | 🔄 In Progress |

## Implementation

Provenance is generated automatically via GitHub Actions:

1. **Release Workflow** (`.github/workflows/release.yml`):
   - Builds binaries with GoReleaser
   - Generates checksums
   - Creates SBOM

2. **SLSA Generator** (called from release workflow):
   - Uses `slsa-framework/slsa-github-generator`
   - Signs provenance with Sigstore
   - Uploads to GitHub Release

## Resources

- [SLSA Specification](https://slsa.dev/spec/v1.0/)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [In-toto Attestation](https://in-toto.io/)
- [Sigstore](https://www.sigstore.dev/)
