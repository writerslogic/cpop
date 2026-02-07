# Frequently Asked Questions

## Table of Contents

- [General Questions](#general-questions)
- [Privacy and Security](#privacy-and-security)
- [Technical Questions](#technical-questions)
- [Legal Questions](#legal-questions)
- [Practical Usage](#practical-usage)

---

## General Questions

### What is witnessd?

Witnessd is a cryptographic authorship witnessing system that creates tamper-evident records proving you created a document over time. It captures:
- **What**: Content hashes at each checkpoint
- **When**: VDF-based timing proofs that cannot be backdated
- **How**: Optional keystroke metrics showing real writing activity
- **Who**: Cryptographic identity tied to your device

### Why would I need this?

Common use cases include:
- **Writers**: Prove original authorship of manuscripts, articles, or scripts
- **Researchers**: Document the development of ideas and discoveries
- **Developers**: Track code evolution with cryptographic evidence
- **Legal/Compliance**: Meet FRE 902(13) self-authentication requirements
- **IP Protection**: Establish prior art or creation dates

### How is this different from version control?

| Feature | witnessd | Git |
|---------|----------|-----|
| Time proofs | VDF - cannot be backdated | Timestamps can be faked |
| Author binding | Hardware-tied identity | Email-based (spoofable) |
| Keystroke evidence | Yes (proves real typing) | No |
| Forward secrecy | Ratcheting keys | No |
| Evidence packets | Self-contained, portable | Requires full repo |

### Is witnessd open source?

Yes! Witnessd is released under the MIT License. The source code is available at:
https://github.com/writerslogic/witnessd

---

## Privacy and Security

### Does witnessd record what I type?

**No.** Witnessd explicitly does NOT capture:
- Which keys you press
- Keyboard content or characters
- Screen content
- Clipboard data
- Any actual text you write

It only records:
- **Count** of keystroke events
- **Timing** of keystrokes (nanosecond jitter)
- **Hashes** of file content (not content itself)

### Where is my data stored?

All data is stored locally on your machine:
- **CLI**: `~/.witnessd/`
- **macOS App**: `~/Library/Application Support/Witnessd/`

No data is sent to any server unless you explicitly export and share it.

### What data is in an evidence packet?

An exported evidence packet (.wpkt) contains:
- File content hashes (not content itself)
- Checkpoint timestamps and VDF proofs
- Keystroke counts and timing statistics
- Your public key and session certificates
- Signed declarations

**Not included** (by default): The actual content of your document.

### Can someone track my identity across documents?

Your master identity (public key fingerprint) is consistent across all documents. This is intentional for:
- Proving the same author created multiple works
- Building reputation and trust

If you need unlinkability, you can:
- Generate a separate identity for different projects
- Use the CLI with a different `--config` directory

### Is my signing key secure?

Your private signing key is stored with 0600 permissions (owner read/write only). The key:
- Never leaves your device
- Is derived from your device's PUF
- Uses Ed25519 (state-of-the-art security)

Best practices:
- Keep a secure backup of `~/.witnessd/signing_key`
- Never share your private key
- Use full disk encryption

---

## Technical Questions

### What is a VDF?

A Verifiable Delay Function (VDF) is a cryptographic function that:
- Takes a predictable amount of time to compute
- Cannot be parallelized or sped up
- Produces a proof that can be quickly verified

Witnessd uses VDFs to prove that real time elapsed between checkpoints. You cannot backdate a checkpoint because you cannot compute the VDF faster than real time.

### What is the key hierarchy?

Witnessd uses a three-tier key hierarchy:

1. **Tier 0 (Identity)**: Master key derived from your device's PUF
   - Persistent author identity
   - Never used directly for signing

2. **Tier 1 (Session)**: Per-session keys certified by master
   - Isolates sessions from each other
   - Includes session certificate

3. **Tier 2 (Ratchet)**: Per-checkpoint keys with forward secrecy
   - Each checkpoint gets unique key
   - Previous keys are securely deleted
   - Cannot forge past checkpoints

### What is a PUF?

A Physical Unclonable Function (PUF) produces a unique response based on physical characteristics of your device. On:
- **Apple Silicon Macs**: Secure Enclave provides hardware PUF
- **Other systems**: Software PUF using hardware identifiers

This binds your identity to your specific device.

### What are the evidence tiers?

| Tier | Name | Requirements |
|------|------|--------------|
| 1 | Basic | Checkpoints + VDF proofs |
| 2 | Software-Attested | + Key hierarchy + Declaration |
| 3 | Hardware-Attested | + TPM/Secure Enclave binding |

Higher tiers provide stronger evidence but require more hardware support.

### How much storage does witnessd use?

Typical usage:
- **Per checkpoint**: ~500 bytes in database
- **Per hour of writing**: ~10 KB (with keystroke tracking)
- **Evidence packet**: 5-50 KB depending on checkpoints

Database grows slowly - thousands of checkpoints fit in a few megabytes.

### Can I use witnessd offline?

Yes! Witnessd works entirely offline. The only network-optional features are:
- External anchoring (e.g., Bitcoin timestamping)
- Fetching drand beacon values (for additional time proof)

All core functionality works without internet.

---

## Legal Questions

### Does this provide legal proof of authorship?

Witnessd creates strong cryptographic evidence of authorship, but legal acceptance depends on:
- Jurisdiction
- Type of proceeding
- Expert testimony to explain the evidence
- Other corroborating evidence

The evidence is designed to be admissible under FRE 902(13) for self-authentication of electronic records.

### What is FRE 902(13)?

Federal Rules of Evidence 902(13) allows electronic records to be self-authenticating if certified by a qualified person. Witnessd evidence packets include:
- Cryptographic verification of integrity
- Chain of custody through signatures
- Declarations of authenticity

### Should I use witnessd for legal disputes?

Witnessd provides technical evidence. For legal matters:
- Consult an attorney
- Expert testimony may be needed to explain evidence
- Combine with other documentation (emails, drafts, etc.)

### Does witnessd guarantee I created the content?

Witnessd proves:
- Content existed at specific times
- Real typing activity occurred
- The same device/identity signed all checkpoints

It cannot prove you didn't copy content from elsewhere. However:
- Keystroke evidence shows real typing occurred
- VDF timing proves work happened over real time
- Consistent identity ties all evidence together

---

## Practical Usage

### How often should I create checkpoints?

Recommendations by use case:

| Use Case | Interval | Reason |
|----------|----------|--------|
| Casual writing | Every session | Minimal overhead |
| Important documents | Every 15-30 minutes | Balance proof strength with workflow |
| Legal/compliance | Every 5-10 minutes | Maximum provability |
| Automatic (sentinel) | Every 1-5 minutes | Hands-off, continuous |

### Should I enable keystroke tracking?

**Pros:**
- Stronger evidence of authentic authorship
- Proves real typing occurred
- Jitter patterns are unique to the author

**Cons:**
- Requires accessibility permissions (macOS)
- Minor battery impact on laptops

For important documents or legal needs, enable tracking. For casual use, basic checkpoints are sufficient.

### Can I checkpoint the same file from multiple devices?

Yes, but each device will have:
- Different master identity
- Separate checkpoint chains
- Independent evidence

To maintain one chain, work on one device or use sync with caution (checkpoint before sync, verify after).

### What happens if I edit an old checkpoint?

Checkpoints are immutable. If you:
1. Revert a file to an old version
2. Create a new checkpoint

The new checkpoint will:
- Show the old content hash
- Link to the previous (newer) checkpoint
- Clearly show the reversion in history

This is transparent and doesn't corrupt the chain.

### Can I use witnessd with cloud documents?

Yes, with caveats:
- Checkpoint local copies of the file
- Google Docs/Notion/etc. can be exported and checkpointed
- The local file must match what you're working on

For best results, work on local files and sync to cloud as backup.

### How do I share evidence with someone?

1. Export the evidence packet:
   ```bash
   witnessd export document.md -o evidence.wpkt
   ```

2. Share the `.wpkt` file

3. Recipient verifies:
   ```bash
   witnessd verify evidence.wpkt
   ```

No account or registration needed - verification is self-contained.

### Can I verify evidence without witnessd installed?

The evidence packet includes verification instructions. Third-party verification requires:
- Understanding the cryptographic primitives (Ed25519, SHA-256, VDF)
- Implementing or using verification code

We're working on a web-based verifier at https://verify.witnessd.io

---

## More Questions?

- **Documentation**: https://docs.witnessd.io
- **GitHub Issues**: https://github.com/writerslogic/witnessd/issues
- **Community Discord**: https://discord.gg/witnessd

---

*Patent Pending: USPTO Application No. 19/460,364*
