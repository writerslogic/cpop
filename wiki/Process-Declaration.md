# Process Declaration Specification

**Version:** 1.0.0

## Overview

A **Process Declaration** is a cryptographically signed attestation by an author describing how they created a document. Unlike behavioral detection (which attempts to infer process from artifacts), declarations shift the burden to **legal and social accountability**.

## Design Philosophy

### Documentation Over Detection
Traditional authorship verification attempts to *detect* AI involvement through statistical analysis. This is an "arms race" that detection tools eventually lose. Process declarations take a different approach: **document what cannot be detected, attest to what cannot be proven**.

### Accountability Framework
A false declaration carries consequences:
- **Professional misconduct** in academia.
- **Breach of contract** in commerce.
- **Fraud or Perjury** in legal contexts.

---

## Declaration Structure

A declaration is a signed JSON object containing:

| Field | Description |
|:------|:------------|
| `document_hash` | SHA-256 hash of the final document. |
| `chain_hash` | Hash of the associated CPoE checkpoint chain. |
| `input_modalities` | How the content was created (keyboard, dictation, paste, etc.). |
| `ai_tools` | List of AI tools used, their purpose, and extent (none, minimal, moderate, substantial). |
| `collaborators` | Human co-authors or editors involved. |
| `statement` | The legally binding attestation text. |
| `signature` | Ed25519 signature over the canonical payload. |

---

## AI Extent Levels

Authors categorize AI involvement using the following levels:

| Level | Guidance |
|:------|:---------|
| `none` | No AI tools were used in the creative process. |
| `minimal` | Minor suggestions accepted (grammar, style, word choice). |
| `moderate` | Significant assistance (paragraph suggestions, structural edits). |
| `substantial` | Major portions were AI-generated and then reviewed/edited by the author. |

---

## Example Declaration

```json
{
  "title": "Quarterly Research Report",
  "input_modalities": [
    { "type": "keyboard", "percentage": 95.0 },
    { "type": "paste", "percentage": 5.0 }
  ],
  "ai_tools": [
    {
      "tool": "Claude",
      "purpose": "feedback",
      "extent": "minimal",
      "interaction": "Used for grammar review and structural suggestions."
    }
  ],
  "statement": "I hereby declare that this document was authored primarily by me. I used AI only for minor editing as documented above. All conclusions are my own.",
  "author_public_key": "...",
  "signature": "..."
}
```

---

*For verification procedures, see the **[[Evidence Format]]**.*
