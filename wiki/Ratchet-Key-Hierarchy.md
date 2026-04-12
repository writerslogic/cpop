# Ratchet Key Hierarchy Specification

CPoE uses a three-tier key hierarchy to provide **persistent identity**, **session isolation**, and **forward secrecy**.

---

## The Three Tiers

### Tier 0: Identity Root (Master Key)
- **Derived From**: [[Glossary#PUF|Hardware PUF (Physical Unclonable Function)]] or [[Glossary#TPM|TPM]].
- **Purpose**: Represents the author's persistent identity.
- **Security**: Never used to sign document checkpoints directly. It only signs "Session Certificates."

### Tier 1: Session Key
- **Derived From**: Master Key + Random Session ID.
- **Purpose**: Isolates different documents or writing sessions.
- **Security**: Certified by the Master Key. If one session is compromised, others remain secure.

### Tier 2: Ratcheting Checkpoint Key
- **Derived From**: Previous Ratchet State + Current Checkpoint Hash.
- **Purpose**: Signs individual checkpoints.
- **Security**: **[[Glossary#Key Ratchet|Forward Secrecy]]**. After a checkpoint is signed, the old key is securely wiped from memory. An attacker who gains access to the current key cannot forge or modify past checkpoints.

---

## Key Derivation Flow

```text
[ Hardware PUF ] 
       |
       v
[ Tier 0: Master Identity ]  <-- Persistent Author ID
       |
       | (Signs Session Cert)
       v
[ Tier 1: Session Key ]      <-- Bound to one document
       |
       | (HKDF Ratchet)
       v
[ Tier 2: Checkpoint Key N ] <-- Signs Checkpoint N
       |
       | (Wipe Key N)
       v
[ Tier 2: Checkpoint Key N+1 ] <-- Signs Checkpoint N+1
```

---

## Security Properties

- **Device Binding**: Evidence is cryptographically linked to the physical hardware where it was created.
- **Forward Secrecy**: Past checkpoints are protected even if the current device state is compromised.
- **Mathematical Foundation**: Built on HKDF-SHA256 (RFC 5869) and Ed25519 (RFC 8032).

---

*For more on evidence structure, see the **[[Evidence Format]]**.*
