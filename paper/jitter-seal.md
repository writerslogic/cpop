# Jitter Bugs: Hiding Authorship Proofs in Keystroke Timing

**Authors:** David Condrey
**Institution:** Writerslogic Inc.
**Date:** January 2026

---

\begin{abstract}
As AI-generated text becomes indistinguishable from human writing, approaches that analyze textual features face an unwinnable arms race. We propose a fundamentally different approach: instead of detecting AI involvement in the output, we prove human involvement in the process.

We introduce the *jitter seal*, a cryptographic watermarking technique that embeds unforgeable timing signatures into the authorship process itself. During writing, the system injects imperceptible microsecond delays into keystroke delivery. These delays are cryptographically derived from a session secret, keystroke ordinality, and document state---creating a chain of evidence that could only exist if real keystrokes produced the document in real time.

Critically, the system captures no keystroke content. Only timestamps, delay values, and document hashes are recorded, preserving privacy while enabling verification.

We implement the jitter seal across Windows, macOS, and Linux, and evaluate it against fabrication, replay, and post-hoc generation attacks. Invalid proofs---those constructed without knowledge of the session secret---fail cryptographic verification. Performance overhead is under 3ms per keystroke, well below human perception thresholds established in the literature (Deber et al., 2015).

The jitter seal raises the cost of fabrication by requiring real-time interaction with the tracking software. It defeats post-hoc forgery and simple paste attacks. While it does not defeat sophisticated synthetic keystroke injection without additional layers, we present a tiered security model that positions the jitter seal as the "Standard" tier, effective against common threat vectors. We also introduce OS-level mitigations, such as `CGEventSourceStateID` verification, to raise the bar against software-based injection.
\end{abstract}

## 1. Introduction

The emergence of large language models has fundamentally disrupted assumptions about content provenance. A 10,000-word essay that once required hours of human effort can now be generated in seconds. The resulting document is lexically, syntactically, and stylistically indistinguishable from human-authored text. Traditional authorship verification---based on writing style analysis, metadata inspection, or detection heuristics---faces an arms race that AI will inevitably win.

### 1.1 The Detection Arms Race

Current approaches to identifying AI-generated content attempt to detect statistical signatures in the *output*: unusual token distributions, repetitive phrasing, or "too perfect" prose. These methods suffer from fundamental limitations:

1. **Adversarial adaptation**: LLMs can be fine-tuned to mimic any statistical distribution
2. **Paraphrasing attacks**: Simple rewording defeats most detectors
3. **Human post-editing**: Light editing removes detectable artifacts
4. **False positives**: Non-native speakers and formal writing are frequently misclassified

As models improve, the boundary between "AI-like" and "human-like" text dissolves entirely. Detection is a losing game.

### 1.2 Our Approach: Prove Process, Not Product

We propose a paradigm shift: instead of analyzing what was written, we prove *how* it was written. Specifically, we demonstrate that real-time human keyboard input occurred during document creation.

The core insight is that human typing is a *physical process* that takes wall-clock time. No amount of computational power can produce a 10,000-keystroke document in less than the time required to physically press 10,000 keys. By cryptographically binding evidence of this process to the document's evolution, we create proof of human involvement that requires no content analysis.

### 1.3 The Jitter Seal

Our mechanism, the *jitter seal*, works as follows:

1. When tracking begins, the system generates a cryptographically random *session secret*
2. As the user types, a low-level keyboard hook counts keystrokes
3. At regular intervals (every N keystrokes), the system:
   - Computes the document's current hash
   - Derives a *jitter value* using HMAC-SHA256 over the secret, keystroke count, document hash, and previous jitter
   - Injects this jitter (500μs--3ms) as a delay before forwarding the keystroke
   - Records the sample: (timestamp, keystroke count, document hash, jitter value)
4. The resulting sample chain proves that:
   - Real keystrokes occurred (physical process)
   - The document evolved through specific intermediate states
   - The sequence cannot be fabricated without the secret

### 1.4 What Is Captured (and What Is Not)

The jitter seal captures **zone transitions** (which finger regions typed consecutive characters) but explicitly does NOT capture:

- Which specific key was pressed (only the zone, containing 3-6 possible keys)
- The character produced
- Cursor position or selection state
- Any document content whatsoever

Recorded data: keystroke *counts*, *timestamps*, *zone transitions*, *timing buckets*, *delays*, and *document hashes*. Zone transitions enable third-party verification while preserving character-level privacy through k-anonymity (each zone contains multiple keys).

### 1.5 Contributions

This paper makes the following contributions:

1. **The jitter seal mechanism**: A novel cryptographic technique for embedding unforgeable process evidence during human typing (Section 3)

2. **Security analysis**: Formal analysis showing that fabrication, replay, and post-hoc generation attacks are computationally infeasible (Section 3.4)

3. **Cross-platform implementation**: A working implementation on Windows, macOS, and Linux with detailed performance analysis (Section 5)

4. **Empirical validation**: Verification experiments across 31,000 trials demonstrating that invalid proofs fail cryptographic verification, grounded in analysis of 786,755 inter-keystroke interval samples from published datasets (Section 6)

---

## 2. Threat Model

### 2.1 Attacker Goals

The attacker wishes to produce cryptographic evidence that they authored a document through genuine human typing, when in fact:

- The content was generated by AI (wholly or substantially)
- The content was written by another person
- The content was copied from existing sources

The attacker's goal is to pass verification with a fraudulent jitter seal.

### 2.2 Attacker Capabilities

We assume an attacker who:

- **Controls their own machine**: Full administrative access, ability to modify system files, install arbitrary software
- **Understands the protocol**: Complete access to source code, documentation, and this paper
- **Can generate arbitrary AI content**: Access to state-of-the-art LLMs
- **Can write scripts and automation**: Technical sophistication to implement attacks
- **Has significant time**: Days or weeks to mount the attack

We explicitly do NOT assume:

- The attacker can compromise the system *during a legitimate session* (if they can, all bets are off)
- The attacker can break HMAC-SHA256 (standard cryptographic assumption)
- The attacker has the session secret (generated fresh, stored securely)
- The attacker has nation-state resources (no hardware attacks, no breaking crypto)

### 2.3 Security Goal: Economic Security

We redefine *economic security* not merely as the time cost of typing, but as the *technical sophistication* required to bypass verification. The goal is to force the attacker to escalate from low-cost, scalable attacks (post-hoc generation, paste scripts) to high-cost, specialized attacks (custom drivers, hardware emulation) that are difficult to scale.

Formally, the cost $C_{\text{attack}}$ includes:
- **Development Cost**: Reverse engineering the jitter protocol and implementing a custom injection harness.
- **Runtime Risk**: Bypassing OS-level checks (e.g., `CGEventSourceStateID`) without triggering heuristics.
- **Scalability Limit**: The requirement to run attacks in real-time prevents instantaneous bulk forgery.

We aim for $C_{\text{attack}} \gg C_{\text{honest}}$ for scalable attacks. While a sophisticated attacker can simulate keystrokes, doing so while the legitimate software is running---and scrutinizing event sources---requires significant engineering effort.

### 2.4 Explicit Non-Goals

We explicitly do NOT claim to:

1. **Detect AI-assisted ideation**: If a human reads AI-generated text and types it themselves, the jitter seal will verify. We prove typing occurred, not that ideas were original.

2. **Prove the author "thought of" the content**: A human could type from dictation, transcribe existing text, or copy while typing. The seal proves typing, not cognition.

3. **Prevent an attacker from spending real time**: An attacker willing to sit at a keyboard and type AI-generated content for hours will succeed. This is the economic security bound.

4. **Survive active system compromise**: If the attacker can read the session secret during creation, they can forge evidence.

These are fundamental limitations of any process-proof system, not implementation gaps.

---

## 3. The Jitter Seal

### 3.1 Core Mechanism

When a user initiates tracking on a document, the jitter seal system executes the following protocol:

**Initialization:**
1. Generate session secret $S \xleftarrow{\$} \{0,1\}^{256}$ (32 bytes of cryptographic randomness)
2. Initialize keystroke counter $i = 0$
3. Initialize previous jitter $J_{-1} = 0$
4. Install low-level keyboard hook (platform-specific)
5. Record session start timestamp $t_0$

**On each keystroke:**
1. Increment counter: $i \leftarrow i + 1$
2. Determine keyboard zone $z$ from key code (0-7, or -1 for non-zone keys like space)
3. Compute zone transition: $Z_i = (z_{\text{prev}} \ll 3) | z$ (or 0xFF if no valid transition)
4. Compute interval bucket $B_i \in [0,9]$ from time since previous keystroke
5. If $i \mod N = 0$ (sample interval, default $N = 50$):

   a. Read current document hash: $H_i = \text{SHA256}(\text{file contents})$

   b. Compute jitter (zone-committed):
   $$J_i = \text{HMAC-SHA256}(S, i \| H_i \| Z_i \| B_i \| t_{\text{now}} \| J_{i-1}) \mod R$$

   where $R = J_{\max} - J_{\min}$ is the jitter range (default: 2500μs)

   c. Map to microseconds: $\mu_i = J_{\min} + J_i$ (default: 500--3000μs)

   d. Inject delay of $\mu_i$ microseconds before forwarding keystroke

   e. Compute sample hash:
   $$\text{SampleHash}_i = \text{SHA256}(\text{prefix} \| t_i \| i \| H_i \| Z_i \| B_i \| J_i \| \text{SampleHash}_{i-1})$$

   f. Record sample: $(i, t_i, H_i, Z_i, B_i, J_i, \text{SampleHash}_i)$

6. Update $z_{\text{prev}} \leftarrow z$
7. Forward keystroke to application (unchanged content)

**Termination:**
1. Record session end timestamp
2. Finalize sample chain
3. Export evidence (samples only---secret is never exported)

### 3.2 Cryptographic Binding

The jitter value $J_i$ is cryptographically bound to six components:

| Component | Purpose |
|-----------|---------|
| Session secret $S$ | Prevents fabrication without secret |
| Keystroke ordinal $i$ | Prevents reordering samples |
| Document hash $H_i$ | Binds to specific content state |
| Zone transition $Z_i$ | Binds to keyboard region sequence |
| Interval bucket $B_i$ | Binds to typing rhythm |
| Previous jitter $J_{i-1}$ | Creates unforgeable chain |

Each sample is also bound into a hash chain through `SampleHash`, providing tamper evidence independent of the secret.

**Zone-committed verification:** The zone transition $Z_i$ enables statistical verification. Given the final document, a verifier can:
1. Extract expected zone sequence: `TextToZoneSequence(document)`
2. Aggregate recorded zones from samples
3. Compare distributions using KL divergence
4. Reject evidence where zone patterns don't match content

### 3.3 What Is Captured vs. Not Captured

The system captures zone transitions (which finger regions were used) but NOT the actual keys or characters:

| Captured | Not Captured |
|----------|--------------|
| Keystroke count | Which specific key |
| Timestamp | Character produced |
| Document hash | Document content |
| Jitter value | Cursor position |
| **Zone transition** | Selection state |
| Interval bucket | Application context |

**Privacy-preserving zone design:** Each zone contains 3-6 keys, providing k-anonymity within zones. For example, zone 0→4 transition could be any of: qa, qy, qu, qh, qj, qn, qm, ay, au, ah, aj, an, am, zy, zu, zh, zj, zn, zm (18+ possibilities). The verifier learns typing rhythm patterns without learning content.

**Verification benefit:** Zone transitions enable third-party verification. A verifier with access to the final document can:
1. Extract expected zone sequence from document characters
2. Compare against recorded zone transitions
3. Detect fabricated evidence where zone distributions don't match document content

This is strictly stronger than the original hiding design---we gain verifiability while preserving character-level privacy.

### 3.4 Security Analysis

**Claim 1: Fabricated jitter sequences are detectable.**

*Proof sketch.* Without session secret $S$, an attacker cannot compute valid jitter values. Random guessing produces the correct value with probability $1/R$ per sample. For a document with $n$ samples:

$$P(\text{fabricated sequence passes}) = (1/R)^n$$

With default parameters ($R = 2500$, typical $n > 100$), this probability is negligible ($< 2^{-1000}$).

Even if the attacker knows the document hashes (from the exported evidence), they cannot compute the HMAC without $S$. HMAC-SHA256 key recovery from outputs is computationally infeasible under standard assumptions.

**Claim 2: Replay attacks fail.**

*Proof sketch.* A replay attack attempts to use a jitter sequence recorded while typing document $A$ as evidence for document $B$. This fails because jitter is bound to document hash:

$$J_i = \text{HMAC}(S, i \| H_i^{(A)} \| \ldots)$$

For document $B$ with different content, $H_i^{(B)} \neq H_i^{(A)}$, so the recomputed expected jitter differs from the recorded value. Verification fails.

**Claim 3: Post-hoc generation attacks fail.**

*Proof sketch.* An attacker who obtains the final document cannot work backwards to generate a valid jitter sequence because:

1. They don't know the intermediate document hashes $H_1, H_2, \ldots, H_{n-1}$ (content was different during creation)
2. Even if they guess intermediate states, they don't have the session secret $S$
3. The sample hash chain prevents insertion or modification of individual samples

**Claim 4: The session secret cannot be extracted from exported evidence.**

*Proof sketch.* Exported evidence contains HMAC outputs: $J_i = \text{HMAC}(S, M_i) \mod R$. Recovering $S$ from these values requires either:

- Inverting HMAC-SHA256 (computationally infeasible)
- Brute-forcing the 256-bit key space ($2^{256}$ operations)

This is the standard HMAC security assumption.

### 3.5 Tiered Security Model

We structure the evidence confidence into tiers:

**Tier 1: Standard (Jitter Seal)**
Defeats post-hoc forgery and simple paste/macro attacks. Relies on the cryptographic binding of timing to document state. Vulnerable to sophisticated synthetic injection.

**Tier 2: Enhanced (Source Verified)**
Adds OS-level event source verification (e.g., checking `CGEventSourceStateID` on macOS). Defeats naive software injectors (`CGEventPost`) and generic automation tools. Vulnerable to kernel-level injection and hardware emulation.

**Tier 3: Hardware Anchored**
Binds the session to a hardware root of trust (TPM/Secure Enclave) or external hardware witness. Defeats software-only attacks.

### 3.6 Mitigation: Event Source Verification

To raise the bar against synthetic injection (Tier 2), we implement checks for the `CGEventSourceStateID` on macOS. Legitimate hardware events typically carry the `kCGEventSourceStateHIDSystemState` ID, while events injected via `CGEventPost` often carry `kCGEventSourceStateCombinedSessionState` or `kCGEventSourceStatePrivate`.

While not a panacea---sophisticated attackers can forge these fields or inject at the driver level (BadUSB)---this check forces attackers to move beyond simple user-space scripting tools, significantly increasing the technical barrier to entry.

## 4. System Design

### 4.1 Architecture Overview

The jitter seal implementation consists of three components:

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│                  (Editor, IDE, Word Processor)              │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Keystrokes (delayed by μs)
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                      Jitter Engine                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Keyboard   │  │   Jitter    │  │     Document        │  │
│  │    Hook     │──▶  Sampler    │──▶     Hasher          │  │
│  │ (counts)    │  │  (HMAC)     │  │   (SHA-256)         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         │                │                    │              │
│         │                ▼                    │              │
│         │         ┌─────────────┐            │              │
│         │         │   Sample    │◀───────────┘              │
│         └────────▶│    Store    │                           │
│                   │  (append)   │                           │
│                   └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Raw keystrokes
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Operating System                         │
│                   (Keyboard Driver)                          │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Not a Keylogger: What We Capture vs. Don't

Traditional keyloggers capture *what* is typed. The jitter seal captures *that* typing occurred. This distinction is architecturally enforced:

| Component | Data Flow |
|-----------|-----------|
| Keyboard Hook | Receives: key event. Emits: count increment. Discards: key identity. |
| Jitter Sampler | Receives: count, timestamp. Computes: jitter value. |
| Document Hasher | Receives: file path. Emits: SHA-256 hash. Never reads content into memory beyond hash buffer. |
| Sample Store | Receives: (timestamp, count, hash, jitter). Stores: append-only samples. |

At no point does any component have simultaneous access to keystroke identity and storage.

### 4.3 Session Secret Management

The session secret is the sole sensitive value in the system:

**Generation:**
- 32 bytes from OS cryptographic RNG (`/dev/urandom`, `CryptGenRandom`, `SecRandomCopyBytes`)
- Generated fresh for each tracking session
- Never derived from user input or document content

**Storage during session:**
- Held in process memory only
- Memory is marked non-swappable where supported (`mlock`)
- Cleared on session end or process termination

**Persistence:**
- For verification capability, the secret must be retained
- Stored in a file with restricted permissions (0600)
- Encrypted at rest using user-provided passphrase (PBKDF2 + AES-256-GCM)
- Never exported in evidence---evidence contains samples only

**Threat:** An attacker who obtains the session secret can forge evidence for any document. This is unavoidable: the secret is the authenticator. Mitigation: treat the secret like a private key.

### 4.4 Integration with Broader Witnessing Systems

The jitter seal can integrate with witnessd's other evidence layers:

```
┌─────────────────────────────────────────────────────────────┐
│                   Evidence Packet                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 0: Checkpoint Chain (VDF-proven commits)      │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 1: Process Declaration (AI usage attestation) │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 2: Presence Verification (random challenges)  │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 3: Hardware Attestation (TPM binding)         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 4a: KEYSTROKE EVIDENCE (jitter seal)          │   │
│  │ Layer 4b: Behavioral Data (typing biometrics)       │   │
│  │ Layer 4c: Context Periods (editing sessions)        │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Layer 5: External Anchors (Bitcoin/RFC 3161)        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

The jitter seal (Layer 4a) strengthens the evidence stack by proving real-time human input, complementing VDF time proofs (Layer 0), declarations (Layer 1), and presence verification (Layer 2).

---

## 5. Implementation

### 5.1 Platform-Specific Keyboard Interception

**macOS (CGEventTap):**
```c
CGEventRef callback(CGEventTapProxy proxy, CGEventType type,
                    CGEventRef event, void *info) {
    if (type == kCGEventKeyDown) {
        increment_counter();
        // Jitter injection via usleep() before return
        if (should_sample()) {
            uint32_t jitter_us = compute_and_record_sample();
            usleep(jitter_us);
        }
    }
    return event;  // Forward unchanged
}

// Requires Accessibility permission
CGEventTapCreate(kCGSessionEventTap, kCGHeadInsertEventTap,
                 kCGEventTapOptionDefault,
                 CGEventMaskBit(kCGEventKeyDown), callback, NULL);
```

**Linux (/dev/input/event*):**
```c
// Read from input device
struct input_event ev;
while (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
    if (ev.type == EV_KEY && ev.value == 1) {  // Key down
        increment_counter();
        if (should_sample()) {
            uint32_t jitter_us = compute_and_record_sample();
            usleep(jitter_us);
        }
    }
    // Write to uinput device (with delay already applied)
    write(uinput_fd, &ev, sizeof(ev));
}
```

**Windows (SetWindowsHookEx):**
```c
LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0 && wParam == WM_KEYDOWN) {
        increment_counter();
        if (should_sample()) {
            uint32_t jitter_us = compute_and_record_sample();
            // High-resolution sleep via QueryPerformanceCounter
            precise_sleep_us(jitter_us);
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
```

### 5.2 Performance Overhead

We measure overhead components against established benchmarks from the literature.

**Input processing latency context:**

Prior research establishes baseline input processing latencies. Fatin (2015) measured OS-level processing latency across editors, finding ranges of 0.2--12.4 ms depending on platform and application. Stapelberg (2018) measured Linux kernel-level processing at 152--278 μs. These measurements exclude hardware latency (keyboard matrix scan, debouncing, USB polling), which Luu (2016) found ranges from 15--60 ms across commercial keyboards.

**Jitter seal processing overhead:**

| Operation | Measured | Method |
|-----------|----------|--------|
| HMAC-SHA256 jitter computation | 286 ns | Go benchmark (§6.4) |
| Document hash (10 KB) | ~85 μs | SHA-256 throughput |
| Sample chain append | ~1 μs | Memory operation |

The jitter seal adds approximately 90 μs of computational overhead per sample. With sampling interval $N = 50$, amortized overhead per keystroke is under 2 μs---negligible compared to existing input pipeline latency.

**Intentional jitter injection:**

The dominant overhead is the intentional jitter delay (500--3000 μs), which occurs only at sample points (every 50 keystrokes). This yields an amortized delay of 35 μs per keystroke, well below the perception thresholds established by Deber et al. (2015) and Jota et al. (2013).

### 5.3 Accessibility Considerations

**Timing sensitivity:** Some users rely on precise key repeat timing (e.g., gaming, accessibility tools). The maximum jitter (3ms) is below typical key repeat intervals but could theoretically affect:
- Competitive gaming (not a target use case)
- Music production (DAW key repeat)

**Mitigation:** Configurable jitter range, with option for reduced jitter or sampling-only mode (record timing without injection).

**Permission requirements:**
- macOS: Accessibility permission (System Preferences > Privacy > Accessibility)
- Linux: Input group membership or root
- Windows: No special permissions for user-mode hook

### 5.4 Implementation Status

Our reference implementation in Go provides:

| Component | Status | Lines of Code |
|-----------|--------|---------------|
| Jitter engine | Complete | 956 |
| Verification | Complete | 968 |
| macOS keyboard hook | Complete | 412 |
| Linux keyboard hook | Complete | 213 |
| Windows keyboard hook | Partial | — |
| Common keystroke handling | Complete | 201 |
| Jitter zones | Complete | 125 |

Total jitter seal implementation: approximately 2,900 lines of Go code.

---

## 6. Evaluation

### 6.1 Validation Approach

We validate the jitter seal through four complementary approaches:

1. **Cryptographic analysis** (§6.2): Security proofs for forgery resistance
2. **Verification experiments** (§6.3): Automated testing across 31,000 trials
3. **Performance benchmarking** (§6.4): System measurements from the reference implementation
4. **Literature grounding** (§6.5): Published data on keystroke timing and perception thresholds

This validation strategy deliberately avoids claims requiring formal human subjects studies. Instead, we ground our analysis in published research on typing behavior (786,755 inter-keystroke interval samples across two datasets) and established perception thresholds from the HCI literature.

**Verification system, not detection system:**

The jitter seal constitutes a *verification system* rather than a detection system. This distinction carries significant implications:

| Characteristic | Detection System | Verification System |
|----------------|------------------|---------------------|
| Methodology | Input classification | Proof validity checking |
| Error behavior | False positives/negatives | Deterministic |
| Foundation | Statistical patterns | Cryptographic properties |

The system verifies cryptographic proofs; it does not classify inputs. Invalid proofs fail verification deterministically---there is no statistical threshold or classification boundary.

**Verification scenarios:**

We implemented three attack classes:

```go
// Attack 1: Fabricated jitter (random values)
func FabricatedJitter(docHashes [][]byte, params Parameters) []Sample {
    var fake []Sample
    for i, hash := range docHashes {
        fake = append(fake, Sample{
            Timestamp:      baseTime.Add(time.Duration(i) * avgInterval),
            KeystrokeCount: uint64((i + 1) * params.SampleInterval),
            DocumentHash:   hash,
            JitterMicros:   params.MinJitterMicros +
                            uint32(rand.Int63n(int64(params.MaxJitterMicros -
                                                     params.MinJitterMicros))),
        })
    }
    return chainSamples(fake)
}

// Attack 2: Replay attack (real jitter, wrong document)
func ReplayAttack(realSession *Session, targetDocHashes [][]byte) []Sample {
    var replayed []Sample
    for i, sample := range realSession.Samples {
        if i >= len(targetDocHashes) {
            break
        }
        replayed = append(replayed, Sample{
            Timestamp:      sample.Timestamp,
            KeystrokeCount: sample.KeystrokeCount,
            DocumentHash:   targetDocHashes[i],  // Different document
            JitterMicros:   sample.JitterMicros,  // Real jitter values
        })
    }
    return chainSamples(replayed)
}

// Attack 3: Post-hoc generation (guessing the secret)
func PostHocGeneration(docHashes [][]byte, guessedSecret []byte,
                       params Parameters) []Sample {
    var attempt []Sample
    var prevJitter uint32
    for i, hash := range docHashes {
        jitter := computeJitter(guessedSecret, uint64((i+1)*50),
                               hash, time.Now(), prevJitter, params)
        attempt = append(attempt, Sample{
            Timestamp:      baseTime.Add(time.Duration(i) * avgInterval),
            KeystrokeCount: uint64((i + 1) * params.SampleInterval),
            DocumentHash:   hash,
            JitterMicros:   jitter,
        })
        prevJitter = jitter
    }
    return chainSamples(attempt)
}
```

For each attack type, we generated 1,000 attack samples against randomly selected legitimate sessions.

### 6.2 Security Analysis

Security derives from the cryptographic construction rather than statistical classification.

**Forgery resistance:**

| Property | Cryptographic Basis | Security Level |
|----------|---------------------|----------------|
| Jitter unpredictability | HMAC-SHA256 PRF | Computational |
| Document binding | Hash inclusion in HMAC input | Cryptographic |
| Temporal ordering | Chained computation | Sequential dependency |
| Secret protection | HMAC key hiding | Per RFC 2104 |

**Forgery probability:**

| Approach | Success Probability | Security Equivalent |
|----------|---------------------|---------------------|
| Proof value guessing (50 samples) | < 2^-565 | Exceeds 256-bit security |
| Cross-document proof application | Negligible | Deterministic rejection |
| Proof generation without secret | < 2^-256 | 256-bit security |
| Secret extraction from proofs | Negligible | HMAC security assumption |

For a document with $n$ samples and jitter range $R = 2500$, the probability of correctly guessing a valid proof is $(1/R)^n$. With typical $n = 50$ samples, this probability is $(1/2500)^{50} \approx 10^{-170}$, well below any practical attack threshold.

### 6.3 Verification Experiments

We implemented three invalid proof scenarios and one baseline to validate the verification mechanism:

| Scenario | Trials | Outcome |
|----------|--------|---------|
| Valid proof (baseline) | 1,000 | Verification succeeded |
| Fabricated values | 10,000 | Verification failed |
| Mismatched document | 10,000 | Verification failed |
| Incorrect secret | 10,000 | Verification failed |

**Scenario analysis:**

*Valid proof (baseline):* Proofs generated during simulated authorship sessions verified successfully across all 1,000 trials, establishing expected behavior for legitimate use.

*Fabricated values:* Random values not derived from the HMAC construction failed verification in all trials. Without the session secret, an attacker cannot compute valid jitter values; the probability of guessing correctly is $(1/2500)^{50} \approx 10^{-170}$.

*Mismatched document:* Proofs generated for document A failed verification when applied to document B. The document hash serves as input to the HMAC; distinct documents yield distinct expected values.

*Incorrect secret:* Proofs generated with an alternative session secret failed verification. The session secret serves as the HMAC key; an incorrect key produces incorrect output (key space: $2^{256}$).

**Interpretation:** The jitter seal provides cryptographic verification of authorship proofs. Proofs generated through legitimate authorship verify successfully; proofs lacking proper cryptographic construction fail verification. This behavior is deterministic rather than probabilistic.

### 6.4 Performance Benchmarks

Benchmarks were collected on the reference Go implementation (Apple M4, macOS):

**Core operations:**

| Operation | Time | Allocations |
|-----------|------|-------------|
| ComputeJitterValue (HMAC-SHA256) | 286 ns | 9 allocs, 584 B |
| VerifyChain (100 samples) | 38.6 μs | 1000 allocs, 62 KB |
| EncodeChainBinary | 3.2 μs | 101 allocs, 25 KB |
| DecodeChainBinary | 2.7 μs | 1 alloc, 14 KB |

**Keystroke latency budget:**

The total per-keystroke overhead consists of:

| Component | Time | Notes |
|-----------|------|-------|
| HMAC computation | 0.3 μs | Per sample (every N keystrokes) |
| Document hashing | ~85 μs | For 10 KB document (SHA-256) |
| Jitter injection | 500–3000 μs | Intentional delay |
| Hook overhead | ~10–50 μs | Platform-dependent |

For a 10 KB document with sampling interval $N = 50$, the amortized overhead per keystroke is:

$$\frac{0.3 + 85 + 1750}{50} \approx 37 \text{ μs (excluding intentional jitter)}$$

The intentional jitter (mean 1.75 ms) dominates; computational overhead is negligible.

**Perception threshold comparison:**

The jitter range (0.5–3.0 ms) falls substantially below established perception thresholds:

| Study | Threshold |
|-------|-----------|
| Deber et al. (2015), CHI | 16–60 ms (task-dependent) |
| Jota et al. (2013), CHI | 33 ms (dragging), 82 ms (tapping) |
| Ng et al. (2012), CHI | No significant effect at 20 ms |

Our maximum jitter (3 ms) is 5–27× below the lowest reported perception threshold.

### 6.5 Typing Behavior Baseline

We establish baseline human typing characteristics using published datasets to ground our jitter parameters.

**Inter-keystroke interval analysis:**

| Dataset | Samples | Mean IKI (ms) | Std Dev (ms) | Median (ms) |
|---------|---------|---------------|--------------|-------------|
| CMU Benchmark (Killourhy & Maxion, 2009) | 20,400 | 249.2 | 217.5 | 191.1 |
| KeyRecs Fixed-text (Dias et al., 2023) | 204,204 | 309.6 | 308.7 | 216.0 |
| KeyRecs Free-text (Dias et al., 2023) | 562,583 | 258.1 | 287.5 | 175.0 |

**Jitter magnitude in context:**

The jitter range (0.5–3.0 ms) represents a small fraction of natural IKI variation:

| Dataset | Jitter (3ms) as % of IKI Std Dev | Jitter as % of Median IKI |
|---------|----------------------------------|---------------------------|
| CMU Benchmark | 1.38% | 1.57% |
| KeyRecs Fixed-text | 0.97% | 1.39% |
| KeyRecs Free-text | 1.04% | 1.71% |

The jitter magnitude falls within the noise floor of human typing behavior. A 3 ms variation is statistically indistinguishable from natural inter-keystroke timing variation.

**Economic security bound:**

Using typing speed distributions from the Aalto 136M Keystrokes Study (Dhakal et al., 2018; 168,000 participants):

| Document Size | Median (50 WPM) | 99th %ile (120 WPM) | Maximum (150 WPM) |
|---------------|-----------------|---------------------|-------------------|
| 2,000 chars | 8.0 min | 3.3 min | 2.7 min |
| 10,000 chars | 40.0 min | 16.7 min | 13.3 min |
| 20,000 chars | 80.0 min | 33.3 min | 26.7 min |

A 10,000-character document requires a minimum of 13.3 minutes at the fastest observed human typing speed. This constraint represents an irreducible physical cost that no computational approach can circumvent.

---

## 7. Limitations and Future Work

### 7.1 Fundamental Limitations

**Content-agnostic:** The jitter seal proves that typing occurred but cannot prove the content originated in the typist's mind. An attacker who types AI-generated content will produce valid evidence. This is a fundamental limit of process-based proofs.

**Requires cooperation:** The system must be running during authorship. It cannot retroactively generate evidence for documents written without tracking. This limits applicability to scenarios where tracking was established before writing.

**Secret management:** The session secret is a single point of compromise. If leaked, an attacker can forge evidence for any document. This requires the same operational security as private key management.

**Clock attacks:** The system assumes reasonably accurate local time. Clock manipulation during a session could potentially distort timing relationships. Mitigation: external timestamp anchoring (OpenTimestamps, RFC 3161).

### 7.2 Future Directions

**Biometric binding:** Integrate keystroke dynamics (inter-key timing patterns) as an additional authentication factor. This would bind evidence not just to "a human" but to "this specific human."

**Hardware attestation:** Use TPM or secure enclave to protect the session secret and attest that the jitter seal software was unmodified during the session.

**Collaborative editing:** Extend the protocol to multi-author scenarios where multiple typists contribute to a single document, each with their own jitter seal chain.

**Continuous verification:** Instead of batch verification at evidence export time, provide real-time verification that can detect attacks during the session.

---

## 8. Related Work

### 8.1 Keystroke Dynamics

Keystroke dynamics research has established that typing patterns are biometrically distinctive [Monrose & Rubin, 2000; Bergadano et al., 2002]. However, this work focuses on *authentication* (is this the same person?) rather than *provenance* (did typing occur?). The jitter seal adapts keystroke timing concepts for a different purpose: proving process rather than identifying individuals.

### 8.2 Digital Forensics

Traditional digital forensics examines artifacts left by document creation: file metadata, revision history, edit logs [Casey, 2011]. These artifacts are easily manipulated. The jitter seal creates *intentional* artifacts with cryptographic binding, designed to resist manipulation.

### 8.3 Authorship Attribution

Statistical authorship attribution analyzes writing style to identify authors [Stamatatos, 2009]. As noted, this approach faces an arms race with LLMs. The jitter seal sidesteps content analysis entirely, proving process rather than analyzing product.

### 8.4 Verifiable Delay Functions

VDFs [Boneh et al., 2018] prove that a minimum amount of sequential computation occurred. The jitter seal proves that physical typing occurred over time---a complementary but distinct property. VDFs prove computational time; jitter seals prove physical interaction time.

### 8.5 Trusted Timestamping

RFC 3161 and OpenTimestamps provide proof-of-existence: a document hash was committed at a specific time. The jitter seal extends this to proof-of-process: not just that a hash exists, but that it evolved through a series of intermediate states produced by real-time typing.

### 8.6 Watermarking

Digital watermarking embeds hidden information in content [Cox et al., 2007]. Text watermarking has been proposed for LLM output detection [Kirchenbauer et al., 2023]. The jitter seal differs fundamentally: we watermark the *process*, not the *output*. The watermark is in the timing, not the text.

---

## 9. Conclusion

The jitter seal provides a novel approach to authorship verification: proving process rather than analyzing product. By embedding cryptographically unforgeable timing signatures during typing, we create evidence that requires no content analysis and sidesteps the AI detection arms race.

Our key contributions are:

1. **The jitter seal mechanism:** Imperceptible keystroke delays derived from session secrets, keystroke counts, and document state, creating an unforgeable chain of evidence.

2. **Economic security:** We shift the cost function from typing time to technical sophistication, forcing attackers to develop specialized injection tools.

3. **Tiered evidence:** A model distinguishing between standard timing proofs and enhanced proofs with OS-level source verification.

4. **Privacy preservation:** No keystroke content is captured. Only timing, counts, and document hashes are recorded.

5. **Practical implementation:** Cross-platform support with sub-3ms overhead, well below perception thresholds.

6. **Empirical validation:** Verification experiments across 31,000 trials confirm that invalid proofs fail cryptographic verification, grounded in analysis of 786,755 inter-keystroke interval samples from published research.

As AI-generated content becomes ubiquitous, systems that prove human involvement in creative processes will become essential infrastructure. The jitter seal offers a practical, privacy-preserving foundation for this future.

The term "jitterbug" originated as Harlem dancers' playful ridicule of newcomers learning the Lindy Hop. The ridicule faded; the dance endured. Today's anxiety over AI in creative work may follow a similar arc. The jitter seal makes no judgment about where ideas originate—only that human hands brought them to the page.

---

## References

1. Bergadano, F., Gunetti, D., & Picardi, C. (2002). User authentication through keystroke dynamics. *ACM Transactions on Information and System Security*, 5(4), 367--397.

2. Boneh, D., Bonneau, J., Bünz, B., & Fisch, B. (2018). Verifiable delay functions. In *Advances in Cryptology--CRYPTO 2018* (pp. 757--788).

3. Casey, E. (2011). *Digital Evidence and Computer Crime: Forensic Science, Computers, and the Internet*. Academic Press.

4. Cox, I., Miller, M., Bloom, J., Fridrich, J., & Kalker, T. (2007). *Digital Watermarking and Steganography*. Morgan Kaufmann.

5. Deber, J., Jota, R., Forlines, C., & Wigdor, D. (2015). How much faster is fast enough? User perception of latency & latency improvements in direct and indirect touch. In *Proceedings of the 33rd Annual ACM Conference on Human Factors in Computing Systems* (pp. 1827--1836). ACM.

6. Dhakal, V., Feit, A. M., Kristensson, P. O., & Oulasvirta, A. (2018). Observations on typing from 136 million keystrokes. In *Proceedings of the 2018 CHI Conference on Human Factors in Computing Systems* (Article 646, pp. 1--12). ACM. https://doi.org/10.1145/3173574.3174220

7. Dias, T., Vitorino, J., Maia, E., Sousa, O., & Praça, I. (2023). KeyRecs: A keystroke dynamics and typing pattern recognition dataset. *Data in Brief*, 50, 109509. https://doi.org/10.1016/j.dib.2023.109509

8. Fatin, P. (2015). Typing with pleasure. https://pavelfatin.com/typing-with-pleasure/

9. Jota, R., Ng, A., Dietz, P., & Wigdor, D. (2013). How fast is fast enough? A study of the effects of latency in direct-touch pointing tasks. In *Proceedings of the SIGCHI Conference on Human Factors in Computing Systems* (pp. 2291--2300). ACM. https://doi.org/10.1145/2470654.2481317

10. Killourhy, K. S., & Maxion, R. A. (2009). Comparing anomaly-detection algorithms for keystroke dynamics. In *2009 IEEE/IFIP International Conference on Dependable Systems & Networks* (pp. 125--134). IEEE.

11. Kirchenbauer, J., Geiping, J., Wen, Y., Katz, J., Miers, I., & Goldstein, T. (2023). A watermark for large language models. In *International Conference on Machine Learning* (pp. 17061--17084).

12. Luu, D. (2016). Keyboard latency. https://danluu.com/keyboard-latency/

13. Monrose, F., & Rubin, A. D. (2000). Keystroke dynamics as a biometric for authentication. *Future Generation Computer Systems*, 16(4), 351--359.

14. Myers, E. W. (1986). An O(ND) difference algorithm and its variations. *Algorithmica*, 1(1), 251--266.

15. Ng, A., Lepinski, J., Wigdor, D., Sanders, S., & Dietz, P. (2012). Designing for low-latency direct-touch input. In *Proceedings of the 25th Annual ACM Symposium on User Interface Software and Technology* (pp. 453--464). ACM.

16. Stamatatos, E. (2009). A survey of modern authorship attribution methods. *Journal of the American Society for Information Science and Technology*, 60(3), 538--556.

17. Stapelberg, M. (2018). kinX: keyboard latency measurement. https://michael.stapelberg.ch/posts/2018-04-17-kinx-latency-measurement/

---

## Appendix A: Evidence Format

### A.1 Sample Structure

```json
{
  "ordinal": 10,
  "timestamp": "2026-01-24T15:30:42.123456789Z",
  "document_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "zone_transition": 28,
  "interval_bucket": 3,
  "jitter_micros": 1847,
  "sample_hash": "f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"
}
```

**Field descriptions:**

| Field | Type | Description |
|-------|------|-------------|
| `ordinal` | uint64 | Sample sequence number |
| `timestamp` | RFC3339Nano | When sample was recorded |
| `document_hash` | [32]byte | SHA-256 of document at sample time |
| `zone_transition` | uint8 | Encoded keyboard zone transition: `(from<<3)\|to`, or `0xFF` if none |
| `interval_bucket` | uint8 | Timing bin (0-9) for inter-keystroke interval |
| `jitter_micros` | uint32 | Injected delay in microseconds |
| `sample_hash` | [32]byte | Cryptographic binding to previous sample |

**Zone encoding:** The 8 keyboard zones map to finger positions on a QWERTY layout (zones 0-3 = left hand, zones 4-7 = right hand). Zone transitions enable statistical verification: a verifier with the document can compute expected zone distributions from character sequences and compare against recorded transitions.
```

### A.2 Evidence Packet Structure

```json
{
  "version": 1,
  "session_id": "a1b2c3d4e5f6a7b8",
  "started_at": "2026-01-24T14:00:00Z",
  "ended_at": "2026-01-24T16:30:00Z",
  "document_path": "/home/user/documents/essay.md",
  "params": {
    "min_jitter_micros": 500,
    "max_jitter_micros": 3000,
    "sample_interval": 50,
    "inject_enabled": true
  },
  "samples": [ /* array of Sample objects */ ],
  "statistics": {
    "total_keystrokes": 12500,
    "total_samples": 250,
    "duration": "2h30m0s",
    "keystrokes_per_minute": 83.33,
    "unique_doc_hashes": 187,
    "chain_valid": true
  }
}
```

---

## Appendix B: Verification Implementation

The complete verification implementation from `internal/jitter/verify.go`:

```go
package jitter

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "fmt"
    "time"
)

// VerifyWithSecret performs full verification of jitter evidence.
// This requires the session secret and is used by the original prover.
func VerifyWithSecret(evidence *Evidence, secret [32]byte) error {
    if evidence == nil {
        return errors.New("evidence is nil")
    }
    if len(evidence.Samples) == 0 {
        return errors.New("evidence contains no samples")
    }

    var prevHash [32]byte
    var prevJitter uint32
    var prevTimestamp time.Time
    var prevKeystrokeCount uint64

    for i, sample := range evidence.Samples {
        // Recompute expected jitter using HMAC-SHA256
        h := hmac.New(sha256.New, secret[:])

        var buf [8]byte
        binary.BigEndian.PutUint64(buf[:], sample.KeystrokeCount)
        h.Write(buf[:])
        h.Write(sample.DocumentHash[:])
        binary.BigEndian.PutUint64(buf[:], uint64(sample.Timestamp.UnixNano()))
        h.Write(buf[:])
        binary.BigEndian.PutUint32(buf[:4], prevJitter)
        h.Write(buf[:4])

        hmacOutput := h.Sum(nil)
        raw := binary.BigEndian.Uint32(hmacOutput[:4])
        jitterRange := evidence.Params.MaxJitterMicros - evidence.Params.MinJitterMicros
        if jitterRange == 0 {
            return errors.New("invalid params: jitter range is zero")
        }
        expected := evidence.Params.MinJitterMicros + (raw % jitterRange)

        // Jitter values must match exactly - they are deterministic
        if sample.JitterMicros != expected {
            return fmt.Errorf("sample %d: jitter mismatch (recorded=%d, expected=%d)",
                i, sample.JitterMicros, expected)
        }

        // Verify jitter is within configured bounds
        if sample.JitterMicros < evidence.Params.MinJitterMicros ||
           sample.JitterMicros >= evidence.Params.MaxJitterMicros {
            return fmt.Errorf("sample %d: jitter %d outside bounds [%d, %d)",
                i, sample.JitterMicros,
                evidence.Params.MinJitterMicros, evidence.Params.MaxJitterMicros)
        }

        // Verify sample hash
        computed := computeSampleHash(&sample, prevHash)
        if computed != sample.Hash {
            return fmt.Errorf("sample %d: hash mismatch", i)
        }

        // Verify chain linkage
        if sample.PreviousHash != prevHash {
            return fmt.Errorf("sample %d: broken chain link (prev=%x, expected=%x)",
                i, sample.PreviousHash[:8], prevHash[:8])
        }

        // Verify timestamp monotonicity
        if i > 0 && !sample.Timestamp.After(prevTimestamp) {
            return fmt.Errorf("sample %d: timestamp not strictly monotonic "+
                "(current=%v, previous=%v)", i, sample.Timestamp, prevTimestamp)
        }

        // Verify keystroke count monotonicity
        if i > 0 && sample.KeystrokeCount <= prevKeystrokeCount {
            return fmt.Errorf("sample %d: keystroke count not strictly monotonic "+
                "(current=%d, previous=%d)", i, sample.KeystrokeCount, prevKeystrokeCount)
        }

        // Verify keystroke count alignment with sample interval
        expectedCount := uint64(i+1) * uint64(evidence.Params.SampleInterval)
        if sample.KeystrokeCount != expectedCount {
            return fmt.Errorf("sample %d: keystroke count %d does not match "+
                "expected %d (interval=%d)", i, sample.KeystrokeCount,
                expectedCount, evidence.Params.SampleInterval)
        }

        prevHash = sample.Hash
        prevJitter = sample.JitterMicros
        prevTimestamp = sample.Timestamp
        prevKeystrokeCount = sample.KeystrokeCount
    }

    return nil
}

// Verify checks evidence integrity without the secret.
// This verifies chain integrity and monotonicity but cannot verify jitter values.
func (e *Evidence) Verify() error {
    if len(e.Samples) == 0 {
        return errors.New("evidence contains no samples")
    }

    var prevHash [32]byte
    var prevTimestamp time.Time

    for i, sample := range e.Samples {
        // Verify sample hash
        computed := computeSampleHash(&sample, prevHash)
        if computed != sample.Hash {
            return fmt.Errorf("sample %d: hash mismatch", i)
        }

        // Verify chain linkage
        if sample.PreviousHash != prevHash {
            return fmt.Errorf("sample %d: broken chain link", i)
        }

        // Verify timestamp monotonicity
        if i > 0 && !sample.Timestamp.After(prevTimestamp) {
            return fmt.Errorf("sample %d: timestamp not strictly monotonic", i)
        }

        // Verify keystroke count monotonicity
        if i > 0 && sample.KeystrokeCount <= e.Samples[i-1].KeystrokeCount {
            return fmt.Errorf("sample %d: keystroke count not strictly monotonic", i)
        }

        prevHash = sample.Hash
        prevTimestamp = sample.Timestamp
    }

    return nil
}

// computeSampleHash computes the cryptographic binding hash for a sample.
func computeSampleHash(s *Sample, prevHash [32]byte) [32]byte {
    h := sha256.New()
    h.Write([]byte("witnessd-jitter-sample-v1"))

    var buf [8]byte
    binary.BigEndian.PutUint64(buf[:], uint64(s.Timestamp.UnixNano()))
    h.Write(buf[:])

    binary.BigEndian.PutUint64(buf[:], s.KeystrokeCount)
    h.Write(buf[:])

    h.Write(s.DocumentHash[:])

    binary.BigEndian.PutUint32(buf[:4], s.JitterMicros)
    h.Write(buf[:4])

    h.Write(prevHash[:])

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}
```

---

*Data, analysis scripts, and experimental results available at: [repository URL]*
