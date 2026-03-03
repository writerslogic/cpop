# Behavioral Metrics Specification

WritersLogic uses behavioral forensic metrics to analyze whether a document's creation process is consistent with human authorship. These metrics look at the **rhythm** and **topology** of edits without ever capturing the content of what is being written.

---

## Core Metrics

### 1. Inter-Event Interval
- **What it measures**: The time elapsed between consecutive edits or keystrokes.
- **Human Baseline**: Typically 150ms to 500ms for active typing.
- **Detection**: Instantaneous bursts (e.g., < 10ms for large blocks) suggest copy-pasting or AI-generated insertions.

### 2. Edit Entropy
- **What it measures**: The spatial distribution of edits across the document.
- **Human Pattern**: Humans tend to jump around a document to revise earlier sections.
- **Detection**: High concentration in only one area (low entropy) or purely sequential appending can be a sign of automated generation.

### 3. Positive/Negative Ratio
- **What it measures**: The balance between adding new text and deleting/revising existing text.
- **Human Pattern**: Natural writing involves significant revision (deletions).
- **Detection**: A document created with 100% insertions and 0% deletions is highly suspicious for non-human origin.

---

## Forensic Metrics Suite

WritersLogic implements a tiered forensic evaluation suite that produces a composite **Authorship Score (PS)**.

### 1. Keystroke Cadence Analysis

Evaluates the rhythm and stability of [[Glossary#IKI|Inter-Keystroke Intervals (IKI)]].

- **Mean IKI (μ):** Average time between key presses.
- **Coefficient of Variation (CV):** Standard deviation divided by mean ($CV = \sigma / \mu$).
- **Robotic Detection:** A $CV < 0.15$ indicates unnatural consistency (robotic cadence), suggesting automated transcription or scripted injection.
- **Cognitive Bursts:** Human typing is characterized by high-velocity word bursts followed by pauses for thought. Stability analysis detects the absence of these bursts.

### 2. Edit Topology (The [[Glossary#The Labyrinth|Labyrinth]])

Analyzes where and how document modifications occur over time.

- **Monotonic Append Ratio:** The percentage of edits occurring within the last 5% of the document. High ratios (>0.90) suggest sequential generation (typical of AI) rather than iterative revision.
- **Edit Entropy:** Shannon entropy of modification locations. Human revision is distributed throughout the text; low entropy indicates highly focused or programmatic edits.
- **Deletion Clustering:** Human authors tend to delete in contiguous blocks during revision. Scattered, single-character deletions are flagged as suspicious.

### 3. Composite Authorship Score (Process Score)

The system computes a final RFC-compliant Process Score using the following weighted formula:

$$PS = 0.3R + 0.3S + 0.4B$$

| Weight | Factor | Name | Description |
|:-------|:-------|:-----|:------------|
| 30% | **R** | **Residency** | Total duration and continuity of the editing session. |
| 30% | **S** | **Sequence** | Integrity of the hash-chain and edit topology entropy. |
| 40% | **B** | **Behavioral** | Keystroke cadence, CV analysis, and burst detection. |

**Verdict Thresholds:**
- **PS ≥ 0.90:** Manual Composition Consistent (Verified Human)
- **0.70 ≤ PS < 0.90:** Manual Composition Likely (Some Anomalies)
- **0.40 ≤ PS < 0.70:** Inconclusive Analysis
- **PS < 0.40:** Automated/Retyped Content Likely (Likely Synthetic)

## [[Glossary#Jitter Seal|Jitter Seals]] (Tier 2 Evidence)

For higher-tier evidence, WritersLogic uses **Jitter Seals**.
 This measures the nanosecond-level timing variations (jitter) between keystrokes. 

- **Uniqueness**: Every person has a unique "typing fingerprint" based on their neuromuscular timing.
- **Cryptographic Binding**: This jitter is used as entropy to seed the cryptographic keys for each checkpoint, proving that the work happened in real-time on a physical device.

---

## Privacy First
- **No Content Capture**: WritersLogic records *when* you type, but never *what* you type.
- **Local Processing**: All behavioral analysis happens on your device.
- **Statistical Aggregates**: Only high-level statistics (e.g., "Median Interval: 250ms") are included in exported evidence packets.

---

*For more on how these are stored, see the **[[Evidence Format]]**.*
