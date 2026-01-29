# Data Acquisition Plan for Jitter Seal Paper

**Last Updated:** 2026-01-25

## Overview

This document outlines the datasets needed to support empirical claims in the jitter seal research paper and identifies available public datasets that can be used.

## Claims Requiring Empirical Support

| Paper Section | Claim | Data Type Needed |
|---------------|-------|------------------|
| §1 | Human typing has distinctive timing patterns | Inter-keystroke interval distributions |
| §6.1 | Ground truth: 12 participants, 847 sessions | Real typing session data |
| §6.2 | Attack simulations (fabricated, replay, post-hoc) | Attack test data |
| §6.3 | 99.65% verification rate | Legitimate session verification |
| §6.4 | Performance benchmarks (latency, memory, CPU) | System performance measurements |
| §6.5 | Jitter imperceptibility (p=0.34) | Human perception study |
| §2.3 | Economic security (typing rate bounds) | Typing speed distributions |

---

## Available Public Datasets

### 1. CMU Keystroke Dynamics Benchmark Dataset

**Best for:** Baseline inter-keystroke timing patterns, verification algorithm testing

| Attribute | Value |
|-----------|-------|
| Subjects | 51 |
| Samples per subject | 400 password entries |
| Timing precision | ±200 microseconds |
| Content type | Fixed text (password) |
| License | Research use |
| URL | https://www.cs.cmu.edu/~keystroke/ |

**Captured features:**
- Key press timestamps
- Key release timestamps
- Dwell time (hold duration)
- Flight time (inter-key latency)

**Limitations:** Fixed text only (password typing), not free-form authoring.

---

### 2. Aalto University 136M Keystrokes Dataset

**Best for:** Typing speed distributions, human baseline statistics

| Attribute | Value |
|-----------|-------|
| Subjects | 168,000 |
| Total keystrokes | 136 million |
| Content type | Free text typing test |
| Average WPM | 51.56 (SD = 20.2) |
| Paper | "Observations on Typing from 136 Million Keystrokes" (CHI 2018) |

**Key statistics from paper:**
- WPM distribution: slight positive skewness (0.513), kurtosis -0.11
- Fastest typists: 120+ WPM
- Inter-keystroke intervals: available in supplementary data

**Limitations:** Web-based collection, may have timing jitter from browser.

---

### 3. KeyRecs Dataset (Zenodo)

**Best for:** Free-text typing patterns, inter-key latencies

| Attribute | Value |
|-----------|-------|
| Subjects | 100 (20 nationalities) |
| Content type | Fixed text AND free text |
| Features | Digraph latencies (DD, DU, UD, UU) |
| License | CC-BY 4.0 |
| URL | https://zenodo.org/records/7886743 |

**Captured features:**
- Inter-key latencies (digraph model)
- Password retyping
- Transcription exercises
- Dwell times

---

### 4. IKDD Dataset (MDPI)

**Best for:** Large-scale free-text keystroke dynamics

| Attribute | Value |
|-----------|-------|
| Subjects | 164 |
| Files | 533 log files |
| Keystrokes per file | 3,500 |
| Content type | Daily computer typing (free text) |
| License | CC-BY 4.0 |
| URL | https://www.mdpi.com/2078-2489/15/9/511 |
| Published | August 2024 |

**Advantages:** Collected during real daily work, not lab conditions.

---

### 5. EmoSurv Dataset (IEEE DataPort)

**Best for:** Timing data with emotional context

| Attribute | Value |
|-----------|-------|
| Content type | Free and fixed text |
| Features | DD, DU, UD, UU latencies |
| Additional | Emotion labels |
| URL | https://ieee-dataport.org/open-access/emosurv-typing-biometric-keystroke-dynamics-dataset-emotion-labels-created-using |

---

### 6. Mendeley Human vs Synthesized Dataset

**Best for:** Attack simulation (distinguishing human from synthetic typing)

| Attribute | Value |
|-----------|-------|
| Content | Human-written + synthesized keystroke samples |
| Source data | CMU, González-Calot, Banerjee datasets |
| Purpose | Evaluate liveness detection |
| URL | https://data.mendeley.com/datasets/mzm86rcxxd/2 |

This dataset is particularly valuable for validating attack detection claims.

---

## Human Perception Threshold Literature

For the imperceptibility claim (§6.5), these studies provide baseline data:

| Study | Finding |
|-------|---------|
| [Ng et al., CHI 2012](https://dl.acm.org/doi/fullHtml/10.1145/3626705.3627784) | No significant performance effect at 20ms latency |
| [Jota et al., CHI 2013](https://www.researchgate.net/publication/221100500_User_Perception_of_Touch_Screen_Latency) | JND for dragging: 33ms, tapping: 82ms |
| [Tactual Labs, CHI 2015](https://www.tactuallabs.com/papers/howMuchFasterIsFastEnoughCHI15.pdf) | Latency perception depends on interaction frequency |
| System Latency Guidelines | Users perceive latencies down to ~16-60ms in demanding tasks |

**Key finding for jitter seal:** Our jitter range (500μs - 3000μs) is 1-2 orders of magnitude below perception thresholds.

---

## Recommended Data Strategy

### Phase 1: Establish Baselines (Use Public Data)

| Claim | Dataset | Approach |
|-------|---------|----------|
| Human typing rate bounds | Aalto 136M | Extract percentiles: 10th, 50th, 90th, 99th |
| Inter-keystroke intervals | CMU Benchmark | Compute IKI distributions |
| Free-text patterns | IKDD, KeyRecs | Analyze timing variability |

### Phase 2: Attack Validation (Synthetic + Public)

| Attack Type | Data Source |
|-------------|-------------|
| Fabricated jitter | Generate random timing sequences |
| Replay attack | Use CMU/KeyRecs timing on different documents |
| Post-hoc generation | Mendeley synthesized samples |

### Phase 3: Collect Proprietary Data

For the core claims about jitter seal verification, we need data collected with the actual jitter seal implementation:

**Minimum viable study:**
| Parameter | Value |
|-----------|-------|
| Participants | 20-30 |
| Sessions per participant | 10-20 |
| Total sessions | 300-600 |
| Duration | 2-4 weeks |
| Document types | Prose, code, notes |

**Data to collect:**
1. Jitter sample chains (timestamp, keystroke count, document hash, jitter value)
2. Session metadata (duration, platform, editor)
3. Final documents (for hash verification)
4. User feedback (perceived responsiveness)

### Phase 4: Perception Study

**Protocol:**
1. Within-subjects design
2. Conditions: No jitter, standard jitter (500-3000μs), elevated jitter (1-10ms)
3. Task: 10-minute typing session per condition
4. Measure: Likert scale responsiveness rating, WPM, error rate
5. Statistical test: Paired t-test or repeated measures ANOVA

**Minimum sample size:** 24 participants (allows detection of medium effect size)

---

## Dataset Licensing Summary

| Dataset | License | Commercial Use |
|---------|---------|----------------|
| CMU Keystroke | Research only | Check with authors |
| Aalto 136M | Paper supplementary | Contact authors |
| KeyRecs | CC-BY 4.0 | Yes, with attribution |
| IKDD | CC-BY 4.0 | Yes, with attribution |
| EmoSurv | IEEE DataPort terms | Check terms |
| Mendeley | CC-BY 4.0 | Yes, with attribution |

---

## Immediate Action Items

1. **Download available datasets:**
   - [ ] CMU Keystroke Benchmark: https://www.cs.cmu.edu/~keystroke/
   - [ ] KeyRecs: https://zenodo.org/records/7886743
   - [ ] IKDD: Request from MDPI paper supplementary
   - [ ] Mendeley synthesized: https://data.mendeley.com/datasets/mzm86rcxxd/2

2. **Analyze baseline statistics:**
   - [ ] Compute IKI distributions from CMU/KeyRecs
   - [ ] Extract typing speed percentiles from Aalto paper
   - [ ] Validate attack detection on Mendeley human vs synthetic

3. **Design proprietary study:**
   - [ ] IRB/ethics approval (if institutional)
   - [ ] Recruitment plan
   - [ ] Data collection protocol
   - [ ] Informed consent template

4. **Update paper with dataset citations:**
   - [ ] Add dataset references to Section 6
   - [ ] Clarify which claims use public data vs proprietary collection
   - [ ] Add data availability statement

---

## References

1. Killourhy, K. S., & Maxion, R. A. (2009). Comparing anomaly-detection algorithms for keystroke dynamics. *DSN 2009*.

2. Dhakal, V., Feit, A. M., Kristensson, P. O., & Oulasvirta, A. (2018). Observations on typing from 136 million keystrokes. *CHI 2018*.

3. González-Calot, et al. (2023). KeyRecs: A keystroke dynamics and typing pattern recognition dataset. *Data in Brief*.

4. Morales, A., et al. (2024). IKDD: A keystroke dynamics dataset for user classification. *Information*, 15(9).

5. Acien, A., et al. (2023). Dataset of human-written and synthesized samples of keystroke dynamics. *Data in Brief*.
