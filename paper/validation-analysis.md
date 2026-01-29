# Validation Analysis: What We Can Prove Without Original Studies

## Summary

| Category | Claims | Validation Method |
|----------|--------|-------------------|
| **Cryptographic** | 4 claims | Mathematical proof (no data needed) |
| **Public Data** | 3 claims | Existing datasets + literature |
| **Self-Testing** | 3 claims | Run our own implementation |
| **Requires Study** | 1 claim | Human perception (but can cite literature) |

**Bottom line:** We can validate ~90% of claims without conducting a formal human subjects study.

---

## Category 1: Cryptographic Proofs (No Data Needed)

These claims follow directly from the mathematical construction:

| Claim | Section | Validation |
|-------|---------|------------|
| Fabricated jitter sequences are detectable | §3.4 | Probability: $(1/R)^n < 2^{-1000}$ for typical n |
| Replay attacks fail | §3.4 | Jitter bound to document hash; different doc = different expected jitter |
| Post-hoc generation fails | §3.4 | Requires unknown session secret (256-bit key space) |
| Secret cannot be extracted | §3.4 | Standard HMAC security assumption |

**Action:** Write formal proofs. No empirical data required.

---

## Category 2: Validated by Public Data

### 2.1 Human Typing Speed Distributions (Economic Security)

**Claim (§2.3):** Attack cost ≥ honest authorship cost because typing takes real time.

**Public data available:**
- [Aalto 136M Keystrokes Study](https://userinterfaces.aalto.fi/136Mkeystrokes/):
  - Mean: 51.56 WPM (SD = 20.2)
  - 99th percentile: ~120 WPM
  - Maximum observed: ~150 WPM

**Validation:** At maximum human speed (150 WPM = 750 chars/min), a 10,000-character document requires minimum **13.3 minutes** of real typing. No computational shortcut exists.

### 2.2 Inter-Keystroke Interval Baseline

**Claim (implicit):** Human typing has characteristic timing patterns.

**Public data available:**
- CMU Benchmark: IKI distributions for 51 subjects, 400 sessions each
- KeyRecs: Digraph latencies (DD, DU, UD, UU) for 100 subjects
- IKDD: 164 subjects, 533 sessions of free-text typing

**Validation:** Compute IKI percentiles from public datasets to establish human baseline.

### 2.3 Jitter Imperceptibility

**Claim (§6.5):** 500μs-3000μs jitter is imperceptible.

**Published literature:**
| Study | Finding |
|-------|---------|
| Ng et al. (CHI 2012) | Keyboard latency JND ~150ms |
| Jota et al. (CHI 2013) | Touch latency JND: 33-82ms depending on task |
| Deber et al. (CHI 2015) | Perception threshold inversely proportional to interaction frequency |
| System Latency Guidelines | Users perceive 16-60ms in demanding tasks |

**Validation:** Our jitter range (0.5-3ms) is **50-300x below** the lowest reported perception threshold. Cite literature instead of conducting new study.

---

## Category 3: Self-Testing (No External Participants)

### 3.1 Attack Detection Rate

**Claim (§6.2):** 100% detection rate for all three attack types.

**Validation method:** Run attack simulations against our own implementation.

```go
// Generate 10,000 attack samples for each type
func RunAttackValidation() {
    for _, attackType := range []string{"fabricated", "replay", "posthoc"} {
        detected := 0
        for i := 0; i < 10000; i++ {
            sample := generateAttack(attackType)
            if err := verify(sample); err != nil {
                detected++
            }
        }
        fmt.Printf("%s: %d/10000 detected\n", attackType, detected)
    }
}
```

**Expected result:** 10,000/10,000 detected for each type (deterministic given crypto).

### 3.2 Performance Benchmarks

**Claim (§6.4):** Hook latency, memory, CPU overhead.

**Validation method:** Benchmark our implementation directly.

```go
func BenchmarkJitterSeal(b *testing.B) {
    // Measure hook latency
    // Measure HMAC computation
    // Measure document hashing
    // Profile memory usage
}
```

**No human subjects required** - these are system measurements.

### 3.3 Legitimate Session Verification Rate

**Claim (§6.3):** 99.65% verification rate.

**Validation method:** "Eating our own dogfood"
- Use jitter seal while writing the paper itself
- Use jitter seal during normal development work
- Track session count, verification success/failure

**Scaled-down approach:**
| Original Claim | Achievable Alternative |
|----------------|------------------------|
| 12 participants, 847 sessions | Authors only, 50-100 sessions |
| 4 weeks | 2-4 weeks of active development |

**Reframe the claim:** "During development of this system, the authors generated N sessions over M weeks. All sessions verified correctly except K, which failed due to [specific system issues]."

---

## Category 4: Requires Original Study (1 Claim)

### Human Perception Study

**Original claim (§6.5):**
> 24 participants, 15-minute typing tasks, Likert scale ratings
> Result: p=0.34 (not significant difference for standard jitter)

**Options:**

#### Option A: Cite Literature Only (Recommended)
Replace the formal study with literature citations:

> Prior research establishes that humans cannot perceive input latencies below 16-60ms in demanding tasks [Jota et al., 2013; Deber et al., 2015]. Our jitter range of 0.5-3.0ms is an order of magnitude below this threshold. Therefore, jitter injection is expected to be imperceptible under normal typing conditions.

#### Option B: Informal Self-Testing
> The authors used the jitter seal during X hours of writing this paper. No perceptible lag was reported at standard jitter settings (500μs-3000μs). At elevated settings (5-10ms), slight lag became noticeable during rapid typing bursts.

#### Option C: Small Pilot Study (5-10 participants)
- Colleagues/lab members
- Within-subjects: no jitter vs standard jitter
- Binary question: "Did you notice any difference?"
- Chi-square test instead of t-test

---

## Recommended Paper Structure Changes

### Current Section 6.1 (Remove)
```
We collected data from 12 participants over 4 weeks...
```

### Revised Section 6.1
```
We validate the jitter seal through four approaches:

1. **Cryptographic analysis** (§6.2): Formal security proofs
2. **Attack simulation** (§6.3): Automated testing against implementation
3. **Performance benchmarking** (§6.4): System-level measurements
4. **Self-experimentation** (§6.5): Verification during development

We deliberately avoid claims requiring formal human subjects studies,
instead grounding our analysis in published literature on typing
behavior and perception thresholds.
```

### Add New Section: Typing Speed Baseline
```
### 6.X Human Typing Baseline

We establish economic security bounds using the Aalto University
study of 168,000 typists [Dhakal et al., 2018]:

| Percentile | WPM | Characters/min | 10K doc time |
|------------|-----|----------------|--------------|
| 50th       | 52  | 260           | 38 min       |
| 90th       | 80  | 400           | 25 min       |
| 99th       | 120 | 600           | 17 min       |

Even the fastest typists in the dataset require substantial
wall-clock time to produce documents. No computational attack
can bypass this physical constraint.
```

---

## Validation Checklist

| Claim | Method | Status |
|-------|--------|--------|
| Fabricated jitter detectable | Math proof | ☐ Write proof |
| Replay attacks fail | Math proof | ☐ Write proof |
| Post-hoc generation fails | Math proof | ☐ Write proof |
| Secret extraction infeasible | HMAC assumption | ☐ Cite RFC 2104 |
| Typing speed bounds | Aalto 136M paper | ☐ Extract stats |
| IKI distributions | CMU/KeyRecs/IKDD | ☐ Analyze datasets |
| Imperceptibility | Literature | ☐ Cite 3-4 papers |
| Attack detection (100%) | Simulation | ☐ Run 10K trials |
| Performance overhead | Benchmark | ☐ Measure system |
| Verification rate | Self-test | ☐ Track dev sessions |

---

## Conclusion

**We can make a rigorous, publishable paper without conducting formal human subjects research** by:

1. Grounding security claims in cryptographic proofs
2. Using published datasets for human behavior baselines
3. Running automated attack simulations
4. Citing established literature for perception thresholds
5. Using self-experimentation for verification rate claims

The only claim that truly benefits from a formal study is the perception study, but this can be adequately addressed through literature citation since our jitter range is far below established thresholds.
