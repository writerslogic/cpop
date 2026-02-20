use crate::jitter::SimpleJitterSample;

pub struct BiologicalCadence;

impl BiologicalCadence {
    pub fn analyze(samples: &[SimpleJitterSample]) -> f64 {
        if samples.len() < 2 {
            return 0.0;
        }

        let mut sum = 0.0;
        let mut count = 0.0;
        for sample in samples {
            let v = sample.duration_since_last_ns as f64;
            if v > 0.0 {
                sum += v;
                count += 1.0;
            }
        }

        if count == 0.0 {
            return 0.0;
        }

        let mean = sum / count;
        let mut variance = 0.0;
        for sample in samples {
            let v = sample.duration_since_last_ns as f64;
            if v > 0.0 {
                let diff = v - mean;
                variance += diff * diff;
            }
        }
        variance /= count;
        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { 0.0 };

        // Lower coefficient of variation indicates steadier cadence (closer to 1.0).
        let score = 1.0 / (1.0 + cv);
        score.clamp(0.0, 1.0)
    }
}
