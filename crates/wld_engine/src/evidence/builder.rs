// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Evidence packet builder with validation and claim generation.

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::analysis::{calculate_hurst_rs, BehavioralFingerprint};
use crate::anchors;
use crate::checkpoint;
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::error::Error;
use crate::jitter;
use crate::keyhierarchy;
use crate::platform::HIDDeviceInfo;
use crate::presence;
use crate::provenance;
use crate::rfc::{self, BiologyInvariantClaim, BiologyMeasurements, JitterBinding, TimeEvidence};
use crate::tpm;
use crate::vdf;

use super::types::*;

/// Minimum hardware entropy ratio (phys_ratio) to qualify as genuine human input.
/// Above this threshold, keystroke evidence is boosted to `Enhanced` strength.
#[cfg(feature = "wld_jitter")]
const HARDWARE_ENTROPY_RATIO_THRESHOLD: f64 = 0.8;

/// Minimum number of jitter samples required to compute a jitter binding.
const MIN_JITTER_SAMPLES_FOR_BINDING: usize = 10;

/// Maximum inter-keystroke interval in microseconds (5 seconds).
/// Intervals beyond this are treated as outliers and filtered out.
const MAX_INTERVAL_US: f64 = 5_000_000.0;

/// Minimum number of interval samples for R/S Hurst exponent analysis.
const MIN_SAMPLES_FOR_HURST: usize = 20;

/// Accumulate evidence layers into a signed evidence packet.
pub struct Builder {
    packet: Packet,
    errors: Vec<String>,
}

impl Builder {
    /// Create a builder from a document title and checkpoint chain.
    pub fn new(title: &str, chain: &checkpoint::Chain) -> Self {
        let mut packet = Packet {
            version: 1,
            exported_at: Utc::now(),
            strength: Strength::Basic,
            provenance: None,
            document: DocumentInfo {
                title: title.to_string(),
                path: chain.document_path.clone(),
                final_hash: String::new(),
                final_size: 0,
            },
            checkpoints: Vec::with_capacity(chain.checkpoints.len()),
            vdf_params: chain.vdf_params,
            chain_hash: String::new(),
            declaration: None,
            presence: None,
            hardware: None,
            keystroke: None,
            behavioral: None,
            contexts: Vec::new(),
            external: None,
            key_hierarchy: None,
            jitter_binding: None,
            time_evidence: None,
            provenance_links: None,
            continuation: None,
            collaboration: None,
            vdf_aggregate: None,
            verifier_nonce: None,
            packet_signature: None,
            signing_public_key: None,
            biology_claim: None,
            physical_context: None,
            trust_tier: None,
            mmr_root: None,
            mmr_proof: None,
            writersproof_certificate_id: None,
            baseline_verification: None,
            claims: Vec::new(),
            limitations: Vec::new(),
        };

        if let Some(latest) = chain.latest() {
            packet.document.final_hash = hex::encode(latest.content_hash);
            packet.document.final_size = latest.content_size;
        }

        for cp in &chain.checkpoints {
            let mut proof = CheckpointProof {
                ordinal: cp.ordinal,
                content_hash: hex::encode(cp.content_hash),
                content_size: cp.content_size,
                timestamp: cp.timestamp,
                message: cp.message.clone(),
                vdf_input: None,
                vdf_output: None,
                vdf_iterations: None,
                elapsed_time: None,
                previous_hash: hex::encode(cp.previous_hash),
                hash: hex::encode(cp.hash),
                signature: None,
            };

            if let Some(sig) = &cp.signature {
                proof.signature = Some(hex::encode(sig));
            }

            if let Some(vdf_proof) = &cp.vdf {
                proof.vdf_input = Some(hex::encode(vdf_proof.input));
                proof.vdf_output = Some(hex::encode(vdf_proof.output));
                proof.vdf_iterations = Some(vdf_proof.iterations);
                proof.elapsed_time = Some(vdf_proof.min_elapsed_time(chain.vdf_params));
            }

            packet.checkpoints.push(proof);
        }

        if let Some(latest) = chain.latest() {
            packet.chain_hash = hex::encode(latest.hash);
        }

        Self {
            packet,
            errors: Vec::new(),
        }
    }

    fn add_claim(
        &mut self,
        claim_type: ClaimType,
        description: impl Into<String>,
        confidence: &str,
    ) {
        self.packet.claims.push(Claim {
            claim_type,
            description: description.into(),
            confidence: confidence.to_string(),
        });
    }

    /// Attach a signed author declaration. Fails silently if signature is invalid.
    pub fn with_declaration(mut self, decl: &declaration::Declaration) -> Self {
        if !decl.verify() {
            self.errors
                .push("declaration signature invalid".to_string());
            return self;
        }
        self.packet.declaration = Some(decl.clone());
        self
    }

    /// Attach presence verification evidence. Boosts strength to `Standard`.
    pub fn with_presence(mut self, sessions: &[presence::Session]) -> Self {
        if sessions.is_empty() {
            return self;
        }
        let evidence = presence::compile_evidence(sessions);
        self.packet.presence = Some(evidence);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Attach TPM hardware attestation evidence. Boosts strength to `Enhanced`.
    pub fn with_hardware(
        mut self,
        bindings: Vec<tpm::Binding>,
        device_id: String,
        attestation_nonce: Option<[u8; 32]>,
    ) -> Self {
        if bindings.is_empty() {
            return self;
        }
        self.packet.hardware = Some(HardwareEvidence {
            bindings,
            device_id,
            attestation_nonce,
        });
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach keystroke timing evidence. Boosts strength to `Standard`.
    pub fn with_keystroke(mut self, evidence: &jitter::Evidence) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors.push("keystroke evidence invalid".to_string());
            return self;
        }

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples: evidence.samples.clone(),
            phys_ratio: None,
        };

        self.packet.keystroke = Some(keystroke);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Attach hybrid keystroke evidence with hardware entropy metrics.
    ///
    /// Boosts to `Enhanced` when `phys_ratio > 0.8`, indicating genuine
    /// hardware input rather than software injection.
    #[cfg(feature = "wld_jitter")]
    pub fn with_hybrid_keystroke(
        mut self,
        evidence: &crate::wld_jitter_bridge::HybridEvidence,
    ) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors
                .push("hybrid keystroke evidence invalid".to_string());
            return self;
        }

        let samples: Vec<jitter::Sample> = evidence
            .samples
            .iter()
            .map(|hs| jitter::Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples,
            phys_ratio: Some(evidence.entropy_quality.phys_ratio),
        };

        self.packet.keystroke = Some(keystroke);

        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }

        if evidence.entropy_quality.phys_ratio > HARDWARE_ENTROPY_RATIO_THRESHOLD {
            if self.packet.strength < Strength::Enhanced {
                self.packet.strength = Strength::Enhanced;
            }
            self.add_claim(
                ClaimType::KeystrokesVerified,
                format!(
                    "Hardware entropy ratio {:.0}% - strong assurance of genuine input",
                    evidence.entropy_quality.phys_ratio * 100.0
                ),
                "high",
            );
        }

        self
    }

    /// Attach behavioral edit topology and forensic metrics. Boosts strength to `Maximum`.
    pub fn with_behavioral(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
    ) -> Self {
        if regions.is_empty() && metrics.is_none() {
            return self;
        }
        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint: None,
            forgery_analysis: None,
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Attach behavioral evidence with fingerprint and forgery analysis from jitter samples.
    pub fn with_behavioral_full(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
        samples: &[jitter::SimpleJitterSample],
    ) -> Self {
        let fingerprint = if samples.len() >= 2 {
            Some(BehavioralFingerprint::from_samples(samples))
        } else {
            None
        };

        let forgery_analysis = if samples.len() >= 10 {
            Some(BehavioralFingerprint::detect_forgery(samples))
        } else {
            None
        };

        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint,
            forgery_analysis,
        });

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Attach context periods (focused, assisted, external).
    pub fn with_contexts(mut self, contexts: Vec<ContextPeriod>) -> Self {
        if contexts.is_empty() {
            return self;
        }
        self.packet.contexts = contexts;
        self
    }

    /// Attach record provenance (OS, build version, device info).
    pub fn with_provenance(mut self, prov: RecordProvenance) -> Self {
        self.packet.provenance = Some(prov);
        self
    }

    /// Populate `input_devices` in provenance from HID enumeration.
    ///
    /// Requires `with_provenance` to have been called first.
    pub fn with_input_devices(mut self, devices: &[HIDDeviceInfo]) -> Self {
        if let Some(ref mut prov) = self.packet.provenance {
            prov.input_devices = devices.iter().map(InputDeviceInfo::from).collect();
        } else {
            self.errors
                .push("with_input_devices requires with_provenance to be called first".to_string());
        }
        self
    }

    /// Attach OpenTimestamps and RFC 3161 external timestamp anchors.
    pub fn with_external_anchors(mut self, ots: Vec<OTSProof>, rfc: Vec<RFC3161Proof>) -> Self {
        if ots.is_empty() && rfc.is_empty() {
            return self;
        }
        self.packet.external = Some(ExternalAnchors {
            opentimestamps: ots,
            rfc3161: rfc,
            proofs: Vec::new(),
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Attach anchor proofs (blockchain, TSA, etc.). Boosts strength to `Maximum`.
    pub fn with_anchors(mut self, proofs: &[anchors::Proof]) -> Self {
        if proofs.is_empty() {
            return self;
        }

        if self.packet.external.is_none() {
            self.packet.external = Some(ExternalAnchors {
                opentimestamps: Vec::new(),
                rfc3161: Vec::new(),
                proofs: Vec::new(),
            });
        }

        let ext = self
            .packet
            .external
            .as_mut()
            .expect("just ensured Some above");
        for proof in proofs {
            ext.proofs.push(convert_anchor_proof(proof));
        }

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Attach key hierarchy evidence (master key, ratchet chain, checkpoint sigs).
    pub fn with_key_hierarchy(mut self, evidence: &keyhierarchy::KeyHierarchyEvidence) -> Self {
        let packet = KeyHierarchyEvidencePacket {
            version: evidence.version,
            master_fingerprint: evidence.master_fingerprint.clone(),
            master_public_key: hex::encode(&evidence.master_public_key),
            device_id: evidence.device_id.clone(),
            session_id: evidence.session_id.clone(),
            session_public_key: hex::encode(&evidence.session_public_key),
            session_started: evidence.session_started,
            session_certificate: general_purpose::STANDARD
                .encode(&evidence.session_certificate_raw),
            ratchet_count: evidence.ratchet_count,
            ratchet_public_keys: evidence
                .ratchet_public_keys
                .iter()
                .map(hex::encode)
                .collect(),
            checkpoint_signatures: evidence
                .checkpoint_signatures
                .iter()
                .enumerate()
                .map(|(idx, sig)| CheckpointSignature {
                    ordinal: sig.ordinal,
                    checkpoint_hash: hex::encode(sig.checkpoint_hash),
                    ratchet_index: i32::try_from(idx).unwrap_or(i32::MAX),
                    signature: general_purpose::STANDARD.encode(sig.signature),
                })
                .collect(),
        };

        self.packet.key_hierarchy = Some(packet);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach provenance parent links for derivative works.
    pub fn with_provenance_links(mut self, section: provenance::ProvenanceSection) -> Self {
        if section.parent_links.is_empty() {
            return self;
        }
        self.packet.provenance_links = Some(section);
        self
    }

    /// Attach continuation section linking to a previous evidence packet.
    pub fn with_continuation(mut self, section: continuation::ContinuationSection) -> Self {
        self.packet.continuation = Some(section);
        self
    }

    /// Attach multi-author collaboration section.
    pub fn with_collaboration(mut self, section: collaboration::CollaborationSection) -> Self {
        if section.participants.is_empty() {
            return self;
        }
        self.packet.collaboration = Some(section);
        self
    }

    /// Attach aggregate VDF proof covering the entire chain.
    pub fn with_vdf_aggregate(mut self, proof: vdf::VdfAggregateProof) -> Self {
        self.packet.vdf_aggregate = Some(proof);
        self
    }

    /// Attach a pre-built jitter binding. Boosts strength to `Enhanced`.
    pub fn with_jitter_binding(mut self, binding: JitterBinding) -> Self {
        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach RFC-compliant time evidence (TSA, blockchain, Roughtime). Boosts to `Enhanced`.
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.packet.time_evidence = Some(evidence);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach RFC-compliant biology invariant claim.
    ///
    /// Millibits scoring from Hurst exponent, pink noise (1/f), and error topology.
    pub fn with_biology_claim(mut self, claim: BiologyInvariantClaim) -> Self {
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach physical context evidence for machine binding and non-repudiation.
    ///
    /// Captures clock skew, thermal proxy, silicon PUF fingerprint, and I/O latency
    /// to bind the evidence session to specific physical hardware.
    pub fn with_physical_context(mut self, ctx: &crate::physics::PhysicalContext) -> Self {
        self.packet.physical_context = Some(PhysicalContextEvidence {
            clock_skew: ctx.clock_skew,
            thermal_proxy: ctx.thermal_proxy,
            silicon_puf_hash: hex::encode(ctx.silicon_puf),
            io_latency_ns: ctx.io_latency_ns,
            combined_hash: hex::encode(ctx.combined_hash),
        });
        if ctx.is_virtualized {
            self.packet.limitations.push(
                "Virtualized environment detected — physical hardware measurements may be \
                 unreliable"
                    .to_string(),
            );
        }
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Build jitter binding from keystroke evidence.
    ///
    /// Computes entropy commitment, statistical summary, Hurst exponent,
    /// and forgery analysis. Pass `None` for `previous_commitment_hash`
    /// on the first binding in a chain.
    pub fn with_jitter_from_keystroke(
        mut self,
        keystroke: &KeystrokeEvidence,
        document_hash: &[u8; 32],
        previous_commitment_hash: Option<[u8; 32]>,
    ) -> Self {
        if keystroke.samples.len() < MIN_JITTER_SAMPLES_FOR_BINDING {
            self.errors
                .push("insufficient jitter samples for binding".to_string());
            return self;
        }

        let intervals_us: Vec<f64> = keystroke
            .samples
            .iter()
            .map(|s| s.jitter_micros as f64)
            .filter(|&i| i > 0.0 && i < MAX_INTERVAL_US)
            .collect();

        if intervals_us.is_empty() {
            self.errors
                .push("no valid jitter intervals found".to_string());
            return self;
        }

        let mean = intervals_us.iter().sum::<f64>() / intervals_us.len() as f64;
        let variance = intervals_us.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals_us.len() as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // O(n) percentile selection via `select_nth_unstable_by`
        let cmp = |a: &f64, b: &f64| a.total_cmp(b);
        let percentiles = if intervals_us.len() >= 10 {
            let mut buf = intervals_us.clone();
            let n = buf.len();
            let indices = [n / 10, n / 4, n / 2, 3 * n / 4, 9 * n / 10];
            let mut vals = [0.0f64; 5];
            for (i, &idx) in indices.iter().enumerate() {
                buf.select_nth_unstable_by(idx, cmp);
                vals[i] = buf[idx];
            }
            vals
        } else {
            [mean; 5] // too few samples for meaningful percentiles
        };

        let hurst_exponent = if intervals_us.len() >= MIN_SAMPLES_FOR_HURST {
            calculate_hurst_rs(&intervals_us).ok().map(|h| h.exponent)
        } else {
            None
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"witnessd-jitter-entropy-v1");
        for s in &keystroke.samples {
            hasher.update(s.timestamp.timestamp_millis().to_be_bytes());
        }
        let entropy_hash: [u8; 32] = hasher.finalize().into();

        let timestamp_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

        let binding = JitterBinding {
            entropy_commitment: rfc::EntropyCommitment {
                hash: entropy_hash,
                timestamp_ms,
                previous_hash: previous_commitment_hash.unwrap_or([0u8; 32]),
            },
            sources: vec![rfc::jitter_binding::SourceDescriptor {
                source_type: "keyboard".to_string(),
                weight: 1000,
                device_fingerprint: None,
                transport_calibration: None,
            }],
            summary: rfc::JitterSummary {
                sample_count: keystroke.samples.len() as u64,
                mean_interval_us: mean,
                std_dev,
                coefficient_of_variation: cv,
                percentiles,
                // Conservative lower bound: log2(n) bits from n independent samples.
                // True Shannon entropy depends on the interval distribution, but
                // log2(n) is a defensible minimum without distribution assumptions.
                entropy_bits: (keystroke.samples.len() as f64).log2(),
                hurst_exponent,
            },
            binding_mac: rfc::BindingMac::compute(
                &entropy_hash,
                *document_hash,
                keystroke.total_keystrokes,
                timestamp_ms,
                &entropy_hash,
            ),
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        };

        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach active probes (Galton invariant, reflex gate) to jitter binding.
    ///
    /// Requires a prior call to `with_jitter_from_keystroke` or `with_jitter_binding`.
    pub fn with_active_probes(
        mut self,
        probes: &crate::analysis::active_probes::ActiveProbeResults,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.active_probes = Some(probes.into());
        } else {
            self.errors
                .push("jitter_binding required before active_probes".to_string());
        }
        self
    }

    /// Attach labyrinth structure (Takens embedding) to jitter binding.
    ///
    /// Requires a prior call to `with_jitter_from_keystroke` or `with_jitter_binding`.
    pub fn with_labyrinth_structure(
        mut self,
        analysis: &crate::analysis::labyrinth::LabyrinthAnalysis,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.labyrinth_structure = Some(analysis.into());
        } else {
            self.errors
                .push("jitter_binding required before labyrinth_structure".to_string());
        }
        self
    }

    /// Build biology invariant claim from Hurst, pink noise, and error topology analyses.
    pub fn with_biology_from_analysis(
        mut self,
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> Self {
        let claim =
            BiologyInvariantClaim::from_analysis(measurements, hurst, pink_noise, error_topology);
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach MMR root hash and range proof for append-only verification.
    pub fn with_mmr_proof(mut self, mmr_root: [u8; 32], range_proof: &[u8]) -> Self {
        self.packet.mmr_root = Some(hex::encode(mmr_root));
        self.packet.mmr_proof = Some(hex::encode(range_proof));
        self
    }

    /// Attach authorship baseline verification (digest + session summary).
    pub fn with_baseline_verification(
        mut self,
        bv: wld_protocol::baseline::BaselineVerification,
    ) -> Self {
        self.packet.baseline_verification = Some(bv);
        self
    }

    /// Set a verifier-supplied nonce for freshness binding.
    pub fn with_writersproof_nonce(mut self, nonce: [u8; 32]) -> Self {
        self.packet.verifier_nonce = Some(nonce);
        self
    }

    /// Set the WritersProof CA certificate ID for this packet.
    pub fn with_writersproof_certificate(mut self, certificate_id: String) -> Self {
        self.packet.writersproof_certificate_id = Some(certificate_id);
        self
    }

    /// Finalize the packet, generating claims, limitations, and trust tier.
    pub fn build(mut self) -> crate::error::Result<Packet> {
        if self.packet.declaration.is_none() {
            self.errors.push("declaration is required".to_string());
        }
        if !self.errors.is_empty() {
            return Err(Error::evidence(format!("build errors: {:?}", self.errors)));
        }
        self.generate_claims();
        self.generate_limitations();
        self.packet.trust_tier = Some(self.packet.compute_trust_tier());
        Ok(self.packet)
    }

    fn generate_claims(&mut self) {
        self.add_claim(
            ClaimType::ChainIntegrity,
            "Content states form an unbroken cryptographic chain",
            "cryptographic",
        );

        let mut total_time = Duration::from_secs(0);
        for cp in &self.packet.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total_time += elapsed;
            }
        }
        if total_time > Duration::from_secs(0) {
            self.add_claim(
                ClaimType::TimeElapsed,
                format!(
                    "At least {:?} elapsed during documented composition",
                    total_time
                ),
                "cryptographic",
            );
        }

        if let Some(decl) = &self.packet.declaration {
            let ai_desc = if decl.has_ai_usage() {
                format!(
                    "AI assistance declared: {} extent",
                    crate::declaration::ai_extent_str(&decl.max_ai_extent())
                )
            } else {
                "No AI tools declared".to_string()
            };
            self.add_claim(
                ClaimType::ProcessDeclared,
                format!("Author signed declaration of creative process. {ai_desc}"),
                "attestation",
            );
        }

        if let Some(presence) = &self.packet.presence {
            self.add_claim(
                ClaimType::PresenceVerified,
                format!(
                    "Author presence verified {:.0}% of challenged sessions",
                    presence.overall_rate * 100.0
                ),
                "cryptographic",
            );
        }

        if let Some(keystroke) = &self.packet.keystroke {
            let mut desc = format!(
                "{} keystrokes recorded over {:?} ({:.0}/min)",
                keystroke.total_keystrokes, keystroke.duration, keystroke.keystrokes_per_minute
            );
            if keystroke.plausible_human_rate {
                desc.push_str(", consistent with human typing");
            }
            self.add_claim(ClaimType::KeystrokesVerified, desc, "cryptographic");
        }

        if self.packet.hardware.is_some() {
            self.add_claim(
                ClaimType::HardwareAttested,
                "TPM attests chain was not rolled back or modified",
                "cryptographic",
            );
        }

        if self.packet.physical_context.is_some() {
            self.add_claim(
                ClaimType::HardwareAttested,
                "Physical context captured: clock skew, thermal proxy, silicon PUF, I/O latency",
                "high",
            );
        }

        if self.packet.behavioral.is_some() {
            self.add_claim(
                ClaimType::BehaviorAnalyzed,
                "Edit patterns captured for forensic analysis",
                "statistical",
            );
        }

        if !self.packet.contexts.is_empty() {
            // TODO(M-005): Replace period_type String with a PeriodType enum
            // (e.g. Focused, Assisted, External, ...) in evidence/types.rs.
            // Blocked on deciding serde wire-compat strategy for existing packets.
            let mut assisted = 0;
            let mut external = 0;
            for ctx in &self.packet.contexts {
                if ctx.period_type == "assisted" {
                    assisted += 1;
                }
                if ctx.period_type == "external" {
                    external += 1;
                }
            }
            let mut desc = format!("{} context periods recorded", self.packet.contexts.len());
            if assisted > 0 {
                desc.push_str(&format!(" ({assisted} AI-assisted)"));
            }
            if external > 0 {
                desc.push_str(&format!(" ({external} external)"));
            }
            self.add_claim(ClaimType::ContextsRecorded, desc, "attestation");
        }

        if let Some(external) = &self.packet.external {
            let count =
                external.opentimestamps.len() + external.rfc3161.len() + external.proofs.len();
            self.add_claim(
                ClaimType::ExternalAnchored,
                format!("Chain anchored to {count} external timestamp authorities"),
                "cryptographic",
            );
        }

        if let Some(kh) = &self.packet.key_hierarchy {
            let mut desc = format!(
                "Identity {} with {} ratchet generations",
                if kh.master_fingerprint.len() > 16 {
                    // Fingerprints are hex-encoded (ASCII-only), safe to slice
                    format!(
                        "{}...",
                        &kh.master_fingerprint[..kh
                            .master_fingerprint
                            .char_indices()
                            .nth(16)
                            .map_or(kh.master_fingerprint.len(), |(i, _)| i)]
                    )
                } else {
                    kh.master_fingerprint.clone()
                },
                kh.ratchet_count
            );
            if !kh.checkpoint_signatures.is_empty() {
                desc.push_str(&format!(
                    ", {} checkpoint signatures",
                    kh.checkpoint_signatures.len()
                ));
            }
            self.add_claim(ClaimType::KeyHierarchy, desc, "cryptographic");
        }
    }

    fn generate_limitations(&mut self) {
        self.packet
            .limitations
            .push("Cannot prove cognitive origin of ideas".to_string());
        self.packet
            .limitations
            .push("Cannot prove absence of AI involvement in ideation".to_string());

        if self.packet.presence.is_none() {
            self.packet.limitations.push(
                "No presence verification - cannot confirm human was at keyboard".to_string(),
            );
        }

        if self.packet.keystroke.is_none() {
            self.packet
                .limitations
                .push("No keystroke evidence - cannot verify real typing occurred".to_string());
        }

        if self.packet.hardware.is_none() {
            self.packet
                .limitations
                .push("No hardware attestation - software-only security".to_string());
        }

        if let Some(decl) = &self.packet.declaration {
            if decl.has_ai_usage() {
                self.packet.limitations.push(
                    "Author declares AI tool usage - verify institutional policy compliance"
                        .to_string(),
                );
            }
        }
    }
}

/// Convert an internal anchor proof to the evidence packet format.
pub fn convert_anchor_proof(proof: &anchors::Proof) -> AnchorProof {
    let provider = format!("{:?}", proof.provider).to_lowercase();
    let timestamp = proof.confirmed_at.unwrap_or(proof.submitted_at);
    let mut anchor = AnchorProof {
        provider: provider.clone(),
        provider_name: provider,
        legal_standing: String::new(),
        regions: Vec::new(),
        hash: hex::encode(proof.anchored_hash),
        timestamp,
        status: format!("{:?}", proof.status).to_lowercase(),
        raw_proof: general_purpose::STANDARD.encode(&proof.proof_data),
        blockchain: None,
        verify_url: proof.location.clone(),
    };

    if matches!(
        proof.provider,
        anchors::ProviderType::Bitcoin | anchors::ProviderType::Ethereum
    ) {
        let chain = match proof.provider {
            anchors::ProviderType::Bitcoin => "bitcoin",
            anchors::ProviderType::Ethereum => "ethereum",
            _ => "unknown",
        };
        let block_height = proof
            .extra
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let block_hash = proof
            .extra
            .get("block_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let block_time = proof
            .extra
            .get("block_time")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(timestamp);
        let tx_id = proof.location.clone();

        anchor.blockchain = Some(BlockchainAnchorInfo {
            chain: chain.to_string(),
            block_height,
            block_hash,
            block_time,
            tx_id,
        });
    }

    anchor
}

/// Compute binding hash over secure events.
///
/// Includes event count to prevent truncation attacks.
pub fn compute_events_binding_hash(events: &[crate::store::SecureEvent]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-events-binding-v1");
    hasher.update((events.len() as u64).to_be_bytes());
    for e in events {
        hasher.update(e.event_hash);
    }
    hasher.finalize().into()
}

/// A content snapshot from an ephemeral session checkpoint.
pub struct EphemeralSnapshot {
    pub timestamp_ns: i64,
    pub content_hash: [u8; 32],
    pub char_count: u64,
    pub message: Option<String>,
}

/// Build an evidence packet from ephemeral session data.
///
/// Constructs a signed declaration and checkpoint chain from in-memory
/// snapshots. The caller provides the signing key and session metadata;
/// this function handles all evidence assembly.
pub fn build_ephemeral_packet(
    final_hash_hex: &str,
    statement: &str,
    context_label: &str,
    snapshots: &[EphemeralSnapshot],
    signing_key: &ed25519_dalek::SigningKey,
) -> crate::error::Result<Packet> {
    let final_hash = hex::decode(final_hash_hex)
        .map_err(|e| Error::evidence(format!("invalid final hash: {e}")))?;
    let mut doc_hash = [0u8; 32];
    if final_hash.len() >= 32 {
        doc_hash.copy_from_slice(&final_hash[..32]);
    }

    let chain_hash = snapshots
        .last()
        .map(|s| s.content_hash)
        .unwrap_or([0u8; 32]);

    let signed_decl =
        declaration::no_ai_declaration(doc_hash, chain_hash, context_label, statement)
            .sign(signing_key)
            .map_err(|e| Error::evidence(format!("declaration signing failed: {e}")))?;

    let checkpoints: Vec<CheckpointProof> = snapshots
        .iter()
        .enumerate()
        .map(|(i, snap)| CheckpointProof {
            ordinal: i as u64,
            timestamp: chrono::DateTime::from_timestamp_nanos(snap.timestamp_ns),
            content_hash: hex::encode(snap.content_hash),
            content_size: snap.char_count,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: None,
            elapsed_time: None,
            previous_hash: if i > 0 {
                hex::encode(snapshots[i - 1].content_hash)
            } else {
                hex::encode([0u8; 32])
            },
            hash: hex::encode(snap.content_hash),
            message: snap.message.clone(),
            signature: None,
        })
        .collect();

    let packet = Packet {
        version: 1,
        exported_at: Utc::now(),
        strength: Strength::Basic,
        provenance: None,
        document: DocumentInfo {
            title: context_label.to_string(),
            path: format!("ephemeral://{}", hex::encode(&doc_hash[..8])),
            final_hash: final_hash_hex.to_string(),
            final_size: snapshots.last().map(|s| s.char_count).unwrap_or(0),
        },
        checkpoints,
        vdf_params: vdf::Parameters {
            iterations_per_second: 0,
            min_iterations: 0,
            max_iterations: 0,
        },
        chain_hash: hex::encode(chain_hash),
        declaration: Some(signed_decl),
        presence: None,
        hardware: None,
        keystroke: None,
        behavioral: None,
        contexts: vec![],
        external: None,
        key_hierarchy: None,
        jitter_binding: None,
        time_evidence: None,
        provenance_links: None,
        continuation: None,
        collaboration: None,
        vdf_aggregate: None,
        verifier_nonce: None,
        packet_signature: None,
        signing_public_key: None,
        biology_claim: None,
        physical_context: None,
        trust_tier: None,
        mmr_root: None,
        mmr_proof: None,
        writersproof_certificate_id: None,
        baseline_verification: None,
        claims: vec![],
        limitations: vec![],
    };

    Ok(packet)
}
