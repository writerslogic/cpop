use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use witnessd_protocol::crypto::hash_sha256;
use witnessd_protocol::evidence::{PoPBuilder, PoPVerifier};
use witnessd_protocol::rfc::DocumentRef;

fn main() -> anyhow::Result<()> {
    println!("--- Proof-of-Process (PoP) Attestation Demo ---");

    // 1. Setup keys (Stub for hardware key)
    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    // 2. Define the document being processed
    let doc_content = b"This is the core document being attested.";
    let doc_hash = hash_sha256(doc_content);

    let document = DocumentRef {
        content_hash: doc_hash,
        filename: Some("attested_doc.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64, // simplified
    };

    // 3. Start Evidence Generation (The Attester)
    println!("[Attester] Starting evidence collection...");
    let mut builder = PoPBuilder::new(document, Box::new(signing_key));

    // Simulate a multi-step process with checkpoints
    let steps = vec![
        "Step 1: Research and initial draft.",
        "Step 2: Peer review and revisions.",
        "Step 3: Finalizing technical specifications.",
    ];

    for (i, step) in steps.iter().enumerate() {
        println!("[Attester] Adding checkpoint {}: {}", i + 1, step);
        builder.add_checkpoint(step.as_bytes(), step.len() as u64)?;

        // Simulate some time passing/work being done
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Finalize and sign the evidence
    let signed_evidence = builder.finalize()?;
    println!(
        "[Attester] Evidence finalized and signed. Size: {} bytes",
        signed_evidence.len()
    );

    // 4. Verification (The Verifier / Relying Party)
    println!("\n[Verifier] Verifying evidence packet...");
    let verifier = PoPVerifier::new(verifying_key);

    match verifier.verify(&signed_evidence) {
        Ok(packet) => {
            println!("[Verifier] SUCCESS: Evidence is authentic.");
            println!("[Verifier] Packet ID: {}", hex::encode(&packet.packet_id));
            println!("[Verifier] Profile URI: {}", packet.profile_uri);
            println!(
                "[Verifier] Document: {:?}",
                packet.document.filename.as_ref().unwrap()
            );
            println!(
                "[Verifier] Checkpoints validated: {}",
                packet.checkpoints.len()
            );

            for cp in &packet.checkpoints {
                println!(
                    "  - Checkpoint {}: TS={}, Hash={}",
                    cp.sequence,
                    cp.timestamp,
                    hex::encode(&cp.checkpoint_hash.digest[..8])
                );
            }
        }
        Err(e) => {
            println!("[Verifier] FAILED: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
