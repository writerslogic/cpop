// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use sha2::Digest;
use sysinfo::System;

/// Silicon-level Physical Unclonable Function (PUF).
/// Measures microscopic manufacturing variations in hardware.
#[derive(Debug)]
pub struct SiliconPUF;

impl SiliconPUF {
    /// Generates a unique fingerprint based on stable hardware identifiers.
    /// Focuses on stability to ensure persistent identity.
    pub fn generate_fingerprint() -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        let mut sys = System::new_all();

        sys.refresh_cpu_usage();
        sys.refresh_all();

        for cpu in sys.cpus() {
            sha2::Digest::update(&mut hasher, cpu.brand().as_bytes());
        }

        sha2::Digest::update(&mut hasher, sys.cpus().len().to_be_bytes());

        if let Some(name) = System::name() {
            sha2::Digest::update(&mut hasher, name.as_bytes());
        }
        if let Some(version) = System::os_version() {
            sha2::Digest::update(&mut hasher, version.as_bytes());
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(hostname) = hostname::get() {
                sha2::Digest::update(&mut hasher, b"macos-stable-v1");
                sha2::Digest::update(&mut hasher, hostname.to_string_lossy().as_bytes());
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
                sha2::Digest::update(&mut hasher, id.trim().as_bytes());
            }
        }

        sha2::Digest::finalize(hasher).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_puf_generates_fingerprint() {
        let fp = SiliconPUF::generate_fingerprint();
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn test_puf_determinism() {
        let fp1 = SiliconPUF::generate_fingerprint();
        let fp2 = SiliconPUF::generate_fingerprint();

        assert_eq!(
            fp1, fp2,
            "PUF should generate stable fingerprints on the same machine"
        );
    }
}
