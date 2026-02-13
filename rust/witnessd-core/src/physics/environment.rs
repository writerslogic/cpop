#[cfg(any(
    all(target_arch = "x86", target_feature = "sse"),
    target_arch = "x86_64"
))]
use raw_cpuid::CpuId;
use sha2::{Digest, Sha256};
use sysinfo::System;

pub struct AmbientSensing;

pub struct AmbientEntropy {
    pub hash: [u8; 32],
    pub is_virtualized: bool,
    pub secure_boot_active: bool,
}

impl AmbientSensing {
    pub fn capture() -> AmbientEntropy {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-ambient-v1");

        if let Some(os_ver) = System::long_os_version() {
            hasher.update(os_ver.as_bytes());
        }
        if let Some(host) = System::host_name() {
            hasher.update(host.as_bytes());
        }
        hasher.update(sys.total_memory().to_be_bytes());

        for process in sys.processes().values() {
            hasher.update(process.pid().as_u32().to_be_bytes());
            hasher.update(process.start_time().to_be_bytes());
        }

        let is_vm = {
            #[cfg(any(
                all(target_arch = "x86", target_feature = "sse"),
                target_arch = "x86_64"
            ))]
            {
                let cpuid = CpuId::new();
                cpuid.get_hypervisor_info().is_some()
            }
            #[cfg(not(any(
                all(target_arch = "x86", target_feature = "sse"),
                target_arch = "x86_64"
            )))]
            {
                false
            }
        };

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);

        AmbientEntropy {
            hash,
            is_virtualized: is_vm,
            secure_boot_active: false,
        }
    }
}
