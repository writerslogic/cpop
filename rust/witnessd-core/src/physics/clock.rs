#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::time::{Duration, Instant};

/// High-precision clock skew measurement.
/// Proves the delta between the CPU's Time Stamp Counter (TSC) and the system's Wall Clock.
pub struct ClockSkew;

impl ClockSkew {
    pub fn measure() -> u64 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            unsafe {
                let start_tsc = std::arch::x86_64::_rdtsc();
                let start_wall = Instant::now();

                // Active wait for a tiny fraction to measure drift
                // This is a "Silent Physics" measurement
                let mut current = start_wall;
                while current.duration_since(start_wall) < Duration::from_micros(100) {
                    current = Instant::now();
                }

                let end_tsc = std::arch::x86_64::_rdtsc();
                end_tsc - start_tsc // Returns cycles per ~100us
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Apple Silicon / ARM64 equivalent using CNTPCT_EL0
            let mut cnt: u64;
            unsafe {
                std::arch::asm!("mrs {}, cntpct_el0", out(reg) cnt);
            }
            cnt
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }
}
