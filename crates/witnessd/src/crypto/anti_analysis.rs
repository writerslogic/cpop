// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::sync::atomic::{AtomicBool, Ordering};

static HARDENED: AtomicBool = AtomicBool::new(false);

pub fn harden_process() {
    if HARDENED.swap(true, Ordering::SeqCst) { return; }
    #[cfg(target_os = "macos")]
    unsafe { libc::ptrace(31, 0, std::ptr::null_mut(), 0); }
}

pub fn is_debugger_present() -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        use libc::{c_int, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID};
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, libc::getpid()];
        let mut buf = [0u8; 648]; // kinfo_proc is ~648 bytes on macOS
        let mut size = buf.len();
        if sysctl(mib.as_mut_ptr(), 4, buf.as_mut_ptr() as *mut _, &mut size, std::ptr::null_mut(), 0) == 0 {
            // p_flag is at offset 16 in extern_proc (kp_proc), which starts at offset 0
            let p_flag = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            return (p_flag & 0x00000800) != 0; // P_TRACED
        }
        false
    }
    #[cfg(target_os = "windows")]
    unsafe {
        extern "system" { fn IsDebuggerPresent() -> i32; }
        IsDebuggerPresent() != 0
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    false
}