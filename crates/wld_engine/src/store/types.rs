// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[derive(Debug, Clone)]
pub struct SecureEvent {
    pub id: Option<i64>,
    pub device_id: [u8; 16],
    pub machine_id: String,
    pub timestamp_ns: i64,
    pub file_path: String,
    pub content_hash: [u8; 32],
    pub file_size: i64,
    pub size_delta: i32,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub context_type: Option<String>,
    pub context_note: Option<String>,
    pub vdf_input: Option<[u8; 32]>,
    pub vdf_output: Option<[u8; 32]>,
    pub vdf_iterations: u64,
    pub forensic_score: f64,
    pub is_paste: bool,
    /// Hardware monotonic counter value at event time (None for software-only)
    pub hardware_counter: Option<u64>,
}
