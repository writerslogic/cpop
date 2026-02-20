//! Smart defaults and helper functions for improved CLI user experience.
//!
//! This module provides utilities for:
//! - Interactive prompts and confirmations
//! - File selection from recently modified files
//! - Path normalization and validation
//! - Default value generation
//! - Quick status display

use anyhow::{anyhow, Result};
use chrono::{TimeZone, Utc};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// =============================================================================
// Initialization Checks
// =============================================================================

/// Check if WitnessD is initialized (signing key exists)
pub fn is_initialized(witnessd_dir: &Path) -> bool {
    witnessd_dir.join("signing_key").exists()
}

/// Check if VDF is calibrated (iterations_per_second > 0)
pub fn is_calibrated(iterations_per_second: u64) -> bool {
    iterations_per_second > 0
}

/// Show a warning if VDF is not calibrated, but don't block
pub fn ensure_vdf_calibrated_with_warning(iterations_per_second: u64) {
    if !is_calibrated(iterations_per_second) {
        eprintln!("Warning: VDF not calibrated. Time proofs may be inaccurate.");
        eprintln!("Run 'witnessd calibrate' for accurate time measurements.");
        eprintln!();
    }
}

// =============================================================================
// Interactive Prompts
// =============================================================================

/// Ask for confirmation with a default value
pub fn ask_confirmation(prompt: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    print!("{} {} ", prompt, suffix);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input.starts_with('y'))
    }
}

// =============================================================================
// File Selection
// =============================================================================

/// Get recently modified files in a directory
pub fn get_recently_modified_files(dir: &Path, max_count: usize) -> Vec<PathBuf> {
    let mut files: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip hidden files, directories, and common non-document files
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }

            if !path.is_file() {
                continue;
            }

            // Skip common non-document extensions
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                if matches!(
                    ext_lower.as_str(),
                    "exe"
                        | "dll"
                        | "so"
                        | "dylib"
                        | "o"
                        | "a"
                        | "zip"
                        | "tar"
                        | "gz"
                        | "rar"
                        | "7z"
                        | "jpg"
                        | "jpeg"
                        | "png"
                        | "gif"
                        | "bmp"
                        | "ico"
                        | "mp3"
                        | "mp4"
                        | "avi"
                        | "mov"
                        | "wav"
                        | "db"
                        | "sqlite"
                        | "lock"
                ) {
                    continue;
                }
            }

            if let Ok(metadata) = path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    files.push((path, modified));
                }
            }
        }
    }

    // Sort by modification time (most recent first)
    files.sort_by(|a, b| b.1.cmp(&a.1));

    // Take top N
    files
        .into_iter()
        .take(max_count)
        .map(|(path, _)| path)
        .collect()
}

/// Select a file from a list interactively
pub fn select_file_from_list(files: &[PathBuf], prompt_prefix: &str) -> Result<Option<PathBuf>> {
    if files.is_empty() {
        return Ok(None);
    }

    if files.len() == 1 {
        return Ok(Some(files[0].clone()));
    }

    println!();
    for (i, file) in files.iter().enumerate() {
        let display = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file.display().to_string());
        println!("  [{}] {}", i + 1, display);
    }
    println!("  [0] Cancel");
    println!();

    let prompt = if prompt_prefix.is_empty() {
        "Enter choice".to_string()
    } else {
        format!("{} - enter choice", prompt_prefix)
    };

    print!("{}: ", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() || input == "0" {
        return Ok(None);
    }

    match input.parse::<usize>() {
        Ok(n) if n > 0 && n <= files.len() => Ok(Some(files[n - 1].clone())),
        _ => {
            // Try to match by filename
            let input_lower = input.to_lowercase();
            for file in files {
                if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                    if name.to_lowercase().contains(&input_lower) {
                        return Ok(Some(file.clone()));
                    }
                }
            }
            Err(anyhow!("Invalid selection: {}", input))
        }
    }
}

// =============================================================================
// Path Utilities
// =============================================================================

/// Normalize a path: expand ~, resolve relative paths, clean up
pub fn normalize_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();

    // Expand tilde
    let expanded = if path_str.starts_with("~/") || path_str == "~" {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        if path_str == "~" {
            home
        } else {
            home.join(&path_str[2..])
        }
    } else {
        path.to_path_buf()
    };

    // Clean up the path
    let cleaned = clean_path(&expanded);

    // Try to canonicalize if the path exists
    if cleaned.exists() {
        fs::canonicalize(&cleaned)
            .map_err(|e| anyhow!("Cannot access path {}: {}", cleaned.display(), e))
    } else {
        // For non-existent paths, just return the cleaned version
        Ok(cleaned)
    }
}

/// Clean up a path by removing redundant components
fn clean_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    // Remove trailing slashes (unless it's just "/" root)
    let trimmed = path_str.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() && path_str.starts_with('/') {
        "/"
    } else if trimmed.is_empty() {
        "."
    } else {
        trimmed
    };

    // Replace multiple consecutive slashes with single slash
    let mut result = String::with_capacity(trimmed.len());
    let mut last_was_slash = false;
    for c in trimmed.chars() {
        if c == '/' || c == '\\' {
            if !last_was_slash {
                result.push('/');
            }
            last_was_slash = true;
        } else {
            result.push(c);
            last_was_slash = false;
        }
    }

    PathBuf::from(result)
}

// =============================================================================
// Default Values
// =============================================================================

/// Generate a default commit message with timestamp
pub fn default_commit_message() -> String {
    format!("Checkpoint at {}", Utc::now().format("%Y-%m-%d %H:%M"))
}

// =============================================================================
// Quick Status Display
// =============================================================================

/// Show a quick status summary when no command is given
pub fn show_quick_status(
    witnessd_dir: &Path,
    iterations_per_second: u64,
    tracked_files: &[(String, i64, i64)],
) {
    println!("=== WitnessD Status ===");
    println!();

    // Initialization status
    if !is_initialized(witnessd_dir) {
        println!("Status: Not initialized");
        println!();
        println!("Get started with: witnessd init");
        return;
    }

    // Calibration status
    if !is_calibrated(iterations_per_second) {
        println!("Status: Initialized but not calibrated");
        println!();
        println!("Next step: witnessd calibrate");
        return;
    }

    println!("Status: Ready");
    println!();

    // Show tracked files summary
    if tracked_files.is_empty() {
        println!("No documents tracked yet.");
        println!();
        println!("Start checkpointing with: witnessd commit <file>");
    } else {
        println!("Tracked documents: {}", tracked_files.len());

        // Show most recent
        let mut recent: Vec<_> = tracked_files.iter().collect();
        recent.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by timestamp desc

        for (path, ts, count) in recent.iter().take(5) {
            let name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            let ts_str = Utc.timestamp_nanos(*ts).format("%m/%d %H:%M");
            println!("  {} ({} checkpoints, {})", name, count, ts_str);
        }

        if tracked_files.len() > 5 {
            println!("  ... and {} more", tracked_files.len() - 5);
        }

        println!();
        println!("Commands: commit, log, export, watch");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_commit_message() {
        let msg = default_commit_message();
        assert!(msg.starts_with("Checkpoint at "));
    }

    #[test]
    fn test_clean_path() {
        assert_eq!(
            clean_path(Path::new("/foo//bar/")),
            PathBuf::from("/foo/bar")
        );
        assert_eq!(clean_path(Path::new("./foo")), PathBuf::from("./foo"));
        assert_eq!(clean_path(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn test_is_initialized() {
        let temp = std::env::temp_dir().join("witnessd_test_init");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        assert!(!is_initialized(&temp));

        fs::write(temp.join("signing_key"), b"test").unwrap();
        assert!(is_initialized(&temp));

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_normalize_path() {
        let cwd = std::env::current_dir().unwrap();
        let normalized = normalize_path(Path::new(".")).unwrap();
        assert_eq!(normalized, cwd);
    }

    #[test]
    fn test_get_recently_modified_files() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");

        fs::write(&f1, "a").unwrap();
        // Wait a bit to ensure different mtime if filesystem precision is low
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&f2, "b").unwrap();

        let files = get_recently_modified_files(dir.path(), 10);
        assert_eq!(files.len(), 2);
        // Most recent first
        assert_eq!(files[0].file_name().unwrap(), "b.txt");
        assert_eq!(files[1].file_name().unwrap(), "a.txt");
    }
}
