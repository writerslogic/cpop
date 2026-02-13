use std::fs;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use witnessd_core::api;

#[test]
fn test_full_pipeline() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("witnessd");
    let watch_dir = tmp.path().join("watch");
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&watch_dir).unwrap();

    // 1. Initialize
    let fingerprint =
        api::init_witnessd(Some(data_dir.to_string_lossy().to_string()), None).unwrap();
    assert!(!fingerprint.is_empty());
    assert!(api::is_initialized());

    // 2. Configure
    let mut config = api::get_config().unwrap();
    config.watch_dirs = vec![watch_dir.clone()];
    api::set_config(config).unwrap();

    // 3. Start Engine
    let status = api::start_engine_default().unwrap();
    assert!(status.running);

    // 4. Create a file and wait for watcher
    let test_file = watch_dir.join("test.txt");
    fs::write(&test_file, "Hello Witnessd").unwrap();

    // Give watcher and engine time to process
    thread::sleep(Duration::from_millis(2000));

    // 5. Verify report
    let reports = api::report_files().unwrap();
    assert!(!reports.is_empty(), "No reports found after file creation");
    let report = reports
        .iter()
        .find(|r| r.file_path.contains("test.txt"))
        .expect("Test file not in reports");
    assert!(report.event_count >= 1);

    // 6. Stop engine
    api::stop_engine().unwrap();
}
