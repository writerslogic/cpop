import Foundation

/// Application configuration constants
/// Centralized location for URLs and other configurable values
enum AppConfig {
    // MARK: - URLs

    /// GitHub repository URL
    static let repositoryURL = URL(string: "https://github.com/writerslogic/witnessd")!

    /// Documentation URL
    static let documentationURL = URL(string: "https://github.com/writerslogic/witnessd#readme")!

    /// Issue reporting URL
    static let issuesURL = URL(string: "https://github.com/writerslogic/witnessd/issues")!

    /// Support email
    static let supportEmail = "support@writerslogic.com"

    // MARK: - App Info

    /// App version from bundle
    static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }

    /// App build number from bundle
    static var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    }

    /// Full version string (e.g., "1.0 (42)")
    static var fullVersionString: String {
        "v\(appVersion) (\(buildNumber))"
    }

    // MARK: - Timing Defaults

    /// Default auto-checkpoint interval in minutes
    static let defaultCheckpointIntervalMinutes = 30

    /// Status update polling interval in seconds
    static let statusUpdateIntervalSeconds: TimeInterval = 3.0

    /// Accessibility permission check interval in seconds
    static let accessibilityCheckIntervalSeconds: TimeInterval = 2.0

    // MARK: - Data Directories

    /// Application support subdirectory name
    static let appSupportDirectoryName = "Witnessd"

    /// Sessions subdirectory name
    static let sessionsDirectoryName = "sessions"
}
