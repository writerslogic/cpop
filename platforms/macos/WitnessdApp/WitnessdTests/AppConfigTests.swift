import XCTest
@testable import witnessd

/// Tests for AppConfig configuration values
final class AppConfigTests: XCTestCase {

    // MARK: - URL Tests

    func testRepositoryURL() {
        XCTAssertEqual(AppConfig.repositoryURL.absoluteString, "https://github.com/writerslogic/witnessd")
        XCTAssertEqual(AppConfig.repositoryURL.scheme, "https")
        XCTAssertEqual(AppConfig.repositoryURL.host, "github.com")
    }

    func testDocumentationURL() {
        XCTAssertEqual(AppConfig.documentationURL.absoluteString, "https://github.com/writerslogic/witnessd#readme")
        XCTAssertTrue(AppConfig.documentationURL.absoluteString.contains("#readme"))
    }

    func testIssuesURL() {
        XCTAssertEqual(AppConfig.issuesURL.absoluteString, "https://github.com/writerslogic/witnessd/issues")
        XCTAssertTrue(AppConfig.issuesURL.absoluteString.hasSuffix("/issues"))
    }

    func testSupportEmail() {
        XCTAssertEqual(AppConfig.supportEmail, "support@writerslogic.com")
        XCTAssertTrue(AppConfig.supportEmail.contains("@"))
    }

    // MARK: - App Info Tests

    func testAppVersionIsNotEmpty() {
        // App version should have a value, even if default
        XCTAssertFalse(AppConfig.appVersion.isEmpty)
    }

    func testBuildNumberIsNotEmpty() {
        // Build number should have a value, even if default
        XCTAssertFalse(AppConfig.buildNumber.isEmpty)
    }

    func testFullVersionStringFormat() {
        let fullVersion = AppConfig.fullVersionString
        // Should start with 'v' and contain parentheses for build number
        XCTAssertTrue(fullVersion.hasPrefix("v"))
        XCTAssertTrue(fullVersion.contains("("))
        XCTAssertTrue(fullVersion.contains(")"))

        // Should match pattern like "v1.0 (1)"
        let regex = try? NSRegularExpression(pattern: "^v\\d+\\.\\d+.*\\(\\d+\\)$")
        let range = NSRange(fullVersion.startIndex..<fullVersion.endIndex, in: fullVersion)
        let match = regex?.firstMatch(in: fullVersion, range: range)
        XCTAssertNotNil(match, "Full version string should match expected format: \(fullVersion)")
    }

    // MARK: - Timing Defaults Tests

    func testDefaultCheckpointIntervalMinutes() {
        XCTAssertEqual(AppConfig.defaultCheckpointIntervalMinutes, 30)
        XCTAssertGreaterThan(AppConfig.defaultCheckpointIntervalMinutes, 0)
    }

    func testStatusUpdateIntervalSeconds() {
        XCTAssertEqual(AppConfig.statusUpdateIntervalSeconds, 3.0)
        XCTAssertGreaterThan(AppConfig.statusUpdateIntervalSeconds, 0)
    }

    func testAccessibilityCheckIntervalSeconds() {
        XCTAssertEqual(AppConfig.accessibilityCheckIntervalSeconds, 2.0)
        XCTAssertGreaterThan(AppConfig.accessibilityCheckIntervalSeconds, 0)
    }

    // MARK: - Data Directory Tests

    func testAppSupportDirectoryName() {
        XCTAssertEqual(AppConfig.appSupportDirectoryName, "Witnessd")
        XCTAssertFalse(AppConfig.appSupportDirectoryName.isEmpty)
    }

    func testSessionsDirectoryName() {
        XCTAssertEqual(AppConfig.sessionsDirectoryName, "sessions")
        XCTAssertFalse(AppConfig.sessionsDirectoryName.isEmpty)
    }

    // MARK: - Consistency Tests

    func testTimingValuesAreReasonable() {
        // Status updates should be more frequent than checkpoint interval
        let statusIntervalMinutes = AppConfig.statusUpdateIntervalSeconds / 60.0
        XCTAssertLessThan(statusIntervalMinutes, Double(AppConfig.defaultCheckpointIntervalMinutes))

        // Accessibility check should be similar to or less than status update
        XCTAssertLessThanOrEqual(AppConfig.accessibilityCheckIntervalSeconds, AppConfig.statusUpdateIntervalSeconds * 2)
    }

    func testURLsAreAccessible() {
        // All URLs should have valid schemes
        XCTAssertNotNil(AppConfig.repositoryURL.scheme)
        XCTAssertNotNil(AppConfig.documentationURL.scheme)
        XCTAssertNotNil(AppConfig.issuesURL.scheme)

        // All URLs should use HTTPS
        XCTAssertEqual(AppConfig.repositoryURL.scheme, "https")
        XCTAssertEqual(AppConfig.documentationURL.scheme, "https")
        XCTAssertEqual(AppConfig.issuesURL.scheme, "https")
    }
}
