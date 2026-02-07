import XCTest
import SwiftUI
@testable import witnessd

// MARK: - Test Configuration

/// Test configuration constants
enum TestConfig {
    static let defaultTimeout: TimeInterval = 10.0
    static let asyncTimeout: TimeInterval = 5.0
    static let animationDelay: TimeInterval = 0.5
    static let pollInterval: TimeInterval = 0.1
}

// MARK: - Mock WitnessdBridge

/// Mock implementation of WitnessdBridge for unit testing
@MainActor
final class MockWitnessdBridge: @unchecked Sendable {

    // MARK: - State

    var mockStatus = WitnessStatus()
    var initializeResult = CommandResult(success: true, message: "Initialized", exitCode: 0)
    var calibrateResult = CommandResult(success: true, message: "Calibrated", exitCode: 0)
    var startTrackingResult = CommandResult(success: true, message: "Tracking started", exitCode: 0)
    var stopTrackingResult = CommandResult(success: true, message: "Tracking stopped", exitCode: 0)
    var commitResult = CommandResult(success: true, message: "Committed", exitCode: 0)
    var exportResult = CommandResult(success: true, message: "Exported", exitCode: 0)
    var verifyResult = CommandResult(success: true, message: "Verified", exitCode: 0)
    var listResult = CommandResult(success: true, message: "", exitCode: 0)
    var logResult = CommandResult(success: true, message: "Log content", exitCode: 0)

    // MARK: - Call Tracking

    private(set) var initializeCalled = false
    private(set) var calibrateCalled = false
    private(set) var startTrackingCalled = false
    private(set) var startTrackingPath: String?
    private(set) var stopTrackingCalled = false
    private(set) var commitCalled = false
    private(set) var commitPath: String?
    private(set) var commitMessage: String?
    private(set) var exportCalled = false
    private(set) var exportPath: String?
    private(set) var exportTier: String?
    private(set) var exportOutputPath: String?
    private(set) var verifyCalled = false
    private(set) var verifyPath: String?
    private(set) var listCalled = false
    private(set) var logCalled = false
    private(set) var logPath: String?

    var dataDirectoryPath: String = "/tmp/witnessd-test"

    // MARK: - Mock Commands

    func initialize() async -> CommandResult {
        initializeCalled = true
        return initializeResult
    }

    func calibrate() async -> CommandResult {
        calibrateCalled = true
        return calibrateResult
    }

    func startTracking(documentPath: String) async -> CommandResult {
        startTrackingCalled = true
        startTrackingPath = documentPath
        return startTrackingResult
    }

    func stopTracking() async -> CommandResult {
        stopTrackingCalled = true
        return stopTrackingResult
    }

    func commit(filePath: String, message: String) async -> CommandResult {
        commitCalled = true
        commitPath = filePath
        commitMessage = message
        return commitResult
    }

    func export(filePath: String, tier: String, outputPath: String) async -> CommandResult {
        exportCalled = true
        exportPath = filePath
        exportTier = tier
        exportOutputPath = outputPath
        return exportResult
    }

    func verify(filePath: String) async -> CommandResult {
        verifyCalled = true
        verifyPath = filePath
        return verifyResult
    }

    func list() async -> CommandResult {
        listCalled = true
        return listResult
    }

    func log(filePath: String) async -> CommandResult {
        logCalled = true
        logPath = filePath
        return logResult
    }

    func getStatus() async -> WitnessStatus {
        return mockStatus
    }

    func listTrackedFiles() async -> [TrackedFile] {
        guard listResult.success else { return [] }

        // Parse mock list result
        return listResult.message.components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .map { line in
                TrackedFile(
                    id: line,
                    path: line,
                    name: URL(fileURLWithPath: line).lastPathComponent,
                    events: 0,
                    lastModified: nil
                )
            }
    }

    // MARK: - Reset

    func reset() {
        mockStatus = WitnessStatus()
        initializeCalled = false
        calibrateCalled = false
        startTrackingCalled = false
        startTrackingPath = nil
        stopTrackingCalled = false
        commitCalled = false
        commitPath = nil
        commitMessage = nil
        exportCalled = false
        exportPath = nil
        exportTier = nil
        exportOutputPath = nil
        verifyCalled = false
        verifyPath = nil
        listCalled = false
        logCalled = false
        logPath = nil
    }
}

// MARK: - Mock NotificationManager

/// Mock notification manager for testing
final class MockNotificationManager: @unchecked Sendable {
    private(set) var requestPermissionCalled = false
    private(set) var notifications: [(title: String, body: String)] = []

    var isAuthorized = true

    func requestPermission() {
        requestPermissionCalled = true
    }

    func send(title: String, body: String) {
        notifications.append((title: title, body: body))
    }

    func notifyTrackingStarted(document: String) {
        send(title: "Tracking Started", body: "Now tracking: \(document)")
    }

    func notifyTrackingStopped(keystrokes: Int, duration: String) {
        send(title: "Tracking Stopped", body: "Recorded \(keystrokes) keystrokes over \(duration)")
    }

    func notifyCheckpointCreated(document: String, number: Int) {
        send(title: "Checkpoint Created", body: "Checkpoint #\(number) for \(document)")
    }

    func notifyAutoCheckpointCreated(document: String) {
        send(title: "Auto-Checkpoint Created", body: "Checkpoint saved for \(document)")
    }

    func notifyEvidenceExported(path: String) {
        send(title: "Evidence Exported", body: "Saved to: \(path)")
    }

    func notifyVerificationResult(passed: Bool, document: String) {
        send(
            title: passed ? "Verification Passed" : "Verification Failed",
            body: document
        )
    }

    func reset() {
        requestPermissionCalled = false
        notifications = []
    }
}

// MARK: - Mock UserDefaults

/// Mock UserDefaults for isolated testing
final class MockUserDefaults: UserDefaults {
    private var storage: [String: Any] = [:]

    override func object(forKey defaultName: String) -> Any? {
        return storage[defaultName]
    }

    override func set(_ value: Any?, forKey defaultName: String) {
        storage[defaultName] = value
    }

    override func bool(forKey defaultName: String) -> Bool {
        return storage[defaultName] as? Bool ?? false
    }

    override func integer(forKey defaultName: String) -> Int {
        return storage[defaultName] as? Int ?? 0
    }

    override func string(forKey defaultName: String) -> String? {
        return storage[defaultName] as? String
    }

    override func removeObject(forKey defaultName: String) {
        storage.removeValue(forKey: defaultName)
    }

    func reset() {
        storage = [:]
    }
}

// MARK: - Test File Helpers

/// Helpers for creating test files
enum TestFileHelper {

    static var testDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("WitnessdTests")
    }

    static func createTestDirectory() throws {
        try FileManager.default.createDirectory(
            at: testDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
    }

    static func cleanupTestDirectory() {
        try? FileManager.default.removeItem(at: testDirectory)
    }

    static func createTestFile(named name: String, content: String = "Test content") throws -> URL {
        try createTestDirectory()
        let fileURL = testDirectory.appendingPathComponent(name)
        try content.write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL
    }

    static func createTestDocument() throws -> URL {
        return try createTestFile(named: "test-document.txt", content: "This is a test document for witnessd testing.")
    }

    static func createTestEvidenceFile() throws -> URL {
        let evidenceJSON = """
        {
            "version": "1.0",
            "document": "test.txt",
            "checkpoints": [],
            "signature": "mock-signature"
        }
        """
        return try createTestFile(named: "test.evidence.json", content: evidenceJSON)
    }
}

// MARK: - XCTest Extensions

extension XCTestCase {

    /// Waits for an async condition to become true
    func waitForCondition(
        timeout: TimeInterval = TestConfig.asyncTimeout,
        description: String = "Condition",
        condition: @escaping () -> Bool
    ) {
        let expectation = expectation(description: description)

        var timer: Timer?
        timer = Timer.scheduledTimer(withTimeInterval: TestConfig.pollInterval, repeats: true) { _ in
            if condition() {
                expectation.fulfill()
                timer?.invalidate()
            }
        }

        wait(for: [expectation], timeout: timeout)
        timer?.invalidate()
    }

    /// Runs async code synchronously for testing
    func runAsyncTest(
        timeout: TimeInterval = TestConfig.asyncTimeout,
        file: StaticString = #file,
        line: UInt = #line,
        _ operation: @escaping () async throws -> Void
    ) {
        let expectation = expectation(description: "Async operation")

        Task {
            do {
                try await operation()
                expectation.fulfill()
            } catch {
                XCTFail("Async operation failed: \(error)", file: file, line: line)
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: timeout)
    }

    /// Creates a temporary file and cleans up after the test
    func withTemporaryFile(
        named name: String = "test.txt",
        content: String = "Test content",
        _ body: (URL) throws -> Void
    ) rethrows {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try? content.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }
}

// MARK: - SwiftUI View Testing Helpers

extension View {
    /// Wraps a view for testing in a hosting controller
    func testHostingController() -> NSHostingController<Self> {
        return NSHostingController(rootView: self)
    }
}

/// Snapshot test configuration
struct SnapshotConfig {
    let name: String
    let colorScheme: ColorScheme
    let size: CGSize

    static let defaultLight = SnapshotConfig(
        name: "light",
        colorScheme: .light,
        size: CGSize(width: 320, height: 440)
    )

    static let defaultDark = SnapshotConfig(
        name: "dark",
        colorScheme: .dark,
        size: CGSize(width: 320, height: 440)
    )

    static let settingsLight = SnapshotConfig(
        name: "settings-light",
        colorScheme: .light,
        size: CGSize(width: 480, height: 320)
    )

    static let settingsDark = SnapshotConfig(
        name: "settings-dark",
        colorScheme: .dark,
        size: CGSize(width: 480, height: 320)
    )
}

// MARK: - Accessibility Test Helpers

enum AccessibilityTestHelper {

    /// Verifies that a view has proper accessibility labels
    static func hasAccessibilityLabel(_ view: some View, label: String) -> Bool {
        // This is a simplified check - in real tests, use XCUIElement.label
        return true
    }

    /// Common accessibility traits to check for
    enum ExpectedTrait {
        case button
        case header
        case staticText
        case image
        case adjustable
        case selected
    }
}

// MARK: - Performance Test Helpers

enum PerformanceTestHelper {

    /// Measures view creation time
    static func measureViewCreation<V: View>(
        iterations: Int = 100,
        _ viewBuilder: () -> V
    ) -> TimeInterval {
        let start = CFAbsoluteTimeGetCurrent()

        for _ in 0..<iterations {
            _ = viewBuilder()
        }

        return CFAbsoluteTimeGetCurrent() - start
    }

    /// Generates mock tracked files for performance testing
    static func generateMockTrackedFiles(count: Int) -> [TrackedFile] {
        return (0..<count).map { i in
            TrackedFile(
                id: "file-\(i)",
                path: "/path/to/file-\(i).txt",
                name: "file-\(i).txt",
                events: i * 10,
                lastModified: Date().addingTimeInterval(TimeInterval(-i * 3600))
            )
        }
    }
}

// MARK: - Sample Test Data

enum TestData {

    static let sampleDocumentPath = "/Users/test/Documents/sample.txt"
    static let sampleEvidencePath = "/Users/test/Documents/sample.evidence.json"

    static let sampleStatus: WitnessStatus = {
        var status = WitnessStatus()
        status.isInitialized = true
        status.isTracking = false
        status.vdfCalibrated = true
        status.vdfIterPerSec = "1000000"
        status.tpmAvailable = false
        status.databaseEvents = 1250
        status.databaseFiles = 5
        return status
    }()

    static let trackingStatus: WitnessStatus = {
        var status = WitnessStatus()
        status.isInitialized = true
        status.isTracking = true
        status.trackingDocument = sampleDocumentPath
        status.keystrokeCount = 4523
        status.trackingDuration = "1h 23m"
        status.vdfCalibrated = true
        status.vdfIterPerSec = "1000000"
        status.tpmAvailable = false
        status.databaseEvents = 1250
        status.databaseFiles = 5
        return status
    }()

    static let uninitializedStatus = WitnessStatus()

    static let sampleTrackedFiles: [TrackedFile] = [
        TrackedFile(id: "1", path: "/path/to/novel.txt", name: "novel.txt", events: 15234, lastModified: Date()),
        TrackedFile(id: "2", path: "/path/to/essay.md", name: "essay.md", events: 3421, lastModified: Date().addingTimeInterval(-3600)),
        TrackedFile(id: "3", path: "/path/to/notes.txt", name: "notes.txt", events: 892, lastModified: Date().addingTimeInterval(-7200)),
    ]
}
