import XCTest
@testable import witnessd

/// Tests for WitnessdBridge daemon IPC functionality
final class ServiceConnectionTests: XCTestCase {

    var mockBridge: MockWitnessdBridge!

    @MainActor
    override func setUp() {
        super.setUp()
        mockBridge = MockWitnessdBridge()
    }

    @MainActor
    override func tearDown() {
        mockBridge.reset()
        mockBridge = nil
        super.tearDown()
    }

    // MARK: - Initialize Tests

    @MainActor
    func testInitializeSuccess() async {
        mockBridge.initializeResult = CommandResult(success: true, message: "Initialized successfully", exitCode: 0)

        let result = await mockBridge.initialize()

        XCTAssertTrue(mockBridge.initializeCalled)
        XCTAssertTrue(result.success)
        XCTAssertEqual(result.message, "Initialized successfully")
        XCTAssertEqual(result.exitCode, 0)
    }

    @MainActor
    func testInitializeFailure() async {
        mockBridge.initializeResult = CommandResult(success: false, message: "Already initialized", exitCode: 1)

        let result = await mockBridge.initialize()

        XCTAssertTrue(mockBridge.initializeCalled)
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.message, "Already initialized")
        XCTAssertEqual(result.exitCode, 1)
    }

    // MARK: - Calibrate Tests

    @MainActor
    func testCalibrateSuccess() async {
        mockBridge.calibrateResult = CommandResult(success: true, message: "VDF calibrated: 1000000 iterations/sec", exitCode: 0)

        let result = await mockBridge.calibrate()

        XCTAssertTrue(mockBridge.calibrateCalled)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("calibrated"))
    }

    @MainActor
    func testCalibrateFailure() async {
        mockBridge.calibrateResult = CommandResult(success: false, message: "Calibration failed", exitCode: 1)

        let result = await mockBridge.calibrate()

        XCTAssertTrue(mockBridge.calibrateCalled)
        XCTAssertFalse(result.success)
    }

    // MARK: - Start Tracking Tests

    @MainActor
    func testStartTrackingSuccess() async {
        let documentPath = "/path/to/document.txt"
        mockBridge.startTrackingResult = CommandResult(success: true, message: "Tracking started", exitCode: 0)

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertTrue(mockBridge.startTrackingCalled)
        XCTAssertEqual(mockBridge.startTrackingPath, documentPath)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testStartTrackingWithInvalidPath() async {
        let documentPath = "/invalid/path/document.txt"
        mockBridge.startTrackingResult = CommandResult(success: false, message: "File not found", exitCode: 1)

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertTrue(mockBridge.startTrackingCalled)
        XCTAssertEqual(mockBridge.startTrackingPath, documentPath)
        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("not found"))
    }

    @MainActor
    func testStartTrackingWhileAlreadyTracking() async {
        mockBridge.startTrackingResult = CommandResult(success: false, message: "Already tracking a session", exitCode: 1)

        let result = await mockBridge.startTracking(documentPath: "/any/path.txt")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("Already tracking"))
    }

    // MARK: - Stop Tracking Tests

    @MainActor
    func testStopTrackingSuccess() async {
        mockBridge.stopTrackingResult = CommandResult(success: true, message: "Tracking stopped. 1500 keystrokes recorded.", exitCode: 0)

        let result = await mockBridge.stopTracking()

        XCTAssertTrue(mockBridge.stopTrackingCalled)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("stopped"))
    }

    @MainActor
    func testStopTrackingWhenNotTracking() async {
        mockBridge.stopTrackingResult = CommandResult(success: false, message: "No active tracking session", exitCode: 1)

        let result = await mockBridge.stopTracking()

        XCTAssertTrue(mockBridge.stopTrackingCalled)
        XCTAssertFalse(result.success)
    }

    // MARK: - Commit Tests

    @MainActor
    func testCommitWithMessage() async {
        let filePath = "/path/to/document.txt"
        let message = "Chapter 1 complete"
        mockBridge.commitResult = CommandResult(success: true, message: "Checkpoint created", exitCode: 0)

        let result = await mockBridge.commit(filePath: filePath, message: message)

        XCTAssertTrue(mockBridge.commitCalled)
        XCTAssertEqual(mockBridge.commitPath, filePath)
        XCTAssertEqual(mockBridge.commitMessage, message)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testCommitWithEmptyMessage() async {
        let filePath = "/path/to/document.txt"
        mockBridge.commitResult = CommandResult(success: true, message: "Checkpoint created", exitCode: 0)

        let result = await mockBridge.commit(filePath: filePath, message: "")

        XCTAssertTrue(mockBridge.commitCalled)
        XCTAssertEqual(mockBridge.commitPath, filePath)
        XCTAssertEqual(mockBridge.commitMessage, "")
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testCommitFailure() async {
        mockBridge.commitResult = CommandResult(success: false, message: "No changes to commit", exitCode: 1)

        let result = await mockBridge.commit(filePath: "/path/to/document.txt", message: "Test")

        XCTAssertFalse(result.success)
    }

    // MARK: - Export Tests

    @MainActor
    func testExportWithTier() async {
        let filePath = "/path/to/document.txt"
        let tier = "standard"
        let outputPath = "/path/to/output.json"
        mockBridge.exportResult = CommandResult(success: true, message: "Exported to output.json", exitCode: 0)

        let result = await mockBridge.export(filePath: filePath, tier: tier, outputPath: outputPath)

        XCTAssertTrue(mockBridge.exportCalled)
        XCTAssertEqual(mockBridge.exportPath, filePath)
        XCTAssertEqual(mockBridge.exportTier, tier)
        XCTAssertEqual(mockBridge.exportOutputPath, outputPath)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testExportAllTiers() async {
        let tiers = ["basic", "standard", "enhanced", "maximum"]

        for tier in tiers {
            mockBridge.reset()
            mockBridge.exportResult = CommandResult(success: true, message: "Exported", exitCode: 0)

            let result = await mockBridge.export(filePath: "/doc.txt", tier: tier, outputPath: "/out.json")

            XCTAssertTrue(mockBridge.exportCalled)
            XCTAssertEqual(mockBridge.exportTier, tier)
            XCTAssertTrue(result.success)
        }
    }

    @MainActor
    func testExportFailure() async {
        mockBridge.exportResult = CommandResult(success: false, message: "No evidence found", exitCode: 1)

        let result = await mockBridge.export(filePath: "/doc.txt", tier: "standard", outputPath: "/out.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("No evidence"))
    }

    // MARK: - Verify Tests

    @MainActor
    func testVerifySuccess() async {
        let filePath = "/path/to/evidence.json"
        mockBridge.verifyResult = CommandResult(success: true, message: "All signatures verified", exitCode: 0)

        let result = await mockBridge.verify(filePath: filePath)

        XCTAssertTrue(mockBridge.verifyCalled)
        XCTAssertEqual(mockBridge.verifyPath, filePath)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testVerifyFailure() async {
        mockBridge.verifyResult = CommandResult(success: false, message: "Invalid signature", exitCode: 1)

        let result = await mockBridge.verify(filePath: "/path/to/tampered.json")

        XCTAssertTrue(mockBridge.verifyCalled)
        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("Invalid"))
    }

    // MARK: - List Tests

    @MainActor
    func testListSuccess() async {
        mockBridge.listResult = CommandResult(success: true, message: "/doc1.txt (100 events)\n/doc2.txt (50 events)", exitCode: 0)

        let result = await mockBridge.list()

        XCTAssertTrue(mockBridge.listCalled)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testListEmpty() async {
        mockBridge.listResult = CommandResult(success: true, message: "", exitCode: 0)

        let result = await mockBridge.list()

        XCTAssertTrue(mockBridge.listCalled)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.isEmpty)
    }

    @MainActor
    func testListTrackedFiles() async {
        mockBridge.listResult = CommandResult(success: true, message: "/doc1.txt\n/doc2.txt", exitCode: 0)

        let files = await mockBridge.listTrackedFiles()

        XCTAssertEqual(files.count, 2)
        XCTAssertEqual(files[0].path, "/doc1.txt")
        XCTAssertEqual(files[1].path, "/doc2.txt")
    }

    // MARK: - Log Tests

    @MainActor
    func testLogSuccess() async {
        let filePath = "/path/to/document.txt"
        mockBridge.logResult = CommandResult(success: true, message: "Event log for document.txt...", exitCode: 0)

        let result = await mockBridge.log(filePath: filePath)

        XCTAssertTrue(mockBridge.logCalled)
        XCTAssertEqual(mockBridge.logPath, filePath)
        XCTAssertTrue(result.success)
    }

    // MARK: - Status Tests

    @MainActor
    func testGetStatusInitialized() async {
        mockBridge.mockStatus = TestData.sampleStatus

        let status = await mockBridge.getStatus()

        XCTAssertTrue(status.isInitialized)
        XCTAssertFalse(status.isTracking)
        XCTAssertTrue(status.vdfCalibrated)
    }

    @MainActor
    func testGetStatusTracking() async {
        mockBridge.mockStatus = TestData.trackingStatus

        let status = await mockBridge.getStatus()

        XCTAssertTrue(status.isInitialized)
        XCTAssertTrue(status.isTracking)
        XCTAssertNotNil(status.trackingDocument)
        XCTAssertEqual(status.keystrokeCount, 4523)
        XCTAssertEqual(status.trackingDuration, "1h 23m")
    }

    @MainActor
    func testGetStatusUninitialized() async {
        mockBridge.mockStatus = TestData.uninitializedStatus

        let status = await mockBridge.getStatus()

        XCTAssertFalse(status.isInitialized)
        XCTAssertFalse(status.isTracking)
    }

    // MARK: - Data Directory Tests

    @MainActor
    func testDataDirectoryPath() {
        XCTAssertEqual(mockBridge.dataDirectoryPath, "/tmp/witnessd-test")
    }

    // MARK: - Reset Tests

    @MainActor
    func testReset() async {
        // Perform various operations
        _ = await mockBridge.initialize()
        _ = await mockBridge.calibrate()
        _ = await mockBridge.startTracking(documentPath: "/test.txt")

        XCTAssertTrue(mockBridge.initializeCalled)
        XCTAssertTrue(mockBridge.calibrateCalled)
        XCTAssertTrue(mockBridge.startTrackingCalled)

        mockBridge.reset()

        XCTAssertFalse(mockBridge.initializeCalled)
        XCTAssertFalse(mockBridge.calibrateCalled)
        XCTAssertFalse(mockBridge.startTrackingCalled)
        XCTAssertNil(mockBridge.startTrackingPath)
    }

    // MARK: - Concurrent Access Tests

    @MainActor
    func testConcurrentStatusCalls() async {
        mockBridge.mockStatus = TestData.sampleStatus

        // Simulate concurrent status requests
        async let status1 = mockBridge.getStatus()
        async let status2 = mockBridge.getStatus()
        async let status3 = mockBridge.getStatus()

        let results = await [status1, status2, status3]

        for status in results {
            XCTAssertTrue(status.isInitialized)
        }
    }

    // MARK: - Error Handling Tests

    @MainActor
    func testHandleProcessNotFound() async {
        mockBridge.initializeResult = CommandResult(success: false, message: "Failed to run witnessd: file not found", exitCode: -1)

        let result = await mockBridge.initialize()

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.exitCode, -1)
    }

    @MainActor
    func testHandlePermissionDenied() async {
        mockBridge.startTrackingResult = CommandResult(success: false, message: "Accessibility permission denied", exitCode: 1)

        let result = await mockBridge.startTracking(documentPath: "/test.txt")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("permission"))
    }
}

// MARK: - CommandResult Tests

final class CommandResultTests: XCTestCase {

    func testCommandResultSuccess() {
        let result = CommandResult(success: true, message: "Operation completed", exitCode: 0)

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.message, "Operation completed")
        XCTAssertEqual(result.exitCode, 0)
    }

    func testCommandResultFailure() {
        let result = CommandResult(success: false, message: "Error occurred", exitCode: 1)

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.message, "Error occurred")
        XCTAssertEqual(result.exitCode, 1)
    }

    func testCommandResultWithEmptyMessage() {
        let result = CommandResult(success: true, message: "", exitCode: 0)

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.isEmpty)
    }

    func testCommandResultWithNegativeExitCode() {
        let result = CommandResult(success: false, message: "Process failed", exitCode: -1)

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.exitCode, -1)
    }
}

// MARK: - WitnessStatus Tests

final class WitnessStatusTests: XCTestCase {

    func testDefaultStatus() {
        let status = WitnessStatus()

        XCTAssertFalse(status.isInitialized)
        XCTAssertFalse(status.isTracking)
        XCTAssertNil(status.trackingDocument)
        XCTAssertEqual(status.keystrokeCount, 0)
        XCTAssertTrue(status.trackingDuration.isEmpty)
        XCTAssertFalse(status.vdfCalibrated)
        XCTAssertTrue(status.vdfIterPerSec.isEmpty)
        XCTAssertFalse(status.tpmAvailable)
        XCTAssertTrue(status.tpmInfo.isEmpty)
        XCTAssertEqual(status.databaseEvents, 0)
        XCTAssertEqual(status.databaseFiles, 0)
    }

    func testInitializedStatus() {
        var status = WitnessStatus()
        status.isInitialized = true
        status.vdfCalibrated = true
        status.vdfIterPerSec = "1000000"
        status.databaseEvents = 100
        status.databaseFiles = 5

        XCTAssertTrue(status.isInitialized)
        XCTAssertTrue(status.vdfCalibrated)
        XCTAssertEqual(status.vdfIterPerSec, "1000000")
        XCTAssertEqual(status.databaseEvents, 100)
        XCTAssertEqual(status.databaseFiles, 5)
    }

    func testTrackingStatus() {
        var status = WitnessStatus()
        status.isInitialized = true
        status.isTracking = true
        status.trackingDocument = "/path/to/document.txt"
        status.keystrokeCount = 500
        status.trackingDuration = "30m 15s"

        XCTAssertTrue(status.isTracking)
        XCTAssertEqual(status.trackingDocument, "/path/to/document.txt")
        XCTAssertEqual(status.keystrokeCount, 500)
        XCTAssertEqual(status.trackingDuration, "30m 15s")
    }
}
