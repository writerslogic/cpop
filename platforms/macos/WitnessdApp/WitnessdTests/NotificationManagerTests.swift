import XCTest
import UserNotifications
@testable import witnessd

/// Tests for NotificationManager functionality
final class NotificationManagerTests: XCTestCase {

    var mockNotificationManager: MockNotificationManager!

    override func setUp() {
        super.setUp()
        mockNotificationManager = MockNotificationManager()
    }

    override func tearDown() {
        mockNotificationManager.reset()
        mockNotificationManager = nil
        super.tearDown()
    }

    // MARK: - Permission Tests

    func testRequestPermission() {
        mockNotificationManager.requestPermission()
        XCTAssertTrue(mockNotificationManager.requestPermissionCalled)
    }

    // MARK: - Tracking Notification Tests

    func testNotifyTrackingStarted() {
        let documentName = "novel.txt"
        mockNotificationManager.notifyTrackingStarted(document: documentName)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Tracking Started")
        XCTAssertTrue(notification.body.contains(documentName))
        XCTAssertTrue(notification.body.contains("Now tracking:"))
    }

    func testNotifyTrackingStopped() {
        let keystrokes = 4523
        let duration = "1h 23m"
        mockNotificationManager.notifyTrackingStopped(keystrokes: keystrokes, duration: duration)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Tracking Stopped")
        XCTAssertTrue(notification.body.contains("\(keystrokes)"))
        XCTAssertTrue(notification.body.contains(duration))
    }

    func testNotifyTrackingStoppedWithZeroKeystrokes() {
        mockNotificationManager.notifyTrackingStopped(keystrokes: 0, duration: "0m")

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertTrue(notification.body.contains("0"))
    }

    // MARK: - Checkpoint Notification Tests

    func testNotifyCheckpointCreated() {
        let document = "essay.md"
        let number = 5
        mockNotificationManager.notifyCheckpointCreated(document: document, number: number)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Checkpoint Created")
        XCTAssertTrue(notification.body.contains("#\(number)"))
        XCTAssertTrue(notification.body.contains(document))
    }

    func testNotifyAutoCheckpointCreated() {
        let document = "notes.txt"
        mockNotificationManager.notifyAutoCheckpointCreated(document: document)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Auto-Checkpoint Created")
        XCTAssertTrue(notification.body.contains(document))
    }

    // MARK: - Export Notification Tests

    func testNotifyEvidenceExported() {
        let path = "/Users/test/Documents/evidence.json"
        mockNotificationManager.notifyEvidenceExported(path: path)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Evidence Exported")
        XCTAssertTrue(notification.body.contains(path))
    }

    // MARK: - Verification Notification Tests

    func testNotifyVerificationResultPassed() {
        let document = "verified-doc.txt"
        mockNotificationManager.notifyVerificationResult(passed: true, document: document)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Verification Passed")
        XCTAssertEqual(notification.body, document)
    }

    func testNotifyVerificationResultFailed() {
        let document = "unverified-doc.txt"
        mockNotificationManager.notifyVerificationResult(passed: false, document: document)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, "Verification Failed")
        XCTAssertEqual(notification.body, document)
    }

    // MARK: - Generic Send Tests

    func testSendGenericNotification() {
        let title = "Custom Title"
        let body = "Custom body message"
        mockNotificationManager.send(title: title, body: body)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        let notification = mockNotificationManager.notifications.first!
        XCTAssertEqual(notification.title, title)
        XCTAssertEqual(notification.body, body)
    }

    // MARK: - Multiple Notifications Tests

    func testMultipleNotifications() {
        mockNotificationManager.notifyTrackingStarted(document: "doc1.txt")
        mockNotificationManager.notifyCheckpointCreated(document: "doc1.txt", number: 1)
        mockNotificationManager.notifyCheckpointCreated(document: "doc1.txt", number: 2)
        mockNotificationManager.notifyTrackingStopped(keystrokes: 1000, duration: "30m")

        XCTAssertEqual(mockNotificationManager.notifications.count, 4)

        XCTAssertEqual(mockNotificationManager.notifications[0].title, "Tracking Started")
        XCTAssertEqual(mockNotificationManager.notifications[1].title, "Checkpoint Created")
        XCTAssertEqual(mockNotificationManager.notifications[2].title, "Checkpoint Created")
        XCTAssertEqual(mockNotificationManager.notifications[3].title, "Tracking Stopped")
    }

    // MARK: - Reset Tests

    func testReset() {
        mockNotificationManager.requestPermission()
        mockNotificationManager.send(title: "Test", body: "Test body")

        XCTAssertTrue(mockNotificationManager.requestPermissionCalled)
        XCTAssertEqual(mockNotificationManager.notifications.count, 1)

        mockNotificationManager.reset()

        XCTAssertFalse(mockNotificationManager.requestPermissionCalled)
        XCTAssertEqual(mockNotificationManager.notifications.count, 0)
    }

    // MARK: - Edge Cases

    func testEmptyDocumentName() {
        mockNotificationManager.notifyTrackingStarted(document: "")

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)
        XCTAssertTrue(mockNotificationManager.notifications.first!.body.contains("Now tracking:"))
    }

    func testLongDocumentName() {
        let longName = String(repeating: "a", count: 500) + ".txt"
        mockNotificationManager.notifyTrackingStarted(document: longName)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)
        XCTAssertTrue(mockNotificationManager.notifications.first!.body.contains(longName))
    }

    func testSpecialCharactersInDocumentName() {
        let specialName = "doc with spaces & symbols!@#$.txt"
        mockNotificationManager.notifyTrackingStarted(document: specialName)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)
        XCTAssertTrue(mockNotificationManager.notifications.first!.body.contains(specialName))
    }

    func testUnicodeInDocumentName() {
        let unicodeName = "document-\u{1F4DD}-notes.txt"
        mockNotificationManager.notifyTrackingStarted(document: unicodeName)

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)
        XCTAssertTrue(mockNotificationManager.notifications.first!.body.contains(unicodeName))
    }

    func testLargeKeystrokeCount() {
        let largeCount = 10_000_000
        mockNotificationManager.notifyTrackingStopped(keystrokes: largeCount, duration: "100h")

        XCTAssertEqual(mockNotificationManager.notifications.count, 1)
        XCTAssertTrue(mockNotificationManager.notifications.first!.body.contains("\(largeCount)"))
    }
}

// MARK: - NotificationManager Integration Tests

/// Integration tests for the real NotificationManager (requires notification permissions)
final class NotificationManagerIntegrationTests: XCTestCase {

    // Note: These tests interact with the real notification system
    // They may require notification permissions to pass

    func testSharedInstanceExists() {
        let manager = NotificationManager.shared
        XCTAssertNotNil(manager)
    }

    func testSharedInstanceIsSingleton() {
        let manager1 = NotificationManager.shared
        let manager2 = NotificationManager.shared
        XCTAssertTrue(manager1 === manager2)
    }
}
