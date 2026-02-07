import Foundation
import UserNotifications
import os.log

/// Thread-safe notification manager for delivering user notifications
final class NotificationManager: @unchecked Sendable {
    static let shared = NotificationManager()

    private let logger = Logger(subsystem: "com.witnessd.app", category: "notifications")
    private var isAuthorized = false

    private init() {
        // Request permission asynchronously to avoid blocking
        Task {
            await requestPermissionAsync()
        }
    }

    func requestPermission() {
        Task {
            await requestPermissionAsync()
        }
    }

    private func requestPermissionAsync() async {
        do {
            let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
            isAuthorized = granted
            if !granted {
                logger.info("Notification permission denied by user")
            }
        } catch {
            logger.error("Notification permission error: \(error.localizedDescription)")
        }
    }

    func notifyTrackingStarted(document: String) {
        sendNotification(
            title: "Tracking Started",
            body: "Now tracking: \(document)",
            sound: .default
        )
    }

    func notifyTrackingStopped(keystrokes: Int, duration: String) {
        sendNotification(
            title: "Tracking Stopped",
            body: "Recorded \(keystrokes) keystrokes over \(duration)",
            sound: .default
        )
    }

    func notifyCheckpointCreated(document: String, number: Int) {
        sendNotification(
            title: "Checkpoint Created",
            body: "Checkpoint #\(number) for \(document)",
            sound: .default
        )
    }

    func notifyAutoCheckpointCreated(document: String) {
        sendNotification(
            title: "Auto-Checkpoint Created",
            body: "Checkpoint saved for \(document)",
            sound: .default
        )
    }

    func notifyEvidenceExported(path: String) {
        sendNotification(
            title: "Evidence Exported",
            body: "Saved to: \(path)",
            sound: .default
        )
    }

    func notifyVerificationResult(passed: Bool, document: String) {
        sendNotification(
            title: passed ? "Verification Passed" : "Verification Failed",
            body: document,
            sound: passed ? .default : .defaultCritical
        )
    }

    /// Simple convenience method for sending notifications
    func send(title: String, body: String) {
        sendNotification(title: title, body: body, sound: .default)
    }

    // MARK: - Private

    private func sendNotification(title: String, body: String, sound: UNNotificationSound) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = sound

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { [weak self] error in
            if let error {
                self?.logger.error("Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }
}
