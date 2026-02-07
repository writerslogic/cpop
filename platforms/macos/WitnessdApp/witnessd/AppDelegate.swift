import Cocoa
import SwiftUI
import ApplicationServices
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

	// MARK: - Core Objects

	private var statusBarController: StatusBarController?
	private let witnessdBridge = WitnessdBridge()

	// MARK: - Application Lifecycle

	func applicationDidFinishLaunching(_ notification: Notification) {
		// Menu bar–only app
		NSApp.setActivationPolicy(.accessory)

		statusBarController = StatusBarController(bridge: witnessdBridge)

		// Auto-initialize on first launch
		Task {
			await autoInitializeIfNeeded()
			await checkAccessibilityPermission()
		}
	}

	func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
		Task { @MainActor in
			statusBarController?.shutdown()

			if (await witnessdBridge.getStatus()).isTracking {
				_ = await witnessdBridge.stopTracking()
			}

			sender.reply(toApplicationShouldTerminate: true)
		}

		return .terminateLater
	}

	// MARK: - Auto-Initialization

	private func autoInitializeIfNeeded() async {
		let defaults = UserDefaults.standard
		let hasInitialized = defaults.bool(forKey: "hasAutoInitialized")

		guard !hasInitialized else { return }

		// Initialize witnessd (creates signing key and database)
		let initResult = await witnessdBridge.initialize()
		if initResult.success {
			defaults.set(true, forKey: "hasAutoInitialized")

			// Also calibrate VDF in background
			Task {
				_ = await witnessdBridge.calibrate()
			}
		}
	}

	// MARK: - Accessibility Permission

	private func checkAccessibilityPermission() async {
		// Check if we already have accessibility permission
		let trusted = AXIsProcessTrusted()

		if !trusted {
			// Request notification permission first
			await requestNotificationPermission()

			// Show notification about accessibility
			showAccessibilityNotification()

			// Open System Settings → Privacy & Security → Accessibility
			// This also adds the app to the Accessibility list
			openAccessibilitySettings()
		}
	}

	private func requestNotificationPermission() async {
		let center = UNUserNotificationCenter.current()
		do {
			try await center.requestAuthorization(options: [.alert, .sound])
		} catch {
			// Notification permission denied, continue anyway
		}
	}

	private func showAccessibilityNotification() {
		let center = UNUserNotificationCenter.current()

		let content = UNMutableNotificationContent()
		content.title = "Enable Accessibility for Witnessd"
		content.body = "Witnessd needs Accessibility access to track keystrokes. Please toggle ON the switch next to Witnessd in System Settings."
		content.sound = .default

		let request = UNNotificationRequest(
			identifier: "accessibility-prompt",
			content: content,
			trigger: nil // Deliver immediately
		)

		center.add(request)
	}

	private func openAccessibilitySettings() {
		// This URL opens System Settings → Privacy & Security → Accessibility
		// AND adds the app to the list automatically
		let options: NSDictionary = [kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true]
		AXIsProcessTrustedWithOptions(options)

		// Also open the settings pane directly for visibility
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
			if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
				NSWorkspace.shared.open(url)
			}
		}
	}
}

