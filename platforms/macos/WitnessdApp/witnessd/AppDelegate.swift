import Cocoa
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

	// MARK: - Core Objects

	private var statusBarController: StatusBarController?
	private let witnessdBridge = WitnessdBridge()

	// MARK: - Onboarding State

	private var hasShownOnboarding = false
	private var onboardingWindow: NSWindow?

	// MARK: - Application Lifecycle

	func applicationDidFinishLaunching(_ notification: Notification) {
		// Menu bar–only app
		NSApp.setActivationPolicy(.accessory)

		statusBarController = StatusBarController(bridge: witnessdBridge)

		checkFirstLaunch()
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

	// MARK: - First Launch / Onboarding

	private func checkFirstLaunch() {
		let defaults = UserDefaults.standard
		let hasLaunched = defaults.bool(forKey: "hasLaunchedBefore")

		guard !hasLaunched else { return }

		defaults.set(true, forKey: "hasLaunchedBefore")
		showOnboarding()
	}

	private func showOnboarding() {
		guard !hasShownOnboarding else { return }
		hasShownOnboarding = true

		let window = NSWindow(
			contentRect: NSRect(
				x: 0,
				y: 0,
				width: Design.Layout.onboardingWidth,
				height: Design.Layout.onboardingHeight
			),
			styleMask: [.titled, .closable],
			backing: .buffered,
			defer: false
		)

		window.title = "Welcome to Witnessd"
		window.center()
		window.isReleasedWhenClosed = false

		let onboardingView = OnboardingView(
			isPresented: .constant(true),
			bridge: witnessdBridge,
			onComplete: { [weak self] in
				self?.onboardingWindow?.close()
				self?.onboardingWindow = nil
			}
		)

		window.contentView = NSHostingView(rootView: onboardingView)

		// Strongly retain the window so it stays alive
		onboardingWindow = window

		window.makeKeyAndOrderFront(nil)
		NSApp.activate(ignoringOtherApps: true)
	}
}

