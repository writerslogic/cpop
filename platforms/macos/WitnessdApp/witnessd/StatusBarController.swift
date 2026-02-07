import Cocoa
import SwiftUI

@MainActor
final class StatusBarController: NSObject, NSPopoverDelegate {
	private let statusItem: NSStatusItem
	private let popover: NSPopover
	private let bridge: WitnessdBridge

	private var statusTimer: Timer?
	private var globalMonitor: Any?
	private var localMonitor: Any?
	private var currentStatus = WitnessStatus()

	// Auto-checkpoint
	private var autoCheckpointTimer: Timer?
	private var settingsObserver: NSObjectProtocol?
	private var wasTrackingPreviously = false

	// Read auto-checkpoint settings from UserDefaults
	private var autoCheckpointEnabled: Bool {
		UserDefaults.standard.bool(forKey: "autoCheckpoint")
	}

	private var checkpointIntervalMinutes: Int {
		let value = UserDefaults.standard.integer(forKey: "checkpointIntervalMinutes")
		return value > 0 ? value : 30  // Default to 30 if not set
	}

	init(bridge: WitnessdBridge) {
		self.bridge = bridge
		self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
		self.popover = NSPopover()
		super.init()

		setupPopover()
		setupStatusBarButton()
		setupEventMonitors()
		setupSettingsObserver()
		startStatusUpdates()
	}

	private func setupSettingsObserver() {
		settingsObserver = NotificationCenter.default.addObserver(
			forName: UserDefaults.didChangeNotification,
			object: nil,
			queue: .main
		) { [weak self] _ in
			Task { @MainActor in
				self?.updateAutoCheckpointTimer()
			}
		}
	}

	// MARK: - Setup

	private func setupPopover() {
		popover.contentSize = NSSize(width: Design.Layout.popoverWidth,
									 height: Design.Layout.popoverHeight)
		popover.behavior = .transient
		popover.animates = true
		popover.delegate = self

		let contentView = PopoverContentView(
			bridge: bridge,
			closeAction: { [weak self] in self?.popover.performClose(nil) }
		)
		popover.contentViewController = NSHostingController(rootView: contentView)
	}

	private func setupStatusBarButton() {
		guard let button = statusItem.button else { return }

		updateIcon(isTracking: false, isInitialized: false)
		button.action = #selector(handleClick)
		button.target = self
		button.sendAction(on: [.leftMouseUp, .rightMouseUp])

		// Accessibility
		button.setAccessibilityLabel("Witnessd")
		button.setAccessibilityRole(.popUpButton)
		button.setAccessibilityValue("Not Initialized")
	}

	private func setupEventMonitors() {
		// Global monitor catches clicks outside the app
		globalMonitor = NSEvent.addGlobalMonitorForEvents(
			matching: [.leftMouseDown, .rightMouseDown]
		) { [weak self] _ in
			Task { @MainActor in
				guard let self else { return }
				if self.popover.isShown { self.popover.performClose(nil) }
			}
		}

		// Local monitor catches clicks inside the app that don't go through the popover
		localMonitor = NSEvent.addLocalMonitorForEvents(
			matching: [.leftMouseDown, .rightMouseDown]
		) { [weak self] event in
			guard let self else { return event }
			if self.popover.isShown, let button = self.statusItem.button {
				// If click is not on the status item button, close the popover
				let clickPoint = NSEvent.mouseLocation
				let buttonFrame = button.window?.convertToScreen(button.convert(button.bounds, to: nil)) ?? .zero
				if !buttonFrame.contains(clickPoint) {
					self.popover.performClose(nil)
				}
			}
			return event
		}
	}

	// MARK: - Status Bar Icon

	private func updateIcon(isTracking: Bool, isInitialized: Bool) {
		guard let button = statusItem.button else { return }

		let symbolName: String
		let tintColor: NSColor

		if isTracking {
			symbolName = "eye.circle.fill"
			tintColor = .systemGreen
		} else if isInitialized {
			symbolName = "eye.circle"
			tintColor = .labelColor
		} else {
			symbolName = "eye.slash.circle"
			tintColor = .secondaryLabelColor
		}

		let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
		if let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "Witnessd") {
			button.image = image.withSymbolConfiguration(config)
			button.contentTintColor = tintColor
		}

		let tooltipStatus = isTracking ? "Tracking Active" : (isInitialized ? "Ready" : "Not Initialized")
		button.toolTip = "Witnessd — \(tooltipStatus)"
		button.setAccessibilityValue(tooltipStatus)
	}

	// MARK: - Status Updates

	/// Polling intervals - faster when tracking, slower when idle
	private static let trackingPollInterval: TimeInterval = 3.0
	private static let idlePollInterval: TimeInterval = 10.0

	private func startStatusUpdates() {
		Task { @MainActor [weak self] in
			await self?.updateStatus()
		}

		scheduleStatusTimer(isTracking: false)
	}

	private func scheduleStatusTimer(isTracking: Bool) {
		statusTimer?.invalidate()
		let interval = isTracking ? Self.trackingPollInterval : Self.idlePollInterval
		statusTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
			Task { @MainActor in
				await self?.updateStatus()
			}
		}
	}

	/// Call this to immediately refresh status after an action
	private func triggerImmediateStatusUpdate() {
		Task { @MainActor in
			await updateStatus()
		}
	}

	private func updateStatus() async {
		let status = await bridge.getStatus()
		currentStatus = status
		updateIcon(isTracking: status.isTracking, isInitialized: status.isInitialized)

		// Check if tracking state changed
		if status.isTracking != wasTrackingPreviously {
			wasTrackingPreviously = status.isTracking
			updateAutoCheckpointTimer()
			// Adjust polling interval based on tracking state
			scheduleStatusTimer(isTracking: status.isTracking)
		}
	}

	// MARK: - Auto-Checkpoint

	private func updateAutoCheckpointTimer() {
		// Invalidate any existing timer
		autoCheckpointTimer?.invalidate()
		autoCheckpointTimer = nil

		// Only start timer if auto-checkpoint is enabled AND we're currently tracking
		guard autoCheckpointEnabled, currentStatus.isTracking else {
			return
		}

		// Create timer with interval from settings (converted to seconds)
		let intervalSeconds = TimeInterval(checkpointIntervalMinutes * 60)
		autoCheckpointTimer = Timer.scheduledTimer(withTimeInterval: intervalSeconds, repeats: true) { [weak self] _ in
			Task { @MainActor in
				await self?.performAutoCheckpoint()
			}
		}
	}

	private func performAutoCheckpoint() async {
		// Guard that tracking is still active
		guard currentStatus.isTracking,
			  let trackingDocument = currentStatus.trackingDocument else {
			return
		}

		// Create timestamp for commit message
		let formatter = DateFormatter()
		formatter.dateFormat = "HH:mm"
		let timeString = formatter.string(from: Date())

		// Perform the commit
		let result = await bridge.commit(filePath: trackingDocument, message: "Auto-checkpoint at \(timeString)")

		// Send notification on success
		if result.success {
			let documentName = URL(fileURLWithPath: trackingDocument).lastPathComponent
			NotificationManager.shared.notifyAutoCheckpointCreated(document: documentName)
		}
	}

	// MARK: - Click Handling

	@objc private func handleClick(_ sender: AnyObject?) {
		// Always show the menu on any click (left or right)
		// This makes it immediately obvious how to start/stop tracking
		showContextMenu()
	}

	private func togglePopover(_ sender: AnyObject?) {
		if popover.isShown {
			popover.performClose(sender)
			return
		}
		guard let button = statusItem.button else { return }
		popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
		NSApp.activate(ignoringOtherApps: true)
	}

	private func showContextMenu() {
		let menu = NSMenu()

		// Status header with keystroke count if tracking
		let header = NSMenuItem()
		if currentStatus.isTracking {
			let docName = currentStatus.trackingDocument.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "Session"
			header.title = "● Tracking: \(docName) (\(currentStatus.keystrokeCount) keystrokes)"
		} else {
			header.title = "○ Ready to Track"
		}
		header.isEnabled = false
		menu.addItem(header)
		menu.addItem(.separator())

		if currentStatus.isTracking {
			// Show stop option when tracking
			menu.addItem(makeMenuItem(
				title: "Stop Tracking",
				systemImage: "stop.fill",
				action: #selector(quickStopTracking),
				keyEquivalent: ""
			))

			menu.addItem(makeMenuItem(
				title: "Create Checkpoint Now",
				systemImage: "checkmark.circle",
				action: #selector(createCheckpointNow),
				keyEquivalent: ""
			))
		} else {
			// Show start options when not tracking
			menu.addItem(makeMenuItem(
				title: "▶ Start Global Tracking",
				systemImage: "keyboard",
				action: #selector(startGlobalTracking),
				keyEquivalent: "g"
			))

			menu.addItem(makeMenuItem(
				title: "Start Tracking Document…",
				systemImage: "doc",
				action: #selector(quickStartTracking),
				keyEquivalent: ""
			))
		}

		menu.addItem(.separator())

		menu.addItem(makeMenuItem(
			title: "View Details…",
			systemImage: "info.circle",
			action: #selector(showDetails),
			keyEquivalent: ""
		))

		menu.addItem(makeMenuItem(
			title: "Settings…",
			systemImage: "gear",
			action: #selector(openSettings),
			keyEquivalent: ","
		))

		menu.addItem(.separator())

		menu.addItem(makeMenuItem(
			title: "Quit Witnessd",
			systemImage: nil,
			action: #selector(quit),
			keyEquivalent: "q"
		))

		statusItem.menu = menu
		statusItem.button?.performClick(nil)
		statusItem.menu = nil
	}

	private func makeMenuItem(title: String,
							  systemImage: String?,
							  action: Selector,
							  keyEquivalent: String) -> NSMenuItem {
		let item = NSMenuItem(title: title, action: action, keyEquivalent: keyEquivalent)
		item.target = self
		if let systemImage {
			item.image = NSImage(systemSymbolName: systemImage, accessibilityDescription: nil)
		}
		return item
	}

	// MARK: - Quick Actions

	@objc private func startGlobalTracking() {
		// Start tracking with a default session file in the data directory
		// This allows tracking all keystrokes without specifying a document
		Task { @MainActor in
			let formatter = DateFormatter()
			formatter.dateFormat = "yyyy-MM-dd"
			let dateString = formatter.string(from: Date())
			let sessionFile = "\(bridge.dataDirectoryPath)/sessions/\(dateString)-session.md"

			// Ensure sessions directory exists
			let sessionsDir = "\(bridge.dataDirectoryPath)/sessions"
			do {
				try FileManager.default.createDirectory(
					atPath: sessionsDir,
					withIntermediateDirectories: true,
					attributes: nil
				)
			} catch {
				showError(title: "Failed to Start Tracking", message: "Could not create sessions directory: \(error.localizedDescription)")
				return
			}

			// Create the session file if it doesn't exist
			if !FileManager.default.fileExists(atPath: sessionFile) {
				let header = "# Writing Session - \(dateString)\n\nKeystroke tracking session.\n"
				do {
					try header.write(toFile: sessionFile, atomically: true, encoding: .utf8)
				} catch {
					showError(title: "Failed to Start Tracking", message: "Could not create session file: \(error.localizedDescription)")
					return
				}
			}

			let result = await bridge.startTracking(documentPath: sessionFile)
			if !result.success {
				showError(title: "Failed to Start Tracking", message: result.message ?? "The witnessd daemon could not start tracking. Check that the application has accessibility permissions.")
				return
			}

			await updateStatus()

			// Notify user
			NotificationManager.shared.send(
				title: "Global Tracking Started",
				body: "Witnessd is now tracking all keystrokes."
			)
		}
	}

	private func showError(title: String, message: String) {
		let alert = NSAlert()
		alert.messageText = title
		alert.informativeText = message
		alert.alertStyle = .warning
		alert.addButton(withTitle: "OK")
		alert.runModal()
	}

	@objc private func quickStartTracking() {
		let panel = NSOpenPanel()
		panel.canChooseFiles = true
		panel.canChooseDirectories = false
		panel.allowsMultipleSelection = false
		panel.message = "Select a document to track"
		panel.prompt = "Start Tracking"

		if panel.runModal() == .OK, let url = panel.url {
			Task { @MainActor in
				_ = await bridge.startTracking(documentPath: url.path)
				await updateStatus()
			}
		}
	}

	@objc private func quickStopTracking() {
		Task { @MainActor in
			// Create final checkpoint before stopping
			if let doc = currentStatus.trackingDocument {
				_ = await bridge.commit(filePath: doc, message: "Session ended")
			}
			_ = await bridge.stopTracking()
			await updateStatus()

			NotificationManager.shared.send(
				title: "Tracking Stopped",
				body: "Your keystroke session has been saved."
			)
		}
	}

	@objc private func createCheckpointNow() {
		Task { @MainActor in
			guard let doc = currentStatus.trackingDocument else { return }
			let formatter = DateFormatter()
			formatter.dateFormat = "HH:mm"
			let timeString = formatter.string(from: Date())
			let result = await bridge.commit(filePath: doc, message: "Manual checkpoint at \(timeString)")
			if result.success {
				NotificationManager.shared.send(
					title: "Checkpoint Created",
					body: "Your progress has been saved."
				)
			}
		}
	}

	@objc private func showDetails() {
		togglePopover(nil)
	}

	@objc private func openSettings() {
		if #available(macOS 14.0, *) {
			NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
		} else {
			NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
		}
		NSApp.activate(ignoringOtherApps: true)
	}

	@objc private func quit() {
		Task { @MainActor in
			if currentStatus.isTracking {
				_ = await bridge.stopTracking()
			}
			shutdown()
			NSApp.terminate(nil)
		}
	}
	
	@MainActor
	func shutdown() {
		if let globalMonitor { NSEvent.removeMonitor(globalMonitor) }
		if let localMonitor { NSEvent.removeMonitor(localMonitor) }
		globalMonitor = nil
		localMonitor = nil

		statusTimer?.invalidate()
		statusTimer = nil

		// Clean up auto-checkpoint timer
		autoCheckpointTimer?.invalidate()
		autoCheckpointTimer = nil

		// Remove settings observer
		if let observer = settingsObserver {
			NotificationCenter.default.removeObserver(observer)
			settingsObserver = nil
		}
	}


}
