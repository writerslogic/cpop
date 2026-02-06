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

	private func startStatusUpdates() {
		Task { @MainActor [weak self] in
			await self?.updateStatus()
		}
		
		statusTimer?.invalidate()
		statusTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
			Task { @MainActor in
				await self?.updateStatus()
			}
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
		guard let event = NSApp.currentEvent else {
			togglePopover(sender)
			return
		}
		if event.type == .rightMouseUp {
			showContextMenu()
		} else {
			togglePopover(sender)
		}
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

		let header = NSMenuItem()
		header.title = currentStatus.isTracking ? "● Tracking Active" : "○ Ready"
		header.isEnabled = false
		menu.addItem(header)
		menu.addItem(.separator())

		if currentStatus.isTracking {
			menu.addItem(makeMenuItem(
				title: "Stop Tracking",
				systemImage: "stop.fill",
				action: #selector(quickStopTracking),
				keyEquivalent: ""
			))
		} else {
			menu.addItem(makeMenuItem(
				title: "Start Tracking…",
				systemImage: "play.fill",
				action: #selector(quickStartTracking),
				keyEquivalent: ""
			))
		}

		menu.addItem(.separator())

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

	@objc private func quickStartTracking() {
		guard let window = statusItem.button?.window else {
			// fallback: if no window, just do blocking modal
			startTrackingWithModalPanel()
			return
		}

		let panel = NSOpenPanel()
		panel.canChooseFiles = true
		panel.canChooseDirectories = false
		panel.allowsMultipleSelection = false
		panel.message = "Select a document to track"
		panel.prompt = "Start Tracking"

		panel.beginSheetModal(for: window) { [weak self] response in
			guard let self else { return }
			guard response == .OK, let url = panel.url else { return }
			Task { @MainActor in
				_ = await self.bridge.startTracking(documentPath: url.path)
				await self.updateStatus()
			}
		}
	}

	private func startTrackingWithModalPanel() {
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
			_ = await bridge.stopTracking()
			await updateStatus()
		}
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
