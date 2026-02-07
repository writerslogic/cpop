// WitnessdIMEApp.swift
// Main Application entry point for the Witnessd Input Method
//
// This file provides a Swift-based application wrapper that handles:
// - Status bar menu integration
// - Preferences window
// - First-run onboarding
// - XPC connection status monitoring

import Cocoa
import InputMethodKit
import os.log

// MARK: - Logging

private let logger = Logger(subsystem: "com.witnessd.inputmethod", category: "App")

// MARK: - Application Delegate

// Note: Entry point is handled by main.m (Objective-C)
// This class is instantiated by the IMKServer, not as the main app delegate
class WitnessdIMEAppDelegate: NSObject, NSApplicationDelegate {

    // MARK: - Properties

    /// The IMKServer instance - must be kept alive
    private var imkServer: IMKServer?

    /// Status bar item for menu bar presence
    private var statusItem: NSStatusItem?

    /// Preferences window controller
    private var preferencesWindowController: NSWindowController?

    /// Onboarding window controller
    private var onboardingWindowController: NSWindowController?

    /// User defaults keys
    private enum DefaultsKeys {
        static let hasCompletedOnboarding = "hasCompletedOnboarding"
        static let showStatusBarIcon = "showStatusBarIcon"
        static let enableNotifications = "enableNotifications"
        static let autoStartSession = "autoStartSession"
    }

    /// Session state
    private var isSessionActive = false
    private var currentSampleCount = 0

    // MARK: - Application Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        logger.info("Witnessd IME starting up")

        // Register default preferences
        registerDefaults()

        // Start the Input Method server
        guard startIMKServer() else {
            logger.error("Failed to start IMKServer - exiting")
            NSApp.terminate(nil)
            return
        }

        // Set up status bar if enabled
        if UserDefaults.standard.bool(forKey: DefaultsKeys.showStatusBarIcon) {
            setupStatusBar()
        }

        // Show onboarding if first launch
        if !UserDefaults.standard.bool(forKey: DefaultsKeys.hasCompletedOnboarding) {
            showOnboarding()
        }

        // Start periodic status updates
        startStatusUpdateTimer()

        logger.info("Witnessd IME started successfully")
    }

    func applicationWillTerminate(_ notification: Notification) {
        logger.info("Witnessd IME shutting down")

        // Clean up the status bar item
        if let statusItem = statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
    }

    // MARK: - IMKServer Setup

    private func startIMKServer() -> Bool {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            logger.error("No bundle identifier found")
            return false
        }

        let connectionName = "\(bundleID)_Connection"

        logger.info("Creating IMKServer with connection: \(connectionName, privacy: .public)")

        imkServer = IMKServer(name: connectionName, bundleIdentifier: bundleID)

        guard imkServer != nil else {
            logger.error("Failed to create IMKServer")
            return false
        }

        return true
    }

    // MARK: - Default Preferences

    private func registerDefaults() {
        UserDefaults.standard.register(defaults: [
            DefaultsKeys.hasCompletedOnboarding: false,
            DefaultsKeys.showStatusBarIcon: true,
            DefaultsKeys.enableNotifications: true,
            DefaultsKeys.autoStartSession: true
        ])
    }

    // MARK: - Status Bar

    private func setupStatusBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "keyboard", accessibilityDescription: "Witnessd")
            button.image?.isTemplate = true
        }

        statusItem?.menu = createStatusMenu()
    }

    private func createStatusMenu() -> NSMenu {
        let menu = NSMenu(title: "Witnessd")

        // Status section
        let statusItem = NSMenuItem(title: "Status: Idle", action: nil, keyEquivalent: "")
        statusItem.tag = 100 // For updating
        statusItem.isEnabled = false
        menu.addItem(statusItem)

        let samplesItem = NSMenuItem(title: "Samples: 0", action: nil, keyEquivalent: "")
        samplesItem.tag = 101 // For updating
        samplesItem.isEnabled = false
        menu.addItem(samplesItem)

        menu.addItem(NSMenuItem.separator())

        // Actions
        let startSessionItem = NSMenuItem(
            title: "Start Session",
            action: #selector(startSessionManually(_:)),
            keyEquivalent: ""
        )
        startSessionItem.target = self
        startSessionItem.tag = 200
        menu.addItem(startSessionItem)

        let endSessionItem = NSMenuItem(
            title: "End Session",
            action: #selector(endSessionManually(_:)),
            keyEquivalent: ""
        )
        endSessionItem.target = self
        endSessionItem.tag = 201
        endSessionItem.isEnabled = false
        menu.addItem(endSessionItem)

        menu.addItem(NSMenuItem.separator())

        // Preferences
        let preferencesItem = NSMenuItem(
            title: "Preferences...",
            action: #selector(showPreferences(_:)),
            keyEquivalent: ","
        )
        preferencesItem.target = self
        menu.addItem(preferencesItem)

        menu.addItem(NSMenuItem.separator())

        // About
        let aboutItem = NSMenuItem(
            title: "About Witnessd",
            action: #selector(showAbout(_:)),
            keyEquivalent: ""
        )
        aboutItem.target = self
        menu.addItem(aboutItem)

        return menu
    }

    private func updateStatusMenu() {
        guard let menu = statusItem?.menu else { return }

        // Update status item
        if let statusMenuItem = menu.item(withTag: 100) {
            statusMenuItem.title = isSessionActive ? "Status: Recording" : "Status: Idle"
        }

        // Update samples count
        if let samplesMenuItem = menu.item(withTag: 101) {
            samplesMenuItem.title = "Samples: \(currentSampleCount)"
        }

        // Update action buttons
        if let startItem = menu.item(withTag: 200),
           let endItem = menu.item(withTag: 201) {
            startItem.isEnabled = !isSessionActive
            endItem.isEnabled = isSessionActive
        }
    }

    // MARK: - Status Updates

    private func startStatusUpdateTimer() {
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.updateSessionStatus()
        }
    }

    private func updateSessionStatus() {
        // In the real implementation, this would query the XPC service
        // For now, we use the Go library directly
        // This is called from the timer to update the UI

        DispatchQueue.main.async { [weak self] in
            self?.updateStatusMenu()
        }
    }

    // MARK: - Actions

    @objc private func startSessionManually(_ sender: Any?) {
        logger.info("Starting session manually")
        // Implementation would call through XPC or directly to Go
        isSessionActive = true
        updateStatusMenu()
    }

    @objc private func endSessionManually(_ sender: Any?) {
        logger.info("Ending session manually")
        // Implementation would call through XPC or directly to Go
        isSessionActive = false
        currentSampleCount = 0
        updateStatusMenu()

        // Show evidence summary
        showSessionSummary()
    }

    @objc private func showPreferences(_ sender: Any?) {
        if preferencesWindowController == nil {
            let window = PreferencesWindow()
            preferencesWindowController = NSWindowController(window: window)
        }
        preferencesWindowController?.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func showAbout(_ sender: Any?) {
        NSApp.orderFrontStandardAboutPanel(nil)
    }

    // MARK: - Onboarding

    private func showOnboarding() {
        if onboardingWindowController == nil {
            let window = OnboardingWindow()
            window.onComplete = { [weak self] in
                UserDefaults.standard.set(true, forKey: DefaultsKeys.hasCompletedOnboarding)
                self?.onboardingWindowController?.close()
                self?.onboardingWindowController = nil
            }
            onboardingWindowController = NSWindowController(window: window)
        }
        onboardingWindowController?.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Session Summary

    private func showSessionSummary() {
        let alert = NSAlert()
        alert.messageText = "Session Ended"
        alert.informativeText = "Your typing session has been recorded. Evidence has been saved locally."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

// MARK: - Preferences Window

class PreferencesWindow: NSWindow {

    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 300),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )

        title = "Witnessd Preferences"
        center()

        setupContent()
    }

    private func setupContent() {
        let contentView = NSView(frame: contentRect(forFrameRect: frame))

        // Show status bar checkbox
        let statusBarCheckbox = NSButton(checkboxWithTitle: "Show status bar icon", target: self, action: #selector(toggleStatusBar(_:)))
        statusBarCheckbox.state = UserDefaults.standard.bool(forKey: "showStatusBarIcon") ? .on : .off
        statusBarCheckbox.frame = NSRect(x: 20, y: 240, width: 360, height: 20)
        contentView.addSubview(statusBarCheckbox)

        // Enable notifications checkbox
        let notificationsCheckbox = NSButton(checkboxWithTitle: "Enable session notifications", target: self, action: #selector(toggleNotifications(_:)))
        notificationsCheckbox.state = UserDefaults.standard.bool(forKey: "enableNotifications") ? .on : .off
        notificationsCheckbox.frame = NSRect(x: 20, y: 210, width: 360, height: 20)
        contentView.addSubview(notificationsCheckbox)

        // Auto start session checkbox
        let autoStartCheckbox = NSButton(checkboxWithTitle: "Automatically start session when typing", target: self, action: #selector(toggleAutoStart(_:)))
        autoStartCheckbox.state = UserDefaults.standard.bool(forKey: "autoStartSession") ? .on : .off
        autoStartCheckbox.frame = NSRect(x: 20, y: 180, width: 360, height: 20)
        contentView.addSubview(autoStartCheckbox)

        // Separator
        let separator = NSBox(frame: NSRect(x: 20, y: 140, width: 360, height: 1))
        separator.boxType = .separator
        contentView.addSubview(separator)

        // Data location label
        let dataLabel = NSTextField(labelWithString: "Evidence data location:")
        dataLabel.frame = NSRect(x: 20, y: 100, width: 360, height: 20)
        contentView.addSubview(dataLabel)

        let dataPath = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Witnessd")
            .path ?? "Unknown"

        let pathLabel = NSTextField(labelWithString: dataPath)
        pathLabel.frame = NSRect(x: 20, y: 75, width: 360, height: 20)
        pathLabel.textColor = .secondaryLabelColor
        pathLabel.font = .systemFont(ofSize: 11)
        contentView.addSubview(pathLabel)

        // Open folder button
        let openButton = NSButton(title: "Open in Finder", target: self, action: #selector(openDataFolder(_:)))
        openButton.frame = NSRect(x: 20, y: 40, width: 120, height: 24)
        contentView.addSubview(openButton)

        self.contentView = contentView
    }

    @objc private func toggleStatusBar(_ sender: NSButton) {
        UserDefaults.standard.set(sender.state == .on, forKey: "showStatusBarIcon")
    }

    @objc private func toggleNotifications(_ sender: NSButton) {
        UserDefaults.standard.set(sender.state == .on, forKey: "enableNotifications")
    }

    @objc private func toggleAutoStart(_ sender: NSButton) {
        UserDefaults.standard.set(sender.state == .on, forKey: "autoStartSession")
    }

    @objc private func openDataFolder(_ sender: Any?) {
        if let dataURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Witnessd") {
            NSWorkspace.shared.open(dataURL)
        }
    }
}

// MARK: - Onboarding Window

class OnboardingWindow: NSWindow {

    var onComplete: (() -> Void)?
    private var currentPage = 0
    private var pageView: NSView?

    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 400),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )

        title = "Welcome to Witnessd"
        center()

        setupContent()
    }

    private func setupContent() {
        showPage(0)
    }

    private func showPage(_ page: Int) {
        currentPage = page

        let contentView = NSView(frame: contentRect(forFrameRect: frame))

        switch page {
        case 0:
            // Welcome page
            let titleLabel = NSTextField(labelWithString: "Welcome to Witnessd")
            titleLabel.font = .boldSystemFont(ofSize: 24)
            titleLabel.frame = NSRect(x: 50, y: 320, width: 400, height: 30)
            contentView.addSubview(titleLabel)

            let descLabel = NSTextField(wrappingLabelWithString: """
                Witnessd creates cryptographic proof of your original authorship by recording your unique typing patterns.

                As you type, Witnessd captures the rhythm and timing of your keystrokes - creating unforgeable evidence that you authored your work.

                Your keystroke data is stored securely on your device and is never transmitted anywhere.
                """)
            descLabel.frame = NSRect(x: 50, y: 140, width: 400, height: 160)
            contentView.addSubview(descLabel)

        case 1:
            // How it works
            let titleLabel = NSTextField(labelWithString: "How It Works")
            titleLabel.font = .boldSystemFont(ofSize: 24)
            titleLabel.frame = NSRect(x: 50, y: 320, width: 400, height: 30)
            contentView.addSubview(titleLabel)

            let descLabel = NSTextField(wrappingLabelWithString: """
                1. Select Witnessd as your input method when writing important content

                2. Type naturally - Witnessd records timing patterns in the background

                3. When finished, your evidence file is automatically saved

                4. Use the evidence to prove you authored your work

                Witnessd never records WHAT you type - only WHEN and HOW you type.
                """)
            descLabel.frame = NSRect(x: 50, y: 120, width: 400, height: 180)
            contentView.addSubview(descLabel)

        case 2:
            // Enable input method
            let titleLabel = NSTextField(labelWithString: "Enable Witnessd")
            titleLabel.font = .boldSystemFont(ofSize: 24)
            titleLabel.frame = NSRect(x: 50, y: 320, width: 400, height: 30)
            contentView.addSubview(titleLabel)

            let descLabel = NSTextField(wrappingLabelWithString: """
                To use Witnessd, you need to add it to your input sources:

                1. Open System Settings
                2. Go to Keyboard > Input Sources
                3. Click the + button
                4. Find "Witnessd" under English
                5. Add it to your input sources

                Then select Witnessd from the input menu in your menu bar when you want to record your typing.
                """)
            descLabel.frame = NSRect(x: 50, y: 100, width: 400, height: 200)
            contentView.addSubview(descLabel)

            let openSettingsButton = NSButton(title: "Open Keyboard Settings", target: self, action: #selector(openKeyboardSettings(_:)))
            openSettingsButton.frame = NSRect(x: 50, y: 60, width: 180, height: 30)
            contentView.addSubview(openSettingsButton)

        default:
            break
        }

        // Navigation buttons
        let prevButton = NSButton(title: "Previous", target: self, action: #selector(previousPage(_:)))
        prevButton.frame = NSRect(x: 50, y: 20, width: 100, height: 30)
        prevButton.isHidden = page == 0
        contentView.addSubview(prevButton)

        let nextTitle = page == 2 ? "Get Started" : "Next"
        let nextButton = NSButton(title: nextTitle, target: self, action: #selector(nextPage(_:)))
        nextButton.frame = NSRect(x: 350, y: 20, width: 100, height: 30)
        nextButton.keyEquivalent = "\r"
        contentView.addSubview(nextButton)

        self.contentView = contentView
    }

    @objc private func previousPage(_ sender: Any?) {
        if currentPage > 0 {
            showPage(currentPage - 1)
        }
    }

    @objc private func nextPage(_ sender: Any?) {
        if currentPage < 2 {
            showPage(currentPage + 1)
        } else {
            onComplete?()
        }
    }

    @objc private func openKeyboardSettings(_ sender: Any?) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.keyboard?InputSources") {
            NSWorkspace.shared.open(url)
        }
    }
}
