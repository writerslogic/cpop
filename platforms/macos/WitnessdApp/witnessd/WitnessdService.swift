import Foundation
import SwiftUI
import Combine
import os.log

// MARK: - Session Model

/// Represents a tracked writing session
struct WritingSession: Identifiable, Hashable, Sendable {
    let id: String
    let documentPath: String
    let documentName: String
    var keystrokeCount: Int
    var checkpointCount: Int
    var startTime: Date
    var endTime: Date?
    var duration: TimeInterval
    var verificationStatus: VerificationStatus

    enum VerificationStatus: String, Sendable {
        case verified = "verified"
        case pending = "pending"
        case failed = "failed"
        case unknown = "unknown"
    }

    var formattedDuration: String {
        let hours = Int(duration) / 3600
        let minutes = Int(duration) / 60 % 60
        let seconds = Int(duration) % 60

        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, seconds)
        } else {
            return String(format: "%d:%02d", minutes, seconds)
        }
    }

    var isActive: Bool {
        endTime == nil
    }
}

// MARK: - Watch Path Model

/// Represents a configured watch path
struct WatchPath: Identifiable, Hashable, Codable {
    let id: UUID
    var path: String
    var isEnabled: Bool

    init(path: String, isEnabled: Bool = true) {
        self.id = UUID()
        self.path = path
        self.isEnabled = isEnabled
    }

    var displayName: String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    var exists: Bool {
        FileManager.default.fileExists(atPath: path)
    }
}

// MARK: - Settings Model

/// Application settings stored in UserDefaults
@Observable
final class WitnessdSettings {
    // MARK: - Watch Paths
    var watchPaths: [WatchPath] = [] {
        didSet { saveWatchPaths() }
    }

    // MARK: - Include Patterns
    var includePatterns: [String] = [".txt", ".md", ".rtf", ".doc", ".docx"] {
        didSet { UserDefaults.standard.set(includePatterns, forKey: "includePatterns") }
    }

    // MARK: - Debounce
    var debounceIntervalMs: Int = 500 {
        didSet { UserDefaults.standard.set(debounceIntervalMs, forKey: "debounceIntervalMs") }
    }

    // MARK: - Signing Key
    var signingKeyPath: String = "" {
        didSet { UserDefaults.standard.set(signingKeyPath, forKey: "signingKeyPath") }
    }

    // MARK: - TPM
    var tpmAttestationEnabled: Bool = false {
        didSet { UserDefaults.standard.set(tpmAttestationEnabled, forKey: "tpmAttestationEnabled") }
    }

    // MARK: - Checkpoint
    var autoCheckpoint: Bool = false {
        didSet { UserDefaults.standard.set(autoCheckpoint, forKey: "autoCheckpoint") }
    }

    var checkpointIntervalMinutes: Int = 30 {
        didSet { UserDefaults.standard.set(checkpointIntervalMinutes, forKey: "checkpointIntervalMinutes") }
    }

    // MARK: - Export
    var defaultExportFormat: String = "json" {
        didSet { UserDefaults.standard.set(defaultExportFormat, forKey: "defaultExportFormat") }
    }

    var defaultExportTier: String = "standard" {
        didSet { UserDefaults.standard.set(defaultExportTier, forKey: "defaultExportTier") }
    }

    // MARK: - Launch
    var openAtLogin: Bool = false {
        didSet {
            UserDefaults.standard.set(openAtLogin, forKey: "openAtLogin")
            LaunchAtLogin.isEnabled = openAtLogin
        }
    }

    // MARK: - Notifications
    var showNotifications: Bool = true {
        didSet { UserDefaults.standard.set(showNotifications, forKey: "showNotifications") }
    }

    init() {
        loadFromUserDefaults()
    }

    private func loadFromUserDefaults() {
        let defaults = UserDefaults.standard

        // Load watch paths
        if let data = defaults.data(forKey: "watchPaths"),
           let paths = try? JSONDecoder().decode([WatchPath].self, from: data) {
            watchPaths = paths
        }

        // Load include patterns
        if let patterns = defaults.array(forKey: "includePatterns") as? [String] {
            includePatterns = patterns
        }

        debounceIntervalMs = defaults.integer(forKey: "debounceIntervalMs")
        if debounceIntervalMs == 0 { debounceIntervalMs = 500 }

        signingKeyPath = defaults.string(forKey: "signingKeyPath") ?? ""
        tpmAttestationEnabled = defaults.bool(forKey: "tpmAttestationEnabled")
        autoCheckpoint = defaults.bool(forKey: "autoCheckpoint")

        checkpointIntervalMinutes = defaults.integer(forKey: "checkpointIntervalMinutes")
        if checkpointIntervalMinutes == 0 { checkpointIntervalMinutes = 30 }

        defaultExportFormat = defaults.string(forKey: "defaultExportFormat") ?? "json"
        defaultExportTier = defaults.string(forKey: "defaultExportTier") ?? "standard"
        openAtLogin = defaults.bool(forKey: "openAtLogin")
        showNotifications = defaults.bool(forKey: "showNotifications")
    }

    private func saveWatchPaths() {
        if let data = try? JSONEncoder().encode(watchPaths) {
            UserDefaults.standard.set(data, forKey: "watchPaths")
        }
    }

    func addWatchPath(_ path: String) {
        guard !watchPaths.contains(where: { $0.path == path }) else { return }
        watchPaths.append(WatchPath(path: path))
    }

    func removeWatchPath(_ id: UUID) {
        watchPaths.removeAll { $0.id == id }
    }

    func toggleWatchPath(_ id: UUID) {
        if let index = watchPaths.firstIndex(where: { $0.id == id }) {
            watchPaths[index].isEnabled.toggle()
        }
    }

    func addIncludePattern(_ pattern: String) {
        let normalized = pattern.hasPrefix(".") ? pattern : ".\(pattern)"
        guard !includePatterns.contains(normalized) else { return }
        includePatterns.append(normalized)
    }

    func removeIncludePattern(_ pattern: String) {
        includePatterns.removeAll { $0 == pattern }
    }
}

// MARK: - Main Service

/// Central service managing all Witnessd state and communication
@MainActor
@Observable
final class WitnessdService {
    // MARK: - Singleton
    static let shared = WitnessdService()

    // MARK: - Dependencies
    let bridge: WitnessdBridge
    let settings: WitnessdSettings

    // MARK: - Status State
    var status: WitnessStatus = WitnessStatus()
    var isLoading: Bool = false
    var loadingMessage: String = ""
    var lastError: String? = nil

    // MARK: - Session State
    var sessions: [WritingSession] = []
    var currentSession: WritingSession? = nil

    // MARK: - Computed Properties
    var isInitialized: Bool { status.isInitialized }
    var isTracking: Bool { status.isTracking }
    var keystrokeCount: Int { status.keystrokeCount }
    var trackingDuration: String { status.trackingDuration }
    var trackingDocument: String? { status.trackingDocument }
    var vdfCalibrated: Bool { status.vdfCalibrated }
    var tpmAvailable: Bool { status.tpmAvailable }

    // MARK: - Private
    private let logger = Logger(subsystem: "com.witnessd.app", category: "service")
    private var statusTimer: Timer?
    private var keystrokeAnimationValue: Int = 0

    // MARK: - Animation State (for keystroke counter)
    var displayedKeystrokeCount: Int = 0
    var keystrokePulse: Bool = false

    // MARK: - Initialization

    private init() {
        self.bridge = WitnessdBridge()
        self.settings = WitnessdSettings()

        // Start status polling
        startStatusPolling()
    }

    // MARK: - Status Polling

    private func startStatusPolling() {
        // Initial fetch
        Task {
            await refreshStatus()
        }

        // Set up timer for regular updates
        statusTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshStatus()
            }
        }
    }

    func refreshStatus() async {
        let newStatus = await bridge.getStatus()

        // Animate keystroke count changes
        let previousCount = status.keystrokeCount
        status = newStatus

        if newStatus.keystrokeCount > previousCount {
            // Trigger pulse animation
            keystrokePulse = true

            // Animate count up
            animateKeystrokeCount(from: previousCount, to: newStatus.keystrokeCount)
        } else {
            displayedKeystrokeCount = newStatus.keystrokeCount
        }

        // Update current session if tracking
        if newStatus.isTracking, let doc = newStatus.trackingDocument {
            if currentSession?.documentPath != doc {
                // New session started
                currentSession = WritingSession(
                    id: UUID().uuidString,
                    documentPath: doc,
                    documentName: URL(fileURLWithPath: doc).lastPathComponent,
                    keystrokeCount: newStatus.keystrokeCount,
                    checkpointCount: 0,
                    startTime: Date(),
                    endTime: nil,
                    duration: 0,
                    verificationStatus: .pending
                )
            } else {
                // Update existing session
                currentSession?.keystrokeCount = newStatus.keystrokeCount
            }
        } else if currentSession != nil && !newStatus.isTracking {
            // Session ended
            currentSession?.endTime = Date()
            if let session = currentSession {
                sessions.insert(session, at: 0)
            }
            currentSession = nil
        }

        // Reset pulse after animation
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            self.keystrokePulse = false
        }
    }

    private func animateKeystrokeCount(from: Int, to: Int) {
        let steps = min(10, to - from)
        let stepDelay = 0.03

        for i in 0..<steps {
            let progress = Double(i + 1) / Double(steps)
            let value = from + Int(Double(to - from) * progress)

            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * stepDelay) {
                self.displayedKeystrokeCount = value
            }
        }
    }

    // MARK: - Actions

    func initialize() async -> CommandResult {
        setLoading(true, message: "Creating keys...")
        let result = await bridge.initialize()
        setLoading(false)

        if result.success {
            await refreshStatus()
        } else {
            lastError = result.message
        }

        return result
    }

    func calibrate() async -> CommandResult {
        setLoading(true, message: "Calibrating VDF...")
        let result = await bridge.calibrate()
        setLoading(false)

        if result.success {
            await refreshStatus()
        } else {
            lastError = result.message
        }

        return result
    }

    func startTracking(documentPath: String) async -> CommandResult {
        setLoading(true, message: "Starting tracking...")
        let result = await bridge.startTracking(documentPath: documentPath)
        setLoading(false)

        if result.success {
            await refreshStatus()
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: documentPath).lastPathComponent
                NotificationManager.shared.notifyTrackingStarted(document: docName)
            }
        } else {
            lastError = result.message
        }

        return result
    }

    func stopTracking() async -> CommandResult {
        setLoading(true, message: "Stopping tracking...")

        // Create final checkpoint if tracking
        if let doc = status.trackingDocument {
            _ = await bridge.commit(filePath: doc, message: "Session ended")
        }

        let result = await bridge.stopTracking()
        setLoading(false)

        if result.success {
            if settings.showNotifications {
                NotificationManager.shared.notifyTrackingStopped(
                    keystrokes: status.keystrokeCount,
                    duration: status.trackingDuration
                )
            }
            await refreshStatus()
        } else {
            lastError = result.message
        }

        return result
    }

    func createCheckpoint(message: String = "") async -> CommandResult {
        guard let doc = status.trackingDocument else {
            return CommandResult(success: false, message: "No active tracking session", exitCode: 1)
        }

        setLoading(true, message: "Creating checkpoint...")
        let result = await bridge.commit(filePath: doc, message: message)
        setLoading(false)

        if result.success {
            currentSession?.checkpointCount += 1
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: doc).lastPathComponent
                NotificationManager.shared.notifyCheckpointCreated(
                    document: docName,
                    number: currentSession?.checkpointCount ?? 1
                )
            }
        } else {
            lastError = result.message
        }

        return result
    }

    func export(filePath: String, tier: String, outputPath: String) async -> CommandResult {
        setLoading(true, message: "Exporting evidence...")
        let result = await bridge.export(filePath: filePath, tier: tier, outputPath: outputPath)
        setLoading(false)

        if result.success {
            if settings.showNotifications {
                NotificationManager.shared.notifyEvidenceExported(path: outputPath)
            }
        } else {
            lastError = result.message
        }

        return result
    }

    func verify(filePath: String) async -> CommandResult {
        setLoading(true, message: "Verifying evidence...")
        let result = await bridge.verify(filePath: filePath)
        setLoading(false)

        if result.success {
            // Update verification status for matching session
            if let index = sessions.firstIndex(where: { $0.documentPath == filePath }) {
                sessions[index].verificationStatus = .verified
            }
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: filePath).lastPathComponent
                NotificationManager.shared.notifyVerificationResult(passed: true, document: docName)
            }
        } else {
            if let index = sessions.firstIndex(where: { $0.documentPath == filePath }) {
                sessions[index].verificationStatus = .failed
            }
            lastError = result.message
        }

        return result
    }

    func log(filePath: String) async -> CommandResult {
        return await bridge.log(filePath: filePath)
    }

    func listTrackedFiles() async -> [TrackedFile] {
        return await bridge.listTrackedFiles()
    }

    // MARK: - History Management

    func loadSessions() async {
        let files = await bridge.listTrackedFiles()

        // Convert TrackedFile to WritingSession
        sessions = files.map { file in
            WritingSession(
                id: file.id,
                documentPath: file.path,
                documentName: file.name,
                keystrokeCount: file.events,
                checkpointCount: 0,
                startTime: file.lastModified ?? Date(),
                endTime: file.lastModified,
                duration: 0,
                verificationStatus: .unknown
            )
        }
    }

    func filterSessions(searchText: String) -> [WritingSession] {
        guard !searchText.isEmpty else { return sessions }

        let lowercasedSearch = searchText.lowercased()
        return sessions.filter { session in
            session.documentName.lowercased().contains(lowercasedSearch) ||
            session.documentPath.lowercased().contains(lowercasedSearch)
        }
    }

    // MARK: - Private Helpers

    private func setLoading(_ loading: Bool, message: String = "") {
        isLoading = loading
        loadingMessage = loading ? message : ""
        if !loading {
            lastError = nil
        }
    }

    func clearError() {
        lastError = nil
    }
}

// MARK: - Environment Key

private struct WitnessdServiceKey: EnvironmentKey {
    static let defaultValue = WitnessdService.shared
}

extension EnvironmentValues {
    var witnessdService: WitnessdService {
        get { self[WitnessdServiceKey.self] }
        set { self[WitnessdServiceKey.self] = newValue }
    }
}
