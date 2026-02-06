import SwiftUI

// MARK: - Export Tier

enum ExportTier: String, CaseIterable, Identifiable {
    case basic, standard, enhanced, maximum

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .basic: return "Basic"
        case .standard: return "Standard"
        case .enhanced: return "Enhanced"
        case .maximum: return "Maximum"
        }
    }

    var description: String {
        switch self {
        case .basic: return "Checkpoint chain + VDF proofs only"
        case .standard: return "Includes keystroke evidence"
        case .enhanced: return "Adds TPM attestation"
        case .maximum: return "All available evidence"
        }
    }

    var icon: String {
        switch self {
        case .basic: return "lock"
        case .standard: return "lock.shield"
        case .enhanced: return "lock.shield.fill"
        case .maximum: return "checkmark.shield.fill"
        }
    }
}

// MARK: - Export Tier Sheet

struct ExportTierSheet: View {
    @Binding var selectedTier: ExportTier
    let onExport: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            // Header
            VStack(spacing: Design.Spacing.xs) {
                Image(systemName: "square.and.arrow.up")
                    .font(.system(size: Design.IconSize.xl))
                    .foregroundStyle(Design.Colors.brandGradient)

                Text("Select Export Tier")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                Text("Choose the level of evidence to include")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
            .padding(.top, Design.Spacing.md)

            // Tier options
            VStack(spacing: Design.Spacing.sm) {
                ForEach(ExportTier.allCases) { tier in
                    ExportTierRow(
                        tier: tier,
                        isSelected: selectedTier == tier,
                        onSelect: { selectedTier = tier }
                    )
                }
            }
            .padding(.horizontal, Design.Spacing.md)

            Spacer()

            // Buttons
            HStack(spacing: Design.Spacing.md) {
                Button("Cancel") {
                    onCancel()
                }
                .buttonStyle(.bordered)
                .keyboardShortcut(.cancelAction)

                Button("Export") {
                    onExport()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
            .padding(.bottom, Design.Spacing.md)
        }
        .frame(width: 300, height: 380)
        .background(Design.Colors.background)
    }
}

struct ExportTierRow: View {
    let tier: ExportTier
    let isSelected: Bool
    let onSelect: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: Design.Spacing.md) {
                // Radio indicator
                ZStack {
                    Circle()
                        .strokeBorder(isSelected ? Color.accentColor : Design.Colors.separator, lineWidth: 2)
                        .frame(width: 20, height: 20)

                    if isSelected {
                        Circle()
                            .fill(Color.accentColor)
                            .frame(width: 12, height: 12)
                    }
                }

                // Icon
                Image(systemName: tier.icon)
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(isSelected ? .accentColor : Design.Colors.secondaryText)
                    .frame(width: Design.IconSize.lg)

                // Text
                VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                    Text(tier.displayName)
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(isSelected ? Design.Colors.primaryText : Design.Colors.secondaryText)

                    Text(tier.description)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                        .lineLimit(1)
                }

                Spacer()
            }
            .padding(Design.Spacing.md)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .fill(isSelected ? Color.accentColor.opacity(0.1) : (isHovered ? Design.Colors.hover : Design.Colors.secondaryBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(isSelected ? Color.accentColor : Design.Colors.separator, lineWidth: isSelected ? 1 : 0.5)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityLabel("\(tier.displayName) tier: \(tier.description)")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

// MARK: - Main Popover Content

struct PopoverContentView: View {
    let bridge: WitnessdBridge
    let closeAction: () -> Void

    @State private var status: WitnessStatus = WitnessStatus()
    @State private var isLoading = false
    @State private var showingAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""

    // Export tier selection state
    @State private var showingTierSheet = false
    @State private var selectedExportTier: ExportTier = .standard
    @State private var pendingExportSourceURL: URL? = nil
    @State private var pendingExportDestURL: URL? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        VStack(spacing: 0) {
            headerSection
            Divider()
            mainContent
            Divider()
            footerSection
        }
        .frame(width: Design.Layout.popoverWidth, height: Design.Layout.popoverHeight)
        .background(Design.Colors.background)
        .task {
            await refreshStatus()
        }
        .alert(alertTitle, isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
        .sheet(isPresented: $showingTierSheet) {
            ExportTierSheet(
                selectedTier: $selectedExportTier,
                onExport: {
                    showingTierSheet = false
                    performExport()
                },
                onCancel: {
                    showingTierSheet = false
                    pendingExportSourceURL = nil
                    pendingExportDestURL = nil
                }
            )
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: Design.Spacing.md) {
            // App icon with status
            ZStack(alignment: .bottomTrailing) {
                Image(systemName: status.isTracking ? "eye.circle.fill" : "eye.circle")
                    .font(.system(size: Design.IconSize.xl, weight: .medium))
                    .foregroundStyle(status.isTracking ? Design.Colors.brandGradient : LinearGradient(colors: [Design.Colors.secondaryText], startPoint: .top, endPoint: .bottom))

                if status.isTracking {
                    Circle()
                        .fill(Design.Colors.success)
                        .frame(width: 8, height: 8)
                        .overlay(
                            Circle()
                                .stroke(Design.Colors.background, lineWidth: 2)
                        )
                        .offset(x: 2, y: 2)
                }
            }
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text("Witnessd")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                HStack(spacing: Design.Spacing.xs) {
                    if status.isTracking {
                        statusPill(text: "Tracking", style: .success)
                    } else if status.isInitialized {
                        statusPill(text: "Ready", style: .neutral)
                    } else {
                        statusPill(text: "Setup Required", style: .warning)
                    }
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Witnessd, \(headerSubtitle)")

            Spacer()

            if isLoading {
                ProgressView()
                    .scaleEffect(0.7)
                    .frame(width: 20, height: 20)
            }

            IconButton(icon: "arrow.clockwise", label: "Refresh") {
                Task { await refreshStatus() }
            }
        }
        .padding(Design.Spacing.lg)
        .background(Design.Colors.secondaryBackground)
    }

    private func statusPill(text: String, style: Badge.BadgeStyle) -> some View {
        HStack(spacing: Design.Spacing.xxs) {
            if differentiateWithoutColor {
                Image(systemName: style == .success ? "checkmark.circle.fill" : style == .warning ? "exclamationmark.triangle.fill" : "circle.fill")
                    .font(.system(size: 8))
            } else {
                Circle()
                    .fill(style == .success ? Design.Colors.success : style == .warning ? Design.Colors.warning : Design.Colors.secondaryText)
                    .frame(width: 6, height: 6)
            }
            Text(text)
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.secondaryText)
        }
        .padding(.horizontal, Design.Spacing.sm)
        .padding(.vertical, Design.Spacing.xxs)
        .background(
            Capsule()
                .fill(Design.Colors.secondaryBackground)
                .overlay(
                    Capsule()
                        .strokeBorder(Design.Colors.separator, lineWidth: 0.5)
                )
        )
    }

    private var headerSubtitle: String {
        if status.isTracking { return "Tracking Active" }
        else if status.isInitialized { return "Ready" }
        else { return "Setup Required" }
    }

    // MARK: - Main Content

    private var mainContent: some View {
        ScrollView {
            VStack(spacing: Design.Spacing.lg) {
                if !status.isInitialized {
                    setupRequiredSection
                } else {
                    trackingSection
                    quickActionsSection
                    systemStatusSection
                }
            }
            .padding(Design.Spacing.lg)
        }
    }

    // MARK: - Setup Required

    private var setupRequiredSection: some View {
        VStack(spacing: Design.Spacing.xl) {
            Spacer(minLength: Design.Spacing.xl)

            Image(systemName: "wand.and.stars")
                .font(.system(size: Design.IconSize.hero))
                .foregroundStyle(Design.Colors.brandGradient)

            VStack(spacing: Design.Spacing.sm) {
                Text("Welcome to Witnessd")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                Text("Set up Witnessd to start creating cryptographic proof of your authorship.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button(action: initializeWitness) {
                HStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "arrow.right.circle.fill")
                    Text("Get Started")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .accessibilityIdentifier("initialize-witness")

            Spacer(minLength: Design.Spacing.xl)
        }
        .padding(.horizontal, Design.Spacing.lg)
    }

    // MARK: - Tracking Section

    private var trackingSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("Tracking")

            if status.isTracking {
                activeTrackingCard
            } else {
                inactiveTrackingCard
            }
        }
    }

    private var activeTrackingCard: some View {
        VStack(spacing: Design.Spacing.md) {
            // Document info
            if let doc = status.trackingDocument {
                HStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "doc.text.fill")
                        .font(.system(size: Design.IconSize.sm))
                        .foregroundColor(.accentColor)

                    Text(URL(fileURLWithPath: doc).lastPathComponent)
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(Design.Colors.primaryText)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Spacer()
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Tracking: \(URL(fileURLWithPath: doc).lastPathComponent)")
            }

            // Stats row
            HStack(spacing: Design.Spacing.lg) {
                StatWidget(
                    icon: "keyboard",
                    value: formatNumber(status.keystrokeCount),
                    label: "Keystrokes"
                )

                Divider()
                    .frame(height: 32)

                StatWidget(
                    icon: "clock",
                    value: status.trackingDuration.isEmpty ? "0:00" : status.trackingDuration,
                    label: "Duration"
                )

                Spacer()
            }

            // Stop button
            Button(action: stopTracking) {
                HStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "stop.fill")
                        .font(.system(size: 10))
                    Text("Stop Tracking")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(.red)
            .accessibilityIdentifier("stop-tracking")
        }
        .cardStyle()
    }

    private var inactiveTrackingCard: some View {
        VStack(spacing: Design.Spacing.md) {
            HStack {
                Image(systemName: "doc.badge.plus")
                    .font(.system(size: Design.IconSize.lg))
                    .foregroundColor(Design.Colors.tertiaryText)

                Text("No active session")
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.secondaryText)

                Spacer()
            }

            CompactDropZone(placeholder: "Drop file to start tracking") { url in
                startTrackingWithFile(url)
            }
            .accessibilityIdentifier("start-tracking-drop-zone")
        }
        .cardStyle()
    }

    private func startTrackingWithFile(_ url: URL) {
        Task {
            isLoading = true
            let result = await bridge.startTracking(documentPath: url.path)
            isLoading = false

            if !result.success {
                showAlert(title: "Error", message: result.message)
            }
            await refreshStatus()
        }
    }

    private func formatNumber(_ n: Int) -> String {
        if n >= 1000 {
            return String(format: "%.1fk", Double(n) / 1000.0)
        }
        return "\(n)"
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("Quick Actions")

            HStack(spacing: Design.Spacing.sm) {
                QuickActionButton(
                    icon: "checkmark.circle",
                    label: "Checkpoint",
                    action: createCheckpoint
                )

                QuickActionButton(
                    icon: "square.and.arrow.up",
                    label: "Export",
                    action: exportEvidence
                )

                QuickActionButton(
                    icon: "checkmark.shield",
                    label: "Verify",
                    action: verifyEvidence
                )

                QuickActionButton(
                    icon: "clock.arrow.circlepath",
                    label: "History",
                    action: viewHistory
                )
            }
        }
    }

    // MARK: - System Status

    private var systemStatusSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("System")

            VStack(spacing: Design.Spacing.xxs) {
                SystemStatusRow(
                    icon: "speedometer",
                    title: "VDF",
                    value: status.vdfCalibrated ? "Calibrated" : "Not calibrated",
                    isGood: status.vdfCalibrated,
                    action: status.vdfCalibrated ? nil : calibrateVDF
                )

                SystemStatusRow(
                    icon: "cpu",
                    title: "TPM",
                    value: status.tpmAvailable ? "Available" : "Unavailable",
                    isGood: status.tpmAvailable,
                    action: nil
                )

                SystemStatusRow(
                    icon: "cylinder.split.1x2",
                    title: "Database",
                    value: "\(status.databaseEvents) events",
                    isGood: true,
                    action: nil
                )
            }
            .cardStyle(padding: Design.Spacing.sm)
        }
    }

    // MARK: - Footer

    private var footerSection: some View {
        HStack {
            IconButton(icon: "gear", label: "Settings", size: Design.IconSize.sm) {
                openSettings()
            }

            Spacer()

            Text("v1.0")
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.tertiaryText)

            Spacer()

            IconButton(icon: "questionmark.circle", label: "Help", size: Design.IconSize.sm) {
                showHelp()
            }
        }
        .padding(.horizontal, Design.Spacing.lg)
        .padding(.vertical, Design.Spacing.md)
        .background(Design.Colors.secondaryBackground)
    }

    // MARK: - Actions

    private func refreshStatus() async {
        isLoading = true
        status = await bridge.getStatus()
        isLoading = false
    }

    private func initializeWitness() {
        Task {
            isLoading = true
            let result = await bridge.initialize()
            isLoading = false

            if result.success {
                await refreshStatus()
                showAlert(title: "Initialized", message: "Witnessd is ready. Consider calibrating VDF for accurate timing proofs.")
            } else {
                showAlert(title: "Error", message: result.message)
            }
        }
    }

    private func startTracking() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Select a document to track"
        panel.prompt = "Start Tracking"

        if panel.runModal() == .OK, let url = panel.url {
            Task {
                isLoading = true
                let result = await bridge.startTracking(documentPath: url.path)
                isLoading = false

                if !result.success {
                    showAlert(title: "Error", message: result.message)
                }
                await refreshStatus()
            }
        }
    }

    private func stopTracking() {
        Task {
            isLoading = true
            let result = await bridge.stopTracking()
            isLoading = false

            if result.success {
                showAlert(title: "Tracking Stopped", message: result.message)
            } else {
                showAlert(title: "Error", message: result.message)
            }
            await refreshStatus()
        }
    }

    private func createCheckpoint() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.message = "Select a document to checkpoint"
        panel.prompt = "Create Checkpoint"

        if panel.runModal() == .OK, let url = panel.url {
            let alert = NSAlert()
            alert.messageText = "Checkpoint Message"
            alert.informativeText = "Enter an optional message for this checkpoint:"
            alert.addButton(withTitle: "Create")
            alert.addButton(withTitle: "Cancel")

            let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
            input.placeholderString = "Optional message..."
            alert.accessoryView = input

            if alert.runModal() == .alertFirstButtonReturn {
                Task {
                    isLoading = true
                    let result = await bridge.commit(filePath: url.path, message: input.stringValue)
                    isLoading = false

                    if result.success {
                        showAlert(title: "Checkpoint Created", message: result.message)
                    } else {
                        showAlert(title: "Error", message: result.message)
                    }
                }
            }
        }
    }

    private func exportEvidence() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.message = "Select a document to export evidence for"
        panel.prompt = "Select"

        if panel.runModal() == .OK, let url = panel.url {
            let savePanel = NSSavePanel()
            savePanel.nameFieldStringValue = url.deletingPathExtension().lastPathComponent + ".evidence.json"
            savePanel.allowedContentTypes = [.json]

            if savePanel.runModal() == .OK, let saveURL = savePanel.url {
                // Store URLs and show tier selection
                pendingExportSourceURL = url
                pendingExportDestURL = saveURL
                selectedExportTier = .standard
                showingTierSheet = true
            }
        }
    }

    private func performExport() {
        guard let sourceURL = pendingExportSourceURL,
              let destURL = pendingExportDestURL else {
            return
        }

        Task {
            isLoading = true
            let result = await bridge.export(filePath: sourceURL.path, tier: selectedExportTier.rawValue, outputPath: destURL.path)
            isLoading = false

            pendingExportSourceURL = nil
            pendingExportDestURL = nil

            if result.success {
                showAlert(title: "Evidence Exported", message: "Saved to: \(destURL.lastPathComponent)")
            } else {
                showAlert(title: "Error", message: result.message)
            }
        }
    }

    private func verifyEvidence() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.json]
        panel.message = "Select an evidence file to verify"
        panel.prompt = "Verify"

        if panel.runModal() == .OK, let url = panel.url {
            Task {
                isLoading = true
                let result = await bridge.verify(filePath: url.path)
                isLoading = false

                showAlert(
                    title: result.success ? "Verification Passed" : "Verification Failed",
                    message: result.message
                )
            }
        }
    }

    private func viewHistory() {
        closeAction()

        let historyWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Design.Layout.historyWidth, height: Design.Layout.historyHeight),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        historyWindow.title = "Tracked Documents"
        historyWindow.center()
        historyWindow.isReleasedWhenClosed = false
        historyWindow.minSize = NSSize(width: 500, height: 400)

        let historyView = HistoryView(
            bridge: bridge,
            closeAction: { [weak historyWindow] in
                historyWindow?.close()
            }
        )

        historyWindow.contentView = NSHostingView(rootView: historyView)
        historyWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func calibrateVDF() {
        Task {
            isLoading = true
            let result = await bridge.calibrate()
            isLoading = false

            if result.success {
                showAlert(title: "Calibration Complete", message: result.message)
                await refreshStatus()
            } else {
                showAlert(title: "Error", message: result.message)
            }
        }
    }

    private func openSettings() {
        if #available(macOS 14.0, *) {
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        } else {
            NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
        }
    }

    private func showHelp() {
        if let url = URL(string: "https://github.com/writerslogic/witnessd") {
            NSWorkspace.shared.open(url)
        }
    }

    private func showAlert(title: String, message: String) {
        alertTitle = title
        alertMessage = message
        showingAlert = true
    }
}

// MARK: - Supporting Components

struct StatWidget: View {
    let icon: String
    let value: String
    let label: String

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(Design.Colors.tertiaryText)
                .frame(width: Design.IconSize.lg)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 0) {
                Text(value)
                    .font(Design.Typography.statValue)
                    .foregroundColor(Design.Colors.primaryText)

                Text(label)
                    .font(Design.Typography.statLabel)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .textCase(.uppercase)
                    .tracking(0.3)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}

struct QuickActionButton: View {
    let icon: String
    let label: String
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: Design.Spacing.xs) {
                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.lg, weight: .medium))
                    .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)

                Text(label)
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, Design.Spacing.md)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .fill(isPressed ? Design.Colors.pressed : (isHovered ? Design.Colors.hover : Design.Colors.secondaryBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(Design.Colors.separator.opacity(0.5), lineWidth: 0.5)
            )
            .scaleEffect(isPressed ? 0.97 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .pressEvents { isPressed = true } onRelease: { isPressed = false }
        .accessibilityLabel(label)
        .accessibilityHint("Double-tap to \(label.lowercased())")
        .accessibilityIdentifier("action-\(label.lowercased())")
    }
}

struct SystemStatusRow: View {
    let icon: String
    let title: String
    let value: String
    let isGood: Bool
    let action: (() -> Void)?

    @State private var isHovered = false
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(Design.Colors.tertiaryText)
                .frame(width: Design.IconSize.lg)
                .accessibilityHidden(true)

            Text(title)
                .font(Design.Typography.bodyMedium)
                .foregroundColor(Design.Colors.primaryText)

            Spacer()

            if let action = action {
                Button(action: action) {
                    HStack(spacing: Design.Spacing.xxs) {
                        if differentiateWithoutColor {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 10))
                        }
                        Text(value)
                            .font(Design.Typography.labelMedium)
                    }
                    .foregroundColor(Design.Colors.warning)
                    .padding(.horizontal, Design.Spacing.sm)
                    .padding(.vertical, Design.Spacing.xxs)
                    .background(
                        Capsule()
                            .fill(Design.Colors.warning.opacity(0.1))
                    )
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(title): \(value)")
                .accessibilityHint("Double-tap to configure")
            } else {
                HStack(spacing: Design.Spacing.xs) {
                    if differentiateWithoutColor {
                        Image(systemName: isGood ? "checkmark.circle.fill" : "xmark.circle")
                            .font(.system(size: 10))
                            .foregroundColor(isGood ? Design.Colors.success : Design.Colors.tertiaryText)
                    } else {
                        Circle()
                            .fill(isGood ? Design.Colors.success : Design.Colors.tertiaryText.opacity(0.5))
                            .frame(width: 6, height: 6)
                    }

                    Text(value)
                        .font(Design.Typography.labelMedium)
                        .foregroundColor(Design.Colors.secondaryText)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(title): \(value)")
                .accessibilityValue(isGood ? "OK" : "")
            }
        }
        .padding(.vertical, Design.Spacing.xs)
        .padding(.horizontal, Design.Spacing.sm)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                .fill(isHovered ? Design.Colors.hover : Color.clear)
        )
        .onHover { isHovered = $0 }
        .accessibilityIdentifier("status-\(title.lowercased())")
    }
}
