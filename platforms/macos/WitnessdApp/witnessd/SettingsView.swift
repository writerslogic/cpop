import SwiftUI

struct SettingsView: View {
    @State private var service = WitnessdService.shared

    // Get data directory from Application Support
    private var dataDirectory: String {
        if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            return appSupport.appendingPathComponent("Witnessd").path
        }
        return "~/Library/Application Support/Witnessd"
    }

    var body: some View {
        TabView {
            generalTab
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            watchPathsTab
                .tabItem {
                    Label("Watch Paths", systemImage: "folder.badge.plus")
                }

            patternsTab
                .tabItem {
                    Label("Patterns", systemImage: "doc.text.magnifyingglass")
                }

            securityTab
                .tabItem {
                    Label("Security", systemImage: "lock.shield")
                }

            notificationsTab
                .tabItem {
                    Label("Notifications", systemImage: "bell")
                }

            advancedTab
                .tabItem {
                    Label("Advanced", systemImage: "gearshape.2")
                }
        }
        .frame(width: 560, height: 420)
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section {
                Toggle("Open Witnessd at Login", isOn: Binding(
                    get: { service.settings.openAtLogin },
                    set: { service.settings.openAtLogin = $0 }
                ))
                .accessibilityIdentifier("toggle-open-at-login")
                .accessibilityHint("Automatically start Witnessd when you log in")
            } header: {
                Label("Startup", systemImage: "power")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                Toggle("Auto-create checkpoints", isOn: Binding(
                    get: { service.settings.autoCheckpoint },
                    set: { service.settings.autoCheckpoint = $0 }
                ))
                .accessibilityIdentifier("toggle-auto-checkpoint")
                .accessibilityHint("Automatically save checkpoints at regular intervals")

                if service.settings.autoCheckpoint {
                    Picker("Interval", selection: Binding(
                        get: { service.settings.checkpointIntervalMinutes },
                        set: { service.settings.checkpointIntervalMinutes = $0 }
                    )) {
                        Text("5 minutes").tag(5)
                        Text("15 minutes").tag(15)
                        Text("30 minutes").tag(30)
                        Text("1 hour").tag(60)
                        Text("2 hours").tag(120)
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("picker-checkpoint-interval")
                }
            } header: {
                Label("Tracking", systemImage: "eye")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                VStack(alignment: .leading, spacing: Design.Spacing.sm) {
                    Text("Debounce Interval")
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(Design.Colors.primaryText)

                    HStack {
                        Slider(
                            value: Binding(
                                get: { Double(service.settings.debounceIntervalMs) },
                                set: { service.settings.debounceIntervalMs = Int($0) }
                            ),
                            in: 100...2000,
                            step: 100
                        )

                        Text("\(service.settings.debounceIntervalMs) ms")
                            .font(Design.Typography.mono)
                            .foregroundColor(Design.Colors.secondaryText)
                            .frame(width: 70, alignment: .trailing)
                    }

                    Text("How long to wait after the last keystroke before saving. Lower values capture more detail but use more resources.")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
            } header: {
                Label("Performance", systemImage: "speedometer")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Watch Paths Tab

    private var watchPathsTab: some View {
        Form {
            Section {
                if service.settings.watchPaths.isEmpty {
                    VStack(spacing: Design.Spacing.md) {
                        Image(systemName: "folder.badge.plus")
                            .font(.system(size: Design.IconSize.xxl))
                            .foregroundColor(Design.Colors.tertiaryText)

                        Text("No watch paths configured")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(Design.Colors.secondaryText)

                        Text("Add directories to automatically track documents when modified.")
                            .font(Design.Typography.bodySmall)
                            .foregroundColor(Design.Colors.tertiaryText)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Design.Spacing.xl)
                } else {
                    ForEach(service.settings.watchPaths) { watchPath in
                        WatchPathRow(
                            watchPath: watchPath,
                            onToggle: { service.settings.toggleWatchPath(watchPath.id) },
                            onRemove: { service.settings.removeWatchPath(watchPath.id) }
                        )
                    }
                }

                Button(action: addWatchPath) {
                    Label("Add Directory...", systemImage: "plus")
                }
                .buttonStyle(.bordered)
            } header: {
                Label("Watched Directories", systemImage: "folder")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            } footer: {
                Text("Documents in these directories will be automatically tracked when modified.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }
        }
        .formStyle(.grouped)
    }

    private func addWatchPath() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Select a directory to watch"
        panel.prompt = "Add"

        if panel.runModal() == .OK, let url = panel.url {
            service.settings.addWatchPath(url.path)
        }
    }

    // MARK: - Patterns Tab

    private var patternsTab: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: Design.Spacing.sm) {
                    Text("Only track files with these extensions:")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.secondaryText)

                    FlowLayout(spacing: Design.Spacing.xs) {
                        ForEach(service.settings.includePatterns, id: \.self) { pattern in
                            PatternChip(
                                pattern: pattern,
                                onRemove: { service.settings.removeIncludePattern(pattern) }
                            )
                        }
                    }

                    HStack {
                        AddPatternField { pattern in
                            service.settings.addIncludePattern(pattern)
                        }
                    }
                }
            } header: {
                Label("File Extensions", systemImage: "doc.text")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                VStack(alignment: .leading, spacing: Design.Spacing.sm) {
                    Text("Quick presets:")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.secondaryText)

                    HStack(spacing: Design.Spacing.sm) {
                        PresetButton(title: "Text Files", patterns: [".txt", ".md", ".rtf"]) {
                            applyPreset([".txt", ".md", ".rtf"])
                        }
                        PresetButton(title: "Documents", patterns: [".doc", ".docx", ".odt", ".pdf"]) {
                            applyPreset([".doc", ".docx", ".odt", ".pdf"])
                        }
                        PresetButton(title: "Code", patterns: [".swift", ".go", ".py", ".js", ".ts"]) {
                            applyPreset([".swift", ".go", ".py", ".js", ".ts"])
                        }
                    }
                }
            } header: {
                Label("Presets", systemImage: "square.stack.3d.up")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .formStyle(.grouped)
    }

    private func applyPreset(_ patterns: [String]) {
        for pattern in patterns {
            service.settings.addIncludePattern(pattern)
        }
    }

    // MARK: - Security Tab

    private var securityTab: some View {
        Form {
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                        Text("Signing Key")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(Design.Colors.primaryText)

                        if service.settings.signingKeyPath.isEmpty {
                            Text("Using default key in data directory")
                                .font(Design.Typography.bodySmall)
                                .foregroundColor(Design.Colors.secondaryText)
                        } else {
                            Text(service.settings.signingKeyPath)
                                .font(Design.Typography.mono)
                                .foregroundColor(Design.Colors.secondaryText)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }

                    Spacer()

                    Button("Browse...") {
                        selectSigningKey()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    if !service.settings.signingKeyPath.isEmpty {
                        Button(action: { service.settings.signingKeyPath = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(Design.Colors.tertiaryText)
                        }
                        .buttonStyle(.plain)
                        .help("Reset to default key")
                    }
                }
            } header: {
                Label("Cryptographic Signing", systemImage: "signature")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            } footer: {
                Text("Your signing key is used to cryptographically sign checkpoints. Keep it secure!")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }

            Section {
                Toggle("Enable TPM Attestation", isOn: Binding(
                    get: { service.settings.tpmAttestationEnabled },
                    set: { service.settings.tpmAttestationEnabled = $0 }
                ))
                .disabled(!service.status.tpmAvailable)

                if service.status.tpmAvailable {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(Design.Colors.success)
                        Text("TPM is available on this device")
                            .font(Design.Typography.bodySmall)
                            .foregroundColor(Design.Colors.secondaryText)
                    }
                } else {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(Design.Colors.warning)
                        Text("TPM is not available on this device")
                            .font(Design.Typography.bodySmall)
                            .foregroundColor(Design.Colors.secondaryText)
                    }
                }
            } header: {
                Label("Hardware Attestation", systemImage: "cpu")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            } footer: {
                Text("When enabled, checkpoints include hardware-backed attestation for stronger proofs.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }

            Section {
                VStack(alignment: .leading, spacing: Design.Spacing.sm) {
                    HStack {
                        Text("VDF Calibration")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(Design.Colors.primaryText)

                        Spacer()

                        if service.status.vdfCalibrated {
                            HStack(spacing: Design.Spacing.xs) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(Design.Colors.success)
                                Text("Calibrated")
                                    .font(Design.Typography.labelMedium)
                                    .foregroundColor(Design.Colors.success)
                            }
                        } else {
                            HStack(spacing: Design.Spacing.xs) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(Design.Colors.warning)
                                Text("Not calibrated")
                                    .font(Design.Typography.labelMedium)
                                    .foregroundColor(Design.Colors.warning)
                            }
                        }
                    }

                    if !service.status.vdfIterPerSec.isEmpty {
                        Text("Performance: \(service.status.vdfIterPerSec) iterations/sec")
                            .font(Design.Typography.mono)
                            .foregroundColor(Design.Colors.tertiaryText)
                    }

                    Button("Recalibrate VDF") {
                        Task {
                            _ = await service.calibrate()
                        }
                    }
                    .buttonStyle(.bordered)
                    .disabled(service.isLoading)
                }
            } header: {
                Label("VDF Timing Proofs", systemImage: "clock.arrow.circlepath")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            } footer: {
                Text("VDF calibration ensures accurate timing proofs for your specific hardware.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }
        }
        .formStyle(.grouped)
    }

    private func selectSigningKey() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.data]
        panel.message = "Select your signing key file"
        panel.prompt = "Select"

        if panel.runModal() == .OK, let url = panel.url {
            service.settings.signingKeyPath = url.path
        }
    }

    // MARK: - Notifications Tab

    private var notificationsTab: some View {
        Form {
            Section {
                Toggle("Show notifications", isOn: Binding(
                    get: { service.settings.showNotifications },
                    set: { service.settings.showNotifications = $0 }
                ))
                .onChange(of: service.settings.showNotifications) { _, newValue in
                    if newValue {
                        NotificationManager.shared.requestPermission()
                    }
                }
                .accessibilityIdentifier("toggle-notifications")
            } header: {
                Label("Alerts", systemImage: "bell.badge")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            } footer: {
                Text("Receive notifications when tracking starts, stops, or when checkpoints are created.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }

            Section {
                VStack(alignment: .leading, spacing: Design.Spacing.sm) {
                    NotificationPreview(
                        title: "Tracking Started",
                        message: "Now tracking: document.txt",
                        icon: "play.circle.fill",
                        color: .green
                    )

                    NotificationPreview(
                        title: "Checkpoint Created",
                        message: "Checkpoint #5 saved",
                        icon: "checkmark.circle.fill",
                        color: .blue
                    )

                    NotificationPreview(
                        title: "Auto-Checkpoint Created",
                        message: "Checkpoint saved for chapter-3.md",
                        icon: "clock.badge.checkmark.fill",
                        color: .purple
                    )
                }
            } header: {
                Label("Preview", systemImage: "eye")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Advanced Tab

    private var advancedTab: some View {
        Form {
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                        Text("Data Location")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(Design.Colors.primaryText)

                        Text(dataDirectory)
                            .font(Design.Typography.mono)
                            .foregroundColor(Design.Colors.secondaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }

                    Spacer()

                    Button("Reveal") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: dataDirectory))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Data stored in Application Support")
            } header: {
                Label("Storage", systemImage: "folder")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                Picker("Default Format", selection: Binding(
                    get: { service.settings.defaultExportFormat },
                    set: { service.settings.defaultExportFormat = $0 }
                )) {
                    Text("JSON").tag("json")
                    Text("CBOR").tag("cbor")
                }
                .pickerStyle(.segmented)

                Picker("Default Tier", selection: Binding(
                    get: { service.settings.defaultExportTier },
                    set: { service.settings.defaultExportTier = $0 }
                )) {
                    ForEach(ExportTier.allCases) { tier in
                        Text(tier.displayName).tag(tier.rawValue)
                    }
                }
                .pickerStyle(.menu)
            } header: {
                Label("Export Defaults", systemImage: "square.and.arrow.up")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                LinkRow(
                    icon: "book",
                    title: "Documentation",
                    url: AppConfig.documentationURL
                )

                LinkRow(
                    icon: "exclamationmark.bubble",
                    title: "Report Issue",
                    url: AppConfig.issuesURL
                )
            } header: {
                Label("Help", systemImage: "questionmark.circle")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                Button(role: .destructive) {
                    showResetConfirmation()
                } label: {
                    HStack {
                        Image(systemName: "trash")
                        Text("Reset Witnessd")
                    }
                }
                .accessibilityIdentifier("button-reset")
            } header: {
                Label("Danger Zone", systemImage: "exclamationmark.triangle")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.error)
            } footer: {
                Text("Permanently deletes your signing key and all evidence data.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }
        }
        .formStyle(.grouped)
    }

    private func showResetConfirmation() {
        let alert = NSAlert()
        alert.messageText = "Reset Witnessd?"
        alert.informativeText = "This will permanently delete your signing key and all evidence data. This action cannot be undone.\n\nAre you absolutely sure?"
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Reset Everything")
        alert.addButton(withTitle: "Cancel")

        // Make the destructive button visually distinct
        alert.buttons[0].hasDestructiveAction = true

        if alert.runModal() == .alertFirstButtonReturn {
            do {
                try FileManager.default.removeItem(atPath: dataDirectory)
                UserDefaults.standard.set(false, forKey: "hasLaunchedBefore")
                UserDefaults.standard.set(false, forKey: "hasAutoInitialized")

                // Show success confirmation
                let successAlert = NSAlert()
                successAlert.messageText = "Reset Complete"
                successAlert.informativeText = "All Witnessd data has been deleted. The app will restart to complete the reset."
                successAlert.alertStyle = .informational
                successAlert.addButton(withTitle: "Restart Now")
                successAlert.runModal()

                // Restart the app
                let url = URL(fileURLWithPath: Bundle.main.resourcePath!)
                let path = url.deletingLastPathComponent().deletingLastPathComponent().absoluteString
                let task = Process()
                task.launchPath = "/usr/bin/open"
                task.arguments = [path]
                task.launch()

                NSApplication.shared.terminate(nil)
            } catch {
                let errorAlert = NSAlert()
                errorAlert.messageText = "Reset Failed"
                errorAlert.informativeText = "Could not delete data: \(error.localizedDescription)"
                errorAlert.alertStyle = .warning
                errorAlert.addButton(withTitle: "OK")
                errorAlert.runModal()
            }
        }
    }
}

// MARK: - Supporting Views

struct NotificationPreview: View {
    let title: String
    let message: String
    let icon: String
    let color: Color

    var body: some View {
        HStack(spacing: Design.Spacing.md) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.lg))
                .foregroundColor(color)
                .frame(width: Design.IconSize.xxl)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(title)
                    .font(Design.Typography.headlineSmall)
                    .foregroundColor(Design.Colors.primaryText)

                Text(message)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Spacer()
        }
        .padding(Design.Spacing.md)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .fill(Design.Colors.secondaryBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                        .strokeBorder(Design.Colors.separator, lineWidth: 0.5)
                )
        )
    }
}

struct LinkRow: View {
    let icon: String
    let title: String
    let url: URL

    @State private var isHovered = false

    var body: some View {
        Link(destination: url) {
            HStack(spacing: Design.Spacing.md) {
                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.sm))
                    .foregroundColor(.accentColor)
                    .frame(width: Design.IconSize.lg)

                Text(title)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)

                Spacer()

                Image(systemName: "arrow.up.right")
                    .font(.system(size: Design.IconSize.xs))
                    .foregroundColor(Design.Colors.tertiaryText)
            }
            .padding(.vertical, Design.Spacing.xxs)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                    .fill(isHovered ? Design.Colors.hover : Color.clear)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityLabel("\(title), opens in browser")
    }
}

struct WatchPathRow: View {
    let watchPath: WatchPath
    let onToggle: () -> Void
    let onRemove: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: Design.Spacing.md) {
            Toggle("", isOn: Binding(
                get: { watchPath.isEnabled },
                set: { _ in onToggle() }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)

            Image(systemName: watchPath.exists ? "folder.fill" : "folder.badge.questionmark")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(watchPath.exists ? .accentColor : Design.Colors.warning)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(watchPath.displayName)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .lineLimit(1)

                Text(watchPath.path)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            if !watchPath.exists {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(Design.Colors.warning)
                    .help("Directory not found")
            }

            Button(action: onRemove) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(Design.Colors.tertiaryText)
            }
            .buttonStyle(.plain)
            .opacity(isHovered ? 1 : 0)
        }
        .padding(.vertical, Design.Spacing.xxs)
        .onHover { isHovered = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(watchPath.displayName), \(watchPath.isEnabled ? "enabled" : "disabled")")
    }
}

struct PatternChip: View {
    let pattern: String
    let onRemove: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: Design.Spacing.xxs) {
            Text(pattern)
                .font(Design.Typography.mono)
                .foregroundColor(Design.Colors.primaryText)

            Button(action: onRemove) {
                Image(systemName: "xmark")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundColor(Design.Colors.secondaryText)
            }
            .buttonStyle(.plain)
            .opacity(isHovered ? 1 : 0.5)
        }
        .padding(.horizontal, Design.Spacing.sm)
        .padding(.vertical, Design.Spacing.xxs)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                .fill(Design.Colors.secondaryBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                        .strokeBorder(Design.Colors.separator, lineWidth: 0.5)
                )
        )
        .onHover { isHovered = $0 }
    }
}

struct AddPatternField: View {
    let onAdd: (String) -> Void

    @State private var newPattern = ""

    var body: some View {
        HStack {
            TextField("Add extension (e.g., .md)", text: $newPattern)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    addPattern()
                }

            Button("Add") {
                addPattern()
            }
            .buttonStyle(.bordered)
            .disabled(newPattern.isEmpty)
        }
    }

    private func addPattern() {
        guard !newPattern.isEmpty else { return }
        onAdd(newPattern)
        newPattern = ""
    }
}

struct PresetButton: View {
    let title: String
    let patterns: [String]
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: Design.Spacing.xxs) {
                Text(title)
                    .font(Design.Typography.labelMedium)
                Text(patterns.joined(separator: ", "))
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
    }
}

// MARK: - Flow Layout for Tags

struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = FlowResult(in: proposal.width ?? 0, subviews: subviews, spacing: spacing)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = FlowResult(in: bounds.width, subviews: subviews, spacing: spacing)
        for (index, subview) in subviews.enumerated() {
            subview.place(at: CGPoint(x: bounds.minX + result.positions[index].x,
                                       y: bounds.minY + result.positions[index].y),
                          proposal: .unspecified)
        }
    }

    struct FlowResult {
        var size: CGSize = .zero
        var positions: [CGPoint] = []

        init(in maxWidth: CGFloat, subviews: Subviews, spacing: CGFloat) {
            var x: CGFloat = 0
            var y: CGFloat = 0
            var rowHeight: CGFloat = 0

            for subview in subviews {
                let size = subview.sizeThatFits(.unspecified)

                if x + size.width > maxWidth && x > 0 {
                    x = 0
                    y += rowHeight + spacing
                    rowHeight = 0
                }

                positions.append(CGPoint(x: x, y: y))
                rowHeight = max(rowHeight, size.height)
                x += size.width + spacing
            }

            self.size = CGSize(width: maxWidth, height: y + rowHeight)
        }
    }
}
