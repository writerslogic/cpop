import SwiftUI

struct SettingsView: View {
    @AppStorage("openAtLogin") private var openAtLogin = false
    @AppStorage("showNotifications") private var showNotifications = true
    @AppStorage("autoCheckpoint") private var autoCheckpoint = false
    @AppStorage("checkpointIntervalMinutes") private var checkpointInterval = 30

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

            notificationsTab
                .tabItem {
                    Label("Notifications", systemImage: "bell")
                }

            advancedTab
                .tabItem {
                    Label("Advanced", systemImage: "gearshape.2")
                }
        }
        .frame(width: Design.Layout.settingsWidth, height: Design.Layout.settingsHeight)
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section {
                Toggle("Open Witnessd at Login", isOn: $openAtLogin)
                    .onChange(of: openAtLogin) { _, newValue in
                        LaunchAtLogin.isEnabled = newValue
                    }
                    .accessibilityIdentifier("toggle-open-at-login")
                    .accessibilityHint("Automatically start Witnessd when you log in")
            } header: {
                Label("Startup", systemImage: "power")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Section {
                Toggle("Auto-create checkpoints", isOn: $autoCheckpoint)
                    .accessibilityIdentifier("toggle-auto-checkpoint")
                    .accessibilityHint("Automatically save checkpoints at regular intervals")

                if autoCheckpoint {
                    Picker("Interval", selection: $checkpointInterval) {
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
        }
        .formStyle(.grouped)
    }

    // MARK: - Notifications Tab

    private var notificationsTab: some View {
        Form {
            Section {
                Toggle("Show notifications", isOn: $showNotifications)
                    .onChange(of: showNotifications) { _, newValue in
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
                LinkRow(
                    icon: "book",
                    title: "Documentation",
                    url: "https://github.com/writerslogic/witnessd"
                )

                LinkRow(
                    icon: "exclamationmark.bubble",
                    title: "Report Issue",
                    url: "https://github.com/writerslogic/witnessd/issues"
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
        alert.informativeText = "This will permanently delete your signing key and all evidence data. This action cannot be undone."
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Reset")

        if alert.runModal() == .alertSecondButtonReturn {
            try? FileManager.default.removeItem(atPath: dataDirectory)
            UserDefaults.standard.set(false, forKey: "hasLaunchedBefore")
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
    let url: String

    @State private var isHovered = false

    var body: some View {
        Link(destination: URL(string: url) ?? URL(string: "https://github.com/writerslogic/witnessd")!) {
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
