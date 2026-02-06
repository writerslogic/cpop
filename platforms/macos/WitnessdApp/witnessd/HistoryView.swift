import SwiftUI

struct HistoryView: View {
    let bridge: WitnessdBridge
    let closeAction: () -> Void

    @State private var files: [TrackedFile] = []
    @State private var isLoading = false
    @State private var selectedFile: TrackedFile? = nil
    @State private var logContent: String = ""

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Tracked Documents")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                Spacer()

                IconButton(icon: "arrow.clockwise", label: "Refresh", size: Design.IconSize.sm) {
                    Task { await loadFiles() }
                }

                IconButton(icon: "xmark.circle.fill", label: "Close", size: Design.IconSize.sm) {
                    closeAction()
                }
            }
            .padding(Design.Spacing.lg)
            .background(Design.Colors.secondaryBackground)

            Divider()

            if isLoading {
                Spacer()
                ProgressView()
                Spacer()
            } else if files.isEmpty {
                Spacer()
                VStack(spacing: Design.Spacing.md) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: Design.IconSize.hero))
                        .foregroundColor(Design.Colors.tertiaryText)

                    Text("No tracked documents")
                        .font(Design.Typography.headlineMedium)
                        .foregroundColor(Design.Colors.secondaryText)

                    Text("Start tracking a document to see it here")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                Spacer()
            } else {
                HSplitView {
                    // File list
                    List(files, selection: $selectedFile) { file in
                        FileRow(file: file)
                            .tag(file)
                    }
                    .listStyle(.sidebar)
                    .frame(minWidth: 200, maxWidth: 300)

                    // Detail view
                    if let file = selectedFile {
                        FileDetailView(file: file, bridge: bridge)
                    } else {
                        VStack {
                            Spacer()
                            Text("Select a document to view details")
                                .foregroundColor(.secondary)
                            Spacer()
                        }
                    }
                }
            }
        }
        .frame(width: Design.Layout.historyWidth, height: Design.Layout.historyHeight)
        .task {
            await loadFiles()
        }
    }

    private func loadFiles() async {
        isLoading = true
        let result = await bridge.listTrackedFiles()
        files = result
        isLoading = false
    }
}

struct TrackedFile: Identifiable, Hashable {
    let id: String
    let path: String
    let name: String
    let events: Int
    let lastModified: Date?

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    static func == (lhs: TrackedFile, rhs: TrackedFile) -> Bool {
        lhs.id == rhs.id
    }
}

struct FileRow: View {
    let file: TrackedFile

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: "doc.text")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(.accentColor)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(file.name)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .lineLimit(1)

                Text("\(file.events) events")
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .padding(.vertical, Design.Spacing.xxs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(file.name), \(file.events) events")
    }
}

struct FileDetailView: View {
    let file: TrackedFile
    let bridge: WitnessdBridge

    @State private var logContent: String = ""
    @State private var isLoading = false

    // Export tier selection state
    @State private var showingTierSheet = false
    @State private var selectedExportTier: ExportTier = .standard
    @State private var pendingExportDestURL: URL? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.lg) {
            // Header
            VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                Text(file.name)
                    .font(Design.Typography.displaySmall)
                    .foregroundColor(Design.Colors.primaryText)

                Text(file.path)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            // Stats
            HStack(spacing: Design.Spacing.xxl) {
                StatBadge(icon: "number", value: "\(file.events)", label: "Events")

                if let date = file.lastModified {
                    StatBadge(icon: "clock", value: date.formatted(.relative(presentation: .named)), label: "Last Modified")
                }
            }

            Divider()

            // Actions
            HStack(spacing: Design.Spacing.md) {
                Button(action: exportEvidence) {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)

                Button(action: verifyEvidence) {
                    Label("Verify", systemImage: "checkmark.shield")
                }
                .buttonStyle(.bordered)

                Button(action: { Task { await loadLog() } }) {
                    Label("Refresh Log", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }

            Divider()

            // Log
            Text("Event Log")
                .font(Design.Typography.headlineMedium)
                .foregroundColor(Design.Colors.primaryText)

            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    Text(logContent)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.primaryText)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Design.Spacing.sm)
                }
                .background(Design.Colors.tertiaryBackground)
                .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
            }
        }
        .padding(Design.Spacing.lg)
        .task {
            await loadLog()
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
                    pendingExportDestURL = nil
                }
            )
        }
    }

    private func loadLog() async {
        isLoading = true
        let result = await bridge.log(filePath: file.path)
        logContent = result.message
        isLoading = false
    }

    private func exportEvidence() {
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = URL(fileURLWithPath: file.path).deletingPathExtension().lastPathComponent + ".evidence.json"
        savePanel.allowedContentTypes = [.json]

        if savePanel.runModal() == .OK, let saveURL = savePanel.url {
            // Store URL and show tier selection
            pendingExportDestURL = saveURL
            selectedExportTier = .standard
            showingTierSheet = true
        }
    }

    private func performExport() {
        guard let destURL = pendingExportDestURL else {
            return
        }

        Task {
            isLoading = true
            let result = await bridge.export(filePath: file.path, tier: selectedExportTier.rawValue, outputPath: destURL.path)
            isLoading = false

            pendingExportDestURL = nil

            if result.success {
                let alert = NSAlert()
                alert.messageText = "Evidence Exported"
                alert.informativeText = "Saved to: \(destURL.lastPathComponent)"
                alert.alertStyle = .informational
                alert.runModal()
            } else {
                let alert = NSAlert()
                alert.messageText = "Export Failed"
                alert.informativeText = result.message
                alert.alertStyle = .warning
                alert.runModal()
            }
        }
    }

    private func verifyEvidence() {
        Task {
            let result = await bridge.verify(filePath: file.path)
            let alert = NSAlert()
            alert.messageText = result.success ? "Verification Passed" : "Verification Failed"
            alert.informativeText = result.message
            alert.alertStyle = result.success ? .informational : .warning
            alert.runModal()
        }
    }
}

struct StatBadge: View {
    let icon: String
    let value: String
    let label: String

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(.accentColor)

            VStack(alignment: .leading, spacing: 0) {
                Text(value)
                    .font(Design.Typography.statValue)
                    .foregroundColor(Design.Colors.primaryText)
                Text(label)
                    .font(Design.Typography.statLabel)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .padding(.horizontal, Design.Spacing.md)
        .padding(.vertical, Design.Spacing.sm)
        .background(Design.Colors.secondaryBackground)
        .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
    }
}

// Extension to WitnessdBridge for listing tracked files
extension WitnessdBridge {
    func listTrackedFiles() async -> [TrackedFile] {
        // Use the list command from witnessd
        let result = await list()

        guard result.success else { return [] }

        // Parse the output to extract tracked files
        var files: [TrackedFile] = []
        let lines = result.message.components(separatedBy: "\n")

        for line in lines {
            // Try to parse each line as a file path with event count
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Expected format: "path/to/file.txt (N events)" or just "path/to/file.txt"
            if let parenIndex = trimmed.lastIndex(of: "("),
               let closeIndex = trimmed.lastIndex(of: ")") {
                let path = String(trimmed[..<parenIndex]).trimmingCharacters(in: .whitespaces)
                let eventPart = String(trimmed[trimmed.index(after: parenIndex)..<closeIndex])
                let events = Int(eventPart.components(separatedBy: " ").first ?? "0") ?? 0

                let url = URL(fileURLWithPath: path)
                files.append(TrackedFile(
                    id: path,
                    path: path,
                    name: url.lastPathComponent,
                    events: events,
                    lastModified: nil
                ))
            } else if FileManager.default.fileExists(atPath: trimmed) {
                let url = URL(fileURLWithPath: trimmed)
                files.append(TrackedFile(
                    id: trimmed,
                    path: trimmed,
                    name: url.lastPathComponent,
                    events: 0,
                    lastModified: nil
                ))
            }
        }

        return files
    }

}
