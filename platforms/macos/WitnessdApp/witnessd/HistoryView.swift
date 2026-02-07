import SwiftUI

struct HistoryView: View {
    let bridge: WitnessdBridge
    let closeAction: () -> Void

    @State private var service = WitnessdService.shared
    @State private var files: [TrackedFile] = []
    @State private var isLoading = false
    @State private var selectedFile: TrackedFile? = nil
    @State private var searchText: String = ""
    @State private var sortOrder: SortOrder = .dateDescending
    @State private var filterStatus: FilterStatus = .all

    enum SortOrder: String, CaseIterable {
        case dateDescending = "Newest First"
        case dateAscending = "Oldest First"
        case nameAscending = "Name A-Z"
        case nameDescending = "Name Z-A"
        case eventsDescending = "Most Events"
    }

    enum FilterStatus: String, CaseIterable {
        case all = "All"
        case verified = "Verified"
        case pending = "Pending"
        case failed = "Failed"
    }

    var filteredAndSortedFiles: [TrackedFile] {
        var result = files

        // Apply search filter
        if !searchText.isEmpty {
            let lowercasedSearch = searchText.lowercased()
            result = result.filter { file in
                file.name.lowercased().contains(lowercasedSearch) ||
                file.path.lowercased().contains(lowercasedSearch)
            }
        }

        // Apply status filter
        switch filterStatus {
        case .all:
            break
        case .verified:
            result = result.filter { $0.verificationStatus == .verified }
        case .pending:
            result = result.filter { $0.verificationStatus == .pending || $0.verificationStatus == .unknown }
        case .failed:
            result = result.filter { $0.verificationStatus == .failed }
        }

        // Apply sort
        switch sortOrder {
        case .dateDescending:
            result.sort { ($0.lastModified ?? Date.distantPast) > ($1.lastModified ?? Date.distantPast) }
        case .dateAscending:
            result.sort { ($0.lastModified ?? Date.distantPast) < ($1.lastModified ?? Date.distantPast) }
        case .nameAscending:
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .nameDescending:
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedDescending }
        case .eventsDescending:
            result.sort { $0.events > $1.events }
        }

        return result
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerView

            Divider()

            // Toolbar
            toolbarView

            Divider()

            if isLoading {
                Spacer()
                ProgressView("Loading documents...")
                    .font(Design.Typography.bodyMedium)
                Spacer()
            } else if files.isEmpty {
                emptyStateView
            } else if filteredAndSortedFiles.isEmpty {
                noResultsView
            } else {
                HSplitView {
                    // File list
                    fileListView
                        .frame(minWidth: 200, maxWidth: 320)

                    // Detail view
                    detailView
                }
            }
        }
        .frame(width: Design.Layout.historyWidth, height: Design.Layout.historyHeight)
        .task {
            await loadFiles()
        }
    }

    // MARK: - Header

    private var headerView: some View {
        HStack {
            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text("Document History")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                Text("\(files.count) tracked documents")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }

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
    }

    // MARK: - Toolbar

    private var toolbarView: some View {
        HStack(spacing: Design.Spacing.md) {
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(Design.Colors.tertiaryText)
                TextField("Search documents...", text: $searchText)
                    .textFieldStyle(.plain)

                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(Design.Colors.tertiaryText)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, Design.Spacing.sm)
            .padding(.vertical, Design.Spacing.xs)
            .background(Design.Colors.secondaryBackground)
            .cornerRadius(Design.Radius.sm)
            .frame(maxWidth: 240)

            Spacer()

            // Filter by status
            Picker("Status", selection: $filterStatus) {
                ForEach(FilterStatus.allCases, id: \.self) { status in
                    Text(status.rawValue).tag(status)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 100)

            // Sort order
            Picker("Sort", selection: $sortOrder) {
                ForEach(SortOrder.allCases, id: \.self) { order in
                    Text(order.rawValue).tag(order)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 140)
        }
        .padding(.horizontal, Design.Spacing.lg)
        .padding(.vertical, Design.Spacing.sm)
    }

    // MARK: - Empty State

    private var emptyStateView: some View {
        VStack(spacing: Design.Spacing.lg) {
            Spacer()

            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: Design.IconSize.hero))
                .foregroundColor(Design.Colors.tertiaryText)

            VStack(spacing: Design.Spacing.sm) {
                Text("No tracked documents")
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.secondaryText)

                Text("Start tracking a document to see it here.\nYour tracked documents and their evidence will appear in this list.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .multilineTextAlignment(.center)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - No Results

    private var noResultsView: some View {
        VStack(spacing: Design.Spacing.lg) {
            Spacer()

            Image(systemName: "magnifyingglass")
                .font(.system(size: Design.IconSize.xxl))
                .foregroundColor(Design.Colors.tertiaryText)

            VStack(spacing: Design.Spacing.sm) {
                Text("No matching documents")
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.secondaryText)

                Text("Try adjusting your search or filters.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
            }

            Button("Clear Filters") {
                searchText = ""
                filterStatus = .all
            }
            .buttonStyle(.bordered)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - File List

    private var fileListView: some View {
        List(filteredAndSortedFiles, selection: $selectedFile) { file in
            FileRowEnhanced(file: file)
                .tag(file)
        }
        .listStyle(.sidebar)
    }

    // MARK: - Detail View

    @ViewBuilder
    private var detailView: some View {
        if let file = selectedFile {
            FileDetailViewEnhanced(file: file, bridge: bridge, service: service)
        } else {
            VStack {
                Spacer()
                VStack(spacing: Design.Spacing.md) {
                    Image(systemName: "doc.text")
                        .font(.system(size: Design.IconSize.xxl))
                        .foregroundColor(Design.Colors.tertiaryText)
                    Text("Select a document to view details")
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(Design.Colors.secondaryText)
                }
                Spacer()
            }
        }
    }

    // MARK: - Data Loading

    private func loadFiles() async {
        isLoading = true
        let result = await bridge.listTrackedFiles()
        files = result
        isLoading = false
    }
}

// MARK: - Enhanced Tracked File Model

struct TrackedFile: Identifiable, Hashable {
    let id: String
    let path: String
    let name: String
    let events: Int
    let lastModified: Date?
    var verificationStatus: VerificationStatus = .unknown
    var checkpointCount: Int = 0
    var keystrokeCount: Int = 0

    enum VerificationStatus: String {
        case verified = "verified"
        case pending = "pending"
        case failed = "failed"
        case unknown = "unknown"
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    static func == (lhs: TrackedFile, rhs: TrackedFile) -> Bool {
        lhs.id == rhs.id
    }
}

// MARK: - Enhanced File Row

struct FileRowEnhanced: View {
    let file: TrackedFile

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            // Status indicator
            statusIcon

            // File info
            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(file.name)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .lineLimit(1)

                HStack(spacing: Design.Spacing.xs) {
                    Label("\(file.events)", systemImage: "number")
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.secondaryText)

                    if let date = file.lastModified {
                        Text(date.formatted(.relative(presentation: .named)))
                            .font(Design.Typography.labelSmall)
                            .foregroundColor(Design.Colors.tertiaryText)
                    }
                }
            }
        }
        .padding(.vertical, Design.Spacing.xxs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(file.name), \(file.events) events, \(verificationLabel)")
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch file.verificationStatus {
        case .verified:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(Design.Colors.success)
                .help("Verified")
        case .pending:
            Image(systemName: "clock.fill")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(Design.Colors.warning)
                .help("Pending verification")
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(Design.Colors.error)
                .help("Verification failed")
        case .unknown:
            Image(systemName: "doc.text.fill")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(.accentColor)
                .help("Not yet verified")
        }
    }

    private var verificationLabel: String {
        switch file.verificationStatus {
        case .verified: return "verified"
        case .pending: return "pending verification"
        case .failed: return "verification failed"
        case .unknown: return "not verified"
        }
    }
}

// MARK: - Enhanced File Detail View

struct FileDetailViewEnhanced: View {
    let file: TrackedFile
    let bridge: WitnessdBridge
    let service: WitnessdService

    @State private var logContent: String = ""
    @State private var isLoading = false
    @State private var isVerifying = false
    @State private var verificationResult: String? = nil
    @State private var verificationPassed: Bool? = nil

    // Export tier selection state
    @State private var showingTierSheet = false
    @State private var selectedExportTier: ExportTier = .standard
    @State private var pendingExportSourceURL: URL? = nil
    @State private var pendingExportDestURL: URL? = nil

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Design.Spacing.xl) {
                // Header with document info
                headerSection

                Divider()

                // Statistics grid
                statsSection

                Divider()

                // Verification section
                verificationSection

                Divider()

                // Actions section
                actionsSection

                Divider()

                // Event log section
                logSection
            }
            .padding(Design.Spacing.lg)
        }
        .task {
            await loadLog()
        }
        .sheet(isPresented: $showingTierSheet) {
            ExportTierSheet(
                selectedTier: $selectedExportTier,
                sourceURL: $pendingExportSourceURL,
                destinationURL: $pendingExportDestURL,
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

    // MARK: - Header Section

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.sm) {
            HStack {
                VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                    Text(file.name)
                        .font(Design.Typography.displaySmall)
                        .foregroundColor(Design.Colors.primaryText)

                    Text(file.path)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.secondaryText)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }

                Spacer()

                // Open in Finder button
                Button(action: openInFinder) {
                    Image(systemName: "folder")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("Reveal in Finder")
            }
        }
    }

    // MARK: - Stats Section

    private var statsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Statistics")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)

            HStack(spacing: Design.Spacing.xxl) {
                StatBadge(icon: "number", value: "\(file.events)", label: "Events")

                if let date = file.lastModified {
                    StatBadge(icon: "clock", value: date.formatted(.relative(presentation: .named)), label: "Last Modified")
                }

                if file.checkpointCount > 0 {
                    StatBadge(icon: "checkmark.circle", value: "\(file.checkpointCount)", label: "Checkpoints")
                }

                if file.keystrokeCount > 0 {
                    StatBadge(icon: "keyboard", value: formatNumber(file.keystrokeCount), label: "Keystrokes")
                }
            }
        }
    }

    // MARK: - Verification Section

    private var verificationSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Verification")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)

            HStack(spacing: Design.Spacing.lg) {
                // Status badge
                verificationStatusBadge

                Spacer()

                // Verify button
                Button(action: { Task { await verifyEvidence() } }) {
                    HStack(spacing: Design.Spacing.xs) {
                        if isVerifying {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "checkmark.shield")
                        }
                        Text("Verify")
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isVerifying)
            }

            if let result = verificationResult {
                VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                    HStack {
                        Image(systemName: verificationPassed == true ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundColor(verificationPassed == true ? Design.Colors.success : Design.Colors.error)
                        Text(verificationPassed == true ? "Verification Passed" : "Verification Failed")
                            .font(Design.Typography.headlineSmall)
                            .foregroundColor(verificationPassed == true ? Design.Colors.success : Design.Colors.error)
                    }

                    Text(result)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.secondaryText)
                        .padding(Design.Spacing.sm)
                        .background(Design.Colors.tertiaryBackground)
                        .cornerRadius(Design.Radius.sm)
                }
            }
        }
    }

    @ViewBuilder
    private var verificationStatusBadge: some View {
        HStack(spacing: Design.Spacing.xs) {
            switch file.verificationStatus {
            case .verified:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(Design.Colors.success)
                Text("Verified")
                    .foregroundColor(Design.Colors.success)
            case .pending:
                Image(systemName: "clock.badge.questionmark")
                    .foregroundColor(Design.Colors.warning)
                Text("Pending")
                    .foregroundColor(Design.Colors.warning)
            case .failed:
                Image(systemName: "xmark.shield.fill")
                    .foregroundColor(Design.Colors.error)
                Text("Failed")
                    .foregroundColor(Design.Colors.error)
            case .unknown:
                Image(systemName: "questionmark.circle")
                    .foregroundColor(Design.Colors.secondaryText)
                Text("Not Verified")
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .font(Design.Typography.labelMedium)
        .padding(.horizontal, Design.Spacing.md)
        .padding(.vertical, Design.Spacing.sm)
        .background(Design.Colors.secondaryBackground)
        .cornerRadius(Design.Radius.md)
    }

    // MARK: - Actions Section

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Actions")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)

            HStack(spacing: Design.Spacing.md) {
                Button(action: exportEvidence) {
                    Label("Export Evidence", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)

                Button(action: { Task { await loadLog() } }) {
                    Label("Refresh Log", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)

                Button(action: copyPath) {
                    Label("Copy Path", systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)
            }
        }
    }

    // MARK: - Log Section

    private var logSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            HStack {
                Text("Event Log")
                    .font(Design.Typography.headlineSmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .textCase(.uppercase)

                Spacer()

                if isLoading {
                    ProgressView()
                        .scaleEffect(0.7)
                }
            }

            if logContent.isEmpty && !isLoading {
                VStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "doc.text")
                        .font(.system(size: Design.IconSize.lg))
                        .foregroundColor(Design.Colors.tertiaryText)
                    Text("No events recorded yet")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .frame(maxWidth: .infinity)
                .padding(Design.Spacing.xl)
                .background(Design.Colors.tertiaryBackground)
                .cornerRadius(Design.Radius.md)
            } else {
                ScrollView {
                    Text(logContent)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.primaryText)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Design.Spacing.sm)
                }
                .frame(minHeight: 200)
                .background(Design.Colors.tertiaryBackground)
                .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
            }
        }
    }

    // MARK: - Actions

    private func loadLog() async {
        isLoading = true
        let result = await bridge.log(filePath: file.path)
        logContent = result.message
        isLoading = false
    }

    private func verifyEvidence() async {
        isVerifying = true
        verificationResult = nil
        verificationPassed = nil

        let result = await bridge.verify(filePath: file.path)

        verificationPassed = result.success
        verificationResult = result.message
        isVerifying = false
    }

    private func exportEvidence() {
        // Pre-fill with the current file
        pendingExportSourceURL = URL(fileURLWithPath: file.path)
        // Suggest destination in Downloads folder
        let suggestedName = URL(fileURLWithPath: file.path).deletingPathExtension().lastPathComponent + ".evidence.json"
        if let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first {
            pendingExportDestURL = downloadsURL.appendingPathComponent(suggestedName)
        }
        selectedExportTier = ExportTier(rawValue: service.settings.defaultExportTier) ?? .standard
        showingTierSheet = true
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

    private func openInFinder() {
        let url = URL(fileURLWithPath: file.path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    private func copyPath() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(file.path, forType: .string)
    }

    private func formatNumber(_ n: Int) -> String {
        if n >= 1000000 {
            return String(format: "%.1fM", Double(n) / 1000000.0)
        } else if n >= 1000 {
            return String(format: "%.1fk", Double(n) / 1000.0)
        }
        return "\(n)"
    }
}

// MARK: - Stat Badge

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

// MARK: - Extension to WitnessdBridge for listing tracked files

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

                // Get file modification date if available
                var lastModified: Date? = nil
                if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                   let modDate = attrs[.modificationDate] as? Date {
                    lastModified = modDate
                }

                files.append(TrackedFile(
                    id: path,
                    path: path,
                    name: url.lastPathComponent,
                    events: events,
                    lastModified: lastModified
                ))
            } else if FileManager.default.fileExists(atPath: trimmed) {
                let url = URL(fileURLWithPath: trimmed)

                var lastModified: Date? = nil
                if let attrs = try? FileManager.default.attributesOfItem(atPath: trimmed),
                   let modDate = attrs[.modificationDate] as? Date {
                    lastModified = modDate
                }

                files.append(TrackedFile(
                    id: trimmed,
                    path: trimmed,
                    name: url.lastPathComponent,
                    events: 0,
                    lastModified: lastModified
                ))
            }
        }

        return files
    }
}
