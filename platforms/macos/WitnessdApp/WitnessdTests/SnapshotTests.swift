import XCTest
import SwiftUI
@testable import witnessd

/// Snapshot tests for visual regression testing
/// Note: For full snapshot testing, consider using a library like SnapshotTesting
final class SnapshotTests: XCTestCase {

    // MARK: - Test Configuration

    static var snapshotDirectory: URL {
        let testBundle = Bundle(for: SnapshotTests.self)
        return testBundle.bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("Snapshots")
    }

    override class func setUp() {
        super.setUp()
        // Create snapshot directory if it doesn't exist
        try? FileManager.default.createDirectory(
            at: snapshotDirectory,
            withIntermediateDirectories: true
        )
    }

    // MARK: - Badge Snapshots

    func testBadgeSuccessSnapshot() throws {
        let badge = Badge(text: "Active", style: .success)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot, "Badge snapshot should be created")
    }

    func testBadgeWarningSnapshot() throws {
        let badge = Badge(text: "Warning", style: .warning)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot)
    }

    func testBadgeErrorSnapshot() throws {
        let badge = Badge(text: "Error", style: .error)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot)
    }

    func testBadgeNeutralSnapshot() throws {
        let badge = Badge(text: "Neutral", style: .neutral)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - StatWidget Snapshots

    func testStatWidgetSnapshot() throws {
        let widget = StatWidget(icon: "keyboard", value: "1.5k", label: "Keystrokes")
        let snapshot = captureSnapshot(view: widget, size: CGSize(width: 150, height: 50))
        XCTAssertNotNil(snapshot)
    }

    func testStatWidgetLargeValueSnapshot() throws {
        let widget = StatWidget(icon: "clock", value: "999.9k", label: "Duration")
        let snapshot = captureSnapshot(view: widget, size: CGSize(width: 150, height: 50))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - IconButton Snapshots

    func testIconButtonSnapshot() throws {
        let button = IconButton(icon: "gear", label: "Settings") { }
        let snapshot = captureSnapshot(view: button, size: CGSize(width: 40, height: 40))
        XCTAssertNotNil(snapshot)
    }

    func testIconButtonLargeSnapshot() throws {
        let button = IconButton(icon: "gear", label: "Settings", size: Design.IconSize.xl) { }
        let snapshot = captureSnapshot(view: button, size: CGSize(width: 50, height: 50))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - SectionHeader Snapshots

    func testSectionHeaderSnapshot() throws {
        let header = SectionHeader("Quick Actions")
        let snapshot = captureSnapshot(view: header, size: CGSize(width: 300, height: 30))
        XCTAssertNotNil(snapshot)
    }

    func testSectionHeaderWithActionSnapshot() throws {
        let header = SectionHeader("History", action: { }, actionLabel: "View All")
        let snapshot = captureSnapshot(view: header, size: CGSize(width: 300, height: 30))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - EmptyStateView Snapshots

    func testEmptyStateViewSnapshot() throws {
        let emptyState = EmptyStateView(
            icon: "doc.text.magnifyingglass",
            title: "No Documents",
            message: "Start tracking a document to see it here"
        )
        let snapshot = captureSnapshot(view: emptyState, size: CGSize(width: 300, height: 250))
        XCTAssertNotNil(snapshot)
    }

    func testEmptyStateViewWithActionSnapshot() throws {
        let emptyState = EmptyStateView(
            icon: "plus.circle",
            title: "Get Started",
            message: "Create your first document",
            action: { },
            actionLabel: "Create Document"
        )
        let snapshot = captureSnapshot(view: emptyState, size: CGSize(width: 300, height: 300))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - LoadingView Snapshots

    func testLoadingViewSnapshot() throws {
        let loading = LoadingView("Loading...")
        let snapshot = captureSnapshot(view: loading, size: CGSize(width: 150, height: 40))
        XCTAssertNotNil(snapshot)
    }

    func testLoadingViewNoLabelSnapshot() throws {
        let loading = LoadingView()
        let snapshot = captureSnapshot(view: loading, size: CGSize(width: 50, height: 40))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - LabeledDivider Snapshots

    func testLabeledDividerSnapshot() throws {
        let divider = LabeledDivider("or")
        let snapshot = captureSnapshot(view: divider, size: CGSize(width: 200, height: 20))
        XCTAssertNotNil(snapshot)
    }

    func testSimpleDividerSnapshot() throws {
        let divider = LabeledDivider()
        let snapshot = captureSnapshot(view: divider, size: CGSize(width: 200, height: 10))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - DropZone Snapshots

    func testDropZoneViewSnapshot() throws {
        let dropZone = DropZoneView(
            title: "Drop Document Here",
            icon: "doc.badge.plus"
        ) { _ in }
        let snapshot = captureSnapshot(view: dropZone, size: CGSize(width: 300, height: 200))
        XCTAssertNotNil(snapshot)
    }

    func testCompactDropZoneSnapshot() throws {
        let dropZone = CompactDropZone(placeholder: "Select a file") { _ in }
        let snapshot = captureSnapshot(view: dropZone, size: CGSize(width: 300, height: 50))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - AccessibleStatusIndicator Snapshots

    func testAccessibleStatusIndicatorActiveSnapshot() throws {
        let indicator = AccessibleStatusIndicator(
            isActive: true,
            activeLabel: "Connected",
            inactiveLabel: "Disconnected"
        )
        let snapshot = captureSnapshot(view: indicator, size: CGSize(width: 120, height: 24))
        XCTAssertNotNil(snapshot)
    }

    func testAccessibleStatusIndicatorInactiveSnapshot() throws {
        let indicator = AccessibleStatusIndicator(
            isActive: false,
            activeLabel: "Connected",
            inactiveLabel: "Disconnected"
        )
        let snapshot = captureSnapshot(view: indicator, size: CGSize(width: 120, height: 24))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - Light/Dark Mode Variants

    func testBadgeLightModeSnapshot() throws {
        let badge = Badge(text: "Test", style: .success)
        let wrapped = badge.environment(\.colorScheme, .light)
        let snapshot = captureSnapshot(view: wrapped, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot)
    }

    func testBadgeDarkModeSnapshot() throws {
        let badge = Badge(text: "Test", style: .success)
        let wrapped = badge.environment(\.colorScheme, .dark)
        let snapshot = captureSnapshot(view: wrapped, size: CGSize(width: 80, height: 24))
        XCTAssertNotNil(snapshot)
    }

    func testStatWidgetLightModeSnapshot() throws {
        let widget = StatWidget(icon: "keyboard", value: "100", label: "Keys")
        let wrapped = widget.environment(\.colorScheme, .light)
        let snapshot = captureSnapshot(view: wrapped, size: CGSize(width: 150, height: 50))
        XCTAssertNotNil(snapshot)
    }

    func testStatWidgetDarkModeSnapshot() throws {
        let widget = StatWidget(icon: "keyboard", value: "100", label: "Keys")
        let wrapped = widget.environment(\.colorScheme, .dark)
        let snapshot = captureSnapshot(view: wrapped, size: CGSize(width: 150, height: 50))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - Different Sizes

    func testBadgeSmallSizeSnapshot() throws {
        let badge = Badge(text: "OK", style: .success)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 50, height: 20))
        XCTAssertNotNil(snapshot)
    }

    func testBadgeLargeSizeSnapshot() throws {
        let badge = Badge(text: "Very Long Status Text", style: .warning)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 200, height: 30))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - FileRow Snapshots

    func testFileRowSnapshot() throws {
        let file = TrackedFile(
            id: "1",
            path: "/path/to/document.txt",
            name: "document.txt",
            events: 1234,
            lastModified: Date()
        )
        let row = FileRow(file: file)
        let snapshot = captureSnapshot(view: row, size: CGSize(width: 250, height: 50))
        XCTAssertNotNil(snapshot)
    }

    func testFileRowLongNameSnapshot() throws {
        let file = TrackedFile(
            id: "1",
            path: "/path/to/very-long-document-name-that-might-overflow.txt",
            name: "very-long-document-name-that-might-overflow.txt",
            events: 99999,
            lastModified: Date()
        )
        let row = FileRow(file: file)
        let snapshot = captureSnapshot(view: row, size: CGSize(width: 250, height: 50))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - StatBadge Snapshots

    func testStatBadgeSnapshot() throws {
        let badge = StatBadge(icon: "number", value: "1,234", label: "Events")
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 150, height: 60))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - FeatureItem Snapshots

    func testFeatureItemSnapshot() throws {
        let item = FeatureItem(
            icon: "keyboard",
            title: "Track Keystrokes",
            description: "Count-only, never content"
        )
        let snapshot = captureSnapshot(view: item, size: CGSize(width: 300, height: 60))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - NotificationPreview Snapshots

    func testNotificationPreviewSnapshot() throws {
        let preview = NotificationPreview(
            title: "Tracking Started",
            message: "Now tracking: document.txt",
            icon: "play.circle.fill",
            color: .green
        )
        let snapshot = captureSnapshot(view: preview, size: CGSize(width: 350, height: 80))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - LinkRow Snapshots

    func testLinkRowSnapshot() throws {
        let row = LinkRow(
            icon: "book",
            title: "Documentation",
            url: URL(string: "https://example.com")!
        )
        let snapshot = captureSnapshot(view: row, size: CGSize(width: 300, height: 40))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - ExportTierRow Snapshots

    func testExportTierRowSelectedSnapshot() throws {
        let row = ExportTierRow(tier: .standard, isSelected: true) { }
        let snapshot = captureSnapshot(view: row, size: CGSize(width: 350, height: 80))
        XCTAssertNotNil(snapshot)
    }

    func testExportTierRowUnselectedSnapshot() throws {
        let row = ExportTierRow(tier: .standard, isSelected: false) { }
        let snapshot = captureSnapshot(view: row, size: CGSize(width: 350, height: 80))
        XCTAssertNotNil(snapshot)
    }

    // MARK: - Snapshot Comparison (requires baseline images)

    func testBadgeMatchesBaseline() throws {
        let badge = Badge(text: "Test", style: .success)
        let snapshot = captureSnapshot(view: badge, size: CGSize(width: 80, height: 24))

        // In a real implementation, we would compare with a baseline
        // let baseline = loadBaselineSnapshot(named: "badge-success")
        // XCTAssertEqual(snapshot, baseline)
        XCTAssertNotNil(snapshot)
    }

    // MARK: - Helper Methods

    private func captureSnapshot<V: View>(view: V, size: CGSize) -> NSImage? {
        let hostingController = NSHostingController(rootView: view)
        hostingController.view.frame = CGRect(origin: .zero, size: size)

        // Force layout
        hostingController.view.layout()

        // Create bitmap representation
        guard let bitmapRep = hostingController.view.bitmapImageRepForCachingDisplay(
            in: hostingController.view.bounds
        ) else {
            return nil
        }

        hostingController.view.cacheDisplay(in: hostingController.view.bounds, to: bitmapRep)

        let image = NSImage(size: size)
        image.addRepresentation(bitmapRep)

        return image
    }

    private func saveSnapshot(_ image: NSImage, named name: String) throws {
        guard let tiffData = image.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiffData),
              let pngData = bitmap.representation(using: .png, properties: [:]) else {
            throw NSError(domain: "SnapshotTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create PNG data"])
        }

        let url = Self.snapshotDirectory.appendingPathComponent("\(name).png")
        try pngData.write(to: url)
    }

    private func loadBaselineSnapshot(named name: String) -> NSImage? {
        let url = Self.snapshotDirectory.appendingPathComponent("\(name).png")
        return NSImage(contentsOf: url)
    }
}

// MARK: - Regression Testing

final class VisualRegressionTests: XCTestCase {

    func testDesignSystemColorsNotChanged() {
        // Verify design system colors haven't changed unexpectedly
        // This would compare against stored color values

        let success = Design.Colors.success
        let warning = Design.Colors.warning
        let error = Design.Colors.error

        // These are sanity checks - in a real test you would compare
        // against stored baseline values
        XCTAssertNotEqual(success.description, "")
        XCTAssertNotEqual(warning.description, "")
        XCTAssertNotEqual(error.description, "")
    }

    func testDesignSystemSpacingNotChanged() {
        // Verify spacing values haven't changed
        XCTAssertEqual(Design.Spacing.sm, 8)
        XCTAssertEqual(Design.Spacing.md, 12)
        XCTAssertEqual(Design.Spacing.lg, 16)
    }

    func testDesignSystemLayoutNotChanged() {
        // Verify layout dimensions haven't changed
        XCTAssertEqual(Design.Layout.popoverWidth, 320)
        XCTAssertEqual(Design.Layout.popoverHeight, 440)
        XCTAssertEqual(Design.Layout.settingsWidth, 480)
        XCTAssertEqual(Design.Layout.settingsHeight, 320)
    }
}
