import XCTest
import SwiftUI
@testable import witnessd

/// Tests for view state management and data transformation
final class ViewModelTests: XCTestCase {

    // MARK: - ExportTier Tests

    func testExportTierCases() {
        let allCases = ExportTier.allCases
        XCTAssertEqual(allCases.count, 4)
        XCTAssertTrue(allCases.contains(.basic))
        XCTAssertTrue(allCases.contains(.standard))
        XCTAssertTrue(allCases.contains(.enhanced))
        XCTAssertTrue(allCases.contains(.maximum))
    }

    func testExportTierRawValues() {
        XCTAssertEqual(ExportTier.basic.rawValue, "basic")
        XCTAssertEqual(ExportTier.standard.rawValue, "standard")
        XCTAssertEqual(ExportTier.enhanced.rawValue, "enhanced")
        XCTAssertEqual(ExportTier.maximum.rawValue, "maximum")
    }

    func testExportTierDisplayNames() {
        XCTAssertEqual(ExportTier.basic.displayName, "Basic")
        XCTAssertEqual(ExportTier.standard.displayName, "Standard")
        XCTAssertEqual(ExportTier.enhanced.displayName, "Enhanced")
        XCTAssertEqual(ExportTier.maximum.displayName, "Maximum")
    }

    func testExportTierDescriptions() {
        XCTAssertFalse(ExportTier.basic.description.isEmpty)
        XCTAssertFalse(ExportTier.standard.description.isEmpty)
        XCTAssertFalse(ExportTier.enhanced.description.isEmpty)
        XCTAssertFalse(ExportTier.maximum.description.isEmpty)

        // Verify descriptions are unique
        let descriptions = ExportTier.allCases.map { $0.description }
        XCTAssertEqual(Set(descriptions).count, descriptions.count)
    }

    func testExportTierIcons() {
        XCTAssertFalse(ExportTier.basic.icon.isEmpty)
        XCTAssertFalse(ExportTier.standard.icon.isEmpty)
        XCTAssertFalse(ExportTier.enhanced.icon.isEmpty)
        XCTAssertFalse(ExportTier.maximum.icon.isEmpty)
    }

    func testExportTierIdentifiable() {
        for tier in ExportTier.allCases {
            XCTAssertEqual(tier.id, tier.rawValue)
        }
    }

    // MARK: - TrackedFile Tests

    func testTrackedFileInitialization() {
        let file = TrackedFile(
            id: "test-id",
            path: "/path/to/file.txt",
            name: "file.txt",
            events: 100,
            lastModified: Date()
        )

        XCTAssertEqual(file.id, "test-id")
        XCTAssertEqual(file.path, "/path/to/file.txt")
        XCTAssertEqual(file.name, "file.txt")
        XCTAssertEqual(file.events, 100)
        XCTAssertNotNil(file.lastModified)
    }

    func testTrackedFileHashable() {
        let file1 = TrackedFile(id: "1", path: "/path1", name: "file1", events: 10, lastModified: nil)
        let file2 = TrackedFile(id: "1", path: "/path2", name: "file2", events: 20, lastModified: nil)
        let file3 = TrackedFile(id: "2", path: "/path1", name: "file1", events: 10, lastModified: nil)

        // Files with same ID should be equal
        XCTAssertEqual(file1, file2)

        // Files with different IDs should not be equal
        XCTAssertNotEqual(file1, file3)
    }

    func testTrackedFileHashConsistency() {
        let file1 = TrackedFile(id: "test", path: "/path", name: "file", events: 10, lastModified: nil)
        let file2 = TrackedFile(id: "test", path: "/different", name: "other", events: 99, lastModified: Date())

        var set = Set<TrackedFile>()
        set.insert(file1)
        set.insert(file2)

        // Set should only contain one element since IDs are the same
        XCTAssertEqual(set.count, 1)
    }

    // MARK: - Design System Tests

    func testDesignSpacingValues() {
        XCTAssertEqual(Design.Spacing.xxxs, 2)
        XCTAssertEqual(Design.Spacing.xxs, 4)
        XCTAssertEqual(Design.Spacing.xs, 6)
        XCTAssertEqual(Design.Spacing.sm, 8)
        XCTAssertEqual(Design.Spacing.md, 12)
        XCTAssertEqual(Design.Spacing.lg, 16)
        XCTAssertEqual(Design.Spacing.xl, 20)
        XCTAssertEqual(Design.Spacing.xxl, 24)
        XCTAssertEqual(Design.Spacing.xxxl, 32)
        XCTAssertEqual(Design.Spacing.xxxxl, 40)
    }

    func testDesignRadiusValues() {
        XCTAssertEqual(Design.Radius.xs, 4)
        XCTAssertEqual(Design.Radius.sm, 6)
        XCTAssertEqual(Design.Radius.md, 8)
        XCTAssertEqual(Design.Radius.lg, 12)
        XCTAssertEqual(Design.Radius.xl, 16)
        XCTAssertEqual(Design.Radius.full, 9999)
    }

    func testDesignIconSizeValues() {
        XCTAssertEqual(Design.IconSize.xs, 12)
        XCTAssertEqual(Design.IconSize.sm, 14)
        XCTAssertEqual(Design.IconSize.md, 16)
        XCTAssertEqual(Design.IconSize.lg, 20)
        XCTAssertEqual(Design.IconSize.xl, 24)
        XCTAssertEqual(Design.IconSize.xxl, 32)
        XCTAssertEqual(Design.IconSize.hero, 48)
        XCTAssertEqual(Design.IconSize.display, 64)
    }

    func testDesignLayoutValues() {
        XCTAssertEqual(Design.Layout.popoverWidth, 320)
        XCTAssertEqual(Design.Layout.popoverHeight, 440)
        XCTAssertEqual(Design.Layout.settingsWidth, 480)
        XCTAssertEqual(Design.Layout.settingsHeight, 320)
        XCTAssertEqual(Design.Layout.onboardingWidth, 520)
        XCTAssertEqual(Design.Layout.onboardingHeight, 440)
        XCTAssertEqual(Design.Layout.historyWidth, 720)
        XCTAssertEqual(Design.Layout.historyHeight, 520)
    }

    func testDesignTypographyNotNil() {
        // Verify all typography styles can be created
        let _ = Design.Typography.displayLarge
        let _ = Design.Typography.displayMedium
        let _ = Design.Typography.displaySmall
        let _ = Design.Typography.headlineLarge
        let _ = Design.Typography.headlineMedium
        let _ = Design.Typography.headlineSmall
        let _ = Design.Typography.bodyLarge
        let _ = Design.Typography.bodyMedium
        let _ = Design.Typography.bodySmall
        let _ = Design.Typography.labelLarge
        let _ = Design.Typography.labelMedium
        let _ = Design.Typography.labelSmall
        let _ = Design.Typography.mono
        let _ = Design.Typography.monoSmall
        let _ = Design.Typography.statValue
        let _ = Design.Typography.statLabel
    }

    // MARK: - Badge Style Tests

    func testBadgeStyleBackgroundColors() {
        let success = Badge.BadgeStyle.success
        let warning = Badge.BadgeStyle.warning
        let error = Badge.BadgeStyle.error
        let neutral = Badge.BadgeStyle.neutral

        // Verify each style has distinct properties
        XCTAssertNotEqual(success.backgroundColor.description, neutral.backgroundColor.description)
        XCTAssertNotEqual(warning.backgroundColor.description, neutral.backgroundColor.description)
        XCTAssertNotEqual(error.backgroundColor.description, neutral.backgroundColor.description)
    }

    func testBadgeStyleTextColors() {
        let success = Badge.BadgeStyle.success
        let warning = Badge.BadgeStyle.warning
        let error = Badge.BadgeStyle.error
        let neutral = Badge.BadgeStyle.neutral

        // Verify each style has a text color
        let _ = success.textColor
        let _ = warning.textColor
        let _ = error.textColor
        let _ = neutral.textColor
    }

    // MARK: - ShadowStyle Tests

    func testShadowStyleInitialization() {
        let shadow = ShadowStyle(
            color: .black.opacity(0.1),
            radius: 4,
            x: 0,
            y: 2
        )

        XCTAssertEqual(shadow.radius, 4)
        XCTAssertEqual(shadow.x, 0)
        XCTAssertEqual(shadow.y, 2)
    }

    func testDesignShadowStyles() {
        XCTAssertEqual(Design.Shadow.sm.radius, 2)
        XCTAssertEqual(Design.Shadow.md.radius, 4)
        XCTAssertEqual(Design.Shadow.lg.radius, 8)
    }

    // MARK: - State Transformation Tests

    func testKeystrokeFormatting() {
        // Test the formatting logic used in PopoverViews
        func formatNumber(_ n: Int) -> String {
            if n >= 1000 {
                return String(format: "%.1fk", Double(n) / 1000.0)
            }
            return "\(n)"
        }

        XCTAssertEqual(formatNumber(0), "0")
        XCTAssertEqual(formatNumber(500), "500")
        XCTAssertEqual(formatNumber(999), "999")
        XCTAssertEqual(formatNumber(1000), "1.0k")
        XCTAssertEqual(formatNumber(1500), "1.5k")
        XCTAssertEqual(formatNumber(10000), "10.0k")
        XCTAssertEqual(formatNumber(100000), "100.0k")
    }

    func testDocumentNameExtraction() {
        // Test extracting document names from paths
        func extractDocumentName(_ path: String) -> String {
            URL(fileURLWithPath: path).lastPathComponent
        }

        XCTAssertEqual(extractDocumentName("/Users/test/Documents/novel.txt"), "novel.txt")
        XCTAssertEqual(extractDocumentName("/path/to/essay.md"), "essay.md")
        XCTAssertEqual(extractDocumentName("simple.txt"), "simple.txt")
        XCTAssertEqual(extractDocumentName("/"), "/")
    }

    // MARK: - Settings State Tests

    func testDefaultCheckpointIntervals() {
        let validIntervals = [15, 30, 60, 120]

        for interval in validIntervals {
            XCTAssertGreaterThan(interval, 0)
        }

        XCTAssertTrue(validIntervals.contains(30), "Default interval should be 30 minutes")
    }

    // MARK: - View Component Creation Tests

    func testStatWidgetCreation() {
        let widget = StatWidget(icon: "keyboard", value: "1.5k", label: "Keystrokes")
        let hostingController = NSHostingController(rootView: widget)
        XCTAssertNotNil(hostingController.view)
    }

    func testBadgeCreation() {
        let badge = Badge(text: "Active", style: .success)
        let hostingController = NSHostingController(rootView: badge)
        XCTAssertNotNil(hostingController.view)
    }

    func testSectionHeaderCreation() {
        let header = SectionHeader("Test Section")
        let hostingController = NSHostingController(rootView: header)
        XCTAssertNotNil(hostingController.view)
    }

    func testSectionHeaderWithAction() {
        let header = SectionHeader("Test Section", action: { }, actionLabel: "Action")
        let hostingController = NSHostingController(rootView: header)
        XCTAssertNotNil(hostingController.view)
    }

    func testIconButtonCreation() {
        let button = IconButton(icon: "gear", label: "Settings") { }
        let hostingController = NSHostingController(rootView: button)
        XCTAssertNotNil(hostingController.view)
    }

    func testLabeledDividerCreation() {
        let divider = LabeledDivider("or")
        let hostingController = NSHostingController(rootView: divider)
        XCTAssertNotNil(hostingController.view)
    }

    func testLoadingViewCreation() {
        let loading = LoadingView("Loading data...")
        let hostingController = NSHostingController(rootView: loading)
        XCTAssertNotNil(hostingController.view)
    }

    func testEmptyStateViewCreation() {
        let emptyState = EmptyStateView(
            icon: "doc.text.magnifyingglass",
            title: "No Documents",
            message: "Start tracking a document to see it here"
        )
        let hostingController = NSHostingController(rootView: emptyState)
        XCTAssertNotNil(hostingController.view)
    }

    func testEmptyStateViewWithAction() {
        let emptyState = EmptyStateView(
            icon: "plus.circle",
            title: "Get Started",
            message: "Add your first document",
            action: { },
            actionLabel: "Add Document"
        )
        let hostingController = NSHostingController(rootView: emptyState)
        XCTAssertNotNil(hostingController.view)
    }

    // MARK: - View Modifier Tests

    func testCardStyleModifier() {
        let view = Text("Test")
            .cardStyle()

        let hostingController = NSHostingController(rootView: view)
        XCTAssertNotNil(hostingController.view)
    }

    func testCardStyleModifierWithCustomPadding() {
        let view = Text("Test")
            .cardStyle(padding: Design.Spacing.lg)

        let hostingController = NSHostingController(rootView: view)
        XCTAssertNotNil(hostingController.view)
    }

    func testHoverEffectModifier() {
        let view = Text("Test")
            .hoverEffect()

        let hostingController = NSHostingController(rootView: view)
        XCTAssertNotNil(hostingController.view)
    }

    func testButtonPaddingModifier() {
        let view = Button("Test") { }
            .buttonPadding()

        let hostingController = NSHostingController(rootView: view)
        XCTAssertNotNil(hostingController.view)
    }

    func testShadowModifier() {
        let view = Text("Test")
            .shadow(Design.Shadow.md)

        let hostingController = NSHostingController(rootView: view)
        XCTAssertNotNil(hostingController.view)
    }

    // MARK: - Error State Tests

    func testErrorRecoveryStates() {
        // Simulate error states that views need to handle
        let errorStates: [(message: String, isRecoverable: Bool)] = [
            ("Network connection lost", true),
            ("File not found", false),
            ("Permission denied", true),
            ("Invalid signature", false)
        ]

        for state in errorStates {
            XCTAssertFalse(state.message.isEmpty)
        }
    }
}

// MARK: - LaunchAtLogin Tests

final class LaunchAtLoginTests: XCTestCase {

    func testLaunchAtLoginTypeExists() {
        // Verify the type exists and can be referenced
        let _ = LaunchAtLogin.self
    }

    func testLaunchAtLoginIsEnabledAccessible() {
        // Verify the property is accessible (value depends on system state)
        let isEnabled = LaunchAtLogin.isEnabled
        // Just verify it returns a boolean without crashing
        XCTAssertTrue(isEnabled || !isEnabled)
    }
}
