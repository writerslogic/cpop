import XCTest
import SwiftUI
@testable import witnessd

/// Performance tests for view rendering and memory usage
final class PerformanceTests: XCTestCase {

    // MARK: - View Creation Performance

    func testPopoverContentViewCreationPerformance() {
        // Note: In real tests, we would inject the bridge dependency
        // This tests that view creation doesn't have performance issues

        measure {
            for _ in 0..<100 {
                let _ = StatWidget(icon: "keyboard", value: "1000", label: "Keystrokes")
            }
        }
    }

    func testBadgeCreationPerformance() {
        measure {
            for _ in 0..<1000 {
                let _ = Badge(text: "Active", style: .success)
            }
        }
    }

    func testIconButtonCreationPerformance() {
        measure {
            for _ in 0..<500 {
                let _ = IconButton(icon: "gear", label: "Settings") { }
            }
        }
    }

    func testSectionHeaderCreationPerformance() {
        measure {
            for _ in 0..<500 {
                let _ = SectionHeader("Test Section", action: nil, actionLabel: nil)
            }
        }
    }

    // MARK: - Design System Performance

    func testDesignTokenAccessPerformance() {
        measure {
            for _ in 0..<10000 {
                let _ = Design.Spacing.md
                let _ = Design.Radius.lg
                let _ = Design.IconSize.xl
                let _ = Design.Layout.popoverWidth
            }
        }
    }

    func testColorAccessPerformance() {
        measure {
            for _ in 0..<5000 {
                let _ = Design.Colors.primaryText
                let _ = Design.Colors.secondaryText
                let _ = Design.Colors.success
                let _ = Design.Colors.warning
                let _ = Design.Colors.error
            }
        }
    }

    func testTypographyAccessPerformance() {
        measure {
            for _ in 0..<5000 {
                let _ = Design.Typography.displayLarge
                let _ = Design.Typography.headlineMedium
                let _ = Design.Typography.bodyMedium
                let _ = Design.Typography.labelSmall
                let _ = Design.Typography.mono
            }
        }
    }

    // MARK: - TrackedFile Performance

    func testTrackedFileCreationPerformance() {
        measure {
            for i in 0..<10000 {
                let _ = TrackedFile(
                    id: "file-\(i)",
                    path: "/path/to/file-\(i).txt",
                    name: "file-\(i).txt",
                    events: i,
                    lastModified: Date()
                )
            }
        }
    }

    func testTrackedFileHashPerformance() {
        let files = PerformanceTestHelper.generateMockTrackedFiles(count: 1000)

        measure {
            var set = Set<TrackedFile>()
            for file in files {
                set.insert(file)
            }
        }
    }

    func testTrackedFileComparisonPerformance() {
        let files = PerformanceTestHelper.generateMockTrackedFiles(count: 1000)

        measure {
            for i in 0..<files.count - 1 {
                let _ = files[i] == files[i + 1]
            }
        }
    }

    // MARK: - Large History List Performance

    func testLargeFileListFilterPerformance() {
        let files = PerformanceTestHelper.generateMockTrackedFiles(count: 10000)

        measure {
            let filtered = files.filter { $0.events > 500 }
            XCTAssertGreaterThan(filtered.count, 0)
        }
    }

    func testLargeFileListSortPerformance() {
        let files = PerformanceTestHelper.generateMockTrackedFiles(count: 10000)

        measure {
            let sorted = files.sorted { $0.events > $1.events }
            XCTAssertEqual(sorted.count, files.count)
        }
    }

    func testLargeFileListSearchPerformance() {
        let files = PerformanceTestHelper.generateMockTrackedFiles(count: 10000)
        let searchTerm = "file-500"

        measure {
            let results = files.filter { $0.name.contains(searchTerm) }
            XCTAssertGreaterThan(results.count, 0)
        }
    }

    // MARK: - View Hosting Performance

    func testViewHostingCreationPerformance() {
        measure {
            for _ in 0..<100 {
                let view = Text("Test")
                    .cardStyle()
                    .padding()
                let controller = NSHostingController(rootView: view)
                XCTAssertNotNil(controller.view)
            }
        }
    }

    // MARK: - ExportTier Performance

    func testExportTierEnumerationPerformance() {
        measure {
            for _ in 0..<10000 {
                for tier in ExportTier.allCases {
                    let _ = tier.displayName
                    let _ = tier.description
                    let _ = tier.icon
                }
            }
        }
    }

    // MARK: - Status Update Performance

    func testStatusParsingPerformance() {
        let sampleOutput = """
        Data directory: /Users/test/.witnessd
        VDF iterations/sec: 1000000
        TPM: available (T2 Security Chip)
        Events: 12500
        Files tracked: 25
        """

        measure {
            for _ in 0..<1000 {
                // Simulate parsing status output
                let _ = sampleOutput.contains("Data directory:")
                let _ = sampleOutput.range(of: #"VDF iterations/sec: (\d+)"#, options: .regularExpression)
                let _ = sampleOutput.contains("TPM: available")
                let _ = sampleOutput.range(of: #"Events: (\d+)"#, options: .regularExpression)
            }
        }
    }

    // MARK: - Keystroke Formatting Performance

    func testKeystrokeFormattingPerformance() {
        func formatNumber(_ n: Int) -> String {
            if n >= 1000 {
                return String(format: "%.1fk", Double(n) / 1000.0)
            }
            return "\(n)"
        }

        measure {
            for i in 0..<100000 {
                let _ = formatNumber(i)
            }
        }
    }

    // MARK: - Path Processing Performance

    func testPathProcessingPerformance() {
        let paths = (0..<1000).map { "/Users/test/Documents/file-\($0).txt" }

        measure {
            for path in paths {
                let url = URL(fileURLWithPath: path)
                let _ = url.lastPathComponent
                let _ = url.deletingPathExtension()
                let _ = url.pathExtension
            }
        }
    }

    // MARK: - Memory Performance

    func testLargeTrackedFileListMemory() {
        // Test memory usage with large number of tracked files
        let startMemory = getMemoryUsage()

        var files: [TrackedFile] = []
        for i in 0..<100000 {
            files.append(TrackedFile(
                id: "file-\(i)",
                path: "/path/to/file-\(i).txt",
                name: "file-\(i).txt",
                events: i,
                lastModified: nil
            ))
        }

        let endMemory = getMemoryUsage()
        let memoryUsed = endMemory - startMemory

        // Verify we have all files
        XCTAssertEqual(files.count, 100000)

        // Memory usage should be reasonable (less than 100MB for 100k files)
        XCTAssertLessThan(memoryUsed, 100 * 1024 * 1024, "Memory usage too high: \(memoryUsed / 1024 / 1024)MB")
    }

    // MARK: - Helper Methods

    private func getMemoryUsage() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? info.resident_size : 0
    }
}

// MARK: - View Rendering Performance Tests

final class ViewRenderingPerformanceTests: XCTestCase {

    func testBadgeRenderingPerformance() {
        let badges: [Badge] = Badge.BadgeStyle.allCases.map { Badge(text: "Test", style: $0) }

        measure {
            for badge in badges {
                let controller = NSHostingController(rootView: badge)
                XCTAssertNotNil(controller.view)
            }
        }
    }

    func testNestedViewHierarchyPerformance() {
        measure {
            let view = VStack {
                ForEach(0..<50, id: \.self) { _ in
                    HStack {
                        Image(systemName: "doc.text")
                        Text("Document")
                        Spacer()
                        Badge(text: "Active", style: .success)
                    }
                    .padding()
                }
            }

            let controller = NSHostingController(rootView: view)
            XCTAssertNotNil(controller.view)
        }
    }
}

// MARK: - Badge.BadgeStyle CaseIterable Conformance

extension Badge.BadgeStyle: CaseIterable {
    static var allCases: [Badge.BadgeStyle] {
        return [.success, .warning, .error, .neutral]
    }
}
