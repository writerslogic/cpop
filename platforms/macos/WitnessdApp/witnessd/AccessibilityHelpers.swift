import SwiftUI

// MARK: - Accessibility Environment Values

extension EnvironmentValues {
    /// Convenience accessor for reduced motion preference
    var prefersReducedMotion: Bool {
        accessibilityReduceMotion
    }

    /// Convenience accessor for differentiate without color
    var differentiateWithoutColor: Bool {
        accessibilityDifferentiateWithoutColor
    }

    /// Convenience accessor for increased contrast
    var increasedContrast: Bool {
        accessibilityDisplayShouldIncreaseContrast
    }
}

// Helper to check if increased contrast is enabled
private extension EnvironmentValues {
    var accessibilityDisplayShouldIncreaseContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    /// Convenience accessor for VoiceOver running
    var isVoiceOverRunning: Bool {
        accessibilityVoiceOverEnabled
    }
}

// MARK: - Accessible Animation

/// Animation that respects reduced motion preference
enum AccessibleAnimation {
    /// Returns animation appropriate for accessibility settings
    static func standard(duration: Double = 0.2) -> Animation? {
        if NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            return nil
        }
        return .easeInOut(duration: duration)
    }

    /// Performs animation respecting accessibility preferences
    static func withAccessibleAnimation<Result>(
        _ animation: Animation? = .easeInOut(duration: 0.2),
        _ body: () throws -> Result
    ) rethrows -> Result {
        if NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            return try body()
        }
        return try withAnimation(animation, body)
    }
}

// MARK: - Accessible Status Indicator

/// A status indicator that works without color alone
struct AccessibleStatusIndicator: View {
    let isActive: Bool
    let activeLabel: String
    let inactiveLabel: String

    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        HStack(spacing: 4) {
            if differentiateWithoutColor {
                // Use icons instead of/alongside color
                Image(systemName: isActive ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(isActive ? .green : .secondary)
                    .font(.system(size: 10))
            } else {
                Circle()
                    .fill(isActive ? Color.green : Color.gray.opacity(0.3))
                    .frame(width: 8, height: 8)
            }

            // Always provide text label for screen readers
            Text(isActive ? activeLabel : inactiveLabel)
                .font(.caption2)
                .foregroundColor(.secondary)
                .accessibilityHidden(true) // The whole component has its own label
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(isActive ? activeLabel : inactiveLabel)
        .accessibilityValue(isActive ? "Active" : "Inactive")
    }
}

// MARK: - View Extensions for Accessibility

extension View {
    /// Adds comprehensive accessibility information to a button
    func accessibleButton(
        label: String,
        hint: String? = nil,
        identifier: String? = nil
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityHint(hint ?? "")
            .accessibilityAddTraits(.isButton)
            .accessibilityIdentifier(identifier ?? label.lowercased().replacingOccurrences(of: " ", with: "-"))
    }

    /// Adds accessibility for a header element
    func accessibleHeader(_ label: String) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityAddTraits(.isHeader)
    }

    /// Adds accessibility for a static text element
    func accessibleText(_ description: String? = nil) -> some View {
        self
            .accessibilityLabel(description ?? "")
            .accessibilityAddTraits(.isStaticText)
    }

    /// Adds accessibility for an image with description
    func accessibleImage(_ description: String) -> some View {
        self
            .accessibilityLabel(description)
            .accessibilityAddTraits(.isImage)
    }

    /// Groups elements for VoiceOver navigation
    func accessibleGroup(label: String, hint: String? = nil) -> some View {
        self
            .accessibilityElement(children: .combine)
            .accessibilityLabel(label)
            .accessibilityHint(hint ?? "")
    }

    /// Makes element a landmark for navigation
    func accessibleLandmark(_ label: String) -> some View {
        self
            .accessibilityElement(children: .contain)
            .accessibilityLabel(label)
    }

    /// Animation that respects reduced motion
    func accessibleAnimation<V: Equatable>(
        _ animation: Animation? = .easeInOut,
        value: V
    ) -> some View {
        self.modifier(AccessibleAnimationModifier(animation: animation, value: value))
    }
}

struct AccessibleAnimationModifier<V: Equatable>: ViewModifier {
    let animation: Animation?
    let value: V

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        if reduceMotion {
            content
        } else {
            content.animation(animation, value: value)
        }
    }
}

// MARK: - Accessibility Announcements

class AccessibilityAnnouncer {
    static let shared = AccessibilityAnnouncer()

    private init() {}

    /// Announces a message to VoiceOver users
    func announce(_ message: String, highPriority: Bool = false) {
        let priority: Int = highPriority ? 1 : 0
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                NSAccessibility.NotificationUserInfoKey.announcement: message,
                NSAccessibility.NotificationUserInfoKey.priority: NSNumber(value: priority)
            ]
        )
    }

    /// Announces completion of an action
    func announceCompletion(_ action: String, success: Bool) {
        let message = success ? "\(action) completed successfully" : "\(action) failed"
        announce(message, highPriority: !success)
    }
}

// MARK: - Focus Management

extension View {
    /// Manages focus for keyboard navigation
    @ViewBuilder
    func focusableElement(
        isFocused: FocusState<Bool>.Binding,
        onFocus: (() -> Void)? = nil
    ) -> some View {
        self
            .focusable()
            .focused(isFocused)
            .onChange(of: isFocused.wrappedValue) { focused in
                if focused {
                    onFocus?()
                }
            }
    }
}

// MARK: - High Contrast Support

extension Color {
    /// Returns a color adjusted for increased contrast if needed
    static func adaptiveColor(
        normal: Color,
        highContrast: Color
    ) -> Color {
        if NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast {
            return highContrast
        }
        return normal
    }
}

// MARK: - Semantic Colors for Accessibility

extension Color {
    /// Accessible success color with sufficient contrast
    static var accessibleSuccess: Color {
        Color.adaptiveColor(
            normal: .green,
            highContrast: Color(red: 0.0, green: 0.6, blue: 0.0)
        )
    }

    /// Accessible warning color with sufficient contrast
    static var accessibleWarning: Color {
        Color.adaptiveColor(
            normal: .orange,
            highContrast: Color(red: 0.8, green: 0.4, blue: 0.0)
        )
    }

    /// Accessible error color with sufficient contrast
    static var accessibleError: Color {
        Color.adaptiveColor(
            normal: .red,
            highContrast: Color(red: 0.8, green: 0.0, blue: 0.0)
        )
    }
}
