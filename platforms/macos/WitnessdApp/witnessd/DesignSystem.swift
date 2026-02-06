import SwiftUI

// MARK: - Design Tokens

/// Centralized design system for consistent styling across the app
enum Design {
    // MARK: - Spacing Scale (4px base unit)
    enum Spacing {
        static let xxxs: CGFloat = 2
        static let xxs: CGFloat = 4
        static let xs: CGFloat = 6
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 20
        static let xxl: CGFloat = 24
        static let xxxl: CGFloat = 32
        static let xxxxl: CGFloat = 40
    }

    // MARK: - Corner Radius
    enum Radius {
        static let xs: CGFloat = 4
        static let sm: CGFloat = 6
        static let md: CGFloat = 8
        static let lg: CGFloat = 12
        static let xl: CGFloat = 16
        static let full: CGFloat = 9999
    }

    // MARK: - Icon Sizes
    enum IconSize {
        static let xs: CGFloat = 12
        static let sm: CGFloat = 14
        static let md: CGFloat = 16
        static let lg: CGFloat = 20
        static let xl: CGFloat = 24
        static let xxl: CGFloat = 32
        static let hero: CGFloat = 48
        static let display: CGFloat = 64
    }

    // MARK: - Typography
    enum Typography {
        static let displayLarge = Font.system(size: 34, weight: .bold, design: .default)
        static let displayMedium = Font.system(size: 28, weight: .bold, design: .default)
        static let displaySmall = Font.system(size: 22, weight: .bold, design: .default)

        static let headlineLarge = Font.system(size: 17, weight: .semibold, design: .default)
        static let headlineMedium = Font.system(size: 15, weight: .semibold, design: .default)
        static let headlineSmall = Font.system(size: 13, weight: .semibold, design: .default)

        static let bodyLarge = Font.system(size: 15, weight: .regular, design: .default)
        static let bodyMedium = Font.system(size: 13, weight: .regular, design: .default)
        static let bodySmall = Font.system(size: 11, weight: .regular, design: .default)

        static let labelLarge = Font.system(size: 13, weight: .medium, design: .default)
        static let labelMedium = Font.system(size: 11, weight: .medium, design: .default)
        static let labelSmall = Font.system(size: 10, weight: .medium, design: .default)

        static let mono = Font.system(size: 12, weight: .regular, design: .monospaced)
        static let monoSmall = Font.system(size: 11, weight: .regular, design: .monospaced)

        static let statValue = Font.system(size: 15, weight: .semibold, design: .rounded)
        static let statLabel = Font.system(size: 10, weight: .medium, design: .default)
    }

    // MARK: - Semantic Colors
    enum Colors {
        // Status colors
        static let success = Color.green
        static let warning = Color.orange
        static let error = Color.red
        static let info = Color.blue

        // UI colors
        static let primaryText = Color(nsColor: .labelColor)
        static let secondaryText = Color(nsColor: .secondaryLabelColor)
        static let tertiaryText = Color(nsColor: .tertiaryLabelColor)

        static let background = Color(nsColor: .windowBackgroundColor)
        static let secondaryBackground = Color(nsColor: .controlBackgroundColor)
        static let tertiaryBackground = Color(nsColor: .underPageBackgroundColor)

        static let separator = Color(nsColor: .separatorColor)
        static let border = Color(nsColor: .separatorColor)

        // Interactive states
        static let hover = Color(nsColor: .controlAccentColor).opacity(0.1)
        static let pressed = Color(nsColor: .controlAccentColor).opacity(0.2)

        // Brand gradient
        static let brandGradient = LinearGradient(
            colors: [.blue, .purple],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    // MARK: - Shadows
    enum Shadow {
        static let sm = ShadowStyle(color: .black.opacity(0.08), radius: 2, x: 0, y: 1)
        static let md = ShadowStyle(color: .black.opacity(0.1), radius: 4, x: 0, y: 2)
        static let lg = ShadowStyle(color: .black.opacity(0.12), radius: 8, x: 0, y: 4)
    }

    // MARK: - Animation
    enum Animation {
        static let fast = SwiftUI.Animation.easeOut(duration: 0.15)
        static let normal = SwiftUI.Animation.easeInOut(duration: 0.2)
        static let slow = SwiftUI.Animation.easeInOut(duration: 0.3)
        static let spring = SwiftUI.Animation.spring(response: 0.3, dampingFraction: 0.7)
    }

    // MARK: - Layout
    enum Layout {
        static let popoverWidth: CGFloat = 320
        static let popoverHeight: CGFloat = 440
        static let settingsWidth: CGFloat = 480
        static let settingsHeight: CGFloat = 320
        static let onboardingWidth: CGFloat = 520
        static let onboardingHeight: CGFloat = 440
        static let historyWidth: CGFloat = 720
        static let historyHeight: CGFloat = 520
    }
}

struct ShadowStyle {
    let color: Color
    let radius: CGFloat
    let x: CGFloat
    let y: CGFloat
}

// MARK: - View Extensions

extension View {
    /// Applies consistent card styling
    func cardStyle(padding: CGFloat = Design.Spacing.md) -> some View {
        self
            .padding(padding)
            .background(Design.Colors.secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
    }

    /// Applies consistent section header styling
    func sectionHeader() -> some View {
        self
            .font(Design.Typography.headlineSmall)
            .foregroundColor(Design.Colors.primaryText)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Applies hover effect
    func hoverEffect() -> some View {
        self.modifier(HoverEffectModifier())
    }

    /// Applies consistent button padding
    func buttonPadding() -> some View {
        self.padding(.horizontal, Design.Spacing.md)
            .padding(.vertical, Design.Spacing.sm)
    }

    /// Applies shadow style
    func shadow(_ style: ShadowStyle) -> some View {
        self.shadow(color: style.color, radius: style.radius, x: style.x, y: style.y)
    }
}

struct HoverEffectModifier: ViewModifier {
    @State private var isHovered = false

    func body(content: Content) -> some View {
        content
            .background(isHovered ? Design.Colors.hover : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous))
            .onHover { hovering in
                withAnimation(Design.Animation.fast) {
                    isHovered = hovering
                }
            }
    }
}

// MARK: - Reusable Components

/// Consistent section header
struct SectionHeader: View {
    let title: String
    let action: (() -> Void)?
    let actionLabel: String?

    init(_ title: String, action: (() -> Void)? = nil, actionLabel: String? = nil) {
        self.title = title
        self.action = action
        self.actionLabel = actionLabel
    }

    var body: some View {
        HStack(alignment: .center) {
            Text(title)
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)
                .tracking(0.5)

            Spacer()

            if let action = action, let label = actionLabel {
                Button(action: action) {
                    Text(label)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(.accentColor)
                }
                .buttonStyle(.plain)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// Consistent icon button
struct IconButton: View {
    let icon: String
    let label: String
    let size: CGFloat
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false

    init(icon: String, label: String, size: CGFloat = Design.IconSize.md, action: @escaping () -> Void) {
        self.icon = icon
        self.label = label
        self.size = size
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: size, weight: .medium))
                .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
                .frame(width: size + Design.Spacing.md, height: size + Design.Spacing.md)
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                        .fill(isPressed ? Design.Colors.pressed : (isHovered ? Design.Colors.hover : Color.clear))
                )
                .scaleEffect(isPressed ? 0.95 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .pressEvents { isPressed = true } onRelease: { isPressed = false }
        .accessibilityLabel(label)
        .accessibilityIdentifier(label.lowercased().replacingOccurrences(of: " ", with: "-"))
    }
}

/// Press events modifier
extension View {
    func pressEvents(onPress: @escaping () -> Void, onRelease: @escaping () -> Void) -> some View {
        self.simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in onPress() }
                .onEnded { _ in onRelease() }
        )
    }
}

/// Consistent badge/pill component
struct Badge: View {
    let text: String
    let style: BadgeStyle

    enum BadgeStyle {
        case success, warning, error, neutral

        var backgroundColor: Color {
            switch self {
            case .success: return Design.Colors.success.opacity(0.15)
            case .warning: return Design.Colors.warning.opacity(0.15)
            case .error: return Design.Colors.error.opacity(0.15)
            case .neutral: return Design.Colors.secondaryBackground
            }
        }

        var textColor: Color {
            switch self {
            case .success: return Design.Colors.success
            case .warning: return Design.Colors.warning
            case .error: return Design.Colors.error
            case .neutral: return Design.Colors.secondaryText
            }
        }
    }

    var body: some View {
        Text(text)
            .font(Design.Typography.labelSmall)
            .foregroundColor(style.textColor)
            .padding(.horizontal, Design.Spacing.sm)
            .padding(.vertical, Design.Spacing.xxs)
            .background(
                Capsule()
                    .fill(style.backgroundColor)
            )
    }
}

/// Consistent divider with optional label
struct LabeledDivider: View {
    let label: String?

    init(_ label: String? = nil) {
        self.label = label
    }

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Rectangle()
                .fill(Design.Colors.separator)
                .frame(height: 1)

            if let label = label {
                Text(label)
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.tertiaryText)

                Rectangle()
                    .fill(Design.Colors.separator)
                    .frame(height: 1)
            }
        }
    }
}

/// Loading indicator with optional label
struct LoadingView: View {
    let label: String?

    init(_ label: String? = nil) {
        self.label = label
    }

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            ProgressView()
                .scaleEffect(0.8)

            if let label = label {
                Text(label)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
    }
}

/// Empty state view
struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    let action: (() -> Void)?
    let actionLabel: String?

    init(
        icon: String,
        title: String,
        message: String,
        action: (() -> Void)? = nil,
        actionLabel: String? = nil
    ) {
        self.icon = icon
        self.title = title
        self.message = message
        self.action = action
        self.actionLabel = actionLabel
    }

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.hero))
                .foregroundColor(Design.Colors.tertiaryText)

            VStack(spacing: Design.Spacing.xs) {
                Text(title)
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.primaryText)

                Text(message)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
            }

            if let action = action, let label = actionLabel {
                Button(action: action) {
                    Text(label)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
            }
        }
        .padding(Design.Spacing.xxxl)
    }
}
