import SwiftUI
import ApplicationServices
import AppKit

struct OnboardingView: View {
    @Binding var isPresented: Bool
    let bridge: WitnessdBridge
    let onComplete: () -> Void

    @State private var currentStep = 0
    @State private var isInitializing = false
    @State private var isCalibrating = false
    @State private var initComplete = false
    @State private var accessibilityGranted = false
    @State private var calibrateComplete = false
    @State private var error: String? = nil
    @State private var accessibilityCheckTimer: Timer? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let steps = ["Welcome", "Initialize", "Accessibility", "Calibrate"]

    var body: some View {
        VStack(spacing: 0) {
            // Progress header
            progressHeader
                .padding(.top, Design.Spacing.xl)
                .padding(.bottom, Design.Spacing.lg)

            // Content
            TabView(selection: $currentStep) {
                welcomeStep.tag(0)
                initializeStep.tag(1)
                accessibilityStep.tag(2)
                calibrateStep.tag(3)
            }
            .tabViewStyle(.automatic)

            // Navigation footer
            navigationFooter
                .padding(Design.Spacing.xl)
        }
        .frame(width: Design.Layout.onboardingWidth, height: Design.Layout.onboardingHeight)
        .background(Design.Colors.background)
    }

    // MARK: - Progress Header

    private var progressHeader: some View {
        HStack(spacing: Design.Spacing.sm) {
            ForEach(0..<steps.count, id: \.self) { index in
                HStack(spacing: Design.Spacing.xs) {
                    // Step indicator
                    ZStack {
                        Circle()
                            .fill(stepColor(for: index))
                            .frame(width: 24, height: 24)

                        if index < currentStep {
                            Image(systemName: "checkmark")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.white)
                        } else {
                            Text("\(index + 1)")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(index == currentStep ? .white : Design.Colors.secondaryText)
                        }
                    }

                    // Step label
                    if index == currentStep {
                        Text(steps[index])
                            .font(Design.Typography.labelMedium)
                            .foregroundColor(Design.Colors.primaryText)
                    }
                }

                // Connector line
                if index < steps.count - 1 {
                    Rectangle()
                        .fill(index < currentStep ? Color.accentColor : Design.Colors.separator)
                        .frame(width: 32, height: 2)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Step \(currentStep + 1) of \(steps.count): \(steps[currentStep])")
    }

    private func stepColor(for index: Int) -> Color {
        if index < currentStep {
            return .accentColor
        } else if index == currentStep {
            return .accentColor
        } else {
            return Design.Colors.separator
        }
    }

    // MARK: - Welcome Step

    private var welcomeStep: some View {
        VStack(spacing: Design.Spacing.xxl) {
            Spacer()

            // Hero icon
            ZStack {
                Circle()
                    .fill(Design.Colors.brandGradient.opacity(0.15))
                    .frame(width: 120, height: 120)

                Image(systemName: "eye.circle.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(Design.Colors.brandGradient)
            }
            .accessibilityHidden(true)

            // Title and subtitle
            VStack(spacing: Design.Spacing.sm) {
                Text("Welcome to Witnessd")
                    .font(Design.Typography.displayMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .accessibilityAddTraits(.isHeader)

                Text("Create unforgeable cryptographic proof\nthat you authored your documents over time.")
                    .font(Design.Typography.bodyLarge)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Feature list
            VStack(spacing: Design.Spacing.md) {
                FeatureItem(
                    icon: "keyboard",
                    title: "Track Keystrokes",
                    description: "Count-only, never content"
                )

                FeatureItem(
                    icon: "clock.badge.checkmark",
                    title: "Prove Time",
                    description: "VDF-backed timing proofs"
                )

                FeatureItem(
                    icon: "signature",
                    title: "Sign Evidence",
                    description: "Cryptographic signatures"
                )
            }
            .padding(.horizontal, Design.Spacing.xxxl)

            Spacer()
        }
        .padding(.horizontal, Design.Spacing.xl)
    }

    // MARK: - Initialize Step

    private var initializeStep: some View {
        VStack(spacing: Design.Spacing.xxl) {
            Spacer()

            if initComplete {
                successState(
                    icon: "checkmark.circle.fill",
                    title: "Initialized!",
                    message: "Your signing key and database are ready."
                )
            } else if isInitializing {
                loadingState(message: "Creating signing key...")
            } else {
                actionState(
                    icon: "key.fill",
                    iconColor: .orange,
                    title: "Initialize Witnessd",
                    message: "This creates your signing key and secure database.\nYour key never leaves your device.",
                    buttonIcon: "wand.and.stars",
                    buttonLabel: "Initialize",
                    action: initialize
                )
            }

            if let error = error {
                errorBanner(message: error)
            }

            Spacer()
        }
        .padding(.horizontal, Design.Spacing.xl)
    }

    // MARK: - Accessibility Step

    private var accessibilityStep: some View {
        VStack(spacing: Design.Spacing.xxl) {
            Spacer()

            if accessibilityGranted {
                successState(
                    icon: "checkmark.circle.fill",
                    title: "Permission Granted!",
                    message: "Witnessd can now count your keystrokes for authorship proof."
                )
            } else {
                VStack(spacing: Design.Spacing.xl) {
                    ZStack {
                        Circle()
                            .fill(Color.purple.opacity(0.15))
                            .frame(width: 100, height: 100)

                        Image(systemName: "hand.raised.fill")
                            .font(.system(size: 44))
                            .foregroundColor(.purple)
                    }
                    .accessibilityHidden(true)

                    VStack(spacing: Design.Spacing.sm) {
                        Text("Accessibility Permission")
                            .font(Design.Typography.displaySmall)
                            .foregroundColor(Design.Colors.primaryText)
                            .accessibilityAddTraits(.isHeader)

                        Text("Keystroke tracking requires Accessibility access.\nWitnessd counts keystrokes only—it does NOT\nrecord which keys you press.")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(Design.Colors.secondaryText)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Button(action: openAccessibilitySettings) {
                        HStack(spacing: Design.Spacing.sm) {
                            Image(systemName: "gear")
                                .font(.system(size: 14, weight: .semibold))
                            Text("Open System Settings")
                                .font(Design.Typography.headlineMedium)
                        }
                        .frame(width: 220)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .accessibilityIdentifier("open-accessibility-settings")

                    Text("Add Witnessd to the Accessibility list,\nthen return here.")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                        .multilineTextAlignment(.center)
                }
            }

            Spacer()
        }
        .padding(.horizontal, Design.Spacing.xl)
        .onAppear {
            startAccessibilityCheck()
        }
        .onDisappear {
            stopAccessibilityCheck()
        }
    }

    // MARK: - Calibrate Step

    private var calibrateStep: some View {
        VStack(spacing: Design.Spacing.xxl) {
            Spacer()

            if calibrateComplete {
                successState(
                    icon: "checkmark.circle.fill",
                    title: "Calibrated!",
                    message: "VDF timing proofs are now accurate for your machine."
                )
            } else if isCalibrating {
                loadingState(message: "Measuring CPU performance...")
            } else {
                actionState(
                    icon: "speedometer",
                    iconColor: .blue,
                    title: "Calibrate VDF",
                    message: "VDF proves minimum time elapsed.\nCalibration measures your CPU speed for accurate proofs.",
                    buttonIcon: "bolt.fill",
                    buttonLabel: "Calibrate",
                    action: calibrate
                )
            }

            Spacer()
        }
        .padding(.horizontal, Design.Spacing.xl)
    }

    // MARK: - State Views

    private func successState(icon: String, title: String, message: String) -> some View {
        VStack(spacing: Design.Spacing.lg) {
            ZStack {
                Circle()
                    .fill(Design.Colors.success.opacity(0.15))
                    .frame(width: 100, height: 100)

                Image(systemName: icon)
                    .font(.system(size: 48))
                    .foregroundColor(Design.Colors.success)
            }
            .accessibilityHidden(true)

            VStack(spacing: Design.Spacing.sm) {
                Text(title)
                    .font(Design.Typography.displaySmall)
                    .foregroundColor(Design.Colors.primaryText)

                Text(message)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
            }
        }
    }

    private func loadingState(message: String) -> some View {
        VStack(spacing: Design.Spacing.lg) {
            ProgressView()
                .scaleEffect(1.5)
                .frame(width: 100, height: 100)

            Text(message)
                .font(Design.Typography.headlineMedium)
                .foregroundColor(Design.Colors.primaryText)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(message)
    }

    private func actionState(
        icon: String,
        iconColor: Color,
        title: String,
        message: String,
        buttonIcon: String,
        buttonLabel: String,
        action: @escaping () -> Void
    ) -> some View {
        VStack(spacing: Design.Spacing.xl) {
            ZStack {
                Circle()
                    .fill(iconColor.opacity(0.15))
                    .frame(width: 100, height: 100)

                Image(systemName: icon)
                    .font(.system(size: 44))
                    .foregroundColor(iconColor)
            }
            .accessibilityHidden(true)

            VStack(spacing: Design.Spacing.sm) {
                Text(title)
                    .font(Design.Typography.displaySmall)
                    .foregroundColor(Design.Colors.primaryText)
                    .accessibilityAddTraits(.isHeader)

                Text(message)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button(action: action) {
                HStack(spacing: Design.Spacing.sm) {
                    Image(systemName: buttonIcon)
                        .font(.system(size: 14, weight: .semibold))
                    Text(buttonLabel)
                        .font(Design.Typography.headlineMedium)
                }
                .frame(width: 200)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .accessibilityIdentifier(buttonLabel.lowercased())
        }
    }

    private func errorBanner(message: String) -> some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(Design.Colors.error)

            Text(message)
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.error)
        }
        .padding(Design.Spacing.md)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .fill(Design.Colors.error.opacity(0.1))
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Error: \(message)")
    }

    // MARK: - Navigation Footer

    private var navigationFooter: some View {
        HStack {
            if currentStep > 0 {
                Button(action: goBack) {
                    HStack(spacing: Design.Spacing.xs) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 12, weight: .semibold))
                        Text("Back")
                    }
                }
                .buttonStyle(.plain)
                .foregroundColor(Design.Colors.secondaryText)
                .accessibilityIdentifier("onboarding-back")
            }

            Spacer()

            if currentStep < 3 {
                Button(action: goNext) {
                    HStack(spacing: Design.Spacing.xs) {
                        Text("Continue")
                        Image(systemName: "chevron.right")
                            .font(.system(size: 12, weight: .semibold))
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled((currentStep == 1 && !initComplete) || (currentStep == 2 && !accessibilityGranted))
                .accessibilityIdentifier("onboarding-next")
            } else {
                Button(action: complete) {
                    HStack(spacing: Design.Spacing.xs) {
                        Text("Get Started")
                        Image(systemName: "arrow.right")
                            .font(.system(size: 12, weight: .semibold))
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!calibrateComplete)
                .accessibilityIdentifier("onboarding-complete")
            }
        }
    }

    // MARK: - Actions

    private func goBack() {
        withOptionalAnimation {
            currentStep -= 1
        }
    }

    private func goNext() {
        withOptionalAnimation {
            currentStep += 1
        }
    }

    private func complete() {
        isPresented = false
        onComplete()
    }

    private func initialize() {
        isInitializing = true
        error = nil

        Task {
            let result = await bridge.initialize()
            await MainActor.run {
                isInitializing = false
                if result.success {
                    initComplete = true
                    // Check if Accessibility is already granted
                    accessibilityGranted = AXIsProcessTrusted()
                    withOptionalAnimation {
                        currentStep = 2 // Go to Accessibility step
                    }
                } else {
                    error = result.message
                }
            }
        }
    }

    private func openAccessibilitySettings() {
        // Open System Settings > Privacy & Security > Accessibility
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }

    private func startAccessibilityCheck() {
        // Check immediately
        accessibilityGranted = AXIsProcessTrusted()

        // Poll every 2 seconds to detect when user grants permission
        accessibilityCheckTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            let granted = AXIsProcessTrusted()
            if granted != self.accessibilityGranted {
                self.accessibilityGranted = granted
                if granted {
                    // Auto-advance to next step when permission granted
                    withOptionalAnimation {
                        currentStep = 3 // Calibrate step
                    }
                }
            }
        }
    }

    private func stopAccessibilityCheck() {
        accessibilityCheckTimer?.invalidate()
        accessibilityCheckTimer = nil
    }

    private func calibrate() {
        isCalibrating = true

        Task {
            let result = await bridge.calibrate()
            await MainActor.run {
                isCalibrating = false
                if result.success {
                    calibrateComplete = true
                }
            }
        }
    }

    private func withOptionalAnimation(_ action: @escaping () -> Void) {
        if reduceMotion {
            action()
        } else {
            withAnimation(Design.Animation.normal) {
                action()
            }
        }
    }
}

// MARK: - Feature Item

struct FeatureItem: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(spacing: Design.Spacing.md) {
            ZStack {
                RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                    .fill(Color.accentColor.opacity(0.1))
                    .frame(width: 36, height: 36)

                Image(systemName: icon)
                    .font(.system(size: 16, weight: .medium))
                    .foregroundColor(.accentColor)
            }
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(title)
                    .font(Design.Typography.headlineSmall)
                    .foregroundColor(Design.Colors.primaryText)

                Text(description)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Spacer()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(description)")
    }
}
