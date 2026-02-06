import SwiftUI
import UniformTypeIdentifiers

struct DropZoneView: View {
    let title: String
    let icon: String
    let action: (URL) -> Void

    @State private var isTargeted = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: Design.Spacing.md) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.xxl))
                .foregroundColor(isTargeted ? .accentColor : Design.Colors.secondaryText)

            Text(title)
                .font(Design.Typography.headlineMedium)
                .foregroundColor(isTargeted ? .accentColor : Design.Colors.primaryText)

            Text("Drop a file here or click to browse")
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.secondaryText)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.lg, style: .continuous)
                .strokeBorder(
                    isTargeted ? Color.accentColor : Design.Colors.separator,
                    style: StrokeStyle(lineWidth: 2, dash: [8])
                )
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.lg, style: .continuous)
                        .fill(isTargeted ? Color.accentColor.opacity(0.1) : Color.clear)
                )
        )
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            handleDrop(providers: providers)
            return true
        }
        .onTapGesture {
            showFilePicker()
        }
        .animation(reduceMotion ? nil : Design.Animation.normal, value: isTargeted)
        .accessibilityLabel(title)
        .accessibilityHint("Drop a file or double-tap to browse")
        .accessibilityAddTraits(.isButton)
    }

    private func handleDrop(providers: [NSItemProvider]) {
        guard let provider = providers.first else { return }

        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
            guard let data = item as? Data,
                  let url = URL(dataRepresentation: data, relativeTo: nil) else {
                return
            }

            DispatchQueue.main.async {
                action(url)
            }
        }
    }

    private func showFilePicker() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false

        if panel.runModal() == .OK, let url = panel.url {
            action(url)
        }
    }
}

// Compact drop zone for inline use
struct CompactDropZone: View {
    let placeholder: String
    let onDrop: (URL) -> Void

    @State private var isTargeted = false
    @State private var droppedFile: URL? = nil

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: "doc.badge.plus")
                .font(.system(size: Design.IconSize.md))
                .foregroundColor(isTargeted ? .accentColor : Design.Colors.secondaryText)

            if let file = droppedFile {
                Text(file.lastPathComponent)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Button(action: { droppedFile = nil }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear selected file")
            } else {
                Text(placeholder)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.secondaryText)
            }

            Spacer()

            if droppedFile == nil {
                Button("Browse") {
                    showFilePicker()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
        .padding(Design.Spacing.md)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .strokeBorder(
                    isTargeted ? Color.accentColor : Design.Colors.separator,
                    lineWidth: 1
                )
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                        .fill(isTargeted ? Color.accentColor.opacity(0.1) : Design.Colors.secondaryBackground)
                )
        )
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            handleDrop(providers: providers)
            return true
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(droppedFile?.lastPathComponent ?? placeholder)
        .accessibilityHint("Drop a file or activate to browse")
    }

    private func handleDrop(providers: [NSItemProvider]) {
        guard let provider = providers.first else { return }

        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
            guard let data = item as? Data,
                  let url = URL(dataRepresentation: data, relativeTo: nil) else {
                return
            }

            DispatchQueue.main.async {
                droppedFile = url
                onDrop(url)
            }
        }
    }

    private func showFilePicker() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false

        if panel.runModal() == .OK, let url = panel.url {
            droppedFile = url
            onDrop(url)
        }
    }
}
