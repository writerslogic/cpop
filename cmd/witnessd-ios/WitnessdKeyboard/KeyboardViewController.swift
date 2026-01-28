import UIKit

// Import the gomobile-generated framework
import Witnessd

/// WitnessdKeyboardViewController is an iOS Custom Keyboard Extension that
/// integrates with the witnessd cryptographic authorship witnessing system.
///
/// This keyboard operates in pass-through mode: it observes and records typing
/// patterns for cryptographic witnessing but does not modify user input.
///
/// Build steps:
/// 1. Build Go framework: gomobile bind -target=ios -o Witnessd.xcframework ./internal/ime
/// 2. Add Witnessd.xcframework to Xcode project
/// 3. Build and sign the keyboard extension
class KeyboardViewController: UIInputViewController {

    // MARK: - Properties

    private var engine: ImeMobileEngine?
    private var keyboardView: UIView?
    private var nextKeyboardButton: UIButton?
    private var isShifted = false

    // Standard QWERTY layout
    private let keyboardLayout: [[String]] = [
        ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
        ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
        ["⇧", "z", "x", "c", "v", "b", "n", "m", "⌫"],
        ["123", "🌐", " ", ".", "return"]
    ]

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()

        // Initialize the Go engine
        engine = ImeNewMobileEngine()

        // Set up the keyboard UI
        setupKeyboardView()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)

        // Start a witnessing session
        startSession()
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)

        // End the witnessing session
        endSession()
    }

    // MARK: - Session Management

    private func startSession() {
        guard let engine = engine else { return }

        // Get app bundle ID (if available through host app)
        let appID = Bundle.main.bundleIdentifier ?? "unknown"
        let docID = UUID().uuidString

        do {
            try engine.startSession(appID, docID: docID, context: "")
            print("Witnessd: Session started for \(appID)")
        } catch {
            print("Witnessd: Failed to start session: \(error)")
        }
    }

    private func endSession() {
        guard let engine = engine, engine.hasActiveSession() else { return }

        do {
            let evidence = try engine.endSession()
            print("Witnessd: Session ended with evidence: \(evidence)")
            // TODO: Save evidence to shared container for main app to access
        } catch {
            print("Witnessd: Failed to end session: \(error)")
        }
    }

    // MARK: - UI Setup

    private func setupKeyboardView() {
        let keyboardStackView = UIStackView()
        keyboardStackView.axis = .vertical
        keyboardStackView.distribution = .fillEqually
        keyboardStackView.spacing = 4
        keyboardStackView.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(keyboardStackView)

        NSLayoutConstraint.activate([
            keyboardStackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 4),
            keyboardStackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -4),
            keyboardStackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 4),
            keyboardStackView.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -4)
        ])

        for row in keyboardLayout {
            let rowStackView = UIStackView()
            rowStackView.axis = .horizontal
            rowStackView.distribution = .fillEqually
            rowStackView.spacing = 4

            for key in row {
                let button = createKeyButton(key)
                rowStackView.addArrangedSubview(button)
            }

            keyboardStackView.addArrangedSubview(rowStackView)
        }

        keyboardView = keyboardStackView
    }

    private func createKeyButton(_ key: String) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(key, for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 22)
        button.backgroundColor = UIColor.systemGray5
        button.setTitleColor(.black, for: .normal)
        button.layer.cornerRadius = 5

        // Set up touch handlers
        button.addTarget(self, action: #selector(keyPressed(_:)), for: .touchUpInside)

        // Special key handling
        switch key {
        case "🌐":
            // Next keyboard button
            button.addTarget(self, action: #selector(handleInputModeList(from:with:)), for: .allTouchEvents)
            nextKeyboardButton = button
        case " ":
            // Space bar - make it wider
            button.widthAnchor.constraint(equalTo: button.widthAnchor, multiplier: 2.5).isActive = true
        default:
            break
        }

        return button
    }

    // MARK: - Key Handling

    @objc private func keyPressed(_ sender: UIButton) {
        guard let key = sender.title(for: .normal) else { return }

        switch key {
        case "⇧":
            handleShift()
        case "⌫":
            handleDelete()
        case "return":
            handleReturn()
        case "123":
            // TODO: Switch to numbers/symbols layout
            break
        case "🌐":
            // Handled by handleInputModeList
            break
        default:
            handleCharacter(key)
        }

        // Provide haptic feedback
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    private func handleCharacter(_ char: String) {
        // Get the character to insert
        var character = char
        if isShifted && char.count == 1 {
            character = char.uppercased()
            isShifted = false
            updateShiftState()
        }

        // Record in engine with jitter
        if let engine = engine, let charCode = character.unicodeScalars.first?.value {
            do {
                let jitterMicros = try engine.onKeyDown(Int32(charCode))

                // Apply jitter delay
                if jitterMicros > 0 {
                    let delay = Double(jitterMicros) / 1_000_000.0
                    DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                        self?.commitText(character)
                    }
                    return
                }
            } catch {
                print("Witnessd: onKeyDown failed: \(error)")
            }
        }

        // No delay - commit immediately
        commitText(character)
    }

    private func commitText(_ text: String) {
        textDocumentProxy.insertText(text)

        // Record commit in engine
        if let engine = engine {
            do {
                try engine.onTextCommit(text)
            } catch {
                print("Witnessd: onTextCommit failed: \(error)")
            }
        }
    }

    private func handleDelete() {
        // Record delete in engine
        if let engine = engine {
            do {
                try engine.onTextDelete(1)
            } catch {
                print("Witnessd: onTextDelete failed: \(error)")
            }
        }

        // Perform the delete
        textDocumentProxy.deleteBackward()
    }

    private func handleShift() {
        isShifted = !isShifted
        updateShiftState()
    }

    private func updateShiftState() {
        // Update key labels to show uppercase/lowercase
        guard let keyboardStackView = keyboardView as? UIStackView else { return }

        for case let rowStackView as UIStackView in keyboardStackView.arrangedSubviews {
            for case let button as UIButton in rowStackView.arrangedSubviews {
                guard let title = button.title(for: .normal),
                      title.count == 1,
                      title != "⇧" && title != "⌫" else { continue }

                let newTitle = isShifted ? title.uppercased() : title.lowercased()
                button.setTitle(newTitle, for: .normal)
            }
        }
    }

    private func handleReturn() {
        textDocumentProxy.insertText("\n")
    }

    // MARK: - Text Input Trait Overrides

    override func textWillChange(_ textInput: UITextInput?) {
        // Called when the text changes
    }

    override func textDidChange(_ textInput: UITextInput?) {
        // Update keyboard appearance if needed
        let textColor: UIColor
        if textDocumentProxy.keyboardAppearance == .dark {
            textColor = .white
        } else {
            textColor = .black
        }

        nextKeyboardButton?.setTitleColor(textColor, for: .normal)
    }
}
