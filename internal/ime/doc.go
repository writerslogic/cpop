// Package ime provides cross-platform Input Method Editor integration for witnessd.
//
// # Architecture Overview
//
// The IME approach eliminates the need for accessibility permissions by having
// users explicitly choose witnessd as their input method. All typing flows
// through the IME naturally, allowing us to:
//
//   - Track zone transitions (which finger typed each key)
//   - Apply cryptographic jitter delays
//   - Build evidence chains in real-time
//   - Hash document state as text is committed
//
// # Permission Model Comparison
//
//	┌─────────────────┬────────────────────────┬─────────────────────────┐
//	│ Aspect          │ CGEventTap (old)       │ IME (new)               │
//	├─────────────────┼────────────────────────┼─────────────────────────┤
//	│ Permission      │ System privacy prompt  │ User selects in prefs   │
//	│ User perception │ "Watching my keyboard" │ "I chose this keyboard" │
//	│ Trust model     │ Implicit surveillance  │ Explicit participation  │
//	│ Zone access     │ Infer from keycodes    │ Direct character access │
//	│ Jitter inject   │ Complex event modify   │ Natural commit delay    │
//	└─────────────────┴────────────────────────┴─────────────────────────┘
//
// # Platform Support
//
// Each platform has its own IME framework, but they share a common pattern:
//
//	Key Event → Process → Commit Text
//	     ↓
//	[witnessd core]
//	     ↓
//	Zone + Jitter + Evidence
//
// Platform-specific implementations:
//
//	┌──────────┬─────────────────────────────────────────────────────────┐
//	│ Platform │ Framework                                               │
//	├──────────┼─────────────────────────────────────────────────────────┤
//	│ macOS    │ Input Method Kit (IMKit) - NSInputServiceProvider       │
//	│ Windows  │ Text Services Framework (TSF) - ITfTextInputProcessor   │
//	│ Linux    │ IBus (primary), Fcitx (fallback) - IBusEngine           │
//	└──────────┴─────────────────────────────────────────────────────────┘
//
// # Core Interface
//
// The Engine interface is implemented by the common core and called by
// platform-specific IME wrappers:
//
//	type Engine interface {
//	    // OnKeyDown processes a key press and returns the jitter delay.
//	    // The platform IME should wait this duration before committing.
//	    OnKeyDown(key Key) (jitterDelay time.Duration, err error)
//
//	    // OnTextCommit records that text was committed to the document.
//	    // Called after the platform IME commits characters.
//	    OnTextCommit(text string) error
//
//	    // GetEvidence returns the current evidence chain.
//	    GetEvidence() *Evidence
//
//	    // StartSession begins a new witnessing session.
//	    StartSession(opts SessionOptions) error
//
//	    // EndSession finalizes the current session.
//	    EndSession() (*Evidence, error)
//	}
//
// # Data Flow
//
//	┌────────────────┐
//	│  User Types    │
//	│   "hello"      │
//	└───────┬────────┘
//	        ↓
//	┌────────────────┐     ┌─────────────────────────────────────────┐
//	│ Platform IME   │     │ For each keystroke:                     │
//	│ (macOS/Win/    │────→│ 1. Key event received                   │
//	│  Linux/mobile) │     │ 2. Call engine.OnKeyDown(key)           │
//	└───────┬────────┘     │ 3. Wait returned jitter delay           │
//	        │              │ 4. Commit character to app              │
//	        ↓              │ 5. Call engine.OnTextCommit(char)       │
//	┌────────────────┐     └─────────────────────────────────────────┘
//	│ witnessd Core  │
//	│                │
//	│ • Zone track   │
//	│ • Jitter calc  │
//	│ • Doc hash     │
//	│ • Evidence     │
//	└───────┬────────┘
//	        ↓
//	┌────────────────┐
//	│ Evidence Chain │
//	│ (exportable)   │
//	└────────────────┘
//
// # Session Model
//
// A "session" corresponds to focused writing in a single document/context.
// The platform IME detects context switches (app change, text field change)
// and can start new sessions or pause/resume existing ones.
//
// Sessions are identified by:
//   - Application bundle ID (macOS) or executable name (Windows/Linux)
//   - Document identifier (URL, file path, or field ID)
//   - User-provided context (optional)
//
// # Privacy Guarantees
//
// The IME core maintains the same privacy properties as the jitter package:
//
//  1. No plaintext storage: Characters flow through but aren't stored
//  2. Zone-only tracking: We record zone transitions, not specific keys
//  3. Hash commitment: Document state is only stored as SHA-256 hashes
//  4. Jitter binding: Timing proves real-time typing without content
//
// # Building Platform IMEs
//
// Each platform requires a separate build artifact:
//
//   - macOS: .app bundle with Info.plist declaring NSInputServiceProvider
//   - Windows: DLL registered as TSF Text Input Processor
//   - Linux: IBus component XML + shared library
//
// The common Go core is linked into each platform's native wrapper.
package ime
