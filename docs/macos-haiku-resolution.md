# macOS Haiku Resolution Prompts

**Focus**: Mechanical, single-file, repeating-pattern fixes from macOS todo.md  
**Total Items**: ~96 (grouped into 12 parallel batches)  
**Model**: Haiku  
**Effort**: Medium (mechanical + test coverage)

---

## Pattern 1: Remove Force-Unwrap (`!`) — Replace with `guard let`

**Items**: H-021, H-039, M-033 (and similar: ~15 total)

### Batch 1-A: Core force-unwraps (3 items, parallel)

---

#### Prompt HK-1A-1: H-021 + H-039 + M-033 -- Force-unwrap removals

**Files to fix**:
- `crates/cpoe/src/verify/verdict.rs` -- NOT a Swift file, skip
- `DeviceAttestationService.swift:400` -- H-021: `lastAttestedAt` force-unwrap
- `BrowserExtensionService.swift:412` -- H-039: `constantTimeEqual` result force-unwrap
- `ExportFormView.swift:117` -- M-033: `destURL.path` force-unwrap

**Task**: For each file:
1. Find the force-unwrap line (noted above with line number)
2. Replace `!` with `guard let` or optional binding
3. Handle the error/nil case appropriately:
   - H-021 `lastAttestedAt`: use `let timestamp = lastAttestedAt ?? Date()`
   - H-039 `constantTimeEqual`: use `guard let result = constantTimeEqual(...) else { return nil }`
   - M-033 `destURL.path`: use `guard let path = destURL.path, !path.isEmpty else { return }`
4. Add test case if the change affects a public method

**Verification**:
- File compiles: `xcodebuild build -scheme WritersProof -configuration Debug 2>&1 | grep -i error`
- Force-unwraps removed: `grep -n '!' DeviceAttestationService.swift BrowserExtensionService.swift ExportFormView.swift | grep -v '//' | wc -l` (should be lower)

**Definition of done**: No new force-unwraps introduced. Optional handling is correct. Compiler warnings = 0.

---

#### Prompt HK-1A-2: Remaining force-unwraps batch

**Affected files** (scan for remaining `!` on optionals):
- `AppDelegate.swift` -- likely candidates
- `SettingsIntegrityService.swift` -- likely candidates  
- `CloudSyncService.swift` -- likely candidates
- `AuthService.swift` -- likely candidates

**Task**: Grep for `!` in each file and replace all force-unwraps on optionals with guards:
```bash
grep -n ' ! \|^\s*.*!' FILE.swift | head -20
```

Fix the top 5-10 instances in each file.

**Verification**: Re-run grep; count should decrease. No compilation errors.

**Definition of done**: At least 5 force-unwraps removed per file. Pattern documented for follow-up.

---

## Pattern 2: `[weak self]` Capture + Task Cancellation

**Items**: M-021, M-039, M-075, M-076, M-079-082, M-098 (and similar: ~20 total)

### Batch 2-A: Closure captures with Task or async (4 items, parallel)

---

#### Prompt HK-2A-1: M-021 + M-039 + M-075 + M-076 -- Weak self in closures

**Files to fix**:
- `CPoEService+Polling.swift:101` -- M-021: closure captures session
- `DashboardView.swift:1340` -- M-039: Task sleep closure captures self
- `NotificationManager.swift:235` -- M-075: groupFlushTask outlives manager
- `CPoEService+Actions.swift:224` -- M-076: Cloud backup Task races with dealloc

**Task**: For each file:
1. Find the closure/Task that captures `self` implicitly
2. Change to `[weak self]` or `[weak self] guard let self = self else { return }`
3. If the closure outlives the object, add explicit cancellation in `deinit`
   - Store Task in property: `var task: Task<Void, Never>?`
   - Cancel in deinit: `task?.cancel()`

**Example fix**:
```swift
// Before
Task {
    try? await someAsyncCall()
    updateUI()  // self implicit
}

// After
Task { [weak self] in
    try? await someAsyncCall()
    self?.updateUI()
}
```

**Verification**: 
- Compile check
- No implicit self captures: `grep -n 'Task {' FILE.swift | grep -v '\[' | head -5` (should be empty)

**Definition of done**: All Task/async closures use `[weak self]`. Long-lived tasks cancelled in deinit.

---

#### Prompt HK-2A-2: Task lifecycle cancellation (M-079 through M-082, M-098)

**Files to fix**:
- `DataDirectoryMonitor.swift:185` -- M-079: MainActor.run after dealloc
- `NotificationManager.swift:254` -- M-080: Init task continues after deinit
- `CPoEService+Polling.swift:149` -- M-081: pulseResetTask not cancelled
- `CPoEService+Polling.swift:161` -- M-082: integrityCheckTask not tracked
- `CPoEService+Polling.swift:125` -- M-098: statusTimer not invalidated on deinit

**Task**: For each service class:
1. Add property to store Task: `var backgroundTask: Task<Void, Never>?`
2. In deinit or shutdown method, add: `backgroundTask?.cancel()`
3. Verify the Task is assigned to this property before starting

**Pattern**:
```swift
class MyService {
    var checkTask: Task<Void, Never>?
    
    func startCheck() {
        checkTask = Task {
            // work
        }
    }
    
    deinit {
        checkTask?.cancel()
    }
}
```

**Verification**: 
- All background Tasks stored and cancelled: search for `Task {` followed by `checkTask =` or similar
- Compile check
- No untracked Tasks in deinit

**Definition of done**: All 5 items fixed. Each Task has an escape hatch in deinit.

---

## Pattern 3: Add `.accessibilityLabel()` to UI Elements

**Items**: H-079, M-030, M-040, M-109 (and similar: ~6 total)

### Batch 3-A: Status bar + metric labels

---

#### Prompt HK-3A-1: H-079 + M-030 + M-040 + M-109 -- Accessibility labels

**Files to fix**:
- `StatusBarController.swift:308` -- H-079: Status bar button lacks VoiceOver label
- `DashboardView.swift:300` -- M-030: Pro badge lacks label
- `BatchVerifyView.swift:668` -- M-040: Empty error message for screen reader
- `DashboardView.swift:300` -- M-109: Keystroke counter and forensic score lack labels

**Task**: For each UI element:
1. Find the view definition (usually a Button, Image, or Text)
2. Add `.accessibilityLabel("...")` with meaningful context
3. For dynamically updated values, use `.accessibilityValue("...")`

**Examples**:
```swift
// Before: Button with no label
Image(systemName: "circle.fill")

// After: With context
Image(systemName: "circle.fill")
    .accessibilityLabel("Status: Tracking active")
    .accessibilityValue("5 checkpoints captured")

// Badge
Text("Pro")
    .accessibilityLabel("Pro subscription active")

// Error message
if let error = error {
    Text(error.localizedDescription)
        .accessibilityLabel("Error: \(error.localizedDescription)")
}
```

**Verification**:
- Build and run on device/simulator
- Test with VoiceOver enabled (Settings > Accessibility > Vision > VoiceOver)
- Verify label is read aloud when element is selected

**Definition of done**: All 4 elements have meaningful, non-empty accessibility labels. VoiceOver test passes.

---

## Pattern 4: Check Return Value / Propagate Error

**Items**: H-041, M-050, M-070, M-089, M-099 (and similar: ~18 total)

### Batch 4-A: File operations + cleanup (4 items, parallel)

---

#### Prompt HK-4A-1: H-041 + M-099 + M-050 + M-070 -- Return value checks

**Files to fix**:
- `SettingsUtilities.swift:115` -- H-041: `flock(LOCK_UN)` failure unchecked
- `CPoEService.swift:215` -- M-099: FileHandle not closed on hash timeout
- `SettingsContent.swift:381` -- M-050: `NSWorkspace.open()` return unchecked
- `ReceiptValidation.swift:630` -- M-070: Invalid RFC3339 date silently accepted

**Task**: For each:
1. H-041: Add error check after `flock(fd, LOCK_UN)`:
   ```swift
   if flock(fd, LOCK_UN) != 0 {
       log.error("Failed to unlock launch file")
   }
   ```
2. M-099: Add `defer { fh.closeFile() }` immediately after opening file
3. M-050: Check `NSWorkspace.shared.open(...)` return bool:
   ```swift
   if !NSWorkspace.shared.open(url) {
       // Show alert
   }
   ```
4. M-070: Guard RFC3339 parsing:
   ```swift
   guard let date = dateFormatter.date(from: dateString) else {
       return nil  // or throw
   }
   ```

**Verification**: Compile check. No unchecked return values on critical operations.

**Definition of done**: All 4 items fixed. Error paths logged or handled.

---

#### Prompt HK-4A-2: Error propagation batch (M-089, M-074, M-080)

**Files to fix**:
- `VerifiableCredentialService.swift:83` -- M-089: `sha256HexStream` failure unchecked
- `SafariExtensionShared.swift:1031` -- M-068: Attr error silently skipped
- `NotificationManager.swift:254` -- M-080: Init task continues after deinit

**Task**: For each:
1. M-089: Guard nil return from `sha256HexStream`:
   ```swift
   guard let hash = sha256HexStream(path) else {
       log.error("Failed to hash file: \(path)")
       return
   }
   ```
2. M-068: Handle attr error:
   ```swift
   if let error = removeXattr(...) {
       log.warn("Failed to clean xattr: \(error)")
       // Continue or return?
   }
   ```
3. M-080: Cancel init task in deinit (see Pattern 2)

**Verification**: Compile. Error cases logged.

**Definition of done**: Unchecked return values eliminated. Caller aware of failure.

---

## Pattern 5: Clamp / `isFinite()` / Bounds Check

**Items**: M-087, M-088, M-095, M-026, M-053 (and similar: ~8 total)

### Batch 5-A: Numeric validation (5 items, parallel)

---

#### Prompt HK-5A-1: M-087 + M-088 + M-095 + M-026 + M-053 -- Numeric validation

**Files to fix**:
- `VoiceFingerprintView.swift:32` -- M-087: Division by zero (samplesGained <= 0)
- `VoiceFingerprintDetailView.swift:176` -- M-088: Confidence > 1.0 not clamped
- `ProofCardService.swift:214` -- M-095: NaN/negative score not guarded
- `EngineService.swift:269` -- M-026: Timestamp not validated for reasonable range
- `CheckpointChainView.swift:225` -- M-053: Timestamp formatting without validation

**Task**: For each:
1. M-087: Add bounds check before division:
   ```swift
   guard samplesGained > 0 else { return 0 }
   let estimate = totalSamples / Double(samplesGained)
   ```
2. M-088: Clamp confidence value:
   ```swift
   let clampedConfidence = confidence.clamped(to: 0.0...1.0)
   ```
3. M-095: Guard isFinite before use:
   ```swift
   guard score.isFinite, score >= 0 else { return 0 }
   ```
4. M-026: Validate timestamp range:
   ```swift
   let year = Calendar.current.component(.year, from: timestamp)
   guard (1970...2100).contains(year) else {
       log.error("Timestamp out of range: \(timestamp)")
       return Date()
   }
   ```
5. M-053: Bounds check before format:
   ```swift
   let components = Calendar.current.dateComponents([.year, .month, .day], from: timestamp)
   guard let year = components.year, (1970...2100).contains(year) else {
       return "Invalid date"
   }
   ```

**Verification**: 
- Build check
- Test with edge case values (0, negative, NaN, year 1900, year 2200)

**Definition of done**: All 5 items handle edge cases. No crashes on invalid input.

---

## Pattern 6: SwiftUI State Management Fixes

**Items**: H-085, H-086, H-088, M-112, M-118, M-122 (and similar: ~7 total)

### Batch 6-A: @ObservedObject → @EnvironmentObject (3 items, parallel)

---

#### Prompt HK-6A-1: H-085 + H-086 + H-088 -- ObservedObject deprecation

**Files to fix**:
- `CheckpointFormView.swift:10` -- H-085: `@ObservedObject nav` recreates on parent redraw
- `PopoverContentView.swift:71` -- H-086: `@ObservedObject nav` recreates entire tree
- `HistoryPopoverViews.swift:15` -- H-088: `@ObservedObject nav` resets scroll/filter

**Task**: For each:
1. Find the property:
   ```swift
   @ObservedObject var nav: NavigationModel
   ```
2. Replace with:
   ```swift
   @EnvironmentObject var nav: NavigationModel
   ```
3. Remove from function parameters if it was passed in
4. Verify the environment object is set upstream (usually in AppDelegate or root view):
   ```swift
   .environmentObject(navigationModel)
   ```

**Verification**:
- Build check
- Navigate and verify state persists (scroll position, filter, form data)
- Test on real device if possible

**Definition of done**: All 3 files updated. State persists across parent redraws.

---

### Batch 6-B: @StateObject fixes (M-112, M-118, M-122)

---

#### Prompt HK-6B-1: M-112 + M-118 + M-122 -- StateObject instead of State

**Files to fix**:
- `BatchVerifyView.swift:327` -- M-112: `_viewModel = State(initialValue:)` recreates
- `NotificationHistoryView.swift:125` -- M-118: Filter state not synced
- `SettingsContent.swift:196` -- M-122: `Bindable()` created every render pass

**Task**: For each:
1. M-112: Change `@State` to `@StateObject`:
   ```swift
   // Before
   @State var viewModel = BatchVerificationViewModel()
   
   // After
   @StateObject var viewModel = BatchVerificationViewModel()
   ```
2. M-118: If using `@State`, change to `@StateObject` for observable objects
3. M-122: If creating `Bindable()` in body, move to property:
   ```swift
   // Before
   var body: some View {
       let binding = Bindable(model)
   }
   
   // After
   @Bindable var model: Model  // if available (iOS 17+)
   ```

**Verification**: Build. State persists on parent redraws.

**Definition of done**: All 3 fixed. Observable objects recreated only on intentional reinit.

---

## Pattern 7: Single-Line Config/Comment Fixes

**Items**: M-002, M-012, M-105, M-106, M-124 (and similar: ~8 total)

### Batch 7-A: Documentation + config

---

#### Prompt HK-7A-1: M-002 + M-012 + M-105 + M-106 + M-124 -- Comments and config

**Files to fix**:
- `SupabaseClient.swift:117` -- M-002: Public anon key lacks clarity comment
- `ReceiptValidation.swift:571` -- M-012: `maxASN1Iterations=1000` unjustified
- `EngineService.swift:10` -- M-105: No FFI actor isolation requirement docs
- `CloudSyncService.swift:145` -- M-106: No operation queue isolation docs
- `project.pbxproj:1344` or `Info.plist:25` -- M-124: Endpoint Security entitlement comment

**Task**: For each:
1. M-002: Add comment before anon key:
   ```swift
   // Public anon key — provides client-side authentication to Supabase.
   // Data is encrypted before transmission (TLS + CBOR+COSE). Not sensitive.
   let anonKey = "..."
   ```
2. M-012: Add comment explaining constant:
   ```swift
   // ASN.1 max iterations cap. Receipts typically <500 iterations.
   // Limit set conservatively to prevent DoS via pathological encoding.
   let maxASN1Iterations = 1000
   ```
3. M-105: Add doc comment to class:
   ```swift
   /// EngineService bridges Swift UI to the native Rust engine via FFI.
   /// ALL public methods must be called on @MainActor to satisfy FFI thread isolation requirements.
   @MainActor
   final class EngineService { ... }
   ```
4. M-106: Add similar doc to CloudSyncService
5. M-124: Uncomment ES entitlement with case number

**Verification**: Build. Comments are readable and accurate.

**Definition of done**: All 5 items documented. Comments match implementation.

---

## Pattern 8: Add `defer { closeFile() }` / Resource Cleanup

**Items**: M-098, M-099, H-027, H-028 (and similar: ~6 total)

### Batch 8-A: File handle cleanup (4 items, parallel)

---

#### Prompt HK-8A-1: M-098 + M-099 + H-027 + H-028 -- Resource cleanup

**Files to fix**:
- `CPoEService+Polling.swift:125` -- M-098: statusTimer not invalidated on deinit
- `CPoEService.swift:215` -- M-099: FileHandle not closed on hash timeout
- `SecurityScopedBookmark.swift:127` -- H-027: startAccessingSecurityScopedResource not paired
- `EndpointSecurityClient.swift:176` -- H-028: `es_delete_client` without unsubscribe

**Task**: For each:
1. M-098: Add invalidate in deinit:
   ```swift
   func shutdown() {
       statusTimer?.invalidate()
       statusTimer = nil
   }
   ```
2. M-099: Add defer immediately after opening file:
   ```swift
   let fh = FileHandle(forReadingAtPath: path)
   defer { fh?.closeFile() }
   ```
3. H-027: Return a handle that auto-stops access:
   ```swift
   struct ScopedAccessHandle {
       let url: URL
       deinit { url.stopAccessingSecurityScopedResource() }
   }
   ```
4. H-028: Add unsubscribe before delete:
   ```swift
   if let client = client {
       es_unsubscribe_all(client)
       es_delete_client(client)
   }
   ```

**Verification**: Build. No resource leaks on Instruments (FileHandles, Timer, ES client).

**Definition of done**: All 4 items properly cleaned up. No file descriptor leaks.

---

## Pattern 9: Tolerance / Validation Tightening

**Items**: H-019, M-016, H-034, H-036, M-065 (and similar: ~8 total)

### Batch 9-A: Security tightening (5 items, parallel)

---

#### Prompt HK-9A-1: H-019 + M-016 + H-034 + H-036 + M-065 -- Tighten validation

**Files to fix**:
- `ReceiptValidation.swift:382` -- H-019: 24-hour future date tolerance (reduce to 1h)
- `ReceiptValidation.swift:403` -- M-016: 30-day old receipt accepted (hard-fail if < build date)
- `AppDelegate.swift:551` -- H-034: URL hash validation doesn't validate hex chars
- `ExportFormView.swift:663` -- H-036: AI tool name filter passes non-ASCII unfiltered
- `DisplayNameValidation.swift:29` -- M-065: Unknown Unicode scripts pass homograph check

**Task**: For each:
1. H-019: Replace 24h with 1h:
   ```swift
   let tolerance: TimeInterval = 3600  // 1 hour instead of 86400
   ```
2. M-016: Hard-fail if receipt older than build:
   ```swift
   guard receiptDate >= buildDate else {
       log.error("Receipt too old: created before build")
       return false
   }
   ```
3. H-034: Validate hex before comparison:
   ```swift
   let hexChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
   guard urlHash.unicodeScalars.allSatisfy({ hexChars.contains($0) }) else {
       return false
   }
   ```
4. H-036: Whitelist ASCII alphanumerics only:
   ```swift
   let filtered = toolName.filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
   ```
5. M-065: Reject Unknown script block:
   ```swift
   let allowedScripts: Set<Unicode.Scalar.Properties> = [...]
   guard allowedScripts.contains(...) else {
       return false
   }
   ```

**Verification**: Build. Test with edge cases (future dates, old dates, hex + invalid chars, unicode).

**Definition of done**: All 5 tightened. Security tests pass.

---

## Execution Order

**Run all batches in parallel:**
- HK-1A-1 (H-021, H-039, M-033)
- HK-1A-2 (remaining force-unwraps)
- HK-2A-1 (M-021, M-039, M-075, M-076)
- HK-2A-2 (M-079-082, M-098)
- HK-3A-1 (H-079, M-030, M-040, M-109)
- HK-4A-1 (H-041, M-099, M-050, M-070)
- HK-4A-2 (M-089, M-068, M-080)
- HK-5A-1 (M-087, M-088, M-095, M-026, M-053)
- HK-6A-1 (H-085, H-086, H-088)
- HK-6B-1 (M-112, M-118, M-122)
- HK-7A-1 (M-002, M-012, M-105, M-106, M-124)
- HK-8A-1 (M-098, M-099, H-027, H-028)
- HK-9A-1 (H-019, M-016, H-034, H-036, M-065)

**After all batches complete:**
1. Run `xcodebuild build -scheme WritersProof 2>&1 | grep -i error | wc -l` — should be 0
2. Run `xcodebuild test -scheme WritersProofTests 2>&1 | grep -E "passed|failed"` — all passed
3. Commit changes in one batch per pattern with message: `fix: [pattern name] across 4 files`

---

## Summary

- **Total items resolved**: ~96 Haiku-level fixes
- **Batches**: 13 (all parallel-safe)
- **Estimated completion**: 4-6 hours for Haiku (mechanical fixes, high parallelism)
- **Next step**: Sonnet batch for ~91 moderate-complexity items (error propagation, concurrency fixes, architecture)
