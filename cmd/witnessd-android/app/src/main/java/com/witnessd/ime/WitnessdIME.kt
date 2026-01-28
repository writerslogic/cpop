package com.witnessd.ime

import android.inputmethodservice.InputMethodService
import android.inputmethodservice.Keyboard
import android.inputmethodservice.KeyboardView
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.os.Handler
import android.os.Looper
import android.util.Log

// Import the gomobile-generated bindings
import ime.Ime
import ime.MobileEngine

/**
 * WitnessdIME is an Android InputMethodService that integrates with the
 * witnessd cryptographic authorship witnessing system.
 *
 * This IME operates in pass-through mode: it observes and records typing
 * patterns for cryptographic witnessing but does not modify user input.
 *
 * Build steps:
 * 1. Build Go library: gomobile bind -target=android -o witnessd.aar ./internal/ime
 * 2. Copy witnessd.aar to app/libs/
 * 3. Build APK: ./gradlew assembleDebug
 */
class WitnessdIME : InputMethodService(), KeyboardView.OnKeyboardActionListener {

    companion object {
        private const val TAG = "WitnessdIME"
    }

    private var engine: MobileEngine? = null
    private var keyboardView: KeyboardView? = null
    private var keyboard: Keyboard? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate")

        // Initialize the Go engine
        try {
            engine = Ime.newMobileEngine()
            Log.d(TAG, "Engine initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize engine", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "onDestroy")

        // End any active session
        engine?.let { eng ->
            if (eng.hasActiveSession()) {
                try {
                    val evidence = eng.endSession()
                    Log.d(TAG, "Session ended: $evidence")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to end session", e)
                }
            }
        }
        engine = null
    }

    override fun onCreateInputView(): View {
        keyboardView = layoutInflater.inflate(
            R.layout.keyboard_view, null
        ) as KeyboardView

        keyboard = Keyboard(this, R.xml.qwerty)
        keyboardView?.keyboard = keyboard
        keyboardView?.setOnKeyboardActionListener(this)

        return keyboardView!!
    }

    override fun onStartInputView(info: EditorInfo, restarting: Boolean) {
        super.onStartInputView(info, restarting)

        // Start a new witnessing session
        val packageName = info.packageName ?: "unknown"
        val fieldId = info.fieldId.toString()

        Log.d(TAG, "onStartInputView: package=$packageName field=$fieldId")

        engine?.let { eng ->
            try {
                // End previous session if any
                if (eng.hasActiveSession()) {
                    eng.endSession()
                }

                // Start new session
                eng.startSession(packageName, fieldId, "")
                Log.d(TAG, "Session started for $packageName")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start session", e)
            }
        }
    }

    override fun onFinishInputView(finishingInput: Boolean) {
        super.onFinishInputView(finishingInput)

        // End session when input view is finished
        engine?.let { eng ->
            if (eng.hasActiveSession()) {
                try {
                    val evidence = eng.endSession()
                    Log.d(TAG, "Session ended: $evidence")
                    // TODO: Save evidence to storage
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to end session", e)
                }
            }
        }
    }

    // KeyboardView.OnKeyboardActionListener implementation

    override fun onKey(primaryCode: Int, keyCodes: IntArray?) {
        val ic = currentInputConnection ?: return

        when (primaryCode) {
            Keyboard.KEYCODE_DELETE -> handleDelete(ic)
            Keyboard.KEYCODE_DONE -> handleDone(ic)
            Keyboard.KEYCODE_SHIFT -> handleShift()
            Keyboard.KEYCODE_MODE_CHANGE -> handleModeChange()
            else -> handleCharacter(ic, primaryCode)
        }
    }

    private fun handleCharacter(ic: InputConnection, code: Int) {
        val char = code.toChar()

        // Record in engine with jitter delay
        engine?.let { eng ->
            try {
                val jitterMicros = eng.onKeyDown(code)

                // Apply jitter delay asynchronously
                if (jitterMicros > 0) {
                    mainHandler.postDelayed({
                        commitCharacter(ic, char)
                    }, jitterMicros / 1000) // Convert to milliseconds
                } else {
                    commitCharacter(ic, char)
                }
            } catch (e: Exception) {
                Log.e(TAG, "onKeyDown failed", e)
                commitCharacter(ic, char)
            }
        } ?: commitCharacter(ic, char)
    }

    private fun commitCharacter(ic: InputConnection, char: Char) {
        ic.commitText(char.toString(), 1)

        // Record commit in engine
        engine?.let { eng ->
            try {
                eng.onTextCommit(char.toString())
            } catch (e: Exception) {
                Log.e(TAG, "onTextCommit failed", e)
            }
        }
    }

    private fun handleDelete(ic: InputConnection) {
        // Record delete in engine
        engine?.let { eng ->
            try {
                eng.onTextDelete(1)
            } catch (e: Exception) {
                Log.e(TAG, "onTextDelete failed", e)
            }
        }

        // Perform the delete
        ic.deleteSurroundingText(1, 0)
    }

    private fun handleDone(ic: InputConnection) {
        ic.sendKeyEvent(KeyEvent(KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_ENTER))
        ic.sendKeyEvent(KeyEvent(KeyEvent.ACTION_UP, KeyEvent.KEYCODE_ENTER))
    }

    private fun handleShift() {
        keyboard?.let { kbd ->
            kbd.isShifted = !kbd.isShifted
            keyboardView?.invalidateAllKeys()
        }
    }

    private fun handleModeChange() {
        // Toggle between letter and symbol keyboards
        // For simplicity, this is a no-op in this implementation
    }

    override fun onPress(primaryCode: Int) {
        // Called when key is pressed
    }

    override fun onRelease(primaryCode: Int) {
        // Called when key is released
    }

    override fun onText(text: CharSequence?) {
        text?.let { t ->
            currentInputConnection?.commitText(t, 1)

            // Record in engine
            engine?.let { eng ->
                try {
                    eng.onTextCommit(t.toString())
                } catch (e: Exception) {
                    Log.e(TAG, "onTextCommit failed", e)
                }
            }
        }
    }

    override fun swipeLeft() {}
    override fun swipeRight() {}
    override fun swipeDown() {}
    override fun swipeUp() {}

    /**
     * Get the current sample count for debugging/display.
     */
    fun getSampleCount(): Int {
        return engine?.getSampleCount() ?: 0
    }

    /**
     * Get session info as JSON for debugging.
     */
    fun getSessionInfo(): String {
        return engine?.getSessionInfo() ?: "{}"
    }
}
