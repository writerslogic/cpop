// WitnessdInputController+Enhanced.h
// Enhanced IMKInputController with dead key and compose support
//
// This category extends WitnessdInputController with:
// - Dead key handling (e.g., ` + e = e)
// - Compose character sequences
// - International keyboard layout support
// - Proper modifier key handling

#import "WitnessdInputController.h"

NS_ASSUME_NONNULL_BEGIN

/// Dead key state enumeration
typedef NS_ENUM(NSInteger, WitnessdDeadKeyState) {
    WitnessdDeadKeyStateNone = 0,
    WitnessdDeadKeyStateGrave,       // `
    WitnessdDeadKeyStateAcute,       // '
    WitnessdDeadKeyStateCircumflex,  // ^
    WitnessdDeadKeyStateTilde,       // ~
    WitnessdDeadKeyStateDieresis,    // "
};

/// Extended properties for dead key and compose handling
@interface WitnessdInputController (Enhanced)

/// Handle a dead key press
/// @param keyCode The virtual key code
/// @param modifiers The modifier flags
/// @return YES if this was a dead key that was handled
- (BOOL)handleDeadKeyWithKeyCode:(unsigned short)keyCode modifiers:(NSEventModifierFlags)modifiers;

/// Compose a character from dead key state and base character
/// @param baseChar The base character
/// @param deadKeyState The current dead key state
/// @return The composed character, or the original if no composition applies
- (unichar)composeCharacter:(unichar)baseChar withDeadKeyState:(WitnessdDeadKeyState)deadKeyState;

/// Reset the dead key state
- (void)resetDeadKeyState;

/// Handle option key combinations for special characters
/// @param keyCode The virtual key code
/// @param modifiers The modifier flags
/// @param client The IMK client
/// @return YES if the option combination was handled
- (BOOL)handleOptionKeyWithKeyCode:(unsigned short)keyCode
                         modifiers:(NSEventModifierFlags)modifiers
                            client:(id)client;

/// Get the current keyboard layout identifier
/// @return The keyboard layout identifier (e.g., "com.apple.keylayout.US")
- (nullable NSString *)currentKeyboardLayout;

/// Map a key code to zone considering keyboard layout
/// @param keyCode The virtual key code
/// @return The zone (0-7) or -1 if unknown
- (int)zoneForKeyCode:(unsigned short)keyCode;

@end

NS_ASSUME_NONNULL_END
