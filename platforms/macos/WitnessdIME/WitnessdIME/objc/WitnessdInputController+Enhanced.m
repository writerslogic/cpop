// WitnessdInputController+Enhanced.m
// Enhanced IMKInputController implementation

#import "WitnessdInputController+Enhanced.h"
#import <Carbon/Carbon.h>
#import <objc/runtime.h>

// Associated object keys
static void* DeadKeyStateKey = &DeadKeyStateKey;

// Dead key virtual key codes (US keyboard layout)
static const unsigned short kVK_Grave = 0x32;      // ` key
static const unsigned short kVK_Quote = 0x27;      // ' key
static const unsigned short kVK_6 = 0x16;          // ^ via Shift+6
static const unsigned short kVK_N = 0x2D;          // ~ via Option+N

// Composition tables for dead keys
static NSDictionary<NSNumber*, NSDictionary<NSNumber*, NSNumber*>*>* _compositionTable;

@implementation WitnessdInputController (Enhanced)

#pragma mark - Composition Table Setup

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _compositionTable = @{
            // Grave accent (`)
            @(WitnessdDeadKeyStateGrave): @{
                @('a'): @(L'\u00E0'),  // a
                @('e'): @(L'\u00E8'),  // e
                @('i'): @(L'\u00EC'),  // i
                @('o'): @(L'\u00F2'),  // o
                @('u'): @(L'\u00F9'),  // u
                @('A'): @(L'\u00C0'),  // A
                @('E'): @(L'\u00C8'),  // E
                @('I'): @(L'\u00CC'),  // I
                @('O'): @(L'\u00D2'),  // O
                @('U'): @(L'\u00D9'),  // U
            },

            // Acute accent (')
            @(WitnessdDeadKeyStateAcute): @{
                @('a'): @(L'\u00E1'),  // a
                @('e'): @(L'\u00E9'),  // e
                @('i'): @(L'\u00ED'),  // i
                @('o'): @(L'\u00F3'),  // o
                @('u'): @(L'\u00FA'),  // u
                @('y'): @(L'\u00FD'),  // y
                @('A'): @(L'\u00C1'),  // A
                @('E'): @(L'\u00C9'),  // E
                @('I'): @(L'\u00CD'),  // I
                @('O'): @(L'\u00D3'),  // O
                @('U'): @(L'\u00DA'),  // U
                @('Y'): @(L'\u00DD'),  // Y
            },

            // Circumflex (^)
            @(WitnessdDeadKeyStateCircumflex): @{
                @('a'): @(L'\u00E2'),  // a
                @('e'): @(L'\u00EA'),  // e
                @('i'): @(L'\u00EE'),  // i
                @('o'): @(L'\u00F4'),  // o
                @('u'): @(L'\u00FB'),  // u
                @('A'): @(L'\u00C2'),  // A
                @('E'): @(L'\u00CA'),  // E
                @('I'): @(L'\u00CE'),  // I
                @('O'): @(L'\u00D4'),  // O
                @('U'): @(L'\u00DB'),  // U
            },

            // Tilde (~)
            @(WitnessdDeadKeyStateTilde): @{
                @('a'): @(L'\u00E3'),  // a
                @('n'): @(L'\u00F1'),  // n
                @('o'): @(L'\u00F5'),  // o
                @('A'): @(L'\u00C3'),  // A
                @('N'): @(L'\u00D1'),  // N
                @('O'): @(L'\u00D5'),  // O
            },

            // Dieresis/Umlaut (")
            @(WitnessdDeadKeyStateDieresis): @{
                @('a'): @(L'\u00E4'),  // a
                @('e'): @(L'\u00EB'),  // e
                @('i'): @(L'\u00EF'),  // i
                @('o'): @(L'\u00F6'),  // o
                @('u'): @(L'\u00FC'),  // u
                @('y'): @(L'\u00FF'),  // y
                @('A'): @(L'\u00C4'),  // A
                @('E'): @(L'\u00CB'),  // E
                @('I'): @(L'\u00CF'),  // I
                @('O'): @(L'\u00D6'),  // O
                @('U'): @(L'\u00DC'),  // U
            },
        };
    });
}

#pragma mark - Dead Key State Management

- (WitnessdDeadKeyState)deadKeyState {
    NSNumber* state = objc_getAssociatedObject(self, DeadKeyStateKey);
    return state ? (WitnessdDeadKeyState)[state integerValue] : WitnessdDeadKeyStateNone;
}

- (void)setDeadKeyState:(WitnessdDeadKeyState)state {
    objc_setAssociatedObject(self, DeadKeyStateKey,
                             @(state), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (void)resetDeadKeyState {
    [self setDeadKeyState:WitnessdDeadKeyStateNone];
}

#pragma mark - Dead Key Handling

- (BOOL)handleDeadKeyWithKeyCode:(unsigned short)keyCode modifiers:(NSEventModifierFlags)modifiers {
    // Check for Option key dead keys (e.g., Option+E for acute)
    if (modifiers & NSEventModifierFlagOption) {
        switch (keyCode) {
            case kVK_ANSI_E:  // Option+E = acute accent
                [self setDeadKeyState:WitnessdDeadKeyStateAcute];
                return YES;

            case kVK_ANSI_I:  // Option+I = circumflex
                [self setDeadKeyState:WitnessdDeadKeyStateCircumflex];
                return YES;

            case kVK_ANSI_U:  // Option+U = dieresis
                [self setDeadKeyState:WitnessdDeadKeyStateDieresis];
                return YES;

            case kVK_ANSI_N:  // Option+N = tilde
                [self setDeadKeyState:WitnessdDeadKeyStateTilde];
                return YES;

            case kVK_ANSI_Grave:  // Option+` = grave
                [self setDeadKeyState:WitnessdDeadKeyStateGrave];
                return YES;

            default:
                break;
        }
    }

    return NO;
}

- (unichar)composeCharacter:(unichar)baseChar withDeadKeyState:(WitnessdDeadKeyState)deadKeyState {
    if (deadKeyState == WitnessdDeadKeyStateNone) {
        return baseChar;
    }

    NSDictionary<NSNumber*, NSNumber*>* compositionMap = _compositionTable[@(deadKeyState)];
    if (!compositionMap) {
        return baseChar;
    }

    NSNumber* composedChar = compositionMap[@(baseChar)];
    if (composedChar) {
        return (unichar)[composedChar unsignedShortValue];
    }

    return baseChar;
}

#pragma mark - Option Key Handling

- (BOOL)handleOptionKeyWithKeyCode:(unsigned short)keyCode
                         modifiers:(NSEventModifierFlags)modifiers
                            client:(id)client {
    // This method handles Option+key combinations that produce special characters
    // on US keyboards (and many international keyboards)

    if (!(modifiers & NSEventModifierFlagOption)) {
        return NO;
    }

    // Common Option+key mappings on US keyboard
    // These are handled by the system keyboard layout, so we just need to
    // ensure we're tracking them properly

    // Check if this is a dead key
    if ([self handleDeadKeyWithKeyCode:keyCode modifiers:modifiers]) {
        return YES;
    }

    return NO;
}

#pragma mark - Keyboard Layout

- (nullable NSString *)currentKeyboardLayout {
    TISInputSourceRef source = TISCopyCurrentKeyboardInputSource();
    if (!source) {
        return nil;
    }

    CFStringRef sourceID = (CFStringRef)TISGetInputSourceProperty(source, kTISPropertyInputSourceID);
    NSString* result = sourceID ? (__bridge NSString*)sourceID : nil;

    CFRelease(source);
    return result;
}

#pragma mark - Zone Mapping

- (int)zoneForKeyCode:(unsigned short)keyCode {
    // Standard QWERTY zone mapping
    // Zone 0-3: Left hand (pinky to index)
    // Zone 4-7: Right hand (index to pinky)

    switch (keyCode) {
        // Zone 0: Left pinky
        case kVK_ANSI_Q:
        case kVK_ANSI_A:
        case kVK_ANSI_Z:
        case kVK_ANSI_1:
        case kVK_Tab:
        case kVK_CapsLock:
        case kVK_Shift:
            return 0;

        // Zone 1: Left ring finger
        case kVK_ANSI_W:
        case kVK_ANSI_S:
        case kVK_ANSI_X:
        case kVK_ANSI_2:
            return 1;

        // Zone 2: Left middle finger
        case kVK_ANSI_E:
        case kVK_ANSI_D:
        case kVK_ANSI_C:
        case kVK_ANSI_3:
            return 2;

        // Zone 3: Left index (includes reach keys)
        case kVK_ANSI_R:
        case kVK_ANSI_T:
        case kVK_ANSI_F:
        case kVK_ANSI_G:
        case kVK_ANSI_V:
        case kVK_ANSI_B:
        case kVK_ANSI_4:
        case kVK_ANSI_5:
            return 3;

        // Zone 4: Right index (includes reach keys)
        case kVK_ANSI_Y:
        case kVK_ANSI_U:
        case kVK_ANSI_H:
        case kVK_ANSI_J:
        case kVK_ANSI_N:
        case kVK_ANSI_M:
        case kVK_ANSI_6:
        case kVK_ANSI_7:
            return 4;

        // Zone 5: Right middle finger
        case kVK_ANSI_I:
        case kVK_ANSI_K:
        case kVK_ANSI_Comma:
        case kVK_ANSI_8:
            return 5;

        // Zone 6: Right ring finger
        case kVK_ANSI_O:
        case kVK_ANSI_L:
        case kVK_ANSI_Period:
        case kVK_ANSI_9:
            return 6;

        // Zone 7: Right pinky
        case kVK_ANSI_P:
        case kVK_ANSI_Semicolon:
        case kVK_ANSI_Slash:
        case kVK_ANSI_0:
        case kVK_ANSI_Minus:
        case kVK_ANSI_Equal:
        case kVK_ANSI_LeftBracket:
        case kVK_ANSI_RightBracket:
        case kVK_ANSI_Quote:
        case kVK_ANSI_Backslash:
        case kVK_Return:
        case kVK_RightShift:
            return 7;

        // Thumbs (space bar) - could be either hand
        case kVK_Space:
            return -1;  // Special case

        default:
            return -1;
    }
}

@end
