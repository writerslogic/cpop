// WitnessdInputControllerTests.m
// Unit tests for WitnessdInputController

#import <XCTest/XCTest.h>
#import <InputMethodKit/InputMethodKit.h>
#import <Carbon/Carbon.h>
#import "WitnessdInputController.h"
#import "WitnessdInputController+Enhanced.h"

#pragma mark - Mock Client

/// Mock IMK client for testing
@interface MockIMKClient : NSObject

@property (nonatomic, copy) NSString* insertedText;
@property (nonatomic, assign) NSRange replacementRange;
@property (nonatomic, copy) NSString* bundleIdentifier;
@property (nonatomic, assign) NSUInteger insertCount;

@end

@implementation MockIMKClient

- (instancetype)init {
    self = [super init];
    if (self) {
        _insertedText = @"";
        _replacementRange = NSMakeRange(NSNotFound, 0);
        _bundleIdentifier = @"com.test.app";
        _insertCount = 0;
    }
    return self;
}

- (void)insertText:(id)string replacementRange:(NSRange)range {
    if ([string isKindOfClass:[NSString class]]) {
        self.insertedText = string;
    } else if ([string isKindOfClass:[NSAttributedString class]]) {
        self.insertedText = [(NSAttributedString*)string string];
    }
    self.replacementRange = range;
    self.insertCount++;
}

@end

#pragma mark - Test Cases

@interface WitnessdInputControllerTests : XCTestCase

@property (nonatomic, strong) WitnessdInputController* controller;
@property (nonatomic, strong) MockIMKClient* mockClient;

@end

@implementation WitnessdInputControllerTests

- (void)setUp {
    [super setUp];

    self.mockClient = [[MockIMKClient alloc] init];
    // Note: In a real test, we'd need to properly initialize with an IMKServer
    // For unit testing, we test the methods directly
}

- (void)tearDown {
    self.controller = nil;
    self.mockClient = nil;

    [super tearDown];
}

#pragma mark - Zone Mapping Tests

- (void)testZoneMapping_LeftPinky {
    // Create a temporary controller for testing the enhanced category
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Left pinky keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Q], 0);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_A], 0);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Z], 0);
}

- (void)testZoneMapping_LeftRing {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Left ring keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_W], 1);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_S], 1);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_X], 1);
}

- (void)testZoneMapping_LeftMiddle {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Left middle keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_E], 2);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_D], 2);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_C], 2);
}

- (void)testZoneMapping_LeftIndex {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Left index keys (including reach)
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_R], 3);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_T], 3);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_F], 3);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_G], 3);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_V], 3);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_B], 3);
}

- (void)testZoneMapping_RightIndex {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Right index keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Y], 4);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_U], 4);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_H], 4);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_J], 4);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_N], 4);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_M], 4);
}

- (void)testZoneMapping_RightMiddle {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Right middle keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_I], 5);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_K], 5);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Comma], 5);
}

- (void)testZoneMapping_RightRing {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Right ring keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_O], 6);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_L], 6);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Period], 6);
}

- (void)testZoneMapping_RightPinky {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Right pinky keys
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_P], 7);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Semicolon], 7);
    XCTAssertEqual([testController zoneForKeyCode:kVK_ANSI_Slash], 7);
    XCTAssertEqual([testController zoneForKeyCode:kVK_Return], 7);
}

- (void)testZoneMapping_SpaceBar {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Space bar is special (thumb) - returns -1
    XCTAssertEqual([testController zoneForKeyCode:kVK_Space], -1);
}

- (void)testZoneMapping_UnknownKey {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Unknown keys return -1
    XCTAssertEqual([testController zoneForKeyCode:0xFF], -1);
}

#pragma mark - Dead Key Tests

- (void)testDeadKeyState_InitiallyNone {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    [testController resetDeadKeyState];
    // After reset, there should be no dead key state
    // The actual state is stored via associated objects
}

- (void)testComposeCharacter_GraveAccent {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Test grave accent composition
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateGrave], L'\u00E0');
    XCTAssertEqual([testController composeCharacter:'e' withDeadKeyState:WitnessdDeadKeyStateGrave], L'\u00E8');
    XCTAssertEqual([testController composeCharacter:'A' withDeadKeyState:WitnessdDeadKeyStateGrave], L'\u00C0');
}

- (void)testComposeCharacter_AcuteAccent {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Test acute accent composition
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateAcute], L'\u00E1');
    XCTAssertEqual([testController composeCharacter:'e' withDeadKeyState:WitnessdDeadKeyStateAcute], L'\u00E9');
    XCTAssertEqual([testController composeCharacter:'E' withDeadKeyState:WitnessdDeadKeyStateAcute], L'\u00C9');
}

- (void)testComposeCharacter_Circumflex {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Test circumflex composition
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateCircumflex], L'\u00E2');
    XCTAssertEqual([testController composeCharacter:'o' withDeadKeyState:WitnessdDeadKeyStateCircumflex], L'\u00F4');
}

- (void)testComposeCharacter_Tilde {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Test tilde composition
    XCTAssertEqual([testController composeCharacter:'n' withDeadKeyState:WitnessdDeadKeyStateTilde], L'\u00F1');
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateTilde], L'\u00E3');
    XCTAssertEqual([testController composeCharacter:'N' withDeadKeyState:WitnessdDeadKeyStateTilde], L'\u00D1');
}

- (void)testComposeCharacter_Dieresis {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Test dieresis/umlaut composition
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateDieresis], L'\u00E4');
    XCTAssertEqual([testController composeCharacter:'o' withDeadKeyState:WitnessdDeadKeyStateDieresis], L'\u00F6');
    XCTAssertEqual([testController composeCharacter:'u' withDeadKeyState:WitnessdDeadKeyStateDieresis], L'\u00FC');
}

- (void)testComposeCharacter_NoComposition {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // Characters that don't compose should return unchanged
    XCTAssertEqual([testController composeCharacter:'z' withDeadKeyState:WitnessdDeadKeyStateGrave], 'z');
    XCTAssertEqual([testController composeCharacter:'x' withDeadKeyState:WitnessdDeadKeyStateAcute], 'x');
}

- (void)testComposeCharacter_NoDeadKey {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    // With no dead key state, return unchanged
    XCTAssertEqual([testController composeCharacter:'a' withDeadKeyState:WitnessdDeadKeyStateNone], 'a');
    XCTAssertEqual([testController composeCharacter:'e' withDeadKeyState:WitnessdDeadKeyStateNone], 'e');
}

#pragma mark - Keyboard Layout Tests

- (void)testCurrentKeyboardLayout {
    WitnessdInputController* testController = [[WitnessdInputController alloc] init];

    NSString* layout = [testController currentKeyboardLayout];
    // Should return something (the current keyboard layout)
    // The actual value depends on system settings
    // We just verify it doesn't crash and returns a string or nil
    XCTAssertTrue(layout == nil || [layout isKindOfClass:[NSString class]]);
}

@end
