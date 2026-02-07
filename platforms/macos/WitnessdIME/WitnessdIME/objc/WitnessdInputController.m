// WitnessdInputController.m
// Implementation of the Witnessd Input Method Controller

#import "WitnessdInputController.h"
#import <Carbon/Carbon.h>

// Key codes kVK_Delete (0x33) and kVK_ForwardDelete (0x75) are defined in Carbon/Events.h

// Engine state
static BOOL gEngineInitialized = NO;
static BOOL gEngineFailed = NO;

@implementation WitnessdInputController

- (instancetype)initWithServer:(IMKServer*)server delegate:(id)delegate client:(id)client {
    self = [super initWithServer:server delegate:delegate client:client];
    if (self) {
        _currentClient = client;
        _composingText = @"";

        // Initialize the Go engine (once)
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            @try {
                int result = WitnessdInit();
                if (result == 0) {
                    gEngineInitialized = YES;
                    NSLog(@"Witnessd: Engine initialized successfully");
                } else {
                    gEngineFailed = YES;
                    NSLog(@"Witnessd: Engine initialization failed with code %d", result);
                }
            } @catch (NSException* e) {
                gEngineFailed = YES;
                NSLog(@"Witnessd: Engine initialization exception: %@", e);
            }
        });

        // Start session for this client (if engine is available)
        if (gEngineInitialized && !gEngineFailed) {
            [self startSessionForClient:client];
        }
    }
    return self;
}

- (void)startSessionForClient:(id)client {
    // Get bundle ID of the client application
    NSString* bundleID = @"unknown";
    if ([client respondsToSelector:@selector(bundleIdentifier)]) {
        bundleID = [client bundleIdentifier] ?: @"unknown";
    }

    // Generate a document ID from the client's selected range
    // In practice, this would be more sophisticated
    NSString* docID = [NSString stringWithFormat:@"doc-%lu",
                       (unsigned long)[[NSProcessInfo processInfo] processIdentifier]];

    self.currentBundleID = bundleID;
    self.currentDocID = docID;

    // Cast to char* for cgo compatibility (UTF8String returns const char*)
    WitnessdStartSession((char*)[bundleID UTF8String], (char*)[docID UTF8String]);
}

- (void)activateServer:(id)client {
    [super activateServer:client];
    self.currentClient = client;

    // Start or resume session (if engine is available)
    if (gEngineInitialized && !gEngineFailed && !WitnessdHasActiveSession()) {
        [self startSessionForClient:client];
    }
}

- (void)deactivateServer:(id)client {
    // End session when deactivating (if engine is available)
    if (gEngineInitialized && !gEngineFailed) {
        @try {
            char* evidence = WitnessdEndSession();
            if (evidence) {
                NSLog(@"Witnessd session ended: %s", evidence);
                WitnessdFreeString(evidence);
            }
        } @catch (NSException* e) {
            NSLog(@"Witnessd: Exception ending session: %@", e);
            gEngineFailed = YES;
        }
    }

    [super deactivateServer:client];
}

#pragma mark - Key Handling

- (BOOL)handleEvent:(NSEvent*)event client:(id)client {
    if (event.type != NSEventTypeKeyDown) {
        return NO;
    }

    // Get key code
    unsigned short keyCode = event.keyCode;

    // Get characters - use charactersIgnoringModifiers for base character
    NSString* chars = event.characters;

    // If engine failed, pass through without processing
    if (gEngineFailed || !gEngineInitialized) {
        return NO;  // Let system handle normally
    }

    // Handle delete keys
    if (keyCode == kVK_Delete || keyCode == kVK_ForwardDelete) {
        @try {
            WitnessdOnTextDelete(1);
        } @catch (NSException* e) {
            NSLog(@"Witnessd: Exception on delete: %@", e);
        }
        return NO;  // Let the system handle the actual deletion
    }

    if (chars.length == 0) {
        return NO;
    }

    // Extract the full Unicode codepoint (handles emoji and surrogate pairs)
    int32_t charCode = 0;
    NSRange range = NSMakeRange(0, chars.length);
    NSUInteger usedLen = 0;
    if ([chars getBytes:NULL maxLength:0 usedLength:&usedLen
               encoding:NSUTF32LittleEndianStringEncoding
                options:0 range:range remainingRange:NULL]) {
        uint32_t codepoint = 0;
        [chars getBytes:&codepoint maxLength:sizeof(codepoint) usedLength:NULL
               encoding:NSUTF32LittleEndianStringEncoding
                options:0 range:NSMakeRange(0, 1) remainingRange:NULL];
        charCode = (int32_t)codepoint;
    } else {
        // Fallback: use first character
        charCode = (int32_t)[chars characterAtIndex:0];
    }

    // Process through witnessd engine with error recovery
    int64_t jitterMicros = 0;
    @try {
        jitterMicros = WitnessdOnKeyDown(keyCode, charCode);
    } @catch (NSException* e) {
        NSLog(@"Witnessd: Exception on keydown: %@", e);
        // Fall through to normal insertion
    }

    // Apply jitter delay asynchronously to avoid blocking
    if (jitterMicros > 0) {
        NSString* charsToInsert = [chars copy];
        id clientCopy = client;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(jitterMicros * NSEC_PER_USEC)),
                       dispatch_get_main_queue(), ^{
            [clientCopy insertText:charsToInsert
                  replacementRange:NSMakeRange(NSNotFound, 0)];
            @try {
                WitnessdOnTextCommit((char*)[charsToInsert UTF8String]);
            } @catch (NSException* e) {
                NSLog(@"Witnessd: Exception on commit: %@", e);
            }
        });
        return YES;
    }

    // No jitter delay - insert immediately
    [client insertText:chars replacementRange:NSMakeRange(NSNotFound, 0)];
    @try {
        WitnessdOnTextCommit((char*)[chars UTF8String]);
    } @catch (NSException* e) {
        NSLog(@"Witnessd: Exception on commit: %@", e);
    }
    return YES;
}

- (BOOL)inputText:(NSString*)string client:(id)client {
    // Direct text input (e.g., paste)
    // We don't apply jitter to pasted text, but we do track it
    if (string.length > 0) {
        WitnessdOnTextCommit((char*)[string UTF8String]);
    }
    return NO; // Let the system handle the actual insertion
}

- (void)commitComposition:(id)client {
    if (self.composingText.length > 0) {
        [client insertText:self.composingText replacementRange:NSMakeRange(NSNotFound, 0)];
        WitnessdOnTextCommit((char*)[self.composingText UTF8String]);
        self.composingText = @"";
    }
}

- (NSArray*)candidates:(id)client {
    // We don't use candidates in pass-through mode
    return @[];
}

#pragma mark - Menu Support

- (NSMenu*)menu {
    NSMenu* menu = [[NSMenu alloc] initWithTitle:@"Witnessd"];

    // Status item
    int sampleCount = WitnessdGetSampleCount();
    NSString* status = [NSString stringWithFormat:@"Samples: %d", sampleCount];
    NSMenuItem* statusItem = [[NSMenuItem alloc] initWithTitle:status
                                                        action:nil
                                                 keyEquivalent:@""];
    statusItem.enabled = NO;
    [menu addItem:statusItem];

    [menu addItem:[NSMenuItem separatorItem]];

    // End session manually
    NSMenuItem* endItem = [[NSMenuItem alloc] initWithTitle:@"End Session"
                                                     action:@selector(endSessionManually:)
                                              keyEquivalent:@""];
    endItem.target = self;
    [menu addItem:endItem];

    return menu;
}

- (void)endSessionManually:(id)sender {
    char* evidence = WitnessdEndSession();
    if (evidence) {
        // Show the evidence in a notification or dialog
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Session Ended";
        alert.informativeText = [NSString stringWithUTF8String:evidence];
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        WitnessdFreeString(evidence);
    }
}

@end
