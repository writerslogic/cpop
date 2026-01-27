// WitnessdInputController.h
// Witnessd Input Method Controller for macOS
//
// This Objective-C class implements the IMKInputController protocol,
// which is required for macOS Input Method Kit integration.

#import <Cocoa/Cocoa.h>
#import <InputMethodKit/InputMethodKit.h>

// Include the cgo-generated header with Go exported functions
#include "libwitnessd.h"

@interface WitnessdInputController : IMKInputController

// Track current client for context
@property (nonatomic, strong) id currentClient;
@property (nonatomic, copy) NSString* currentBundleID;
@property (nonatomic, copy) NSString* currentDocID;

// Pending composition (for IME candidate window, if needed)
@property (nonatomic, copy) NSString* composingText;

@end
