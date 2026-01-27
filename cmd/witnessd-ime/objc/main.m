// main.m
// Witnessd Input Method - macOS Entry Point
//
// This file sets up the Input Method Kit server and runs the event loop.
// The actual input handling is done in WitnessdInputController.

#import <Cocoa/Cocoa.h>
#import <InputMethodKit/InputMethodKit.h>
#import "WitnessdInputController.h"

// The IMKServer instance must be kept alive for the duration of the process
static IMKServer* server = nil;

int main(int argc, const char* argv[]) {
    @autoreleasepool {
        // Get the bundle ID from Info.plist
        NSBundle* bundle = [NSBundle mainBundle];
        NSString* bundleID = [bundle bundleIdentifier];

        if (!bundleID) {
            NSLog(@"Error: No bundle identifier found");
            return 1;
        }

        // The connection name must match InputMethodConnectionName in Info.plist
        NSString* connectionName = [NSString stringWithFormat:@"%@_Connection", bundleID];

        // Create the Input Method server
        server = [[IMKServer alloc] initWithName:connectionName
                                bundleIdentifier:bundleID];

        if (!server) {
            NSLog(@"Error: Failed to create IMKServer");
            return 1;
        }

        NSLog(@"Witnessd IME started with connection: %@", connectionName);

        // Run the application event loop
        [[NSApplication sharedApplication] run];
    }
    return 0;
}
