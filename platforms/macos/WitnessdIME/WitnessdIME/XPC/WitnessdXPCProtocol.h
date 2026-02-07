// WitnessdXPCProtocol.h
// XPC Protocol for communication between IME and Witnessd daemon
//
// This protocol defines the interface for the XPC service that bridges
// the IME component with the main Witnessd daemon for keystroke transmission.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Protocol for the XPC service interface
/// The IME uses this to send keystroke data to the daemon
@protocol WitnessdXPCProtocol <NSObject>

/// Initialize a new session for keystroke monitoring
/// @param bundleIdentifier The bundle ID of the application being monitored
/// @param documentIdentifier A unique identifier for the document/text field
/// @param reply Callback with success status and session ID (or nil on failure)
- (void)startSessionWithBundleIdentifier:(NSString *)bundleIdentifier
                      documentIdentifier:(NSString *)documentIdentifier
                              withReply:(void (^)(BOOL success, NSString * _Nullable sessionID))reply;

/// End the current session and finalize evidence
/// @param reply Callback with success status and evidence summary JSON (or nil)
- (void)endSessionWithReply:(void (^)(BOOL success, NSString * _Nullable evidenceJSON))reply;

/// Record a keystroke event
/// @param keyCode The virtual key code
/// @param charCode The Unicode character code
/// @param timestamp The timestamp of the keystroke (microseconds since epoch)
/// @param reply Callback with the jitter delay in microseconds
- (void)recordKeystrokeWithKeyCode:(uint16_t)keyCode
                          charCode:(int32_t)charCode
                         timestamp:(uint64_t)timestamp
                         withReply:(void (^)(int64_t jitterMicros))reply;

/// Record text deletion
/// @param count Number of characters deleted
- (void)recordTextDeletionWithCount:(int)count;

/// Record text commit (text was inserted into the document)
/// @param text The text that was committed
- (void)recordTextCommit:(NSString *)text;

/// Check if a session is currently active
/// @param reply Callback with active status
- (void)isSessionActiveWithReply:(void (^)(BOOL active))reply;

/// Get current sample count
/// @param reply Callback with sample count
- (void)getSampleCountWithReply:(void (^)(int count))reply;

/// Ping the service to check if it's alive
/// @param reply Callback to confirm service is responsive
- (void)pingWithReply:(void (^)(BOOL alive))reply;

@end

/// Protocol for handling XPC connection events
@protocol WitnessdXPCConnectionDelegate <NSObject>

/// Called when the XPC connection is interrupted
- (void)xpcConnectionInterrupted;

/// Called when the XPC connection is invalidated
- (void)xpcConnectionInvalidated;

@end

/// Mach service name for the XPC connection
/// Format: <team-id>.<bundle-id>.xpc
extern NSString * const WitnessdXPCServiceName;

NS_ASSUME_NONNULL_END
