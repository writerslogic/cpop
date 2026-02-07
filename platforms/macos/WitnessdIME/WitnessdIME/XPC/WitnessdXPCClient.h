// WitnessdXPCClient.h
// XPC Client for connecting to the Witnessd daemon
//
// This class manages the XPC connection lifecycle and provides a clean
// interface for the IME to communicate with the daemon.

#import <Foundation/Foundation.h>
#import "WitnessdXPCProtocol.h"

NS_ASSUME_NONNULL_BEGIN

/// XPC Client for communicating with the Witnessd daemon
/// Thread-safe and handles automatic reconnection
@interface WitnessdXPCClient : NSObject

/// Shared singleton instance
@property (class, readonly, strong) WitnessdXPCClient *shared;

/// Whether the client is currently connected to the daemon
@property (nonatomic, readonly, getter=isConnected) BOOL connected;

/// Delegate for connection events
@property (nonatomic, weak, nullable) id<WitnessdXPCConnectionDelegate> delegate;

/// Connect to the XPC service
/// @param completion Callback with success status
- (void)connectWithCompletion:(void (^)(BOOL success))completion;

/// Disconnect from the XPC service
- (void)disconnect;

/// Start a new session
/// @param bundleID Bundle identifier of the monitored app
/// @param docID Document/field identifier
/// @param completion Callback with session ID or nil on failure
- (void)startSessionWithBundleID:(NSString *)bundleID
                           docID:(NSString *)docID
                      completion:(void (^)(NSString * _Nullable sessionID))completion;

/// End the current session
/// @param completion Callback with evidence summary JSON or nil
- (void)endSessionWithCompletion:(void (^)(NSString * _Nullable evidenceJSON))completion;

/// Record a keystroke
/// @param keyCode Virtual key code
/// @param charCode Unicode character code
/// @param timestamp Timestamp in microseconds
/// @param completion Callback with jitter delay in microseconds
- (void)recordKeystrokeWithKeyCode:(uint16_t)keyCode
                          charCode:(int32_t)charCode
                         timestamp:(uint64_t)timestamp
                        completion:(void (^)(int64_t jitterMicros))completion;

/// Record text deletion (async, no reply)
/// @param count Number of characters deleted
- (void)recordTextDeletionWithCount:(int)count;

/// Record text commit (async, no reply)
/// @param text The committed text
- (void)recordTextCommit:(NSString *)text;

/// Check if session is active
/// @param completion Callback with active status
- (void)isSessionActiveWithCompletion:(void (^)(BOOL active))completion;

/// Get current sample count
/// @param completion Callback with sample count
- (void)getSampleCountWithCompletion:(void (^)(int count))completion;

@end

NS_ASSUME_NONNULL_END
