// WitnessdXPCClient.m
// XPC Client Implementation

#import "WitnessdXPCClient.h"
#import <os/log.h>

// Define the Mach service name
NSString * const WitnessdXPCServiceName = @"com.witnessd.daemon.xpc";

// Logging subsystem
static os_log_t _Nonnull WitnessdXPCLog(void) {
    static os_log_t log = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        log = os_log_create("com.witnessd.inputmethod", "XPC");
    });
    return log;
}

@interface WitnessdXPCClient ()

@property (nonatomic, strong, nullable) NSXPCConnection *connection;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, assign) BOOL isReconnecting;

@end

@implementation WitnessdXPCClient

#pragma mark - Singleton

+ (WitnessdXPCClient *)shared {
    static WitnessdXPCClient *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[WitnessdXPCClient alloc] init];
    });
    return sharedInstance;
}

#pragma mark - Initialization

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.witnessd.xpc.client", DISPATCH_QUEUE_SERIAL);
        _isReconnecting = NO;
    }
    return self;
}

- (void)dealloc {
    [self disconnect];
}

#pragma mark - Connection Management

- (BOOL)isConnected {
    __block BOOL connected = NO;
    dispatch_sync(self.queue, ^{
        connected = (self.connection != nil);
    });
    return connected;
}

- (void)connectWithCompletion:(void (^)(BOOL success))completion {
    dispatch_async(self.queue, ^{
        if (self.connection) {
            os_log(WitnessdXPCLog(), "Already connected to XPC service");
            if (completion) completion(YES);
            return;
        }

        [self establishConnectionWithCompletion:completion];
    });
}

- (void)establishConnectionWithCompletion:(void (^)(BOOL success))completion {
    os_log(WitnessdXPCLog(), "Establishing XPC connection to %{public}@", WitnessdXPCServiceName);

    // Create connection to the Mach service
    self.connection = [[NSXPCConnection alloc] initWithMachServiceName:WitnessdXPCServiceName
                                                               options:0];

    // Set the interface
    self.connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WitnessdXPCProtocol)];

    // Set up interruption handler
    __weak typeof(self) weakSelf = self;
    self.connection.interruptionHandler = ^{
        os_log(WitnessdXPCLog(), "XPC connection interrupted");
        dispatch_async(weakSelf.queue, ^{
            weakSelf.connection = nil;
            [weakSelf scheduleReconnection];
        });
        [weakSelf.delegate xpcConnectionInterrupted];
    };

    // Set up invalidation handler
    self.connection.invalidationHandler = ^{
        os_log(WitnessdXPCLog(), "XPC connection invalidated");
        dispatch_async(weakSelf.queue, ^{
            weakSelf.connection = nil;
        });
        [weakSelf.delegate xpcConnectionInvalidated];
    };

    // Resume the connection
    [self.connection resume];

    // Verify connection by pinging
    id<WitnessdXPCProtocol> proxy = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        os_log_error(WitnessdXPCLog(), "XPC proxy error: %{public}@", error.localizedDescription);
        if (completion) completion(NO);
    }];

    [proxy pingWithReply:^(BOOL alive) {
        if (alive) {
            os_log(WitnessdXPCLog(), "XPC connection established successfully");
            if (completion) completion(YES);
        } else {
            os_log_error(WitnessdXPCLog(), "XPC service not responding");
            if (completion) completion(NO);
        }
    }];
}

- (void)disconnect {
    dispatch_sync(self.queue, ^{
        if (self.connection) {
            [self.connection invalidate];
            self.connection = nil;
        }
    });
}

- (void)scheduleReconnection {
    if (self.isReconnecting) {
        return;
    }

    self.isReconnecting = YES;

    // Exponential backoff for reconnection
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), self.queue, ^{
        self.isReconnecting = NO;
        [self establishConnectionWithCompletion:^(BOOL success) {
            if (!success) {
                os_log(WitnessdXPCLog(), "Reconnection attempt failed, will retry");
                [self scheduleReconnection];
            }
        }];
    });
}

#pragma mark - Remote Object Access

- (nullable id<WitnessdXPCProtocol>)remoteProxy {
    __block id<WitnessdXPCProtocol> proxy = nil;
    dispatch_sync(self.queue, ^{
        if (self.connection) {
            proxy = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                os_log_error(WitnessdXPCLog(), "Remote proxy error: %{public}@", error.localizedDescription);
            }];
        }
    });
    return proxy;
}

#pragma mark - Session Management

- (void)startSessionWithBundleID:(NSString *)bundleID
                           docID:(NSString *)docID
                      completion:(void (^)(NSString * _Nullable))completion {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        os_log_error(WitnessdXPCLog(), "No XPC connection available for startSession");
        if (completion) completion(nil);
        return;
    }

    [proxy startSessionWithBundleIdentifier:bundleID
                         documentIdentifier:docID
                                 withReply:^(BOOL success, NSString * _Nullable sessionID) {
        if (success) {
            os_log(WitnessdXPCLog(), "Session started: %{public}@", sessionID ?: @"unknown");
        }
        if (completion) completion(success ? sessionID : nil);
    }];
}

- (void)endSessionWithCompletion:(void (^)(NSString * _Nullable))completion {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        os_log_error(WitnessdXPCLog(), "No XPC connection available for endSession");
        if (completion) completion(nil);
        return;
    }

    [proxy endSessionWithReply:^(BOOL success, NSString * _Nullable evidenceJSON) {
        if (success) {
            os_log(WitnessdXPCLog(), "Session ended successfully");
        }
        if (completion) completion(success ? evidenceJSON : nil);
    }];
}

#pragma mark - Keystroke Recording

- (void)recordKeystrokeWithKeyCode:(uint16_t)keyCode
                          charCode:(int32_t)charCode
                         timestamp:(uint64_t)timestamp
                        completion:(void (^)(int64_t))completion {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        if (completion) completion(0);
        return;
    }

    [proxy recordKeystrokeWithKeyCode:keyCode
                             charCode:charCode
                            timestamp:timestamp
                            withReply:^(int64_t jitterMicros) {
        if (completion) completion(jitterMicros);
    }];
}

- (void)recordTextDeletionWithCount:(int)count {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        return;
    }

    [proxy recordTextDeletionWithCount:count];
}

- (void)recordTextCommit:(NSString *)text {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        return;
    }

    [proxy recordTextCommit:text];
}

#pragma mark - Status Queries

- (void)isSessionActiveWithCompletion:(void (^)(BOOL))completion {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        if (completion) completion(NO);
        return;
    }

    [proxy isSessionActiveWithReply:^(BOOL active) {
        if (completion) completion(active);
    }];
}

- (void)getSampleCountWithCompletion:(void (^)(int))completion {
    id<WitnessdXPCProtocol> proxy = [self remoteProxy];
    if (!proxy) {
        if (completion) completion(0);
        return;
    }

    [proxy getSampleCountWithReply:^(int count) {
        if (completion) completion(count);
    }];
}

@end
