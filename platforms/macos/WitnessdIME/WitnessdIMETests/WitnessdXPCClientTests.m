// WitnessdXPCClientTests.m
// Integration tests for XPC communication

#import <XCTest/XCTest.h>
#import "WitnessdXPCClient.h"
#import "WitnessdXPCProtocol.h"

#pragma mark - Mock XPC Service

/// Mock implementation of the XPC protocol for testing
@interface MockWitnessdXPCService : NSObject <WitnessdXPCProtocol>

@property (nonatomic, assign) BOOL sessionActive;
@property (nonatomic, copy) NSString* currentSessionID;
@property (nonatomic, assign) int sampleCount;
@property (nonatomic, assign) int64_t nextJitterValue;

@end

@implementation MockWitnessdXPCService

- (instancetype)init {
    self = [super init];
    if (self) {
        _sessionActive = NO;
        _currentSessionID = nil;
        _sampleCount = 0;
        _nextJitterValue = 500;  // 500 microseconds default
    }
    return self;
}

- (void)startSessionWithBundleIdentifier:(NSString *)bundleIdentifier
                      documentIdentifier:(NSString *)documentIdentifier
                              withReply:(void (^)(BOOL, NSString * _Nullable))reply {
    if (self.sessionActive) {
        reply(NO, nil);
        return;
    }

    self.sessionActive = YES;
    self.currentSessionID = [[NSUUID UUID] UUIDString];
    self.sampleCount = 0;

    reply(YES, self.currentSessionID);
}

- (void)endSessionWithReply:(void (^)(BOOL, NSString * _Nullable))reply {
    if (!self.sessionActive) {
        reply(NO, nil);
        return;
    }

    NSString* evidence = [NSString stringWithFormat:
        @"{\"session_id\":\"%@\",\"samples\":%d}",
        self.currentSessionID, self.sampleCount];

    self.sessionActive = NO;
    self.currentSessionID = nil;

    reply(YES, evidence);
}

- (void)recordKeystrokeWithKeyCode:(uint16_t)keyCode
                          charCode:(int32_t)charCode
                         timestamp:(uint64_t)timestamp
                         withReply:(void (^)(int64_t))reply {
    if (self.sessionActive) {
        self.sampleCount++;
    }
    reply(self.nextJitterValue);
}

- (void)recordTextDeletionWithCount:(int)count {
    // No-op for mock
}

- (void)recordTextCommit:(NSString *)text {
    // No-op for mock
}

- (void)isSessionActiveWithReply:(void (^)(BOOL))reply {
    reply(self.sessionActive);
}

- (void)getSampleCountWithReply:(void (^)(int))reply {
    reply(self.sampleCount);
}

- (void)pingWithReply:(void (^)(BOOL))reply {
    reply(YES);
}

@end

#pragma mark - Test Cases

@interface WitnessdXPCClientTests : XCTestCase

@property (nonatomic, strong) MockWitnessdXPCService* mockService;

@end

@implementation WitnessdXPCClientTests

- (void)setUp {
    [super setUp];
    self.mockService = [[MockWitnessdXPCService alloc] init];
}

- (void)tearDown {
    self.mockService = nil;
    [super tearDown];
}

#pragma mark - Mock Service Unit Tests

- (void)testMockService_StartSession {
    XCTestExpectation* expectation = [self expectationWithDescription:@"Start session"];

    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {
        XCTAssertTrue(success);
        XCTAssertNotNil(sessionID);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_StartSession_AlreadyActive {
    // Start first session
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {}];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Second session fails"];

    // Try to start second session
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-2"
                                            withReply:^(BOOL success, NSString* sessionID) {
        XCTAssertFalse(success);
        XCTAssertNil(sessionID);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_EndSession {
    // Start session first
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {}];

    XCTestExpectation* expectation = [self expectationWithDescription:@"End session"];

    [self.mockService endSessionWithReply:^(BOOL success, NSString* evidenceJSON) {
        XCTAssertTrue(success);
        XCTAssertNotNil(evidenceJSON);
        XCTAssertTrue([evidenceJSON containsString:@"session_id"]);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_EndSession_NoActiveSession {
    XCTestExpectation* expectation = [self expectationWithDescription:@"End session fails"];

    [self.mockService endSessionWithReply:^(BOOL success, NSString* evidenceJSON) {
        XCTAssertFalse(success);
        XCTAssertNil(evidenceJSON);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_RecordKeystroke {
    // Start session first
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {}];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Record keystroke"];

    [self.mockService recordKeystrokeWithKeyCode:0x00  // 'A' key
                                        charCode:'a'
                                       timestamp:0
                                       withReply:^(int64_t jitterMicros) {
        XCTAssertEqual(jitterMicros, 500);  // Default mock value
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_SampleCount {
    // Start session
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {}];

    // Record some keystrokes
    for (int i = 0; i < 5; i++) {
        [self.mockService recordKeystrokeWithKeyCode:0x00
                                            charCode:'a'
                                           timestamp:0
                                           withReply:^(int64_t jitterMicros) {}];
    }

    XCTestExpectation* expectation = [self expectationWithDescription:@"Get sample count"];

    [self.mockService getSampleCountWithReply:^(int count) {
        XCTAssertEqual(count, 5);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_IsSessionActive {
    XCTestExpectation* expectation1 = [self expectationWithDescription:@"Initially inactive"];

    [self.mockService isSessionActiveWithReply:^(BOOL active) {
        XCTAssertFalse(active);
        [expectation1 fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];

    // Start session
    [self.mockService startSessionWithBundleIdentifier:@"com.test.app"
                                    documentIdentifier:@"doc-1"
                                            withReply:^(BOOL success, NSString* sessionID) {}];

    XCTestExpectation* expectation2 = [self expectationWithDescription:@"Now active"];

    [self.mockService isSessionActiveWithReply:^(BOOL active) {
        XCTAssertTrue(active);
        [expectation2 fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testMockService_Ping {
    XCTestExpectation* expectation = [self expectationWithDescription:@"Ping"];

    [self.mockService pingWithReply:^(BOOL alive) {
        XCTAssertTrue(alive);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

#pragma mark - XPC Client Tests

- (void)testXPCClient_Singleton {
    WitnessdXPCClient* client1 = [WitnessdXPCClient shared];
    WitnessdXPCClient* client2 = [WitnessdXPCClient shared];

    XCTAssertEqual(client1, client2);
    XCTAssertNotNil(client1);
}

- (void)testXPCClient_InitiallyDisconnected {
    WitnessdXPCClient* client = [WitnessdXPCClient shared];

    // Disconnect any previous connection
    [client disconnect];

    XCTAssertFalse(client.isConnected);
}

// Note: Full XPC integration tests require a running XPC service
// These tests verify the client's interface and basic behavior

@end
