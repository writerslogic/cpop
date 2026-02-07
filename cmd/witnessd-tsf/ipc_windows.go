//go:build windows

package main

/*
#cgo LDFLAGS: -lkernel32

#include <windows.h>
#include <stdint.h>

// ============================================================================
// Named Pipe IPC for Witnessd Daemon Communication
// ============================================================================
//
// This module provides IPC communication between the TSF input processor
// and the witnessd daemon using Windows named pipes.
//
// Protocol:
// - Messages are prefixed with a 4-byte length header (little-endian)
// - Message format is JSON for flexibility and debugging
// - The daemon acts as the server, TSF connects as client
//
// ============================================================================

#define PIPE_NAME L"\\\\.\\pipe\\witnessd"
#define PIPE_BUFFER_SIZE 65536
#define PIPE_TIMEOUT_MS 5000

// Connection state
static HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeLock;
static int g_pipeLockInit = 0;
static volatile int g_connected = 0;

// Statistics
static volatile int64_t g_messagesSent = 0;
static volatile int64_t g_messagesReceived = 0;
static volatile int64_t g_bytesSent = 0;
static volatile int64_t g_bytesReceived = 0;
static volatile int64_t g_connectAttempts = 0;
static volatile int64_t g_connectFailures = 0;

// Initialize IPC
static void InitIPC() {
	if (!g_pipeLockInit) {
		InitializeCriticalSection(&g_pipeLock);
		g_pipeLockInit = 1;
	}
}

// Cleanup IPC
static void CleanupIPC() {
	if (g_pipeHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(g_pipeHandle);
		g_pipeHandle = INVALID_HANDLE_VALUE;
	}
	g_connected = 0;

	if (g_pipeLockInit) {
		DeleteCriticalSection(&g_pipeLock);
		g_pipeLockInit = 0;
	}
}

// Connect to daemon
static int ConnectToDaemon() {
	InitIPC();

	EnterCriticalSection(&g_pipeLock);

	if (g_connected) {
		LeaveCriticalSection(&g_pipeLock);
		return 0;
	}

	g_connectAttempts++;

	// Try to connect to named pipe
	g_pipeHandle = CreateFileW(
		PIPE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (g_pipeHandle == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();

		// If the pipe is busy, wait a bit
		if (err == ERROR_PIPE_BUSY) {
			if (WaitNamedPipeW(PIPE_NAME, PIPE_TIMEOUT_MS)) {
				g_pipeHandle = CreateFileW(
					PIPE_NAME,
					GENERIC_READ | GENERIC_WRITE,
					0,
					NULL,
					OPEN_EXISTING,
					0,
					NULL
				);
			}
		}
	}

	if (g_pipeHandle == INVALID_HANDLE_VALUE) {
		g_connectFailures++;
		LeaveCriticalSection(&g_pipeLock);
		return -1;
	}

	// Set pipe to message mode
	DWORD mode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(g_pipeHandle, &mode, NULL, NULL);

	g_connected = 1;
	LeaveCriticalSection(&g_pipeLock);
	return 0;
}

// Disconnect from daemon
static void DisconnectFromDaemon() {
	EnterCriticalSection(&g_pipeLock);

	if (g_pipeHandle != INVALID_HANDLE_VALUE) {
		FlushFileBuffers(g_pipeHandle);
		DisconnectNamedPipe(g_pipeHandle);
		CloseHandle(g_pipeHandle);
		g_pipeHandle = INVALID_HANDLE_VALUE;
	}
	g_connected = 0;

	LeaveCriticalSection(&g_pipeLock);
}

// Check if connected
static int IsConnected() {
	return g_connected;
}

// Send message (with length prefix)
static int SendMessage(const char* data, int dataLen) {
	if (!g_connected || g_pipeHandle == INVALID_HANDLE_VALUE) {
		return -1;
	}

	EnterCriticalSection(&g_pipeLock);

	// Write length prefix (4 bytes, little-endian)
	uint32_t len = (uint32_t)dataLen;
	DWORD written;

	if (!WriteFile(g_pipeHandle, &len, 4, &written, NULL) || written != 4) {
		g_connected = 0;
		LeaveCriticalSection(&g_pipeLock);
		return -2;
	}

	// Write data
	if (!WriteFile(g_pipeHandle, data, dataLen, &written, NULL) || (int)written != dataLen) {
		g_connected = 0;
		LeaveCriticalSection(&g_pipeLock);
		return -3;
	}

	g_messagesSent++;
	g_bytesSent += dataLen + 4;

	LeaveCriticalSection(&g_pipeLock);
	return 0;
}

// Receive message (with length prefix)
// Returns the number of bytes read, or negative on error
// buffer must be at least PIPE_BUFFER_SIZE bytes
static int ReceiveMessage(char* buffer, int bufferLen) {
	if (!g_connected || g_pipeHandle == INVALID_HANDLE_VALUE) {
		return -1;
	}

	EnterCriticalSection(&g_pipeLock);

	// Read length prefix
	uint32_t len;
	DWORD read;

	if (!ReadFile(g_pipeHandle, &len, 4, &read, NULL) || read != 4) {
		g_connected = 0;
		LeaveCriticalSection(&g_pipeLock);
		return -2;
	}

	if ((int)len > bufferLen) {
		LeaveCriticalSection(&g_pipeLock);
		return -3; // Buffer too small
	}

	// Read data
	if (!ReadFile(g_pipeHandle, buffer, len, &read, NULL) || read != len) {
		g_connected = 0;
		LeaveCriticalSection(&g_pipeLock);
		return -4;
	}

	g_messagesReceived++;
	g_bytesReceived += len + 4;

	LeaveCriticalSection(&g_pipeLock);
	return (int)len;
}

// Check if message is available (non-blocking)
static int MessageAvailable() {
	if (!g_connected || g_pipeHandle == INVALID_HANDLE_VALUE) {
		return 0;
	}

	DWORD avail;
	if (!PeekNamedPipe(g_pipeHandle, NULL, 0, NULL, &avail, NULL)) {
		return 0;
	}

	return avail > 0 ? 1 : 0;
}

// Get statistics
static int64_t GetMessagesSent() { return g_messagesSent; }
static int64_t GetMessagesReceived() { return g_messagesReceived; }
static int64_t GetBytesSent() { return g_bytesSent; }
static int64_t GetBytesReceived() { return g_bytesReceived; }
static int64_t GetConnectAttempts() { return g_connectAttempts; }
static int64_t GetConnectFailures() { return g_connectFailures; }
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unsafe"
)

const (
	// IPCBufferSize is the maximum message size.
	IPCBufferSize = 65536

	// IPCReconnectInterval is the delay between reconnection attempts.
	IPCReconnectInterval = 5 * time.Second

	// IPCPipeName is the name of the named pipe.
	IPCPipeName = `\\.\pipe\witnessd`
)

// IPCClient handles communication with the witnessd daemon.
type IPCClient struct {
	mu sync.RWMutex

	connected        bool
	reconnecting     bool
	lastConnectTime  time.Time
	lastError        error
	onConnect        func()
	onDisconnect     func(error)
	onMessage        func(Message)

	// Receive buffer
	recvBuffer []byte

	// Auto-reconnect
	autoReconnect   bool
	reconnectTicker *time.Ticker
	stopReconnect   chan struct{}
}

// Message represents an IPC message.
type Message struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// MessageType constants for IPC protocol.
const (
	MsgTypeKeystroke      = "keystroke"
	MsgTypeFocusChange    = "focus_change"
	MsgTypeSessionStart   = "session_start"
	MsgTypeSessionEnd     = "session_end"
	MsgTypeConfig         = "config"
	MsgTypeConfigUpdate   = "config_update"
	MsgTypeHeartbeat      = "heartbeat"
	MsgTypePing           = "ping"
	MsgTypePong           = "pong"
	MsgTypeError          = "error"
)

// KeystrokeMessage contains keystroke data for IPC.
type KeystrokeMessage struct {
	VirtualKey  uint16 `json:"vk"`
	ScanCode    uint16 `json:"sc"`
	Character   string `json:"char,omitempty"`
	IsKeyDown   bool   `json:"down"`
	IsInjected  bool   `json:"injected,omitempty"`
	Modifiers   uint32 `json:"mods,omitempty"`
	TimestampNs int64  `json:"ts"`
}

// FocusChangeMessage contains focus change data for IPC.
type FocusChangeMessage struct {
	WindowHandle uint64 `json:"hwnd"`
	ProcessID    uint32 `json:"pid"`
	AppPath      string `json:"app_path"`
	AppName      string `json:"app_name"`
	WindowTitle  string `json:"title"`
	DocumentPath string `json:"doc_path,omitempty"`
	TimestampNs  int64  `json:"ts"`
}

// SessionMessage contains session data for IPC.
type SessionMessage struct {
	SessionID   string `json:"session_id,omitempty"`
	AppID       string `json:"app_id"`
	DocID       string `json:"doc_id"`
	TimestampNs int64  `json:"ts"`
}

// ConfigMessage contains configuration data for IPC.
type ConfigMessage struct {
	// Sampling configuration
	SampleInterval   int  `json:"sample_interval_ms,omitempty"`
	MinSamples       int  `json:"min_samples,omitempty"`
	RejectInjected   bool `json:"reject_injected,omitempty"`

	// Focus tracking
	TrackFocus       bool `json:"track_focus,omitempty"`
	AutoStartSession bool `json:"auto_start_session,omitempty"`
}

// IPCStats contains IPC statistics.
type IPCStats struct {
	MessagesSent      int64
	MessagesReceived  int64
	BytesSent         int64
	BytesReceived     int64
	ConnectAttempts   int64
	ConnectFailures   int64
	Connected         bool
	LastConnectTime   time.Time
}

// NewIPCClient creates a new IPC client.
func NewIPCClient() *IPCClient {
	return &IPCClient{
		recvBuffer:    make([]byte, IPCBufferSize),
		autoReconnect: true,
	}
}

// Connect establishes a connection to the daemon.
func (c *IPCClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	result := C.ConnectToDaemon()
	if result != 0 {
		c.lastError = &IPCError{Code: int(result), Op: "connect"}
		return c.lastError
	}

	c.connected = true
	c.lastConnectTime = time.Now()

	if c.onConnect != nil {
		go c.onConnect()
	}

	return nil
}

// Disconnect closes the connection to the daemon.
func (c *IPCClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	C.DisconnectFromDaemon()
	c.connected = false

	if c.onDisconnect != nil {
		go c.onDisconnect(nil)
	}

	return nil
}

// IsConnected returns whether the client is connected.
func (c *IPCClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// SetConnectCallback sets the callback for connection events.
func (c *IPCClient) SetConnectCallback(cb func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConnect = cb
}

// SetDisconnectCallback sets the callback for disconnection events.
func (c *IPCClient) SetDisconnectCallback(cb func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnect = cb
}

// SetMessageCallback sets the callback for incoming messages.
func (c *IPCClient) SetMessageCallback(cb func(Message)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onMessage = cb
}

// EnableAutoReconnect enables or disables automatic reconnection.
func (c *IPCClient) EnableAutoReconnect(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.autoReconnect = enable

	if enable && c.reconnectTicker == nil {
		c.stopReconnect = make(chan struct{})
		c.reconnectTicker = time.NewTicker(IPCReconnectInterval)
		go c.reconnectLoop()
	} else if !enable && c.reconnectTicker != nil {
		close(c.stopReconnect)
		c.reconnectTicker.Stop()
		c.reconnectTicker = nil
	}
}

// reconnectLoop attempts to reconnect periodically.
func (c *IPCClient) reconnectLoop() {
	for {
		select {
		case <-c.stopReconnect:
			return
		case <-c.reconnectTicker.C:
			if !c.IsConnected() {
				_ = c.Connect()
			}
		}
	}
}

// Send sends a message to the daemon.
func (c *IPCClient) Send(msg Message) error {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return errors.New("not connected")
	}
	c.mu.RUnlock()

	// Set timestamp if not set
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UnixNano()
	}

	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	cData := C.CString(string(data))
	defer C.free(unsafe.Pointer(cData))

	result := C.SendMessage(cData, C.int(len(data)))
	if result != 0 {
		c.handleDisconnect(&IPCError{Code: int(result), Op: "send"})
		return &IPCError{Code: int(result), Op: "send"}
	}

	return nil
}

// SendKeystroke sends a keystroke event to the daemon.
func (c *IPCClient) SendKeystroke(ks RawKeystroke) error {
	charStr := ""
	if ks.Character != 0 {
		charStr = string(ks.Character)
	}

	data, err := json.Marshal(KeystrokeMessage{
		VirtualKey:  ks.VirtualKey,
		ScanCode:    ks.ScanCode,
		Character:   charStr,
		IsKeyDown:   ks.IsKeyDown,
		IsInjected:  ks.IsInjected,
		Modifiers:   ks.Modifiers,
		TimestampNs: ks.Timestamp,
	})
	if err != nil {
		return err
	}

	return c.Send(Message{
		Type: MsgTypeKeystroke,
		Data: data,
	})
}

// SendFocusChange sends a focus change event to the daemon.
func (c *IPCClient) SendFocusChange(info FocusInfo) error {
	data, err := json.Marshal(FocusChangeMessage{
		WindowHandle: uint64(info.WindowHandle),
		ProcessID:    info.ProcessID,
		AppPath:      info.AppPath,
		AppName:      info.AppName,
		WindowTitle:  info.WindowTitle,
		DocumentPath: info.DocumentPath,
		TimestampNs:  info.Timestamp.UnixNano(),
	})
	if err != nil {
		return err
	}

	return c.Send(Message{
		Type: MsgTypeFocusChange,
		Data: data,
	})
}

// SendSessionStart sends a session start message.
func (c *IPCClient) SendSessionStart(appID, docID string) error {
	data, err := json.Marshal(SessionMessage{
		AppID:       appID,
		DocID:       docID,
		TimestampNs: time.Now().UnixNano(),
	})
	if err != nil {
		return err
	}

	return c.Send(Message{
		Type: MsgTypeSessionStart,
		Data: data,
	})
}

// SendSessionEnd sends a session end message.
func (c *IPCClient) SendSessionEnd(sessionID string) error {
	data, err := json.Marshal(SessionMessage{
		SessionID:   sessionID,
		TimestampNs: time.Now().UnixNano(),
	})
	if err != nil {
		return err
	}

	return c.Send(Message{
		Type: MsgTypeSessionEnd,
		Data: data,
	})
}

// SendHeartbeat sends a heartbeat message.
func (c *IPCClient) SendHeartbeat() error {
	return c.Send(Message{
		Type: MsgTypeHeartbeat,
	})
}

// Receive receives a message from the daemon (blocking).
func (c *IPCClient) Receive() (Message, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return Message{}, errors.New("not connected")
	}
	c.mu.RUnlock()

	cBuffer := (*C.char)(unsafe.Pointer(&c.recvBuffer[0]))
	n := C.ReceiveMessage(cBuffer, C.int(len(c.recvBuffer)))

	if n < 0 {
		err := &IPCError{Code: int(n), Op: "receive"}
		c.handleDisconnect(err)
		return Message{}, err
	}

	var msg Message
	if err := json.Unmarshal(c.recvBuffer[:n], &msg); err != nil {
		return Message{}, err
	}

	if c.onMessage != nil {
		go c.onMessage(msg)
	}

	return msg, nil
}

// HasMessage checks if a message is available (non-blocking).
func (c *IPCClient) HasMessage() bool {
	return C.MessageAvailable() != 0
}

// GetStats returns IPC statistics.
func (c *IPCClient) GetStats() IPCStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return IPCStats{
		MessagesSent:     int64(C.GetMessagesSent()),
		MessagesReceived: int64(C.GetMessagesReceived()),
		BytesSent:        int64(C.GetBytesSent()),
		BytesReceived:    int64(C.GetBytesReceived()),
		ConnectAttempts:  int64(C.GetConnectAttempts()),
		ConnectFailures:  int64(C.GetConnectFailures()),
		Connected:        c.connected,
		LastConnectTime:  c.lastConnectTime,
	}
}

// handleDisconnect handles a disconnection event.
func (c *IPCClient) handleDisconnect(err error) {
	c.mu.Lock()
	wasConnected := c.connected
	c.connected = false
	c.lastError = err
	cb := c.onDisconnect
	c.mu.Unlock()

	if wasConnected && cb != nil {
		go cb(err)
	}
}

// IPCError represents an IPC error.
type IPCError struct {
	Code int
	Op   string
}

func (e *IPCError) Error() string {
	switch e.Code {
	case -1:
		return "IPC " + e.Op + ": not connected"
	case -2:
		return "IPC " + e.Op + ": failed to write length prefix"
	case -3:
		return "IPC " + e.Op + ": failed to write data / buffer too small"
	case -4:
		return "IPC " + e.Op + ": failed to read data"
	default:
		return "IPC " + e.Op + ": unknown error"
	}
}

// KeystrokeBatcher batches keystrokes for efficient IPC transmission.
type KeystrokeBatcher struct {
	mu         sync.Mutex
	client     *IPCClient
	batch      []KeystrokeMessage
	maxSize    int
	flushTimer *time.Timer
	flushDelay time.Duration
}

// NewKeystrokeBatcher creates a new keystroke batcher.
func NewKeystrokeBatcher(client *IPCClient, maxSize int, flushDelay time.Duration) *KeystrokeBatcher {
	return &KeystrokeBatcher{
		client:     client,
		batch:      make([]KeystrokeMessage, 0, maxSize),
		maxSize:    maxSize,
		flushDelay: flushDelay,
	}
}

// Add adds a keystroke to the batch.
func (b *KeystrokeBatcher) Add(ks RawKeystroke) {
	b.mu.Lock()
	defer b.mu.Unlock()

	charStr := ""
	if ks.Character != 0 {
		charStr = string(ks.Character)
	}

	b.batch = append(b.batch, KeystrokeMessage{
		VirtualKey:  ks.VirtualKey,
		ScanCode:    ks.ScanCode,
		Character:   charStr,
		IsKeyDown:   ks.IsKeyDown,
		IsInjected:  ks.IsInjected,
		Modifiers:   ks.Modifiers,
		TimestampNs: ks.Timestamp,
	})

	// Flush if batch is full
	if len(b.batch) >= b.maxSize {
		b.flushLocked()
		return
	}

	// Start/reset flush timer
	if b.flushTimer != nil {
		b.flushTimer.Stop()
	}
	b.flushTimer = time.AfterFunc(b.flushDelay, b.Flush)
}

// Flush sends the current batch.
func (b *KeystrokeBatcher) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

func (b *KeystrokeBatcher) flushLocked() {
	if len(b.batch) == 0 {
		return
	}

	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.flushTimer = nil
	}

	// Create batch message
	data, err := json.Marshal(b.batch)
	if err != nil {
		return
	}

	msg := Message{
		Type: MsgTypeKeystroke,
		Data: data,
	}

	_ = b.client.Send(msg)

	// Clear batch
	b.batch = b.batch[:0]
}
