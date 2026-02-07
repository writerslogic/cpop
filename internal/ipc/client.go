// Package ipc provides client implementation for daemon-client communication.
//
// The client supports:
// - Automatic connection and reconnection
// - Request/response pattern with timeouts
// - Event streaming for real-time updates
// - Thread-safe operations
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors
var (
	ErrNotConnected    = errors.New("not connected to daemon")
	ErrConnectionLost  = errors.New("connection to daemon lost")
	ErrTimeout         = errors.New("request timeout")
	ErrDaemonNotRunning = errors.New("daemon is not running")
)

// IPCClient is the client for communicating with the witnessd daemon
type IPCClient struct {
	mu         sync.RWMutex
	conn       net.Conn
	socketPath string
	sessionID  string
	version    string
	permission PermissionLevel

	// Connection state
	connected    atomic.Bool
	reconnecting atomic.Bool

	// Request handling
	pending     map[uint32]chan *Message
	pendingMu   sync.Mutex
	nextReqID   atomic.Uint32

	// Event handling
	eventChan    chan *Event
	eventHandler EventHandler
	eventMu      sync.RWMutex

	// Reconnection
	autoReconnect bool
	reconnectWait time.Duration
	maxReconnect  int

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Configuration
	config ClientConfig
}

// ClientConfig configures the IPC client
type ClientConfig struct {
	SocketPath     string
	ClientName     string
	ClientVersion  string
	ConnectTimeout time.Duration
	RequestTimeout time.Duration
	AutoReconnect  bool
	ReconnectWait  time.Duration
	MaxReconnect   int
}

// DefaultClientConfig returns sensible defaults
func DefaultClientConfig(witnessdDir string) ClientConfig {
	return ClientConfig{
		SocketPath:     filepath.Join(witnessdDir, "daemon.sock"),
		ClientName:     "witnessctl",
		ClientVersion:  "1.0.0",
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 30 * time.Second,
		AutoReconnect:  true,
		ReconnectWait:  time.Second,
		MaxReconnect:   3,
	}
}

// EventHandler is called when events are received
type EventHandler func(event *Event)

// NewClient creates a new IPC client
func NewClient(cfg ClientConfig) *IPCClient {
	ctx, cancel := context.WithCancel(context.Background())

	return &IPCClient{
		socketPath:    cfg.SocketPath,
		pending:       make(map[uint32]chan *Message),
		eventChan:     make(chan *Event, 100),
		autoReconnect: cfg.AutoReconnect,
		reconnectWait: cfg.ReconnectWait,
		maxReconnect:  cfg.MaxReconnect,
		ctx:           ctx,
		cancel:        cancel,
		config:        cfg,
	}
}

// Connect establishes a connection to the daemon
func (c *IPCClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return nil
	}

	// Determine connection type based on platform
	var conn net.Conn
	var err error

	if runtime.GOOS == "windows" {
		// Use named pipe on Windows
		conn, err = c.connectWindows()
	} else {
		// Use Unix socket on other platforms
		conn, err = c.connectUnix()
	}

	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	c.conn = conn
	c.connected.Store(true)

	// Start reader goroutine
	c.wg.Add(1)
	go c.readLoop()

	// Perform handshake
	if err := c.handshake(); err != nil {
		c.close()
		return fmt.Errorf("handshake: %w", err)
	}

	// Authenticate
	if err := c.authenticate(); err != nil {
		c.close()
		return fmt.Errorf("authenticate: %w", err)
	}

	return nil
}

// connectUnix establishes a Unix socket connection
func (c *IPCClient) connectUnix() (net.Conn, error) {
	dialer := net.Dialer{
		Timeout: c.config.ConnectTimeout,
	}

	conn, err := dialer.Dial("unix", c.socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrDaemonNotRunning
		}
		return nil, err
	}

	return conn, nil
}

// connectWindows establishes a Windows named pipe connection
func (c *IPCClient) connectWindows() (net.Conn, error) {
	// For Windows, we need to use the WindowsPipeConn
	// This is handled in client_windows.go
	return nil, errors.New("windows connection not implemented in this file")
}

// Close closes the connection to the daemon
func (c *IPCClient) Close() error {
	c.cancel()
	c.close()

	// Wait for reader to finish
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}

	close(c.eventChan)
	return nil
}

// close closes the connection without signaling shutdown
func (c *IPCClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected.Store(false)

	// Cancel all pending requests
	c.pendingMu.Lock()
	for _, ch := range c.pending {
		close(ch)
	}
	c.pending = make(map[uint32]chan *Message)
	c.pendingMu.Unlock()
}

// IsConnected returns whether the client is connected
func (c *IPCClient) IsConnected() bool {
	return c.connected.Load()
}

// SessionID returns the session ID assigned by the server
func (c *IPCClient) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

// SetEventHandler sets the handler for streamed events
func (c *IPCClient) SetEventHandler(handler EventHandler) {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	c.eventHandler = handler
}

// Events returns the event channel for streaming events
func (c *IPCClient) Events() <-chan *Event {
	return c.eventChan
}

// handshake performs the initial handshake with the server
func (c *IPCClient) handshake() error {
	req := &HandshakeRequest{
		ClientVersion:   c.config.ClientVersion,
		ClientName:      c.config.ClientName,
		ProtocolVersion: ProtocolVersion,
	}

	resp, err := c.request(MsgHandshake, req)
	if err != nil {
		return err
	}

	if resp.Header.Type != MsgHandshakeAck {
		return fmt.Errorf("unexpected response type: %d", resp.Header.Type)
	}

	var ack HandshakeResponse
	if err := Decode(resp.Payload, &ack); err != nil {
		return err
	}

	c.sessionID = ack.SessionID
	c.version = ack.ServerVersion
	c.permission = ack.Permission

	return nil
}

// authenticate authenticates with the server
func (c *IPCClient) authenticate() error {
	req := &AuthRequest{
		Method: "pid",
		PID:    os.Getpid(),
	}

	resp, err := c.request(MsgAuthenticate, req)
	if err != nil {
		return err
	}

	if resp.Header.Type != MsgAuthResponse {
		return fmt.Errorf("unexpected response type: %d", resp.Header.Type)
	}

	var authResp AuthResponse
	if err := Decode(resp.Payload, &authResp); err != nil {
		return err
	}

	if !authResp.Success {
		return fmt.Errorf("authentication failed: %s", authResp.Error)
	}

	c.permission = authResp.Permission
	return nil
}

// request sends a request and waits for a response
func (c *IPCClient) request(msgType MessageType, payload any) (*Message, error) {
	return c.requestWithTimeout(msgType, payload, c.config.RequestTimeout)
}

// requestWithTimeout sends a request with a custom timeout
func (c *IPCClient) requestWithTimeout(msgType MessageType, payload any, timeout time.Duration) (*Message, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	// Encode payload
	data, err := Encode(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	// Create message
	reqID := c.nextReqID.Add(1)
	msg := NewMessage(msgType, reqID, data)

	// Create response channel
	respChan := make(chan *Message, 1)
	c.pendingMu.Lock()
	c.pending[reqID] = respChan
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, reqID)
		c.pendingMu.Unlock()
	}()

	// Send message
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := msg.Write(conn); err != nil {
		c.handleConnectionError(err)
		return nil, fmt.Errorf("write message: %w", err)
	}

	// Wait for response
	select {
	case resp, ok := <-respChan:
		if !ok {
			return nil, ErrConnectionLost
		}
		return resp, nil
	case <-time.After(timeout):
		return nil, ErrTimeout
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// readLoop reads messages from the connection
func (c *IPCClient) readLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			if c.autoReconnect {
				c.tryReconnect()
				continue
			}
			return
		}

		// Read message
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		msg, err := ReadMessage(conn)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}

			// Handle timeout (send ping)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.sendPing()
				continue
			}

			c.handleConnectionError(err)
			if c.autoReconnect {
				c.tryReconnect()
				continue
			}
			return
		}

		// Handle message
		c.handleMessage(msg)
	}
}

// handleMessage processes an incoming message
func (c *IPCClient) handleMessage(msg *Message) {
	switch msg.Header.Type {
	case MsgPong:
		// Ping response, ignore

	case MsgPing:
		// Respond to ping
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		if conn != nil {
			pong := NewMessage(MsgPong, msg.Header.RequestID, nil)
			pong.Write(conn)
		}

	case MsgEvent:
		// Dispatch event
		var event Event
		if err := Decode(msg.Payload, &event); err == nil {
			select {
			case c.eventChan <- &event:
			default:
				// Channel full, drop event
			}

			c.eventMu.RLock()
			handler := c.eventHandler
			c.eventMu.RUnlock()
			if handler != nil {
				go handler(&event)
			}
		}

	default:
		// Response to a request
		c.pendingMu.Lock()
		if ch, ok := c.pending[msg.Header.RequestID]; ok {
			select {
			case ch <- msg:
			default:
			}
		}
		c.pendingMu.Unlock()
	}
}

// sendPing sends a ping to keep connection alive
func (c *IPCClient) sendPing() {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn != nil {
		msg := NewMessage(MsgPing, c.nextReqID.Add(1), nil)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		msg.Write(conn)
	}
}

// handleConnectionError handles connection errors
func (c *IPCClient) handleConnectionError(err error) {
	c.close()
}

// tryReconnect attempts to reconnect to the daemon
func (c *IPCClient) tryReconnect() {
	if !c.reconnecting.CompareAndSwap(false, true) {
		return // Already reconnecting
	}
	defer c.reconnecting.Store(false)

	for i := 0; i < c.maxReconnect; i++ {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.reconnectWait):
		}

		if err := c.Connect(); err == nil {
			return
		}
	}
}

// High-level API methods

// Status requests the daemon status
func (c *IPCClient) Status() (*StatusResponse, error) {
	req := &StatusRequest{
		IncludeConfig:   true,
		IncludeSessions: true,
	}

	resp, err := c.request(MsgStatusRequest, req)
	if err != nil {
		return nil, err
	}

	if resp.Header.Type == MsgError {
		var errResp ErrorResponse
		Decode(resp.Payload, &errResp)
		return nil, fmt.Errorf("%s", errResp.Message)
	}

	var status StatusResponse
	if err := Decode(resp.Payload, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// Ping checks if the daemon is responsive
func (c *IPCClient) Ping() error {
	resp, err := c.requestWithTimeout(MsgPing, nil, 5*time.Second)
	if err != nil {
		return err
	}

	if resp.Header.Type != MsgPong {
		return fmt.Errorf("unexpected response: %d", resp.Header.Type)
	}

	return nil
}

// StartSession starts a tracking session
func (c *IPCClient) StartSession(documentPath string, useTPM, strictMode bool) (*StartSessionResponse, error) {
	req := &StartSessionRequest{
		DocumentPath: documentPath,
		UseTPM:       useTPM,
		StrictMode:   strictMode,
	}

	resp, err := c.request(MsgStartSession, req)
	if err != nil {
		return nil, err
	}

	var result StartSessionResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// StopSession stops a tracking session
func (c *IPCClient) StopSession(sessionID string, save bool) (*StopSessionResponse, error) {
	req := &StopSessionRequest{
		SessionID: sessionID,
		Save:      save,
	}

	resp, err := c.request(MsgStopSession, req)
	if err != nil {
		return nil, err
	}

	var result StopSessionResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ListSessions lists tracking sessions
func (c *IPCClient) ListSessions(activeOnly bool, limit int) (*ListSessionsResponse, error) {
	req := &ListSessionsRequest{
		ActiveOnly: activeOnly,
		Limit:      limit,
	}

	resp, err := c.request(MsgListSessions, req)
	if err != nil {
		return nil, err
	}

	var result ListSessionsResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetSessionStatus gets detailed session status
func (c *IPCClient) GetSessionStatus(sessionID string) (*SessionStatus, error) {
	req := &SessionStatusRequest{
		SessionID: sessionID,
	}

	resp, err := c.request(MsgSessionStatus, req)
	if err != nil {
		return nil, err
	}

	var result SessionStatus
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CommitCheckpoint creates a checkpoint
func (c *IPCClient) CommitCheckpoint(filePath, message string) (*CommitCheckpointResponse, error) {
	req := &CommitCheckpointRequest{
		FilePath: filePath,
		Message:  message,
	}

	resp, err := c.requestWithTimeout(MsgCommitCheckpoint, req, 2*time.Minute)
	if err != nil {
		return nil, err
	}

	var result CommitCheckpointResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetHistory gets checkpoint history
func (c *IPCClient) GetHistory(filePath string, limit, offset int) (*GetHistoryResponse, error) {
	req := &GetHistoryRequest{
		FilePath: filePath,
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := c.request(MsgGetHistory, req)
	if err != nil {
		return nil, err
	}

	var result GetHistoryResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ExportEvidence exports evidence for a file
func (c *IPCClient) ExportEvidence(filePath, tier, format string) (*ExportEvidenceResponse, error) {
	req := &ExportEvidenceRequest{
		FilePath: filePath,
		Tier:     tier,
		Format:   format,
	}

	resp, err := c.requestWithTimeout(MsgExportEvidence, req, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	var result ExportEvidenceResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// VerifyChain verifies a checkpoint chain
func (c *IPCClient) VerifyChain(filePath string, evidence []byte) (*VerifyChainResponse, error) {
	req := &VerifyChainRequest{
		FilePath: filePath,
		Evidence: evidence,
	}

	resp, err := c.requestWithTimeout(MsgVerifyChain, req, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	var result VerifyChainResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Subscribe subscribes to events
func (c *IPCClient) Subscribe(events []EventType) error {
	req := &SubscribeRequest{
		Events: events,
	}

	resp, err := c.request(MsgSubscribe, req)
	if err != nil {
		return err
	}

	var result SubscribeResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return err
	}

	if !result.Success {
		return errors.New("subscription failed")
	}

	return nil
}

// Unsubscribe unsubscribes from events
func (c *IPCClient) Unsubscribe() error {
	req := &UnsubscribeRequest{}

	resp, err := c.request(MsgUnsubscribe, req)
	if err != nil {
		return err
	}

	if resp.Header.Type != MsgUnsubscribeResp {
		return fmt.Errorf("unexpected response: %d", resp.Header.Type)
	}

	return nil
}

// TrackingStart starts tracking a document
func (c *IPCClient) TrackingStart(documentPath string, useTPM, strictMode bool) (*TrackingStartResponse, error) {
	req := &TrackingStartRequest{
		DocumentPath: documentPath,
		UseTPM:       useTPM,
		StrictMode:   strictMode,
	}

	resp, err := c.request(MsgTrackingStart, req)
	if err != nil {
		return nil, err
	}

	var result TrackingStartResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// TrackingStop stops tracking
func (c *IPCClient) TrackingStop(sessionID string) (*TrackingStopResponse, error) {
	req := &TrackingStopRequest{
		SessionID: sessionID,
	}

	resp, err := c.request(MsgTrackingStop, req)
	if err != nil {
		return nil, err
	}

	var result TrackingStopResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// TrackingStatus gets tracking status
func (c *IPCClient) TrackingStatus(sessionID string) (*TrackingStatusResponse, error) {
	req := &TrackingStatusRequest{
		SessionID: sessionID,
	}

	resp, err := c.request(MsgTrackingStatus, req)
	if err != nil {
		return nil, err
	}

	var result TrackingStatusResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetConfig gets daemon configuration
func (c *IPCClient) GetConfig(keys []string) (*ConfigResponse, error) {
	req := &ConfigRequest{
		Keys: keys,
	}

	resp, err := c.request(MsgGetConfig, req)
	if err != nil {
		return nil, err
	}

	var result ConfigResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SetConfig sets daemon configuration
func (c *IPCClient) SetConfig(config map[string]any) error {
	req := &SetConfigRequest{
		Config: config,
	}

	resp, err := c.request(MsgSetConfig, req)
	if err != nil {
		return err
	}

	var result SetConfigResponse
	if err := Decode(resp.Payload, &result); err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("set config failed: %s", result.Error)
	}

	return nil
}
