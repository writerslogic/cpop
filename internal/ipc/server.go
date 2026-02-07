// Package ipc provides server implementation for daemon-client communication.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Handler processes IPC messages
type Handler interface {
	// HandleMessage processes a message and returns a response
	HandleMessage(ctx context.Context, client *Client, msg *Message) (*Message, error)
}

// HandlerFunc is a function that implements Handler
type HandlerFunc func(ctx context.Context, client *Client, msg *Message) (*Message, error)

func (f HandlerFunc) HandleMessage(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	return f(ctx, client, msg)
}

// Server is the IPC server that manages client connections
type Server struct {
	mu          sync.RWMutex
	listener    net.Listener
	socketPath  string
	handler     Handler
	clients     map[string]*Client
	subscribers map[string]*subscription
	version     string
	startedAt   time.Time

	// Shutdown coordination
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	running    atomic.Bool

	// Request ID counter
	nextRequestID atomic.Uint32

	// Event channel for broadcasting
	eventChan chan *Event
}

// Client represents a connected client
type Client struct {
	mu           sync.Mutex
	ID           string
	conn         net.Conn
	Permission   PermissionLevel
	Authenticated bool
	Version      string
	Name         string
	ConnectedAt  time.Time
	LastActivity time.Time

	// Write serialization
	writeMu sync.Mutex
}

// subscription tracks event subscriptions
type subscription struct {
	clientID string
	events   map[EventType]bool
}

// ServerConfig configures the IPC server
type ServerConfig struct {
	SocketPath     string        // Unix socket path
	Version        string        // Server version
	DefaultPerm    PermissionLevel
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxConnections int
}

// DefaultServerConfig returns sensible defaults
func DefaultServerConfig(witnessdDir string) ServerConfig {
	return ServerConfig{
		SocketPath:     filepath.Join(witnessdDir, "daemon.sock"),
		Version:        "1.0.0",
		DefaultPerm:    PermReadWrite,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxConnections: 100,
	}
}

// NewServer creates a new IPC server
func NewServer(cfg ServerConfig, handler Handler) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		socketPath:  cfg.SocketPath,
		handler:     handler,
		version:     cfg.Version,
		clients:     make(map[string]*Client),
		subscribers: make(map[string]*subscription),
		ctx:         ctx,
		cancel:      cancel,
		eventChan:   make(chan *Event, 100),
	}, nil
}

// Start begins listening for connections
func (s *Server) Start() error {
	// Ensure socket directory exists
	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	// Remove stale socket file
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}

	// Set socket permissions (owner only)
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("set socket permissions: %w", err)
	}

	s.listener = listener
	s.startedAt = time.Now()
	s.running.Store(true)

	// Start event broadcaster
	s.wg.Add(1)
	go s.eventBroadcaster()

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return nil // Already stopped
	}

	// Signal shutdown
	s.cancel()

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all client connections
	s.mu.Lock()
	for _, client := range s.clients {
		client.conn.Close()
	}
	s.mu.Unlock()

	// Close event channel
	close(s.eventChan)

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(5 * time.Second):
		// Timeout
	}

	// Remove socket file
	os.Remove(s.socketPath)

	return nil
}

// SocketPath returns the socket path
func (s *Server) SocketPath() string {
	return s.socketPath
}

// ClientCount returns the number of connected clients
func (s *Server) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// Broadcast sends an event to all subscribed clients
func (s *Server) Broadcast(event *Event) {
	select {
	case s.eventChan <- event:
	default:
		// Channel full, drop event
	}
}

// acceptLoop accepts new connections
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if !errors.Is(err, net.ErrClosed) {
					// Log error but continue
				}
				continue
			}
		}

		// Check connection limit
		s.mu.RLock()
		count := len(s.clients)
		s.mu.RUnlock()

		if count >= 100 { // Max connections
			conn.Close()
			continue
		}

		// Create client and handle connection
		client := &Client{
			ID:          generateClientID(),
			conn:        conn,
			Permission:  PermReadOnly, // Start with read-only until authenticated
			ConnectedAt: time.Now(),
			LastActivity: time.Now(),
		}

		s.mu.Lock()
		s.clients[client.ID] = client
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConnection(client)
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(client *Client) {
	defer s.wg.Done()
	defer func() {
		// Remove client on disconnect
		s.mu.Lock()
		delete(s.clients, client.ID)
		delete(s.subscribers, client.ID)
		s.mu.Unlock()
		client.conn.Close()
	}()

	// Main message loop
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set read deadline
		client.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read message
		msg, err := ReadMessage(client.conn)
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return
			}
			// Timeout or other error - continue
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Send ping to keep connection alive
				s.sendPing(client)
				continue
			}
			return
		}

		client.mu.Lock()
		client.LastActivity = time.Now()
		client.mu.Unlock()

		// Handle message
		response, err := s.processMessage(client, msg)
		if err != nil {
			response = NewErrorMessage(msg.Header.RequestID, ErrInternalError, err.Error())
		}

		if response != nil {
			if err := s.sendMessage(client, response); err != nil {
				return
			}
		}
	}
}

// processMessage processes a single message
func (s *Server) processMessage(client *Client, msg *Message) (*Message, error) {
	// Handle protocol messages internally
	switch msg.Header.Type {
	case MsgPing:
		return NewMessage(MsgPong, msg.Header.RequestID, nil), nil

	case MsgHandshake:
		return s.handleHandshake(client, msg)

	case MsgAuthenticate:
		return s.handleAuthenticate(client, msg)

	case MsgSubscribe:
		return s.handleSubscribe(client, msg)

	case MsgUnsubscribe:
		return s.handleUnsubscribe(client, msg)

	default:
		// Check permissions for write operations
		if !client.Authenticated && msg.Header.Type != MsgStatusRequest {
			return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "not authenticated"), nil
		}

		if s.handler != nil {
			return s.handler.HandleMessage(s.ctx, client, msg)
		}
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "no handler"), nil
	}
}

// handleHandshake processes handshake request
func (s *Server) handleHandshake(client *Client, msg *Message) (*Message, error) {
	var req HandshakeRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid handshake"), nil
	}

	client.mu.Lock()
	client.Version = req.ClientVersion
	client.Name = req.ClientName
	client.mu.Unlock()

	resp := &HandshakeResponse{
		ServerVersion:   s.version,
		ProtocolVersion: ProtocolVersion,
		SessionID:       client.ID,
		Permission:      client.Permission,
		Capabilities:    0, // Future expansion
	}

	return NewResponse(MsgHandshakeAck, msg.Header.RequestID, resp)
}

// handleAuthenticate processes authentication request
func (s *Server) handleAuthenticate(client *Client, msg *Message) (*Message, error) {
	var req AuthRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid auth request"), nil
	}

	// Simple authentication - verify PID or accept all local connections
	// For Unix sockets, the kernel verifies the connecting process
	success := true
	permission := PermReadWrite // Default for local connections

	if req.Method == "pid" {
		// Could verify the PID matches the connecting process
		// via SO_PEERCRED on Linux or LOCAL_PEERCRED on macOS
		success = true
		permission = PermFullControl
	}

	if success {
		client.mu.Lock()
		client.Authenticated = true
		client.Permission = permission
		client.mu.Unlock()
	}

	resp := &AuthResponse{
		Success:    success,
		Permission: permission,
	}
	if !success {
		resp.Error = "authentication failed"
	}

	return NewResponse(MsgAuthResponse, msg.Header.RequestID, resp)
}

// handleSubscribe processes event subscription
func (s *Server) handleSubscribe(client *Client, msg *Message) (*Message, error) {
	var req SubscribeRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid subscribe request"), nil
	}

	s.mu.Lock()
	sub := &subscription{
		clientID: client.ID,
		events:   make(map[EventType]bool),
	}
	if len(req.Events) == 0 {
		// Subscribe to all events
		sub.events[EventKeystrokeUpdate] = true
		sub.events[EventSessionStart] = true
		sub.events[EventSessionStop] = true
		sub.events[EventCheckpointCreated] = true
		sub.events[EventTrackingUpdate] = true
		sub.events[EventError] = true
	} else {
		for _, et := range req.Events {
			sub.events[et] = true
		}
	}
	s.subscribers[client.ID] = sub
	s.mu.Unlock()

	resp := &SubscribeResponse{
		Success:        true,
		SubscriptionID: client.ID,
	}

	return NewResponse(MsgSubscribeResp, msg.Header.RequestID, resp)
}

// handleUnsubscribe processes event unsubscription
func (s *Server) handleUnsubscribe(client *Client, msg *Message) (*Message, error) {
	s.mu.Lock()
	delete(s.subscribers, client.ID)
	s.mu.Unlock()

	return NewMessage(MsgUnsubscribeResp, msg.Header.RequestID, nil), nil
}

// eventBroadcaster broadcasts events to subscribers
func (s *Server) eventBroadcaster() {
	defer s.wg.Done()

	for event := range s.eventChan {
		s.mu.RLock()
		for clientID, sub := range s.subscribers {
			if sub.events[event.Type] {
				if client, ok := s.clients[clientID]; ok {
					go s.sendEvent(client, event)
				}
			}
		}
		s.mu.RUnlock()
	}
}

// sendEvent sends an event to a client
func (s *Server) sendEvent(client *Client, event *Event) {
	payload, err := Encode(event)
	if err != nil {
		return
	}

	msg := NewMessage(MsgEvent, s.nextRequestID.Add(1), payload)
	s.sendMessage(client, msg)
}

// sendMessage sends a message to a client
func (s *Server) sendMessage(client *Client, msg *Message) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()

	client.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return msg.Write(client.conn)
}

// sendPing sends a ping to keep connection alive
func (s *Server) sendPing(client *Client) {
	msg := NewMessage(MsgPing, s.nextRequestID.Add(1), nil)
	s.sendMessage(client, msg)
}

// generateClientID generates a unique client ID
func generateClientID() string {
	return fmt.Sprintf("client-%d-%d", time.Now().UnixNano(), os.Getpid())
}
