// Package ipc provides inter-process communication between the witnessd daemon
// and client applications (CLI, GUI, third-party tools).
//
// The protocol is designed for:
// - Request/response pattern for commands
// - Event streaming for real-time updates
// - Binary efficiency with MessagePack serialization
// - Protocol versioning for compatibility
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Protocol version for compatibility checking
const (
	ProtocolVersion = 1
	ProtocolMagic   = 0x57495043 // "WIPC" - Witnessd IPC
)

// MessageType identifies the type of IPC message
type MessageType uint16

const (
	// Control messages (0x00xx)
	MsgPing          MessageType = 0x0001
	MsgPong          MessageType = 0x0002
	MsgHandshake     MessageType = 0x0003
	MsgHandshakeAck  MessageType = 0x0004
	MsgError         MessageType = 0x0005
	MsgShutdown      MessageType = 0x0006
	MsgAuthenticate  MessageType = 0x0007
	MsgAuthResponse  MessageType = 0x0008

	// Status messages (0x01xx)
	MsgStatusRequest  MessageType = 0x0100
	MsgStatusResponse MessageType = 0x0101
	MsgHealthCheck    MessageType = 0x0102
	MsgHealthResponse MessageType = 0x0103

	// Session management (0x02xx)
	MsgStartSession     MessageType = 0x0200
	MsgStartSessionResp MessageType = 0x0201
	MsgStopSession      MessageType = 0x0202
	MsgStopSessionResp  MessageType = 0x0203
	MsgListSessions     MessageType = 0x0204
	MsgListSessionsResp MessageType = 0x0205
	MsgSessionStatus    MessageType = 0x0206
	MsgSessionStatusResp MessageType = 0x0207

	// Checkpoint operations (0x03xx)
	MsgCommitCheckpoint     MessageType = 0x0300
	MsgCommitCheckpointResp MessageType = 0x0301
	MsgGetHistory           MessageType = 0x0302
	MsgGetHistoryResp       MessageType = 0x0303
	MsgExportEvidence       MessageType = 0x0304
	MsgExportEvidenceResp   MessageType = 0x0305
	MsgVerifyChain          MessageType = 0x0306
	MsgVerifyChainResp      MessageType = 0x0307

	// Configuration (0x04xx)
	MsgGetConfig     MessageType = 0x0400
	MsgGetConfigResp MessageType = 0x0401
	MsgSetConfig     MessageType = 0x0402
	MsgSetConfigResp MessageType = 0x0403
	MsgReloadConfig  MessageType = 0x0404

	// Event streaming (0x05xx)
	MsgSubscribe       MessageType = 0x0500
	MsgSubscribeResp   MessageType = 0x0501
	MsgUnsubscribe     MessageType = 0x0502
	MsgUnsubscribeResp MessageType = 0x0503
	MsgEvent           MessageType = 0x0504

	// Tracking operations (0x06xx)
	MsgTrackingStart     MessageType = 0x0600
	MsgTrackingStartResp MessageType = 0x0601
	MsgTrackingStop      MessageType = 0x0602
	MsgTrackingStopResp  MessageType = 0x0603
	MsgTrackingStatus    MessageType = 0x0604
	MsgTrackingStatusResp MessageType = 0x0605
)

// EventType identifies the type of streamed event
type EventType uint16

const (
	EventKeystrokeUpdate   EventType = 0x0001
	EventSessionStart      EventType = 0x0002
	EventSessionStop       EventType = 0x0003
	EventCheckpointCreated EventType = 0x0004
	EventTrackingUpdate    EventType = 0x0005
	EventError             EventType = 0x0006
	EventDaemonShutdown    EventType = 0x0007
	EventConfigChanged     EventType = 0x0008
)

// PermissionLevel defines client access levels
type PermissionLevel uint8

const (
	PermReadOnly    PermissionLevel = 0x01
	PermReadWrite   PermissionLevel = 0x02
	PermFullControl PermissionLevel = 0x03
)

// Header is the fixed-size message header (16 bytes)
type Header struct {
	Magic     uint32      // Protocol magic number
	Version   uint8       // Protocol version
	Flags     uint8       // Message flags
	Type      MessageType // Message type
	RequestID uint32      // Request ID for correlation
	Length    uint32      // Payload length (not including header)
}

// HeaderSize is the size of the header in bytes
const HeaderSize = 16

// Header flags
const (
	FlagCompressed  uint8 = 0x01
	FlagEncrypted   uint8 = 0x02
	FlagJSON        uint8 = 0x04 // Use JSON instead of MessagePack
	FlagStreamStart uint8 = 0x08
	FlagStreamEnd   uint8 = 0x10
)

// Message wraps a header and payload
type Message struct {
	Header  Header
	Payload []byte
}

// NewMessage creates a new message with the given type and payload
func NewMessage(msgType MessageType, requestID uint32, payload []byte) *Message {
	return &Message{
		Header: Header{
			Magic:     ProtocolMagic,
			Version:   ProtocolVersion,
			Flags:     FlagJSON, // Default to JSON for readability
			Type:      msgType,
			RequestID: requestID,
			Length:    uint32(len(payload)),
		},
		Payload: payload,
	}
}

// WriteHeader writes the header to a writer
func (h *Header) Write(w io.Writer) error {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(buf[0:4], h.Magic)
	buf[4] = h.Version
	buf[5] = h.Flags
	binary.BigEndian.PutUint16(buf[6:8], uint16(h.Type))
	binary.BigEndian.PutUint32(buf[8:12], h.RequestID)
	binary.BigEndian.PutUint32(buf[12:16], h.Length)
	_, err := w.Write(buf)
	return err
}

// ReadHeader reads a header from a reader
func ReadHeader(r io.Reader) (*Header, error) {
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	h := &Header{
		Magic:     binary.BigEndian.Uint32(buf[0:4]),
		Version:   buf[4],
		Flags:     buf[5],
		Type:      MessageType(binary.BigEndian.Uint16(buf[6:8])),
		RequestID: binary.BigEndian.Uint32(buf[8:12]),
		Length:    binary.BigEndian.Uint32(buf[12:16]),
	}

	if h.Magic != ProtocolMagic {
		return nil, fmt.Errorf("invalid magic number: %x", h.Magic)
	}

	if h.Version > ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", h.Version)
	}

	return h, nil
}

// Write writes the message to a writer
func (m *Message) Write(w io.Writer) error {
	if err := m.Header.Write(w); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		_, err := w.Write(m.Payload)
		return err
	}
	return nil
}

// ReadMessage reads a complete message from a reader
func ReadMessage(r io.Reader) (*Message, error) {
	h, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}

	m := &Message{Header: *h}
	if h.Length > 0 {
		// Limit payload size to 64MB
		if h.Length > 64*1024*1024 {
			return nil, fmt.Errorf("payload too large: %d bytes", h.Length)
		}
		m.Payload = make([]byte, h.Length)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// Request/Response payloads

// HandshakeRequest is sent by the client to initiate connection
type HandshakeRequest struct {
	ClientVersion   string `json:"client_version"`
	ClientName      string `json:"client_name"`
	ProtocolVersion uint8  `json:"protocol_version"`
	Capabilities    uint32 `json:"capabilities"` // Bitmask of supported features
}

// HandshakeResponse is sent by the server to acknowledge connection
type HandshakeResponse struct {
	ServerVersion   string          `json:"server_version"`
	ProtocolVersion uint8           `json:"protocol_version"`
	SessionID       string          `json:"session_id"`
	Permission      PermissionLevel `json:"permission"`
	Capabilities    uint32          `json:"capabilities"`
}

// AuthRequest is sent to authenticate a client
type AuthRequest struct {
	Method string `json:"method"` // "pid", "token", "none"
	PID    int    `json:"pid,omitempty"`
	Token  string `json:"token,omitempty"`
}

// AuthResponse acknowledges authentication
type AuthResponse struct {
	Success    bool            `json:"success"`
	Permission PermissionLevel `json:"permission"`
	Error      string          `json:"error,omitempty"`
}

// ErrorResponse is sent when an operation fails
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error codes
const (
	ErrUnknown         = 1
	ErrInvalidRequest  = 2
	ErrNotFound        = 3
	ErrPermissionDenied = 4
	ErrInternalError   = 5
	ErrAlreadyExists   = 6
	ErrNotInitialized  = 7
	ErrSessionActive   = 8
	ErrNoActiveSession = 9
)

// StatusRequest requests daemon status
type StatusRequest struct {
	IncludeConfig   bool `json:"include_config,omitempty"`
	IncludeSessions bool `json:"include_sessions,omitempty"`
}

// StatusResponse contains daemon status
type StatusResponse struct {
	Version        string           `json:"version"`
	Uptime         time.Duration    `json:"uptime"`
	StartedAt      time.Time        `json:"started_at"`
	Initialized    bool             `json:"initialized"`
	DatabaseStatus DatabaseStatus   `json:"database_status"`
	TPMStatus      TPMStatus        `json:"tpm_status,omitempty"`
	ActiveSessions []SessionSummary `json:"active_sessions,omitempty"`
	Config         map[string]any   `json:"config,omitempty"`
}

// DatabaseStatus contains database health info
type DatabaseStatus struct {
	Type        string    `json:"type"` // "sqlite", "mmr"
	EventCount  int64     `json:"event_count"`
	FileCount   int       `json:"file_count"`
	IntegrityOK bool      `json:"integrity_ok"`
	LastEvent   time.Time `json:"last_event,omitempty"`
}

// TPMStatus contains TPM availability info
type TPMStatus struct {
	Available       bool   `json:"available"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// SessionSummary provides brief session info
type SessionSummary struct {
	ID           string        `json:"id"`
	DocumentPath string        `json:"document_path"`
	StartedAt    time.Time     `json:"started_at"`
	Duration     time.Duration `json:"duration"`
	Keystrokes   uint64        `json:"keystrokes"`
}

// StartSessionRequest requests to start a tracking session
type StartSessionRequest struct {
	DocumentPath string `json:"document_path"`
	UseTPM       bool   `json:"use_tpm,omitempty"`
	StrictMode   bool   `json:"strict_mode,omitempty"`
}

// StartSessionResponse acknowledges session start
type StartSessionResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// StopSessionRequest requests to stop a tracking session
type StopSessionRequest struct {
	SessionID string `json:"session_id"`
	Save      bool   `json:"save,omitempty"`
}

// StopSessionResponse acknowledges session stop
type StopSessionResponse struct {
	Success   bool           `json:"success"`
	Summary   *SessionStatus `json:"summary,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// ListSessionsRequest requests session list
type ListSessionsRequest struct {
	ActiveOnly bool `json:"active_only,omitempty"`
	Limit      int  `json:"limit,omitempty"`
}

// ListSessionsResponse contains session list
type ListSessionsResponse struct {
	Sessions []SessionSummary `json:"sessions"`
}

// SessionStatusRequest requests detailed session status
type SessionStatusRequest struct {
	SessionID string `json:"session_id"`
}

// SessionStatus contains detailed session information
type SessionStatus struct {
	ID               string        `json:"id"`
	Running          bool          `json:"running"`
	StartedAt        time.Time     `json:"started_at"`
	EndedAt          time.Time     `json:"ended_at,omitempty"`
	Duration         time.Duration `json:"duration"`
	DocumentPath     string        `json:"document_path"`
	KeystrokeCount   uint64        `json:"keystroke_count"`
	SampleCount      int           `json:"sample_count"`
	KeystrokesPerMin float64       `json:"keystrokes_per_minute"`
	Checkpoints      int           `json:"checkpoints"`
	TPMAvailable     bool          `json:"tpm_available"`
	Compromised      bool          `json:"compromised"`
	CompromiseReason string        `json:"compromise_reason,omitempty"`
}

// CommitCheckpointRequest requests a checkpoint creation
type CommitCheckpointRequest struct {
	FilePath string `json:"file_path"`
	Message  string `json:"message,omitempty"`
}

// CommitCheckpointResponse acknowledges checkpoint creation
type CommitCheckpointResponse struct {
	Success      bool   `json:"success"`
	CheckpointID int    `json:"checkpoint_id,omitempty"`
	ContentHash  string `json:"content_hash,omitempty"`
	EventHash    string `json:"event_hash,omitempty"`
	VDFElapsed   string `json:"vdf_elapsed,omitempty"`
	Error        string `json:"error,omitempty"`
}

// GetHistoryRequest requests checkpoint history
type GetHistoryRequest struct {
	FilePath string `json:"file_path"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

// CheckpointInfo contains checkpoint details
type CheckpointInfo struct {
	Ordinal      int       `json:"ordinal"`
	Timestamp    time.Time `json:"timestamp"`
	ContentHash  string    `json:"content_hash"`
	EventHash    string    `json:"event_hash"`
	FileSize     int64     `json:"file_size"`
	SizeDelta    int32     `json:"size_delta"`
	VDFElapsed   string    `json:"vdf_elapsed"`
	Message      string    `json:"message,omitempty"`
}

// GetHistoryResponse contains checkpoint history
type GetHistoryResponse struct {
	FilePath     string           `json:"file_path"`
	Total        int              `json:"total"`
	TotalVDFTime string           `json:"total_vdf_time"`
	Checkpoints  []CheckpointInfo `json:"checkpoints"`
}

// ExportEvidenceRequest requests evidence export
type ExportEvidenceRequest struct {
	FilePath string `json:"file_path"`
	Tier     string `json:"tier,omitempty"` // "basic", "standard", "enhanced", "maximum"
	Format   string `json:"format,omitempty"` // "json", "wpkt"
}

// ExportEvidenceResponse contains exported evidence
type ExportEvidenceResponse struct {
	Success  bool   `json:"success"`
	Evidence []byte `json:"evidence,omitempty"` // Encoded evidence packet
	Filename string `json:"filename,omitempty"`
	Error    string `json:"error,omitempty"`
}

// VerifyChainRequest requests chain verification
type VerifyChainRequest struct {
	FilePath string `json:"file_path,omitempty"`
	Evidence []byte `json:"evidence,omitempty"` // Or verify evidence packet
}

// VerifyChainResponse contains verification results
type VerifyChainResponse struct {
	Valid       bool     `json:"valid"`
	Checkpoints int      `json:"checkpoints"`
	TotalTime   string   `json:"total_time"`
	Claims      []string `json:"claims,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// SubscribeRequest requests event subscription
type SubscribeRequest struct {
	Events []EventType `json:"events"` // Empty means all events
}

// SubscribeResponse acknowledges subscription
type SubscribeResponse struct {
	Success        bool   `json:"success"`
	SubscriptionID string `json:"subscription_id"`
}

// UnsubscribeRequest requests event unsubscription
type UnsubscribeRequest struct {
	SubscriptionID string `json:"subscription_id"`
}

// Event is a streamed event
type Event struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id,omitempty"`
	Data      any       `json:"data"`
}

// KeystrokeUpdateEvent contains keystroke count update
type KeystrokeUpdateEvent struct {
	SessionID    string        `json:"session_id"`
	Count        uint64        `json:"count"`
	SampleCount  int           `json:"sample_count"`
	Rate         float64       `json:"rate"` // Keystrokes per minute
	Duration     time.Duration `json:"duration"`
}

// TrackingStartRequest requests to start tracking a document
type TrackingStartRequest struct {
	DocumentPath string `json:"document_path"`
	UseTPM       bool   `json:"use_tpm,omitempty"`
	StrictMode   bool   `json:"strict_mode,omitempty"`
}

// TrackingStartResponse acknowledges tracking start
type TrackingStartResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// TrackingStopRequest requests to stop tracking
type TrackingStopRequest struct {
	SessionID string `json:"session_id,omitempty"` // If empty, stops current session
}

// TrackingStopResponse acknowledges tracking stop
type TrackingStopResponse struct {
	Success        bool           `json:"success"`
	SessionSummary *SessionStatus `json:"session_summary,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// TrackingStatusRequest requests current tracking status
type TrackingStatusRequest struct {
	SessionID string `json:"session_id,omitempty"` // If empty, returns current session
}

// TrackingStatusResponse contains tracking status
type TrackingStatusResponse struct {
	Active  bool           `json:"active"`
	Session *SessionStatus `json:"session,omitempty"`
}

// ConfigRequest requests configuration
type ConfigRequest struct {
	Keys []string `json:"keys,omitempty"` // If empty, returns all config
}

// ConfigResponse contains configuration
type ConfigResponse struct {
	Config map[string]any `json:"config"`
}

// SetConfigRequest sets configuration values
type SetConfigRequest struct {
	Config map[string]any `json:"config"`
}

// SetConfigResponse acknowledges config change
type SetConfigResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Encode encodes a payload to JSON bytes
func Encode(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Decode decodes JSON bytes to a payload
func Decode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// NewErrorMessage creates an error message
func NewErrorMessage(requestID uint32, code int, message string) *Message {
	payload, _ := Encode(&ErrorResponse{
		Code:    code,
		Message: message,
	})
	return NewMessage(MsgError, requestID, payload)
}

// NewResponse creates a response message
func NewResponse(msgType MessageType, requestID uint32, v any) (*Message, error) {
	payload, err := Encode(v)
	if err != nil {
		return nil, err
	}
	return NewMessage(msgType, requestID, payload), nil
}
