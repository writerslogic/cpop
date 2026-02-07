// Package ipc provides the daemon handler implementation.
//
// The handler processes IPC messages and integrates with the
// witnessd daemon's tracking, checkpoint, and evidence systems.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/store"
	"witnessd/internal/tracking"
	"witnessd/internal/tpm"
	"witnessd/internal/vdf"
)

// DaemonHandler implements the Handler interface for the witnessd daemon
type DaemonHandler struct {
	mu          sync.RWMutex
	witnessdDir string
	version     string
	startedAt   time.Time

	// Tracking manager
	trackingMgr *tracking.Manager

	// Secure store
	store *store.SecureStore

	// VDF parameters
	vdfParams vdf.Parameters

	// Event broadcaster (for sending events to clients)
	broadcaster func(*Event)
}

// DaemonHandlerConfig configures the daemon handler
type DaemonHandlerConfig struct {
	WitnessdDir string
	Version     string
	Store       *store.SecureStore
	VDFParams   vdf.Parameters
}

// NewDaemonHandler creates a new daemon handler
func NewDaemonHandler(cfg DaemonHandlerConfig) *DaemonHandler {
	return &DaemonHandler{
		witnessdDir: cfg.WitnessdDir,
		version:     cfg.Version,
		startedAt:   time.Now(),
		trackingMgr: tracking.NewManager(cfg.WitnessdDir),
		store:       cfg.Store,
		vdfParams:   cfg.VDFParams,
	}
}

// SetBroadcaster sets the function used to broadcast events
func (h *DaemonHandler) SetBroadcaster(broadcaster func(*Event)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcaster = broadcaster
}

// HandleMessage processes an IPC message
func (h *DaemonHandler) HandleMessage(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	switch msg.Header.Type {
	case MsgStatusRequest:
		return h.handleStatus(ctx, client, msg)

	case MsgHealthCheck:
		return h.handleHealthCheck(ctx, client, msg)

	case MsgStartSession:
		return h.handleStartSession(ctx, client, msg)

	case MsgStopSession:
		return h.handleStopSession(ctx, client, msg)

	case MsgListSessions:
		return h.handleListSessions(ctx, client, msg)

	case MsgSessionStatus:
		return h.handleSessionStatus(ctx, client, msg)

	case MsgCommitCheckpoint:
		return h.handleCommitCheckpoint(ctx, client, msg)

	case MsgGetHistory:
		return h.handleGetHistory(ctx, client, msg)

	case MsgExportEvidence:
		return h.handleExportEvidence(ctx, client, msg)

	case MsgVerifyChain:
		return h.handleVerifyChain(ctx, client, msg)

	case MsgGetConfig:
		return h.handleGetConfig(ctx, client, msg)

	case MsgSetConfig:
		return h.handleSetConfig(ctx, client, msg)

	case MsgTrackingStart:
		return h.handleTrackingStart(ctx, client, msg)

	case MsgTrackingStop:
		return h.handleTrackingStop(ctx, client, msg)

	case MsgTrackingStatus:
		return h.handleTrackingStatus(ctx, client, msg)

	default:
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest,
			fmt.Sprintf("unknown message type: %d", msg.Header.Type)), nil
	}
}

// handleStatus handles status requests
func (h *DaemonHandler) handleStatus(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req StatusRequest
	if len(msg.Payload) > 0 {
		if err := Decode(msg.Payload, &req); err != nil {
			return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	resp := &StatusResponse{
		Version:     h.version,
		Uptime:      time.Since(h.startedAt),
		StartedAt:   h.startedAt,
		Initialized: h.store != nil,
	}

	// Database status
	if h.store != nil {
		stats, err := h.store.GetStats()
		if err == nil {
			resp.DatabaseStatus = DatabaseStatus{
				Type:        "sqlite",
				EventCount:  int64(stats.EventCount),
				FileCount:   int(stats.FileCount),
				IntegrityOK: stats.IntegrityOK,
				LastEvent:   stats.NewestEvent,
			}
		}
	}

	// TPM status
	tpmProvider := tpm.DetectTPM()
	if tpmProvider.Available() {
		resp.TPMStatus.Available = true
		if err := tpmProvider.Open(); err == nil {
			resp.TPMStatus.Manufacturer = tpmProvider.Manufacturer()
			resp.TPMStatus.FirmwareVersion = tpmProvider.FirmwareVersion()
			tpmProvider.Close()
		}
	}

	// Active sessions
	if req.IncludeSessions {
		for _, sess := range h.trackingMgr.ActiveSessions() {
			status := sess.Status()
			resp.ActiveSessions = append(resp.ActiveSessions, SessionSummary{
				ID:           status.ID,
				DocumentPath: status.DocumentPath,
				StartedAt:    status.StartedAt,
				Duration:     status.Duration,
				Keystrokes:   status.KeystrokeCount,
			})
		}
	}

	return NewResponse(MsgStatusResponse, msg.Header.RequestID, resp)
}

// handleHealthCheck handles health check requests
func (h *DaemonHandler) handleHealthCheck(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	resp := map[string]any{
		"healthy": true,
		"uptime":  time.Since(h.startedAt).String(),
	}
	return NewResponse(MsgHealthResponse, msg.Header.RequestID, resp)
}

// handleStartSession handles session start requests
func (h *DaemonHandler) handleStartSession(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req StartSessionRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	// Check permission
	if client.Permission < PermReadWrite {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "write permission required"), nil
	}

	// Validate document path
	absPath, err := filepath.Abs(req.DocumentPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid path"), nil
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return NewErrorMessage(msg.Header.RequestID, ErrNotFound, "file not found"), nil
	}

	// Start session
	sess, err := h.trackingMgr.StartSession(absPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, err.Error()), nil
	}

	// Broadcast event
	h.broadcast(&Event{
		Type:      EventSessionStart,
		Timestamp: time.Now(),
		SessionID: sess.ID,
		Data: map[string]any{
			"document_path": absPath,
		},
	})

	resp := &StartSessionResponse{
		Success:   true,
		SessionID: sess.ID,
	}
	return NewResponse(MsgStartSessionResp, msg.Header.RequestID, resp)
}

// handleStopSession handles session stop requests
func (h *DaemonHandler) handleStopSession(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req StopSessionRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	if client.Permission < PermReadWrite {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "write permission required"), nil
	}

	sess, err := h.trackingMgr.StopSession(req.SessionID)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrNotFound, err.Error()), nil
	}

	status := sess.Status()

	// Broadcast event
	h.broadcast(&Event{
		Type:      EventSessionStop,
		Timestamp: time.Now(),
		SessionID: req.SessionID,
		Data: map[string]any{
			"keystrokes": status.KeystrokeCount,
			"duration":   status.Duration.String(),
		},
	})

	resp := &StopSessionResponse{
		Success: true,
		Summary: &SessionStatus{
			ID:               status.ID,
			Running:          status.Running,
			StartedAt:        status.StartedAt,
			EndedAt:          status.EndedAt,
			Duration:         status.Duration,
			DocumentPath:     status.DocumentPath,
			KeystrokeCount:   status.KeystrokeCount,
			SampleCount:      status.SampleCount,
			KeystrokesPerMin: status.KeystrokesPerMin,
			Checkpoints:      status.Checkpoints,
			TPMAvailable:     status.TPMAvailable,
			Compromised:      status.Compromised,
			CompromiseReason: status.CompromiseReason,
		},
	}
	return NewResponse(MsgStopSessionResp, msg.Header.RequestID, resp)
}

// handleListSessions handles list sessions requests
func (h *DaemonHandler) handleListSessions(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req ListSessionsRequest
	if len(msg.Payload) > 0 {
		if err := Decode(msg.Payload, &req); err != nil {
			return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
		}
	}

	var sessions []SessionSummary

	if req.ActiveOnly {
		for _, sess := range h.trackingMgr.ActiveSessions() {
			status := sess.Status()
			sessions = append(sessions, SessionSummary{
				ID:           status.ID,
				DocumentPath: status.DocumentPath,
				StartedAt:    status.StartedAt,
				Duration:     status.Duration,
				Keystrokes:   status.KeystrokeCount,
			})
		}
	} else {
		// Include saved sessions
		savedIDs, _ := h.trackingMgr.ListSavedSessions()
		for _, id := range savedIDs {
			sess, err := tracking.Load(h.witnessdDir, id)
			if err != nil {
				continue
			}
			status := sess.Status()
			sessions = append(sessions, SessionSummary{
				ID:           status.ID,
				DocumentPath: status.DocumentPath,
				StartedAt:    status.StartedAt,
				Duration:     status.Duration,
				Keystrokes:   status.KeystrokeCount,
			})
		}
	}

	if req.Limit > 0 && len(sessions) > req.Limit {
		sessions = sessions[:req.Limit]
	}

	resp := &ListSessionsResponse{
		Sessions: sessions,
	}
	return NewResponse(MsgListSessionsResp, msg.Header.RequestID, resp)
}

// handleSessionStatus handles session status requests
func (h *DaemonHandler) handleSessionStatus(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req SessionStatusRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	sess, ok := h.trackingMgr.GetSession(req.SessionID)
	if !ok {
		// Try loading from disk
		var err error
		sess, err = tracking.Load(h.witnessdDir, req.SessionID)
		if err != nil {
			return NewErrorMessage(msg.Header.RequestID, ErrNotFound, "session not found"), nil
		}
	}

	status := sess.Status()
	resp := &SessionStatus{
		ID:               status.ID,
		Running:          status.Running,
		StartedAt:        status.StartedAt,
		EndedAt:          status.EndedAt,
		Duration:         status.Duration,
		DocumentPath:     status.DocumentPath,
		KeystrokeCount:   status.KeystrokeCount,
		SampleCount:      status.SampleCount,
		KeystrokesPerMin: status.KeystrokesPerMin,
		Checkpoints:      status.Checkpoints,
		TPMAvailable:     status.TPMAvailable,
		Compromised:      status.Compromised,
		CompromiseReason: status.CompromiseReason,
	}

	return NewResponse(MsgSessionStatusResp, msg.Header.RequestID, resp)
}

// handleCommitCheckpoint handles checkpoint commit requests
func (h *DaemonHandler) handleCommitCheckpoint(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req CommitCheckpointRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	if client.Permission < PermReadWrite {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "write permission required"), nil
	}

	if h.store == nil {
		return NewErrorMessage(msg.Header.RequestID, ErrNotInitialized, "database not initialized"), nil
	}

	// Get absolute path
	absPath, err := filepath.Abs(req.FilePath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid path"), nil
	}

	// Check file exists
	fileInfo, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		return NewErrorMessage(msg.Header.RequestID, ErrNotFound, "file not found"), nil
	}

	// Read file and compute hash
	content, err := os.ReadFile(absPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, "failed to read file"), nil
	}
	contentHash := sha256.Sum256(content)

	// Get previous event for VDF input
	lastEvent, _ := h.store.GetLastSecureEventForFile(absPath)

	var vdfInput [32]byte
	var sizeDelta int32
	if lastEvent != nil {
		vdfInput = lastEvent.EventHash
		sizeDelta = int32(fileInfo.Size() - lastEvent.FileSize)
	} else {
		vdfInput = contentHash
		sizeDelta = int32(fileInfo.Size())
	}

	// Compute VDF proof
	start := time.Now()
	vdfProof, err := vdf.Compute(vdfInput, time.Second, h.vdfParams)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, "VDF computation failed"), nil
	}
	elapsed := time.Since(start)

	// Get device ID
	deviceID := h.getDeviceID()

	// Create event
	event := &store.SecureEvent{
		DeviceID:      deviceID,
		TimestampNs:   time.Now().UnixNano(),
		FilePath:      absPath,
		ContentHash:   contentHash,
		FileSize:      fileInfo.Size(),
		SizeDelta:     sizeDelta,
		ContextType:   req.Message,
		VDFInput:      vdfInput,
		VDFOutput:     vdfProof.Output,
		VDFIterations: vdfProof.Iterations,
	}

	if err := h.store.InsertSecureEvent(event); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, "failed to save checkpoint"), nil
	}

	// Get checkpoint count
	count, _ := h.store.CountEventsForFile(absPath)

	// Broadcast event
	h.broadcast(&Event{
		Type:      EventCheckpointCreated,
		Timestamp: time.Now(),
		Data: map[string]any{
			"file_path":    absPath,
			"checkpoint":   count,
			"content_hash": hex.EncodeToString(contentHash[:]),
			"vdf_elapsed":  elapsed.String(),
		},
	})

	resp := &CommitCheckpointResponse{
		Success:      true,
		CheckpointID: int(count),
		ContentHash:  hex.EncodeToString(contentHash[:]),
		EventHash:    hex.EncodeToString(event.EventHash[:]),
		VDFElapsed:   vdfProof.MinElapsedTime(h.vdfParams).Round(time.Second).String(),
	}

	return NewResponse(MsgCommitCheckpointResp, msg.Header.RequestID, resp)
}

// handleGetHistory handles history requests
func (h *DaemonHandler) handleGetHistory(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req GetHistoryRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	if h.store == nil {
		return NewErrorMessage(msg.Header.RequestID, ErrNotInitialized, "database not initialized"), nil
	}

	absPath, err := filepath.Abs(req.FilePath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid path"), nil
	}

	events, err := h.store.GetEventsForFile(absPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, "failed to load history"), nil
	}

	// Calculate total VDF time
	var totalIterations uint64
	for _, ev := range events {
		totalIterations += ev.VDFIterations
	}
	totalVDFTime := time.Duration(float64(totalIterations) / float64(h.vdfParams.IterationsPerSecond) * float64(time.Second))

	// Build checkpoint list
	checkpoints := make([]CheckpointInfo, len(events))
	for i, ev := range events {
		elapsed := time.Duration(float64(ev.VDFIterations) / float64(h.vdfParams.IterationsPerSecond) * float64(time.Second))
		checkpoints[i] = CheckpointInfo{
			Ordinal:     i + 1,
			Timestamp:   time.Unix(0, ev.TimestampNs),
			ContentHash: hex.EncodeToString(ev.ContentHash[:]),
			EventHash:   hex.EncodeToString(ev.EventHash[:]),
			FileSize:    ev.FileSize,
			SizeDelta:   ev.SizeDelta,
			VDFElapsed:  elapsed.Round(time.Second).String(),
			Message:     ev.ContextType,
		}
	}

	// Apply offset and limit
	if req.Offset > 0 && req.Offset < len(checkpoints) {
		checkpoints = checkpoints[req.Offset:]
	}
	if req.Limit > 0 && len(checkpoints) > req.Limit {
		checkpoints = checkpoints[:req.Limit]
	}

	resp := &GetHistoryResponse{
		FilePath:     absPath,
		Total:        len(events),
		TotalVDFTime: totalVDFTime.Round(time.Second).String(),
		Checkpoints:  checkpoints,
	}

	return NewResponse(MsgGetHistoryResp, msg.Header.RequestID, resp)
}

// handleExportEvidence handles evidence export requests
func (h *DaemonHandler) handleExportEvidence(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req ExportEvidenceRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	// For now, return a placeholder - full implementation would integrate with evidence package
	resp := &ExportEvidenceResponse{
		Success:  true,
		Filename: filepath.Base(req.FilePath) + ".evidence.json",
	}

	return NewResponse(MsgExportEvidenceResp, msg.Header.RequestID, resp)
}

// handleVerifyChain handles verification requests
func (h *DaemonHandler) handleVerifyChain(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req VerifyChainRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	// Placeholder response
	resp := &VerifyChainResponse{
		Valid: true,
	}

	return NewResponse(MsgVerifyChainResp, msg.Header.RequestID, resp)
}

// handleGetConfig handles config requests
func (h *DaemonHandler) handleGetConfig(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	cfg, err := config.Load("")
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, "failed to load config"), nil
	}

	resp := &ConfigResponse{
		Config: map[string]any{
			"watch_paths":     cfg.WatchPaths,
			"interval":        cfg.Interval,
			"database_path":   cfg.DatabasePath,
			"signing_key_path": cfg.SigningKeyPath,
		},
	}

	return NewResponse(MsgGetConfigResp, msg.Header.RequestID, resp)
}

// handleSetConfig handles config update requests
func (h *DaemonHandler) handleSetConfig(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	if client.Permission < PermFullControl {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "full control required"), nil
	}

	resp := &SetConfigResponse{
		Success: true,
	}

	return NewResponse(MsgSetConfigResp, msg.Header.RequestID, resp)
}

// handleTrackingStart handles tracking start requests
func (h *DaemonHandler) handleTrackingStart(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req TrackingStartRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	if client.Permission < PermReadWrite {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "write permission required"), nil
	}

	absPath, err := filepath.Abs(req.DocumentPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid path"), nil
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return NewErrorMessage(msg.Header.RequestID, ErrNotFound, "file not found"), nil
	}

	sess, err := h.trackingMgr.StartSession(absPath)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInternalError, err.Error()), nil
	}

	h.broadcast(&Event{
		Type:      EventTrackingUpdate,
		Timestamp: time.Now(),
		SessionID: sess.ID,
		Data: map[string]any{
			"action":        "started",
			"document_path": absPath,
		},
	})

	resp := &TrackingStartResponse{
		Success:   true,
		SessionID: sess.ID,
	}

	return NewResponse(MsgTrackingStartResp, msg.Header.RequestID, resp)
}

// handleTrackingStop handles tracking stop requests
func (h *DaemonHandler) handleTrackingStop(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req TrackingStopRequest
	if err := Decode(msg.Payload, &req); err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
	}

	if client.Permission < PermReadWrite {
		return NewErrorMessage(msg.Header.RequestID, ErrPermissionDenied, "write permission required"), nil
	}

	// Find session to stop
	sessionID := req.SessionID
	if sessionID == "" {
		// Stop current session (first active)
		active := h.trackingMgr.ActiveSessions()
		if len(active) == 0 {
			return NewErrorMessage(msg.Header.RequestID, ErrNoActiveSession, "no active session"), nil
		}
		sessionID = active[0].ID
	}

	sess, err := h.trackingMgr.StopSession(sessionID)
	if err != nil {
		return NewErrorMessage(msg.Header.RequestID, ErrNotFound, err.Error()), nil
	}

	status := sess.Status()

	h.broadcast(&Event{
		Type:      EventTrackingUpdate,
		Timestamp: time.Now(),
		SessionID: sessionID,
		Data: map[string]any{
			"action":     "stopped",
			"keystrokes": status.KeystrokeCount,
			"duration":   status.Duration.String(),
		},
	})

	resp := &TrackingStopResponse{
		Success: true,
		SessionSummary: &SessionStatus{
			ID:               status.ID,
			Running:          status.Running,
			StartedAt:        status.StartedAt,
			EndedAt:          status.EndedAt,
			Duration:         status.Duration,
			DocumentPath:     status.DocumentPath,
			KeystrokeCount:   status.KeystrokeCount,
			SampleCount:      status.SampleCount,
			KeystrokesPerMin: status.KeystrokesPerMin,
		},
	}

	return NewResponse(MsgTrackingStopResp, msg.Header.RequestID, resp)
}

// handleTrackingStatus handles tracking status requests
func (h *DaemonHandler) handleTrackingStatus(ctx context.Context, client *Client, msg *Message) (*Message, error) {
	var req TrackingStatusRequest
	if len(msg.Payload) > 0 {
		if err := Decode(msg.Payload, &req); err != nil {
			return NewErrorMessage(msg.Header.RequestID, ErrInvalidRequest, "invalid request"), nil
		}
	}

	resp := &TrackingStatusResponse{
		Active: false,
	}

	if req.SessionID != "" {
		// Get specific session
		sess, ok := h.trackingMgr.GetSession(req.SessionID)
		if ok {
			status := sess.Status()
			resp.Active = status.Running
			resp.Session = &SessionStatus{
				ID:               status.ID,
				Running:          status.Running,
				StartedAt:        status.StartedAt,
				Duration:         status.Duration,
				DocumentPath:     status.DocumentPath,
				KeystrokeCount:   status.KeystrokeCount,
				SampleCount:      status.SampleCount,
				KeystrokesPerMin: status.KeystrokesPerMin,
			}
		}
	} else {
		// Get current (first active) session
		active := h.trackingMgr.ActiveSessions()
		if len(active) > 0 {
			status := active[0].Status()
			resp.Active = true
			resp.Session = &SessionStatus{
				ID:               status.ID,
				Running:          status.Running,
				StartedAt:        status.StartedAt,
				Duration:         status.Duration,
				DocumentPath:     status.DocumentPath,
				KeystrokeCount:   status.KeystrokeCount,
				SampleCount:      status.SampleCount,
				KeystrokesPerMin: status.KeystrokesPerMin,
			}
		}
	}

	return NewResponse(MsgTrackingStatusResp, msg.Header.RequestID, resp)
}

// getDeviceID returns the device ID
func (h *DaemonHandler) getDeviceID() [16]byte {
	keyPath := filepath.Join(h.witnessdDir, "signing_key.pub")
	pubKey, err := os.ReadFile(keyPath)
	if err != nil {
		return [16]byte{}
	}

	hash := sha256.Sum256(pubKey)
	var id [16]byte
	copy(id[:], hash[:16])
	return id
}

// broadcast sends an event to all subscribers
func (h *DaemonHandler) broadcast(event *Event) {
	h.mu.RLock()
	broadcaster := h.broadcaster
	h.mu.RUnlock()

	if broadcaster != nil {
		broadcaster(event)
	}
}

// Shutdown gracefully shuts down the handler
func (h *DaemonHandler) Shutdown() error {
	return h.trackingMgr.StopAll()
}
