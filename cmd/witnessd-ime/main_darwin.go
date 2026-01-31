//go:build darwin

// witnessd-ime is the macOS Input Method server.
//
// This program runs as a background service and handles key events from
// the macOS Input Method Kit framework. It uses cgo to export functions
// that the Objective-C InputMethodController can call.
//
// Build:
//
//	go build -o Witnessd.app/Contents/MacOS/Witnessd ./cmd/witnessd-ime
//
// Install:
//
//	cp -r Witnessd.app ~/Library/Input\ Methods/
//	# Then enable in System Preferences > Keyboard > Input Sources
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"witnessd/internal/ime"
)

var (
	engine      *ime.Engine
	engineOnce  sync.Once
	engineMu    sync.Mutex
	logFile     *os.File
	storage     *ime.EvidenceStorage
	storageErr  error
	storageOnce sync.Once
)

func getEngine() *ime.Engine {
	engineOnce.Do(func() {
		engine = ime.NewEngine()
	})
	return engine
}

func getStorage() (*ime.EvidenceStorage, error) {
	storageOnce.Do(func() {
		storage, storageErr = ime.NewEvidenceStorage("")
	})
	return storage, storageErr
}

func saveEvidence(evidence *ime.Evidence) {
	if evidence == nil {
		return
	}
	storage, err := getStorage()
	if err != nil {
		log.Printf("Failed to init evidence storage: %v", err)
		return
	}
	if err := storage.Save(evidence); err != nil {
		log.Printf("Failed to save evidence: %v", err)
	}
}

//export WitnessdInit
func WitnessdInit() C.int {
	// Initialize logging
	home, err := os.UserHomeDir()
	if err != nil {
		return -1
	}

	logDir := filepath.Join(home, ".witnessd", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return -2
	}

	var logErr error
	logFile, logErr = os.OpenFile(
		filepath.Join(logDir, "ime.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if logErr != nil {
		return -3
	}
	log.SetOutput(logFile)
	log.Println("Witnessd IME initialized")

	// Initialize engine
	_ = getEngine()
	return 0
}

//export WitnessdShutdown
func WitnessdShutdown() {
	engineMu.Lock()
	defer engineMu.Unlock()

	// End any active session
	if engine != nil && engine.HasActiveSession() {
		if evidence, err := engine.EndSession(); err != nil {
			log.Printf("Shutdown: EndSession error: %v", err)
		} else {
			saveEvidence(evidence)
		}
	}

	// Close log file
	if logFile != nil {
		log.Println("Witnessd IME shutting down")
		logFile.Close()
		logFile = nil
	}
}

//export WitnessdStartSession
func WitnessdStartSession(appID *C.char, docID *C.char) C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()

	// End any existing session
	if eng.HasActiveSession() {
		eng.EndSession()
	}

	err := eng.StartSession(ime.SessionOptions{
		AppID: C.GoString(appID),
		DocID: C.GoString(docID),
	})
	if err != nil {
		log.Printf("StartSession error: %v", err)
		return -1
	}

	log.Printf("Started session for app=%s doc=%s", C.GoString(appID), C.GoString(docID))
	return 0
}

//export WitnessdEndSession
func WitnessdEndSession() *C.char {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	if !eng.HasActiveSession() {
		return nil
	}

	evidence, err := eng.EndSession()
	if err != nil {
		log.Printf("EndSession error: %v", err)
		return nil
	}
	saveEvidence(evidence)

	// Return JSON summary
	summary := evidenceToJSON(evidence)
	return C.CString(summary)
}

//export WitnessdOnKeyDown
func WitnessdOnKeyDown(keyCode C.uint16_t, charCode C.int32_t) C.int64_t {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	if !eng.HasActiveSession() {
		return 0
	}

	// Use proper Key constructor to ensure zone detection works
	key := ime.NewKeyWithCode(uint16(keyCode), rune(charCode))

	delay, err := eng.OnKeyDown(key)
	if err != nil {
		log.Printf("OnKeyDown error: %v", err)
		return 0
	}

	return C.int64_t(delay.Microseconds())
}

//export WitnessdOnTextCommit
func WitnessdOnTextCommit(text *C.char) {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	if !eng.HasActiveSession() {
		return
	}

	if err := eng.OnTextCommit(C.GoString(text)); err != nil {
		log.Printf("OnTextCommit error: %v", err)
	}
}

//export WitnessdOnTextDelete
func WitnessdOnTextDelete(count C.int) {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	if !eng.HasActiveSession() {
		return
	}

	if err := eng.OnTextDelete(int(count)); err != nil {
		log.Printf("OnTextDelete error: %v", err)
	}
}

//export WitnessdGetSampleCount
func WitnessdGetSampleCount() C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	return C.int(eng.GetSampleCount())
}

//export WitnessdHasActiveSession
func WitnessdHasActiveSession() C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	eng := getEngine()
	if eng.HasActiveSession() {
		return 1
	}
	return 0
}

//export WitnessdFreeString
func WitnessdFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// evidenceSummary is a minimal JSON-friendly struct for C interop.
type evidenceSummary struct {
	SessionID       string  `json:"session_id"`
	Keystrokes      uint64  `json:"keystrokes"`
	Samples         int     `json:"samples"`
	HandAlternation float32 `json:"hand_alternation"`
}

func evidenceToJSON(e *ime.Evidence) string {
	summary := evidenceSummary{
		SessionID:       e.SessionID,
		Keystrokes:      e.TotalKeystrokes,
		Samples:         len(e.Samples),
		HandAlternation: e.Profile.HandAlternation,
	}
	data, err := json.Marshal(summary)
	if err != nil {
		log.Printf("evidenceToJSON error: %v", err)
		return "{}"
	}
	return string(data)
}

func main() {
	// When run directly, just keep the IME service alive
	// The actual IME functionality is accessed via the exported C functions
	log.Println("Witnessd IME service started")

	// Handle shutdown signals gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down", sig)

	WitnessdShutdown()
}
