//go:build windows

// witnessd-tsf is the Windows Text Services Framework (TSF) Input Method.
//
// This implements a Windows IME using TSF, the modern text input framework.
// The Go code handles the engine logic while C++ handles COM/TSF interfaces.
//
// Build:
//   go build -buildmode=c-archive -o witnessd.a ./cmd/witnessd-tsf
//   cl /EHsc /LD tsf/*.cpp witnessd.a /link /OUT:witnessd.dll
//
// Install:
//   regsvr32 witnessd.dll
//
// The binary must be signed for production use on Windows.
package main

/*
#include <stdlib.h>
#include <stdint.h>

// Forward declarations for TSF C++ code
typedef void* HWND;
*/
import "C"

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"witnessd/internal/ime"
)

var (
	engine   *ime.Engine
	engineMu sync.Mutex
	logFile  *os.File
)

//export WitnessdInit
func WitnessdInit() C.int {
	// Initialize logging
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		return -1
	}

	logDir := filepath.Join(appData, "Witnessd", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return -2
	}

	var err error
	logFile, err = os.OpenFile(
		filepath.Join(logDir, "tsf.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return -3
	}
	log.SetOutput(logFile)
	log.Println("Witnessd TSF initialized")

	engine = ime.NewEngine()
	return 0
}

//export WitnessdShutdown
func WitnessdShutdown() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine != nil && engine.HasActiveSession() {
		if evidence, err := engine.EndSession(); err == nil && evidence != nil {
			saveEvidence(evidence)
		}
	}

	if logFile != nil {
		log.Println("Witnessd TSF shutting down")
		logFile.Close()
		logFile = nil
	}
}

//export WitnessdStartSession
func WitnessdStartSession(appID *C.char, docID *C.char) C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine == nil {
		return -1
	}

	if engine.HasActiveSession() {
		engine.EndSession()
	}

	err := engine.StartSession(ime.SessionOptions{
		AppID: C.GoString(appID),
		DocID: C.GoString(docID),
	})
	if err != nil {
		log.Printf("StartSession error: %v", err)
		return -1
	}

	log.Printf("Started session: app=%s doc=%s", C.GoString(appID), C.GoString(docID))
	return 0
}

//export WitnessdEndSession
func WitnessdEndSession() *C.char {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine == nil || !engine.HasActiveSession() {
		return nil
	}

	evidence, err := engine.EndSession()
	if err != nil {
		log.Printf("EndSession error: %v", err)
		return nil
	}

	saveEvidence(evidence)

	summary := evidenceToJSON(evidence)
	return C.CString(summary)
}

//export WitnessdOnKeyDown
func WitnessdOnKeyDown(vkCode C.uint16_t, charCode C.int32_t) C.int64_t {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine == nil || !engine.HasActiveSession() {
		return 0
	}

	// Handle backspace (VK_BACK = 0x08)
	if vkCode == 0x08 {
		if err := engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return 0
	}

	// Handle delete (VK_DELETE = 0x2E)
	if vkCode == 0x2E {
		if err := engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return 0
	}

	// Use proper Key constructor
	key := ime.NewKeyWithCode(uint16(vkCode), rune(charCode))

	delay, err := engine.OnKeyDown(key)
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

	if engine == nil || !engine.HasActiveSession() {
		return
	}

	if err := engine.OnTextCommit(C.GoString(text)); err != nil {
		log.Printf("OnTextCommit error: %v", err)
	}
}

//export WitnessdOnTextDelete
func WitnessdOnTextDelete(count C.int) {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine == nil || !engine.HasActiveSession() {
		return
	}

	if err := engine.OnTextDelete(int(count)); err != nil {
		log.Printf("OnTextDelete error: %v", err)
	}
}

//export WitnessdGetSampleCount
func WitnessdGetSampleCount() C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine == nil {
		return 0
	}
	return C.int(engine.GetSampleCount())
}

//export WitnessdHasActiveSession
func WitnessdHasActiveSession() C.int {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine != nil && engine.HasActiveSession() {
		return 1
	}
	return 0
}

//export WitnessdFreeString
func WitnessdFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

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

func saveEvidence(evidence *ime.Evidence) {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		return
	}

	evidenceDir := filepath.Join(appData, "Witnessd", "evidence")
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		log.Printf("Failed to create evidence dir: %v", err)
		return
	}

	jsonData, err := json.Marshal(evidence)
	if err != nil {
		log.Printf("Failed to marshal evidence: %v", err)
		return
	}

	filename := filepath.Join(evidenceDir, evidence.SessionID+".json")
	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		log.Printf("Failed to write evidence: %v", err)
		return
	}

	log.Printf("Saved evidence to %s", filename)
}

func main() {
	// The DLL is loaded by TSF, this main is not used
	log.Println("Witnessd TSF loaded")
	select {}
}
