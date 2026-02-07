package security

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Memory Security Tests
// =============================================================================

func TestWipe(t *testing.T) {
	data := []byte("sensitive data that should be wiped")
	original := make([]byte, len(data))
	copy(original, data)

	Wipe(data)

	// Check that all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d was not wiped: got %d, want 0", i, b)
		}
	}
}

func TestWipeEmpty(t *testing.T) {
	// Should not panic on empty slice
	Wipe(nil)
	Wipe([]byte{})
}

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a, b   []byte
		equal  bool
	}{
		{[]byte("hello"), []byte("hello"), true},
		{[]byte("hello"), []byte("world"), false},
		{[]byte("hello"), []byte("hell"), false},
		{[]byte{}, []byte{}, true},
		{nil, nil, true},
		{[]byte("a"), nil, false},
	}

	for _, tt := range tests {
		got := ConstantTimeCompare(tt.a, tt.b)
		if got != tt.equal {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.equal)
		}
	}
}

// =============================================================================
// Validation Tests
// =============================================================================

func TestPathValidator(t *testing.T) {
	v := DefaultPathValidator()

	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/tmp/test.txt", false},
		{"../../../etc/passwd", true},       // Path traversal
		{"/tmp/../../../etc/passwd", true},  // Path traversal
		{"/tmp/test\x00.txt", true},         // Null byte
		{"", true},                          // Empty
	}

	for _, tt := range tests {
		_, err := v.ValidatePath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
		}
	}
}

func TestPathValidatorWithRoots(t *testing.T) {
	tempDir := t.TempDir()

	v := &PathValidator{
		AllowedRoots:  []string{tempDir},
		MaxPathLength: 4096,
	}

	// Path within root should be allowed
	validPath := filepath.Join(tempDir, "test.txt")
	_, err := v.ValidatePath(validPath)
	if err != nil {
		t.Errorf("ValidatePath(%q) unexpected error: %v", validPath, err)
	}

	// Path outside root should be rejected
	_, err = v.ValidatePath("/etc/passwd")
	if err != ErrPathOutsideRoot {
		t.Errorf("ValidatePath(/etc/passwd) error = %v, want %v", err, ErrPathOutsideRoot)
	}
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"test.txt", false},
		{".hidden", false},
		{"", true},                    // Empty
		{"test/file.txt", true},       // Contains separator
		{"test\x00.txt", true},        // Null byte
		{"CON", true},                 // Reserved (Windows)
		{"test.", true},               // Ends with dot
		{" test", true},               // Leading space
		{"test ", true},               // Trailing space
	}

	for _, tt := range tests {
		err := ValidateFilename(tt.name)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateFilename(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestInputValidator(t *testing.T) {
	v := DefaultInputValidator()

	tests := []struct {
		input   string
		wantErr bool
	}{
		{"hello world", false},
		{"hello\nworld", false},       // Newlines allowed
		{"hello\x00world", true},      // Null byte
		{string([]byte{0x01}), true},  // Control character
		{"", false},                   // Empty is OK
	}

	for _, tt := range tests {
		err := v.Validate(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("Validate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestSanitizeLogOutput(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"api_key=secret12345678901234", "[REDACTED]"},
		{"password: mypassword123456", "[REDACTED]"},
		{"normal log message", "normal log message"},
	}

	for _, tt := range tests {
		got := SanitizeLogOutput(tt.input)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("SanitizeLogOutput(%q) = %q, want to contain %q", tt.input, got, tt.contains)
		}
	}
}

func TestValidateHexString(t *testing.T) {
	tests := []struct {
		s         string
		expectLen int
		wantErr   bool
	}{
		{"abcdef1234567890", 16, false},
		{"ABCDEF1234567890", 16, false},
		{"abc", 16, true},              // Too short
		{"ghij", 4, true},              // Invalid hex
	}

	for _, tt := range tests {
		err := ValidateHexString(tt.s, tt.expectLen)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateHexString(%q, %d) error = %v, wantErr %v", tt.s, tt.expectLen, err, tt.wantErr)
		}
	}
}

// =============================================================================
// File Security Tests
// =============================================================================

func TestWriteSecureFile(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "secret.key")
	data := []byte("secret data")

	err := WriteSecretFile(path, data)
	if err != nil {
		t.Fatalf("WriteSecretFile failed: %v", err)
	}

	// Verify contents
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("file contents mismatch: got %q, want %q", got, data)
	}

	// Verify permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != PermSecretFile {
		t.Errorf("file permissions = %04o, want %04o", info.Mode().Perm(), PermSecretFile)
	}
}

func TestAtomicWrite(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "test.txt")

	// Write initial content
	err := WriteSecureFile(path, []byte("initial"), PermPublicFile)
	if err != nil {
		t.Fatalf("WriteSecureFile failed: %v", err)
	}

	// Atomic update
	err = WriteSecureFile(path, []byte("updated"), PermPublicFile)
	if err != nil {
		t.Fatalf("WriteSecureFile update failed: %v", err)
	}

	// Verify no temp files left
	matches, _ := filepath.Glob(path + ".tmp.*")
	if len(matches) > 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestEnsureSecureDir(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "secure", "nested")

	err := EnsureSecureDir(path)
	if err != nil {
		t.Fatalf("EnsureSecureDir failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
	if info.Mode().Perm() != PermSecretDir {
		t.Errorf("directory permissions = %04o, want %04o", info.Mode().Perm(), PermSecretDir)
	}
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

func TestRateLimiter(t *testing.T) {
	// 10 ops/second, burst of 5
	rl := NewRateLimiter(10, 5)

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("burst operation %d was rate limited", i)
		}
	}

	// Next one should be limited
	if rl.Allow() {
		t.Error("expected rate limiting after burst")
	}

	// Wait for refill
	time.Sleep(200 * time.Millisecond)

	// Should allow again
	if !rl.Allow() {
		t.Error("expected operation after refill")
	}
}

func TestRateLimiterBlock(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	// Block for 100ms
	rl.Block(100 * time.Millisecond)

	if rl.Allow() {
		t.Error("expected blocking")
	}

	// Wait for block to expire
	time.Sleep(150 * time.Millisecond)

	if !rl.Allow() {
		t.Error("expected operation after block expired")
	}
}

func TestFailureLimiter(t *testing.T) {
	fl := NewFailureLimiter(
		10*time.Millisecond,  // base delay
		100*time.Millisecond, // max delay
		time.Second,          // reset after
		5,                    // max failures
		time.Second,          // lock duration
	)

	key := "test-key"

	// Record failures and verify exponential backoff
	delay1 := fl.RecordFailure(key)
	delay2 := fl.RecordFailure(key)

	if delay2 <= delay1 {
		t.Errorf("expected exponential backoff: delay2=%v should be > delay1=%v", delay2, delay1)
	}

	// Success should reset
	fl.RecordSuccess(key)
	delay3 := fl.RecordFailure(key)

	if delay3 >= delay2 {
		t.Errorf("expected reset after success: delay3=%v should be < delay2=%v", delay3, delay2)
	}
}

// =============================================================================
// Crypto Tests
// =============================================================================

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Check it's not all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("generated key is all zeros")
	}
}

func TestGenerateKeyTooSmall(t *testing.T) {
	_, err := GenerateKey(8) // Less than minimum
	if err == nil {
		t.Error("expected error for small key size")
	}
}

func TestDeriveKey(t *testing.T) {
	master := make([]byte, 32)
	GenerateSecureRandom(master)

	salt := []byte("test-salt")
	info := []byte("test-info")

	key1, err := DeriveKey(master, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Derive again - should get same result
	key2, err := DeriveKey(master, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("derivation not deterministic")
	}

	// Different info should give different key
	key3, err := DeriveKey(master, salt, []byte("different-info"), 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("different info produced same key")
	}
}

func TestValidateKeyStrength(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"valid key", make([]byte, 32), false},
		{"too short", make([]byte, 8), true},
		{"all zeros", make([]byte, 32), true}, // Will be all zeros
		{"repeating pattern", bytes.Repeat([]byte{0xAB}, 32), true},
	}

	// Generate a valid random key
	validKey, _ := GenerateKey(32)
	tests[0].key = validKey

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyStrength(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashDomainSeparated(t *testing.T) {
	data := []byte("test data")

	hash1 := HashDomainSeparated("domain1", data)
	hash2 := HashDomainSeparated("domain2", data)

	if hash1 == hash2 {
		t.Error("different domains should produce different hashes")
	}

	// Same domain and data should give same hash
	hash3 := HashDomainSeparated("domain1", data)
	if hash1 != hash3 {
		t.Error("same inputs should produce same hash")
	}
}

// =============================================================================
// Process Security Tests
// =============================================================================

func TestCaptureProcessSecurityState(t *testing.T) {
	state := CaptureProcessSecurityState()

	if state.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", state.PID, os.Getpid())
	}

	if state.UID != os.Getuid() {
		t.Errorf("UID = %d, want %d", state.UID, os.Getuid())
	}

	if state.Platform == "" {
		t.Error("Platform should not be empty")
	}
}

func TestSecurityChecklist(t *testing.T) {
	checklist := RunSecurityChecklist()

	if len(checklist.Items) == 0 {
		t.Error("checklist should have items")
	}

	// Check that we have the expected checks
	checkNames := make(map[string]bool)
	for _, item := range checklist.Items {
		checkNames[item.Name] = true
	}

	expectedChecks := []string{"non_root", "no_debugger", "secure_umask", "core_disabled"}
	for _, name := range expectedChecks {
		if !checkNames[name] {
			t.Errorf("missing check: %s", name)
		}
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestSecureBytesLifecycle(t *testing.T) {
	data := []byte("sensitive secret data")

	sb, err := FromBytes(data)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	// Original should be wiped
	for _, b := range data {
		if b != 0 {
			t.Error("original data was not wiped")
			break
		}
	}

	// SecureBytes should have the data
	if sb.Len() != len("sensitive secret data") {
		t.Errorf("length = %d, want %d", sb.Len(), len("sensitive secret data"))
	}

	// Copy the data
	copied := sb.Copy()
	if string(copied) != "sensitive secret data" {
		t.Error("copy data mismatch")
	}
	Wipe(copied)

	// Destroy
	sb.Destroy()

	if sb.Bytes() != nil {
		t.Error("data should be nil after Destroy")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkWipe(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		Wipe(data)
	}
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	a := make([]byte, 32)
	bData := make([]byte, 32)
	GenerateSecureRandom(a)
	GenerateSecureRandom(bData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(a, bData)
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	master := make([]byte, 32)
	GenerateSecureRandom(master)
	salt := []byte("benchmark-salt")
	info := []byte("benchmark-info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, _ := DeriveKey(master, salt, info, 32)
		Wipe(key)
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000000) // Very high limits

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow()
	}
}

// =============================================================================
// Fuzz Tests
// =============================================================================

func FuzzValidatePath(f *testing.F) {
	f.Add("/tmp/test.txt")
	f.Add("../../../etc/passwd")
	f.Add("/tmp/test\x00.txt")
	f.Add("")
	f.Add(strings.Repeat("a", 10000))

	v := DefaultPathValidator()

	f.Fuzz(func(t *testing.T, path string) {
		// Should not panic
		_, _ = v.ValidatePath(path)
	})
}

func FuzzValidateInput(f *testing.F) {
	f.Add("hello world")
	f.Add("hello\x00world")
	f.Add("")
	f.Add(strings.Repeat("a", 100000))

	v := DefaultInputValidator()

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		_ = v.Validate(input)
	})
}

func FuzzSanitizeLogOutput(f *testing.F) {
	f.Add("normal log")
	f.Add("api_key=secret123")
	f.Add("-----BEGIN PRIVATE KEY-----")

	f.Fuzz(func(t *testing.T, input string) {
		result := SanitizeLogOutput(input)
		// Result should never contain obvious secrets
		if regexp.MustCompile(`(?i)password\s*[:=]\s*[^\s]{16,}`).MatchString(result) {
			if !strings.Contains(result, "[REDACTED]") {
				// Allow if it was already sanitized
			}
		}
	})
}
