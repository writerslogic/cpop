package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Validation errors
var (
	ErrPathTraversal     = errors.New("security: path traversal detected")
	ErrInvalidPath       = errors.New("security: invalid path")
	ErrPathOutsideRoot   = errors.New("security: path outside allowed root")
	ErrInvalidInput      = errors.New("security: invalid input")
	ErrInputTooLong      = errors.New("security: input exceeds maximum length")
	ErrNullByte          = errors.New("security: null byte in input")
	ErrInvalidUTF8       = errors.New("security: invalid UTF-8 encoding")
	ErrControlCharacters = errors.New("security: control characters in input")
)

// PathValidator provides secure path validation.
type PathValidator struct {
	// AllowedRoots are the directories that paths must be within
	AllowedRoots []string

	// AllowSymlinks controls whether symbolic links are followed
	AllowSymlinks bool

	// MaxPathLength is the maximum allowed path length
	MaxPathLength int
}

// DefaultPathValidator returns a PathValidator with sensible defaults.
func DefaultPathValidator() *PathValidator {
	return &PathValidator{
		AllowSymlinks: false,
		MaxPathLength: 4096,
	}
}

// ValidatePath checks if a path is safe to use.
// It returns the cleaned, absolute path if valid.
func (v *PathValidator) ValidatePath(path string) (string, error) {
	if path == "" {
		return "", ErrInvalidPath
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return "", ErrNullByte
	}

	// Check length
	if v.MaxPathLength > 0 && len(path) > v.MaxPathLength {
		return "", fmt.Errorf("%w: length %d exceeds maximum %d", ErrInputTooLong, len(path), v.MaxPathLength)
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Convert to absolute path
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}

	// Check for path traversal attempts
	if containsTraversal(path) {
		return "", ErrPathTraversal
	}

	// If allowed roots are specified, ensure path is within them
	if len(v.AllowedRoots) > 0 {
		withinRoot := false
		for _, root := range v.AllowedRoots {
			absRoot, err := filepath.Abs(root)
			if err != nil {
				continue
			}
			if strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) || absPath == absRoot {
				withinRoot = true
				break
			}
		}
		if !withinRoot {
			return "", ErrPathOutsideRoot
		}
	}

	// Check for symlinks if not allowed
	if !v.AllowSymlinks {
		// Evaluate symlinks to get the real path
		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			// Path might not exist yet, which is OK
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("%w: symlink evaluation failed: %v", ErrInvalidPath, err)
			}
			// For non-existent paths, check parent directory
			parentDir := filepath.Dir(absPath)
			realParent, err := filepath.EvalSymlinks(parentDir)
			if err != nil && !os.IsNotExist(err) {
				return "", fmt.Errorf("%w: parent symlink evaluation failed: %v", ErrInvalidPath, err)
			}
			if realParent != "" && realParent != parentDir {
				// Parent is a symlink, reconstruct path
				absPath = filepath.Join(realParent, filepath.Base(absPath))
			}
		} else {
			absPath = realPath
		}
	}

	return absPath, nil
}

// containsTraversal checks for common path traversal patterns.
func containsTraversal(path string) bool {
	// Check for .. components
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if part == ".." {
			return true
		}
	}

	// Check for URL-encoded traversal
	if strings.Contains(strings.ToLower(path), "%2e%2e") {
		return true
	}

	// Check for backslash-based traversal (Windows)
	if strings.Contains(path, "..\\") || strings.Contains(path, "\\..") {
		return true
	}

	return false
}

// ValidateFilename validates a filename (not a path).
// It ensures the filename is safe for use on all platforms.
func ValidateFilename(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty filename", ErrInvalidInput)
	}

	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return ErrNullByte
	}

	// Check for path separators (should not be in filename)
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%w: filename contains path separator", ErrInvalidInput)
	}

	// Check for reserved names (Windows)
	reserved := []string{"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
	upperName := strings.ToUpper(name)
	baseName := strings.TrimSuffix(upperName, filepath.Ext(upperName))
	for _, r := range reserved {
		if baseName == r {
			return fmt.Errorf("%w: reserved filename", ErrInvalidInput)
		}
	}

	// Check for invalid characters
	invalidChars := `<>:"|?*`
	if strings.ContainsAny(name, invalidChars) {
		return fmt.Errorf("%w: invalid characters in filename", ErrInvalidInput)
	}

	// Check for leading/trailing dots or spaces (problematic on Windows)
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		// Leading dot is OK for hidden files on Unix
	}
	if strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("%w: filename has leading/trailing spaces", ErrInvalidInput)
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("%w: filename ends with dot", ErrInvalidInput)
	}

	return nil
}

// InputValidator provides general input validation.
type InputValidator struct {
	// MaxLength is the maximum allowed input length
	MaxLength int

	// AllowNullBytes controls whether null bytes are allowed
	AllowNullBytes bool

	// AllowControlChars controls whether control characters are allowed
	AllowControlChars bool

	// RequireUTF8 ensures the input is valid UTF-8
	RequireUTF8 bool

	// AllowedPattern is a regex pattern the input must match (if set)
	AllowedPattern *regexp.Regexp
}

// DefaultInputValidator returns an InputValidator with secure defaults.
func DefaultInputValidator() *InputValidator {
	return &InputValidator{
		MaxLength:         65536, // 64KB default
		AllowNullBytes:    false,
		AllowControlChars: false,
		RequireUTF8:       true,
	}
}

// Validate checks if input meets the validation requirements.
func (v *InputValidator) Validate(input string) error {
	// Check length
	if v.MaxLength > 0 && len(input) > v.MaxLength {
		return fmt.Errorf("%w: length %d exceeds maximum %d", ErrInputTooLong, len(input), v.MaxLength)
	}

	// Check for null bytes
	if !v.AllowNullBytes && strings.Contains(input, "\x00") {
		return ErrNullByte
	}

	// Check UTF-8 validity
	if v.RequireUTF8 && !utf8.ValidString(input) {
		return ErrInvalidUTF8
	}

	// Check for control characters
	if !v.AllowControlChars {
		for _, r := range input {
			if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
				return ErrControlCharacters
			}
		}
	}

	// Check pattern if specified
	if v.AllowedPattern != nil && !v.AllowedPattern.MatchString(input) {
		return fmt.Errorf("%w: does not match required pattern", ErrInvalidInput)
	}

	return nil
}

// ValidateBytes validates byte input.
func (v *InputValidator) ValidateBytes(input []byte) error {
	// Check length
	if v.MaxLength > 0 && len(input) > v.MaxLength {
		return fmt.Errorf("%w: length %d exceeds maximum %d", ErrInputTooLong, len(input), v.MaxLength)
	}

	// Check for null bytes
	if !v.AllowNullBytes {
		for _, b := range input {
			if b == 0 {
				return ErrNullByte
			}
		}
	}

	// Check UTF-8 if required
	if v.RequireUTF8 && !utf8.Valid(input) {
		return ErrInvalidUTF8
	}

	return nil
}

// SanitizeLogOutput removes or masks sensitive data from log output.
// This prevents accidental logging of secrets.
func SanitizeLogOutput(input string) string {
	// Patterns that might indicate sensitive data
	sensitivePatterns := []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
		// API keys and tokens
		{regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|pwd|auth)[\s:=]+["']?[\w\-./+=]{16,}["']?`), "$1=[REDACTED]"},
		// Hex-encoded keys (32+ chars)
		{regexp.MustCompile(`(?i)(key|seed|private|secret)[\s:=]+["']?[0-9a-f]{64,}["']?`), "$1=[REDACTED]"},
		// Base64-encoded data that looks like keys
		{regexp.MustCompile(`(?i)(key|seed|private|secret)[\s:=]+["']?[A-Za-z0-9+/]{32,}={0,2}["']?`), "$1=[REDACTED]"},
		// AWS-style credentials
		{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)[\s:=]+["']?[\w]{16,}["']?`), "$1=[REDACTED]"},
		// Private key blocks
		{regexp.MustCompile(`(?s)-----BEGIN[\w\s]+PRIVATE KEY-----.*?-----END[\w\s]+PRIVATE KEY-----`), "[PRIVATE KEY REDACTED]"},
	}

	result := input
	for _, sp := range sensitivePatterns {
		result = sp.pattern.ReplaceAllString(result, sp.replacement)
	}

	return result
}

// ValidateHexString validates that a string is valid hexadecimal.
func ValidateHexString(s string, expectedLen int) error {
	if len(s) != expectedLen {
		return fmt.Errorf("%w: expected %d hex characters, got %d", ErrInvalidInput, expectedLen, len(s))
	}

	for i, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("%w: invalid hex character at position %d", ErrInvalidInput, i)
		}
	}

	return nil
}

// ValidateBase64String validates that a string is valid base64.
func ValidateBase64String(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("%w: empty base64 string", ErrInvalidInput)
	}

	// Check for valid base64 characters
	validChars := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	if !validChars.MatchString(s) {
		return fmt.Errorf("%w: invalid base64 characters", ErrInvalidInput)
	}

	// Check padding
	stripped := strings.TrimRight(s, "=")
	padding := len(s) - len(stripped)
	if padding > 2 {
		return fmt.Errorf("%w: invalid base64 padding", ErrInvalidInput)
	}

	return nil
}
