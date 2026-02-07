// Package sentinel document correlation and path resolution.
//
// The DocumentCorrelator matches active windows to actual file paths,
// handling IDE-specific behaviors, temporary files, and URL filtering.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// DocumentCorrelatorConfig configures the document correlator.
type DocumentCorrelatorConfig struct {
	// EnableIDESupport enables IDE-specific file resolution.
	EnableIDESupport bool

	// FilterTempFiles filters out temporary files.
	FilterTempFiles bool

	// FilterURLs filters out URLs and web content.
	FilterURLs bool

	// IgnoredApplications is a list of applications to ignore.
	IgnoredApplications []string

	// IgnoredPathPrefixes is a list of path prefixes to ignore.
	IgnoredPathPrefixes []string

	// CustomEditors maps application IDs to custom path resolution functions.
	CustomEditors map[string]PathResolver
}

// PathResolver is a function that resolves a document path from window info.
type PathResolver func(info WindowInfo) string

// DefaultCorrelatorConfig returns sensible defaults.
func DefaultCorrelatorConfig() DocumentCorrelatorConfig {
	return DocumentCorrelatorConfig{
		EnableIDESupport: true,
		FilterTempFiles:  true,
		FilterURLs:       true,
		IgnoredApplications: []string{
			// System utilities
			"com.apple.finder",
			"com.apple.Spotlight",
			"com.apple.systempreferences",
			"com.apple.Terminal",
			"com.googlecode.iterm2",
			"explorer.exe",
			"nautilus",
			"dolphin",
			"konsole",
			"gnome-terminal",
			// Browsers (unless explicitly writing)
			"com.google.Chrome",
			"org.mozilla.firefox",
			"com.apple.Safari",
			"com.microsoft.edgemac",
		},
		IgnoredPathPrefixes: []string{
			"/tmp/",
			"/var/tmp/",
			"/private/tmp/",
			"/dev/",
			"/proc/",
			"/sys/",
		},
	}
}

// DocumentCorrelator matches windows to file paths.
type DocumentCorrelator struct {
	config DocumentCorrelatorConfig

	mu            sync.RWMutex
	projectCache  map[string]string            // path -> project root
	editorConfigs map[string]*EditorConfig     // app bundle ID -> config
}

// EditorConfig contains configuration for a specific editor.
type EditorConfig struct {
	// Name is the human-readable name.
	Name string

	// ProjectMarkers are files/directories that indicate a project root.
	ProjectMarkers []string

	// TitlePattern is a regex to extract filename from window title.
	TitlePattern *regexp.Regexp

	// ExtractPath is a custom function to extract path from title.
	ExtractPath func(title string) string

	// WorkspaceFile is the workspace/project file extension.
	WorkspaceFile string

	// SupportsAXDocument indicates if the editor provides AXDocument attribute.
	SupportsAXDocument bool
}

// NewDocumentCorrelator creates a new document correlator.
func NewDocumentCorrelator(config DocumentCorrelatorConfig) *DocumentCorrelator {
	c := &DocumentCorrelator{
		config:        config,
		projectCache:  make(map[string]string),
		editorConfigs: make(map[string]*EditorConfig),
	}

	// Register built-in editor configurations
	c.registerBuiltInEditors()

	return c
}

// registerBuiltInEditors registers configurations for common editors.
func (c *DocumentCorrelator) registerBuiltInEditors() {
	// VS Code
	c.editorConfigs["com.microsoft.VSCode"] = &EditorConfig{
		Name:           "Visual Studio Code",
		ProjectMarkers: []string{".vscode", ".git", "package.json", "go.mod"},
		TitlePattern:   regexp.MustCompile(`^(\*?\s*)([^-]+?)\s*(?:—|-)\s*(.+?)(?:\s*—|-\s*Visual Studio Code)?$`),
		WorkspaceFile:  ".code-workspace",
	}
	c.editorConfigs["com.microsoft.VSCodeInsiders"] = c.editorConfigs["com.microsoft.VSCode"]

	// Sublime Text
	c.editorConfigs["com.sublimetext.4"] = &EditorConfig{
		Name:           "Sublime Text",
		ProjectMarkers: []string{".sublime-project", ".git"},
		TitlePattern:   regexp.MustCompile(`^([^()]+?)(?:\s*\(([^)]+)\))?\s*(?:—|-)\s*Sublime Text$`),
		WorkspaceFile:  ".sublime-project",
	}
	c.editorConfigs["com.sublimetext.3"] = c.editorConfigs["com.sublimetext.4"]

	// Xcode
	c.editorConfigs["com.apple.dt.Xcode"] = &EditorConfig{
		Name:               "Xcode",
		ProjectMarkers:     []string{".xcodeproj", ".xcworkspace"},
		WorkspaceFile:      ".xcworkspace",
		SupportsAXDocument: true,
	}

	// JetBrains IDEs
	jetbrainsConfig := &EditorConfig{
		Name:           "JetBrains IDE",
		ProjectMarkers: []string{".idea", ".git"},
		TitlePattern:   regexp.MustCompile(`^([^–]+?)\s*–\s*([^–]+?)(?:\s*–\s*.+)?$`),
	}
	for _, bundleID := range []string{
		"com.jetbrains.intellij",
		"com.jetbrains.goland",
		"com.jetbrains.pycharm",
		"com.jetbrains.WebStorm",
		"com.jetbrains.PhpStorm",
		"com.jetbrains.CLion",
		"com.jetbrains.rider",
	} {
		c.editorConfigs[bundleID] = jetbrainsConfig
	}

	// Vim/Neovim
	vimConfig := &EditorConfig{
		Name:           "Vim",
		ProjectMarkers: []string{".git", "Makefile"},
		TitlePattern:   regexp.MustCompile(`^([^-]+?)(?:\s*[+-]?\s*(?:VIM|NVIM)?)?$`),
	}
	c.editorConfigs["org.vim.MacVim"] = vimConfig
	c.editorConfigs["io.neovim"] = vimConfig

	// Emacs
	c.editorConfigs["org.gnu.Emacs"] = &EditorConfig{
		Name:           "Emacs",
		ProjectMarkers: []string{".git", ".projectile", ".dir-locals.el"},
		TitlePattern:   regexp.MustCompile(`^([^-]+?)(?:\s*-\s*.+)?$`),
	}

	// Microsoft Word
	c.editorConfigs["com.microsoft.Word"] = &EditorConfig{
		Name:               "Microsoft Word",
		ProjectMarkers:     nil,
		SupportsAXDocument: true,
	}

	// Apple Pages
	c.editorConfigs["com.apple.iWork.Pages"] = &EditorConfig{
		Name:               "Pages",
		ProjectMarkers:     nil,
		SupportsAXDocument: true,
	}

	// TextEdit
	c.editorConfigs["com.apple.TextEdit"] = &EditorConfig{
		Name:               "TextEdit",
		ProjectMarkers:     nil,
		SupportsAXDocument: true,
	}
}

// ShouldIgnore checks if a window should be ignored.
func (c *DocumentCorrelator) ShouldIgnore(app, path string) bool {
	// Check ignored applications
	for _, ignored := range c.config.IgnoredApplications {
		if app == ignored {
			return true
		}
	}

	// Check path prefixes
	if path != "" {
		for _, prefix := range c.config.IgnoredPathPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}

		// Filter temp files
		if c.config.FilterTempFiles {
			if c.isTempFile(path) {
				return true
			}
		}

		// Filter URLs
		if c.config.FilterURLs {
			if c.isURL(path) {
				return true
			}
		}
	}

	return false
}

// isTempFile checks if a path is a temporary file.
func (c *DocumentCorrelator) isTempFile(path string) bool {
	// Common temp file patterns
	tempPatterns := []string{
		".tmp", ".temp", ".swp", ".swo", "~",
		".bak", ".backup", ".orig",
	}

	base := filepath.Base(path)
	lower := strings.ToLower(base)

	for _, pattern := range tempPatterns {
		if strings.HasSuffix(lower, pattern) {
			return true
		}
	}

	// Vim swap files
	if strings.HasPrefix(base, ".") && strings.HasSuffix(base, ".swp") {
		return true
	}

	// Emacs backup files
	if strings.HasSuffix(base, "~") {
		return true
	}

	// macOS temp files
	if strings.HasPrefix(base, "._") {
		return true
	}

	return false
}

// isURL checks if a path is a URL.
func (c *DocumentCorrelator) isURL(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://") ||
		strings.HasPrefix(lower, "file://")
}

// ResolveFilePath resolves the actual file path from window info.
func (c *DocumentCorrelator) ResolveFilePath(info WindowInfo) string {
	// If we already have a valid path, verify and return it
	if info.Path != "" {
		resolved := c.resolvePath(info.Path)
		if resolved != "" {
			return resolved
		}
	}

	// Try IDE-specific resolution
	if c.config.EnableIDESupport {
		if config, exists := c.editorConfigs[info.Application]; exists {
			if resolved := c.resolveWithEditorConfig(info, config); resolved != "" {
				return resolved
			}
		}
	}

	// Fallback: extract from window title
	if info.Title != "" {
		if resolved := c.extractFromTitle(info.Title, info.Application); resolved != "" {
			return c.resolvePath(resolved)
		}
	}

	return ""
}

// resolvePath normalizes and validates a path.
func (c *DocumentCorrelator) resolvePath(path string) string {
	if path == "" {
		return ""
	}

	// Expand home directory
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return ""
	}

	// Clean the path
	absPath = filepath.Clean(absPath)

	// Resolve symlinks
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	// Verify the file exists
	if _, err := os.Stat(absPath); err != nil {
		// File doesn't exist - might be unsaved
		// Return the path anyway if it looks valid
		if filepath.IsAbs(absPath) && !c.isTempFile(absPath) {
			return absPath
		}
		return ""
	}

	return absPath
}

// resolveWithEditorConfig uses editor-specific logic to resolve the path.
func (c *DocumentCorrelator) resolveWithEditorConfig(info WindowInfo, config *EditorConfig) string {
	// If the editor supports AXDocument and we have a path, use it
	if config.SupportsAXDocument && info.Path != "" {
		return c.resolvePath(info.Path)
	}

	// Try title pattern matching
	if config.TitlePattern != nil && info.Title != "" {
		matches := config.TitlePattern.FindStringSubmatch(info.Title)
		if len(matches) >= 2 {
			filename := strings.TrimSpace(matches[1])
			filename = strings.TrimPrefix(filename, "* ") // Remove modified indicator

			// Check if we have a folder hint (for Sublime-style titles)
			var folder string
			if len(matches) >= 3 {
				folder = strings.TrimSpace(matches[2])
			}

			return c.resolveFileWithFolder(filename, folder, config.ProjectMarkers)
		}
	}

	return ""
}

// resolveFileWithFolder tries to resolve a filename with an optional folder hint.
func (c *DocumentCorrelator) resolveFileWithFolder(filename, folder string, projectMarkers []string) string {
	// If filename is an absolute path, just resolve it
	if filepath.IsAbs(filename) {
		return c.resolvePath(filename)
	}

	// If we have a folder, try to construct the full path
	if folder != "" {
		// Folder might be a full path or just a name
		if filepath.IsAbs(folder) {
			fullPath := filepath.Join(folder, filename)
			if _, err := os.Stat(fullPath); err == nil {
				return fullPath
			}
		}

		// Try to find the folder in common locations
		for _, baseDir := range c.getSearchDirs() {
			candidatePath := filepath.Join(baseDir, folder, filename)
			if _, err := os.Stat(candidatePath); err == nil {
				return candidatePath
			}
		}
	}

	// Try to find the file in recently opened projects
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, projectRoot := range c.projectCache {
		candidatePath := filepath.Join(projectRoot, filename)
		if _, err := os.Stat(candidatePath); err == nil {
			return candidatePath
		}
	}

	return ""
}

// getSearchDirs returns directories to search for files.
func (c *DocumentCorrelator) getSearchDirs() []string {
	var dirs []string

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			home,
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Projects"),
			filepath.Join(home, "Workspace"),
			filepath.Join(home, "Code"),
			filepath.Join(home, "Development"),
		)
	}

	return dirs
}

// extractFromTitle extracts a potential file path from a window title.
func (c *DocumentCorrelator) extractFromTitle(title, app string) string {
	if title == "" {
		return ""
	}

	// Remove common suffixes
	suffixes := []string{
		" - Visual Studio Code",
		" - Sublime Text",
		" - Xcode",
		" - Microsoft Word",
		" - Pages",
		" - TextEdit",
		" — ",
		" - ",
	}

	cleaned := title
	for _, suffix := range suffixes {
		if idx := strings.LastIndex(cleaned, suffix); idx != -1 {
			cleaned = cleaned[:idx]
		}
	}

	// Remove modified indicators
	cleaned = strings.TrimPrefix(cleaned, "* ")
	cleaned = strings.TrimPrefix(cleaned, "• ")
	cleaned = strings.TrimSuffix(cleaned, " [Modified]")
	cleaned = strings.TrimSuffix(cleaned, " - Edited")
	cleaned = strings.TrimSpace(cleaned)

	// Check if it looks like a path
	if cleaned == "" {
		return ""
	}

	// If it starts with /, it's probably a path
	if strings.HasPrefix(cleaned, "/") {
		return cleaned
	}

	// If it contains a dot and no spaces, it might be a filename
	if strings.Contains(cleaned, ".") && !strings.Contains(cleaned, " ") {
		return cleaned
	}

	return cleaned
}

// GetProjectRoot returns the project root for a file path.
func (c *DocumentCorrelator) GetProjectRoot(path string) string {
	if path == "" {
		return ""
	}

	// Check cache
	c.mu.RLock()
	if root, exists := c.projectCache[path]; exists {
		c.mu.RUnlock()
		return root
	}
	c.mu.RUnlock()

	// Walk up directory tree looking for project markers
	dir := filepath.Dir(path)
	for dir != "/" && dir != "." {
		for _, marker := range []string{
			".git", ".hg", ".svn",
			".vscode", ".idea",
			"go.mod", "go.sum",
			"package.json", "package-lock.json",
			"Cargo.toml", "Cargo.lock",
			"pom.xml", "build.gradle",
			"Makefile", "CMakeLists.txt",
			"requirements.txt", "pyproject.toml",
			".xcodeproj", ".xcworkspace",
		} {
			markerPath := filepath.Join(dir, marker)
			if _, err := os.Stat(markerPath); err == nil {
				c.mu.Lock()
				c.projectCache[path] = dir
				c.mu.Unlock()
				return dir
			}
			// Check for glob patterns (e.g., *.xcodeproj)
			if strings.HasPrefix(marker, ".") && strings.HasSuffix(marker, "proj") {
				if matches, _ := filepath.Glob(filepath.Join(dir, "*"+marker)); len(matches) > 0 {
					c.mu.Lock()
					c.projectCache[path] = dir
					c.mu.Unlock()
					return dir
				}
			}
		}
		dir = filepath.Dir(dir)
	}

	return ""
}

// ClearCache clears the project cache.
func (c *DocumentCorrelator) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.projectCache = make(map[string]string)
}

// RegisterEditor registers a custom editor configuration.
func (c *DocumentCorrelator) RegisterEditor(bundleID string, config *EditorConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.editorConfigs[bundleID] = config
}
