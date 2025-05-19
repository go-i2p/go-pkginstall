package security

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestPathMapperOptions(t *testing.T) {
	t.Run("WithBaseTransformDir", func(t *testing.T) {
		// Test with valid directory
		pm := NewPathMapper(WithBaseTransformDir("/custom/opt"))
		if pm.baseTransformDir != "/custom/opt" {
			t.Errorf("Expected baseTransformDir to be /custom/opt, got %s", pm.baseTransformDir)
		}

		// Test with empty directory (should use default)
		pm = NewPathMapper(WithBaseTransformDir(""))
		if pm.baseTransformDir != "/opt" {
			t.Errorf("Expected baseTransformDir to remain /opt when empty string provided, got %s", pm.baseTransformDir)
		}
	})

	t.Run("WithCustomMapping", func(t *testing.T) {
		// Test with valid mapping
		pm := NewPathMapper(WithCustomMapping("/custom/dir", "/opt/custom/dir"))
		if pm.systemDirs["/custom/dir"] != "/opt/custom/dir" {
			t.Errorf("Expected custom mapping to be added")
		}

		// Test with empty source or target (should not be added)
		pm = NewPathMapper(WithCustomMapping("", "/opt/empty"))
		if pm.systemDirs[""] == "/opt/empty" {
			t.Errorf("Empty source should not be added to mappings")
		}

		pm = NewPathMapper(WithCustomMapping("/empty", ""))
		if pm.systemDirs["/empty"] == "" {
			t.Errorf("Empty target should not be added to mappings")
		}
	})

	t.Run("WithSymlinkDir", func(t *testing.T) {
		// Test with valid directory
		customDir := "/custom/symlink/dir"
		pm := NewPathMapper(WithSymlinkDir(customDir))

		found := false
		for _, dir := range pm.symlinkDirs {
			if dir == customDir {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected symlink directory %s to be added", customDir)
		}

		// Test with empty directory (should not be added)
		initialCount := len(NewPathMapper().symlinkDirs)
		pm = NewPathMapper(WithSymlinkDir(""))
		if len(pm.symlinkDirs) != initialCount {
			t.Errorf("Empty directory should not be added to symlink directories")
		}
	})

	t.Run("WithVerboseLogging", func(t *testing.T) {
		// Test enabling verbose logging
		pm := NewPathMapper(WithVerboseLogging(true))
		if !pm.verbose {
			t.Errorf("Expected verbose logging to be enabled")
		}

		// Test disabling verbose logging
		pm = NewPathMapper(WithVerboseLogging(false))
		if pm.verbose {
			t.Errorf("Expected verbose logging to be disabled")
		}
	})

	t.Run("Multiple options", func(t *testing.T) {
		pm := NewPathMapper(
			WithBaseTransformDir("/custom/opt"),
			WithCustomMapping("/custom/dir", "/custom/opt/dir"),
			WithSymlinkDir("/custom/symlink/dir"),
			WithVerboseLogging(true),
		)

		if pm.baseTransformDir != "/custom/opt" {
			t.Errorf("Expected baseTransformDir to be /custom/opt, got %s", pm.baseTransformDir)
		}

		if pm.systemDirs["/custom/dir"] != "/custom/opt/dir" {
			t.Errorf("Expected custom mapping to be added")
		}

		found := false
		for _, dir := range pm.symlinkDirs {
			if dir == "/custom/symlink/dir" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected symlink directory to be added")
		}

		if !pm.verbose {
			t.Errorf("Expected verbose logging to be enabled")
		}
	})
}

func TestNewPathMapper(t *testing.T) {
	t.Run("Default initialization", func(t *testing.T) {
		pm := NewPathMapper()

		// Check defaults
		if pm.baseTransformDir != "/opt" {
			t.Errorf("Expected default baseTransformDir to be /opt, got %s", pm.baseTransformDir)
		}

		if pm.verbose {
			t.Errorf("Expected default verbose setting to be false")
		}

		// Check system directories are initialized
		requiredDirs := []string{"/bin", "/etc", "/var", "/usr", "/lib"}
		for _, dir := range requiredDirs {
			if _, exists := pm.systemDirs[dir]; !exists {
				t.Errorf("Expected system directory mapping for %s to exist", dir)
			}
		}

		// Check symlink directories are initialized
		if len(pm.symlinkDirs) == 0 {
			t.Errorf("Expected symlink directories to be initialized")
		}
	})
}

func TestSetLogger(t *testing.T) {
	pm := NewPathMapper()

	// Custom logger
	var buf bytes.Buffer
	customLogger := func(format string, args ...interface{}) (int, error) {
		return fmt.Fprintf(&buf, format, args...)
	}

	pm.SetLogger(customLogger)
	pm.verbose = true
	pm.log("Test message %s", "content")

	if !strings.Contains(buf.String(), "Test message content") {
		t.Errorf("Custom logger not used correctly")
	}

	// Test with nil logger (should not change current logger)
	pm.SetLogger(nil)
	buf.Reset()
	pm.log("Another test")
	if !strings.Contains(buf.String(), "Another test") {
		t.Errorf("Logger should not be changed when nil is provided")
	}
}

func TestIsTransformedPath(t *testing.T) {
	pm := NewPathMapper(WithBaseTransformDir("/opt"))

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Empty path", "", false},
		{"Already transformed path", "/opt/bin/app", true},
		{"Already transformed path with trailing slash", "/opt/bin/", true},
		{"System path", "/bin/app", false},
		{"Path with . and ..", "/opt/../opt/bin", true},
		{"Path with non-transform prefix", "/optional/bin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.IsTransformedPath(tt.path)
			if result != tt.expected {
				t.Errorf("IsTransformedPath(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsSystemPath(t *testing.T) {
	pm := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Empty path", "", false},
		{"System root path", "/bin", true},
		{"System subdirectory", "/etc/systemd/system", true},
		{"System path with trailing slash", "/usr/", true},
		{"Non-system path", "/opt/bin/app", false},
		{"Path with dots", "/etc/../etc/hosts", true},
		{"Similar but not system path", "/optical/drive", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.IsSystemPath(tt.path)
			if result != tt.expected {
				t.Errorf("IsSystemPath(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestTransformPath(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		options          []PathMapperOption
		expectedPath     string
		expectedSymlink  bool
		expectError      bool
		errorMsgContains string
	}{
		{
			name:             "Empty path",
			path:             "",
			options:          nil,
			expectedPath:     "",
			expectedSymlink:  false,
			expectError:      true,
			errorMsgContains: "empty path",
		},
		{
			name:            "Already transformed path",
			path:            "/opt/bin/app",
			options:         nil,
			expectedPath:    "/opt/bin/app",
			expectedSymlink: false,
			expectError:     false,
		},
		{
			name:            "System path without symlink",
			path:            "/var/log/app.log",
			options:         nil,
			expectedPath:    "/opt/var/log/app.log",
			expectedSymlink: false,
			expectError:     false,
		},
		{
			name:            "System path requiring symlink",
			path:            "/bin/myapp",
			options:         nil,
			expectedPath:    "/opt/bin/myapp",
			expectedSymlink: true,
			expectError:     false,
		},
		{
			name:            "Path needing normalization",
			path:            "/usr/local/../bin/app",
			options:         nil,
			expectedPath:    "/opt/usr/bin/app",
			expectedSymlink: true,
			expectError:     false,
		},
		{
			name:             "Non-system path",
			path:             "/some/random/path",
			options:          nil,
			expectedPath:     "",
			expectedSymlink:  false,
			expectError:      true,
			errorMsgContains: "no transformation rule",
		},
		{
			name:            "Custom transform root",
			path:            "/usr/bin/app",
			options:         []PathMapperOption{WithBaseTransformDir("/custom")},
			expectedPath:    "/custom/usr/bin/app",
			expectedSymlink: true,
			expectError:     false,
		},
		{
			name:            "Custom mapping",
			path:            "/custom/dir/file",
			options:         []PathMapperOption{WithCustomMapping("/custom/dir", "/opt/special/dir")},
			expectedPath:    "/opt/special/dir/file",
			expectedSymlink: false,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPathMapper(tt.options...)

			transformedPath, needsSymlink, err := pm.TransformPath(tt.path)

			// Check error condition
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsgContains != "" && !strings.Contains(err.Error(), tt.errorMsgContains) {
					t.Errorf("Error message does not contain expected text. Got: %s, Want: %s",
						err.Error(), tt.errorMsgContains)
				}
				return
			}

			// No error expected
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if transformedPath != tt.expectedPath {
				t.Errorf("TransformPath(%s) path = %s, want %s", tt.path, transformedPath, tt.expectedPath)
			}

			if needsSymlink != tt.expectedSymlink {
				t.Errorf("TransformPath(%s) symlink = %v, want %v", tt.path, needsSymlink, tt.expectedSymlink)
			}
		})
	}
}

func TestShouldCreateSymlink(t *testing.T) {
	pm := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Empty path", "", false},
		{"Symlink directory exact match", "/etc/systemd/system", true},
		{"Symlink directory subdirectory", "/etc/systemd/system/myapp.service", true},
		{"Path in usr bin", "/usr/bin/myapp", true},
		{"Non-symlink directory", "/var/log/myapp.log", false},
		{"Similar but not symlink directory", "/etc/systemdesk/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.shouldCreateSymlink(tt.path)
			if result != tt.expected {
				t.Errorf("shouldCreateSymlink(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetTransformedRoot(t *testing.T) {
	// Default root
	pm := NewPathMapper()
	if root := pm.GetTransformedRoot(); root != "/opt" {
		t.Errorf("Expected default root to be /opt, got %s", root)
	}

	// Custom root
	pm = NewPathMapper(WithBaseTransformDir("/custom/opt"))
	if root := pm.GetTransformedRoot(); root != "/custom/opt" {
		t.Errorf("Expected custom root to be /custom/opt, got %s", root)
	}
}

func TestGetSystemDirMappings(t *testing.T) {
	pm := NewPathMapper(
		WithCustomMapping("/custom/dir", "/opt/custom/dir"),
	)

	mappings := pm.GetSystemDirMappings()

	// Check if returned map is a copy
	originalLen := len(pm.systemDirs)
	mappings["new"] = "value"
	if len(pm.systemDirs) != originalLen {
		t.Errorf("GetSystemDirMappings should return a copy, not the original map")
	}

	// Check if mappings contain expected values
	if mappings["/bin"] != "/opt/bin" {
		t.Errorf("Expected /bin mapping to be /opt/bin, got %s", mappings["/bin"])
	}

	if mappings["/custom/dir"] != "/opt/custom/dir" {
		t.Errorf("Expected custom mapping to be present, got %s", mappings["/custom/dir"])
	}
}

func TestGetSymlinkDirs(t *testing.T) {
	customDir := "/custom/symlink/dir"
	pm := NewPathMapper(WithSymlinkDir(customDir))

	dirs := pm.GetSymlinkDirs()

	// Check if returned slice is a copy
	originalLen := len(pm.symlinkDirs)
	dirs = append(dirs, "/new/dir")
	if len(pm.symlinkDirs) != originalLen {
		t.Errorf("GetSymlinkDirs should return a copy, not the original slice")
	}

	// Check if dirs contain expected values
	customDirFound := false
	for _, dir := range dirs {
		if dir == customDir {
			customDirFound = true
			break
		}
	}

	if !customDirFound {
		t.Errorf("Custom symlink directory not found in returned dirs")
	}
}

func TestAddSystemDirMapping(t *testing.T) {
	pm := NewPathMapper()

	// Add valid mapping
	pm.AddSystemDirMapping("/new/dir", "/opt/new/dir")
	if pm.systemDirs["/new/dir"] != "/opt/new/dir" {
		t.Errorf("Expected mapping to be added")
	}

	// Add mapping with empty source - should be ignored
	originalLen := len(pm.systemDirs)
	pm.AddSystemDirMapping("", "/opt/empty")
	if len(pm.systemDirs) != originalLen {
		t.Errorf("Empty source mapping should be ignored")
	}

	// Add mapping with empty target - should be ignored
	pm.AddSystemDirMapping("/empty", "")
	if len(pm.systemDirs) != originalLen {
		t.Errorf("Empty target mapping should be ignored")
	}

	// Update existing mapping
	pm.AddSystemDirMapping("/bin", "/custom/bin")
	if pm.systemDirs["/bin"] != "/custom/bin" {
		t.Errorf("Expected existing mapping to be updated")
	}
}

func TestAddSymlinkDir(t *testing.T) {
	pm := NewPathMapper()

	originalLen := len(pm.symlinkDirs)

	// Add valid directory
	newDir := "/new/symlink/dir"
	pm.AddSymlinkDir(newDir)

	found := false
	for _, dir := range pm.symlinkDirs {
		if dir == newDir {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected directory to be added to symlink dirs")
	}

	// Add empty directory - should be ignored
	pm.AddSymlinkDir("")
	if len(pm.symlinkDirs) != originalLen+1 {
		t.Errorf("Empty directory should not be added")
	}

	// Add duplicate directory
	pm.AddSymlinkDir(newDir)
	dupCount := 0
	for _, dir := range pm.symlinkDirs {
		if dir == newDir {
			dupCount++
		}
	}

	if dupCount != 2 {
		t.Errorf("Expected duplicate to be added (no uniqueness check in implementation)")
	}
}

func TestLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := func(format string, args ...interface{}) (int, error) {
		return fmt.Fprintf(&buf, format, args...)
	}

	pm := NewPathMapper(WithVerboseLogging(true))
	pm.SetLogger(logger)

	// Test that logging works when verbose is true
	pm.log("Test message %d", 123)
	if !strings.Contains(buf.String(), "Test message 123") {
		t.Errorf("Expected log message to be written")
	}

	// Test that logging is suppressed when verbose is false
	buf.Reset()
	pm.verbose = false
	pm.log("Should not appear")
	if buf.Len() > 0 {
		t.Errorf("Expected no output when verbose is false")
	}
}
