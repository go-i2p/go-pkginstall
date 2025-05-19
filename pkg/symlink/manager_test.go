package symlink

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewSymlinkManager(t *testing.T) {
	t.Run("with directories", func(t *testing.T) {
		dirs := []string{"/usr/bin", "/usr/lib"}
		sm := NewSymlinkManager(dirs)

		if sm == nil {
			t.Fatal("Expected non-nil SymlinkManager")
		}

		if len(sm.symlinkDirs) != len(dirs) {
			t.Errorf("Expected %d directories, got %d", len(dirs), len(sm.symlinkDirs))
		}

		for i, dir := range dirs {
			if sm.symlinkDirs[i] != dir {
				t.Errorf("Expected directory %s, got %s", dir, sm.symlinkDirs[i])
			}
		}
	})

	t.Run("with empty directory list", func(t *testing.T) {
		sm := NewSymlinkManager([]string{})

		if sm == nil {
			t.Fatal("Expected non-nil SymlinkManager")
		}

		if len(sm.symlinkDirs) != 0 {
			t.Errorf("Expected empty directory list, got %d directories", len(sm.symlinkDirs))
		}
	})
}

func TestSymlinkManager_IsSymlinkAllowed(t *testing.T) {
	t.Run("allowed directory", func(t *testing.T) {
		allowedDirs := []string{"/usr/bin", "/usr/lib", "/etc/systemd"}
		sm := NewSymlinkManager(allowedDirs)

		for _, dir := range allowedDirs {
			if !sm.IsSymlinkAllowed(dir) {
				t.Errorf("Expected directory %s to be allowed", dir)
			}
		}
	})

	t.Run("disallowed directory", func(t *testing.T) {
		allowedDirs := []string{"/usr/bin", "/usr/lib"}
		sm := NewSymlinkManager(allowedDirs)

		disallowedDirs := []string{"/etc", "/var", "/root"}
		for _, dir := range disallowedDirs {
			if sm.IsSymlinkAllowed(dir) {
				t.Errorf("Expected directory %s to be disallowed", dir)
			}
		}
	})

	t.Run("empty allowed directories", func(t *testing.T) {
		sm := NewSymlinkManager([]string{})

		testDirs := []string{"/usr/bin", "/etc", "/var"}
		for _, dir := range testDirs {
			if sm.IsSymlinkAllowed(dir) {
				t.Errorf("Expected directory %s to be disallowed with empty allowed list", dir)
			}
		}
	})
}

func TestSymlinkManager_CreateSymlink(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "symlink_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sm := NewSymlinkManager([]string{tempDir})

	t.Run("successful symlink creation", func(t *testing.T) {
		// Create a source file
		sourceFile := filepath.Join(tempDir, "source.txt")
		if err := os.WriteFile(sourceFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		// Create a symlink to the source file
		targetLink := filepath.Join(tempDir, "target.link")

		err := sm.CreateSymlink(sourceFile, targetLink)
		if err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		// Verify the symlink was created
		linkTarget, err := os.Readlink(targetLink)
		if err != nil {
			t.Fatalf("Failed to read symlink: %v", err)
		}

		if linkTarget != sourceFile {
			t.Errorf("Symlink points to %s, expected %s", linkTarget, sourceFile)
		}
	})

	t.Run("collision detection", func(t *testing.T) {
		// Create a file that will cause a collision
		existingFile := filepath.Join(tempDir, "existing.file")
		if err := os.WriteFile(existingFile, []byte("existing content"), 0644); err != nil {
			t.Fatalf("Failed to create existing file: %v", err)
		}

		// Try to create a symlink with the same target name
		sourceFile := filepath.Join(tempDir, "another_source.txt")
		if err := os.WriteFile(sourceFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		err := sm.CreateSymlink(sourceFile, existingFile)
		if err == nil {
			t.Error("Expected error due to collision, got nil")
		}

		// Verify the error message contains "collision detected"
		if err != nil && !containsSubstring(err.Error(), "collision detected") {
			t.Errorf("Expected error message to contain 'collision detected', got: %v", err)
		}
	})

	t.Run("parent directory doesn't exist", func(t *testing.T) {
		sourceFile := filepath.Join(tempDir, "source.txt")
		nonExistentDir := filepath.Join(tempDir, "non_existent_dir")
		targetLink := filepath.Join(nonExistentDir, "target.link")

		err := sm.CreateSymlink(sourceFile, targetLink)
		if err == nil {
			t.Error("Expected error when parent directory doesn't exist, got nil")
		}

		// Verify the error message contains information about the failure
		if err != nil && !containsSubstring(err.Error(), "failed to create symlink") {
			t.Errorf("Expected error message to contain 'failed to create symlink', got: %v", err)
		}
	})
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}
