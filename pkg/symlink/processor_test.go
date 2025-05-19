package symlink

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-i2p/go-pkginstall/pkg/security"
)

// TestSymlinkProcessor tests the core functionality of SymlinkProcessor
func TestSymlinkProcessor(t *testing.T) {
	// Create a temporary directory for our tests
	tempDir, err := ioutil.TempDir("", "symlink-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some test directories inside
	secureDir := filepath.Join(tempDir, "secure")
	if err := os.MkdirAll(secureDir, 0755); err != nil {
		t.Fatalf("Failed to create secure directory: %v", err)
	}

	// Create our test dependencies
	pathMapper := security.NewPathMapper()

	symlinkManager := &SymlinkManager{} // Use the real implementation

	// Configure the validator with our test paths
	validator := security.NewValidator()

	// Setup the processor
	processor := NewSymlinkProcessor(pathMapper, symlinkManager, validator, true)

	// Capture logs for verification
	var logs []string
	processor.SetLogger(func(format string, args ...interface{}) (int, error) {
		log := fmt.Sprintf(format, args...)
		logs = append(logs, log)
		return len(log), nil
	})

	// Test 1: Queue a symlink
	t.Run("QueueSymlink", func(t *testing.T) {
		request := SymlinkRequest{
			Source:      filepath.Join(secureDir, "bin/app"),
			Target:      "/system/bin/app",
			Description: "Test application symlink",
		}

		if err := processor.QueueSymlink(request); err != nil {
			t.Errorf("Failed to queue symlink: %v", err)
		}

		// Verify it was queued
		if count := processor.GetQueuedSymlinkCount(); count != 1 {
			t.Errorf("Expected 1 queued symlink, got %d", count)
		}

		// Verify log message
		foundLog := false
		for _, log := range logs {
			if strings.Contains(log, "Queued symlink") {
				foundLog = true
				break
			}
		}
		if !foundLog {
			t.Errorf("Expected log message about queued symlink")
		}
	})

	// Test 2: Queue a duplicate symlink (should fail)
	t.Run("QueueDuplicateSymlink", func(t *testing.T) {
		request := SymlinkRequest{
			Source:      filepath.Join(secureDir, "bin/another-app"),
			Target:      "/system/bin/app", // Same target as before
			Description: "Duplicate target symlink",
		}

		err := processor.QueueSymlink(request)
		if err == nil {
			t.Errorf("Expected error when queuing duplicate symlink")
		}
		if !strings.Contains(err.Error(), "duplicate symlink target") {
			t.Errorf("Expected duplicate target error, got: %v", err)
		}
	})

	// Test 3: Process a path
	t.Run("ProcessPath", func(t *testing.T) {
		// Reset the queue and logs for this test
		processor = NewSymlinkProcessor(pathMapper, symlinkManager, validator, true)
		logs = nil
		processor.SetLogger(func(format string, args ...interface{}) (int, error) {
			log := fmt.Sprintf(format, args...)
			logs = append(logs, log)
			return len(log), nil
		})

		// Process a path that should need a symlink
		if err := processor.ProcessPath("/system/bin/tool", ""); err != nil {
			t.Errorf("Failed to process path: %v", err)
		}

		// Verify a symlink was queued
		if count := processor.GetQueuedSymlinkCount(); count != 1 {
			t.Errorf("Expected 1 queued symlink after processing path, got %d", count)
		}
	})

	// Test 4: Process queued symlinks in dry run mode
	t.Run("ProcessQueuedSymlinksDryRun", func(t *testing.T) {
		// Setup dry run mode
		processor.SetDryRun(true)

		// Process the queue
		if err := processor.ProcessQueuedSymlinks(); err != nil {
			t.Errorf("Failed to process symlinks in dry run mode: %v", err)
		}

		// Verify dry run log message
		foundDryRunLog := false
		for _, log := range logs {
			if strings.Contains(log, "[DRY RUN]") {
				foundDryRunLog = true
				break
			}
		}
		if !foundDryRunLog {
			t.Errorf("Expected log message about dry run")
		}

		// Queue should be empty after processing
		if count := processor.GetQueuedSymlinkCount(); count != 0 {
			t.Errorf("Expected empty queue after processing, got %d items", count)
		}
	})

	// Test 5: Process queued symlinks with actual symlink creation
	t.Run("ProcessQueuedSymlinksReal", func(t *testing.T) {
		// Create source file
		sourceDir := filepath.Join(secureDir, "bin")
		if err := os.MkdirAll(sourceDir, 0755); err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		sourceFile := filepath.Join(sourceDir, "real-app")
		if err := ioutil.WriteFile(sourceFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		// Create target directory
		targetDir := filepath.Join(tempDir, "target")
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			t.Fatalf("Failed to create target directory: %v", err)
		}

		// Reset processor
		processor = NewSymlinkProcessor(pathMapper, symlinkManager, validator, true)
		processor.SetDryRun(false) // Ensure real operation

		// Queue a symlink with real paths
		request := SymlinkRequest{
			Source:      sourceFile,
			Target:      filepath.Join(targetDir, "real-app"),
			Description: "Real symlink for testing",
		}

		if err := processor.QueueSymlink(request); err != nil {
			t.Errorf("Failed to queue real symlink: %v", err)
		}

		// Process the queue
		if err := processor.ProcessQueuedSymlinks(); err != nil {
			t.Errorf("Failed to process real symlinks: %v", err)
		}

		// Verify the symlink was created
		targetPath := filepath.Join(targetDir, "real-app")
		fileInfo, err := os.Lstat(targetPath)
		if err != nil {
			t.Errorf("Failed to stat target path: %v", err)
		}

		if fileInfo.Mode()&os.ModeSymlink == 0 {
			t.Errorf("Expected %s to be a symlink", targetPath)
		}

		// Verify the symlink points to the correct location
		linkDest, err := os.Readlink(targetPath)
		if err != nil {
			t.Errorf("Failed to read symlink: %v", err)
		}

		if linkDest != sourceFile {
			t.Errorf("Symlink points to %s, expected %s", linkDest, sourceFile)
		}
	})

	// Test 6: GetQueuedSymlinks returns a copy
	t.Run("GetQueuedSymlinks", func(t *testing.T) {
		// Reset processor and add a symlink
		processor = NewSymlinkProcessor(pathMapper, symlinkManager, validator, false)

		originalRequest := SymlinkRequest{
			Source:      "/source/path",
			Target:      "/target/path",
			Description: "Test symlink",
		}

		processor.QueueSymlink(originalRequest)

		// Get a copy of the queue
		queue := processor.GetQueuedSymlinks()

		// Verify the length
		if len(queue) != 1 {
			t.Errorf("Expected queue length 1, got %d", len(queue))
		}

		// Modify the copy and verify it doesn't affect the original
		queue[0].Description = "Modified description"

		// Queue the original again to access it
		newQueue := processor.GetQueuedSymlinks()
		if newQueue[0].Description != "Test symlink" {
			t.Errorf("Original queue was modified when copy was changed")
		}
	})
}
