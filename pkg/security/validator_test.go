package security

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePath(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Empty path", "", true},
		{"Relative path", "etc/passwd", true},
		{"Valid path", "/opt/myapp/config.json", false},
		{"Forbidden path", "/bin/dangerous", true},
		{"Path with traversal", "/opt/myapp/../../../etc/passwd", true},
		{"Path with encoded traversal", "/opt/myapp/%2e%2e/config", true},
		{"Long path", "/" + string(make([]byte, 5000, 5000)), true},
		{"Valid transformed path", "/opt/etc/myapp.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSymlink(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := ioutil.TempDir("", "validator-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file that already exists
	existingFile := filepath.Join(tmpDir, "existing.txt")
	if err := ioutil.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	validator := NewValidator(WithTransformedDir(tmpDir))

	tests := []struct {
		name    string
		source  string
		target  string
		wantErr bool
	}{
		{"Valid symlink", filepath.Join(tmpDir, "source.txt"), filepath.Join(tmpDir, "target.txt"), false},
		{"Target exists", filepath.Join(tmpDir, "source.txt"), existingFile, true},
		{"Forbidden target", filepath.Join(tmpDir, "source.txt"), "/bin/bash", true},
		{"Cyclic symlink", filepath.Join(tmpDir, "parent"), filepath.Join(tmpDir, "parent/child"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSymlink(tt.source, tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSymlink() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePackage(t *testing.T) {
	// Create a temporary directory structure for testing
	tmpDir, err := ioutil.TempDir("", "package-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a valid package structure
	validPkgDir := filepath.Join(tmpDir, "valid-pkg")
	if err := os.Mkdir(validPkgDir, 0755); err != nil {
		t.Fatalf("Failed to create valid package dir: %v", err)
	}

	debianDir := filepath.Join(validPkgDir, "DEBIAN")
	if err := os.Mkdir(debianDir, 0755); err != nil {
		t.Fatalf("Failed to create DEBIAN dir: %v", err)
	}

	controlFile := filepath.Join(debianDir, "control")
	if err := ioutil.WriteFile(controlFile, []byte("Package: test\nVersion: 1.0\n"), 0644); err != nil {
		t.Fatalf("Failed to create control file: %v", err)
	}

	// Create an invalid package structure
	invalidPkgDir := filepath.Join(tmpDir, "invalid-pkg")
	if err := os.Mkdir(invalidPkgDir, 0755); err != nil {
		t.Fatalf("Failed to create invalid package dir: %v", err)
	}

	// No DEBIAN directory in invalid package

	validator := NewValidator()

	tests := []struct {
		name    string
		pkgDir  string
		wantErr bool
	}{
		{"Valid package", validPkgDir, false},
		{"Invalid package", invalidPkgDir, true},
		{"Non-existent package", filepath.Join(tmpDir, "nonexistent"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePackage(tt.pkgDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePackage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePathTraversalEnhanced(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Valid path", "/opt/myapp/config.json", false},
		{"Basic traversal", "/opt/myapp/../../../etc/passwd", true},
		{"URL encoded", "/opt/myapp/%2e%2e/%2e%2e/etc/passwd", true},
		{"Double encoded", "/opt/myapp/%252e%252e/etc/passwd", true},
		{"Mixed encoding", "/opt/myapp/..%2f../../etc/passwd", true},
		{"Unicode fullwidth", "/opt/myapp/．．/etc/passwd", true},
		{"Multiple slashes", "/opt/myapp//..//..//etc/passwd", true},
		{"Backslash variant", "/opt/myapp/..\\/../etc/passwd", true},
		{"Null byte injection", "/opt/myapp/config.json\x00/../../../etc/passwd", true},
		{"Current directory", "/opt/myapp/./config.json", false},
		{"Multiple current", "/opt/myapp/././config.json", false},
		{"Overlong UTF-8", "/opt/myapp/%c0%ae%c0%ae/etc/passwd", true},
		{"Home directory", "/opt/myapp/~/etc/passwd", false},  // Warning but not error
		{"Environment var", "/opt/myapp/$HOME/config", false}, // Warning but not error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePathTraversal(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePathTraversal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
