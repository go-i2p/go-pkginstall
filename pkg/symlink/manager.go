package symlink

import (
	"fmt"
	"os"
)

type SymlinkManager struct {
	symlinkDirs []string
}

func NewSymlinkManager(symlinkDirs []string) *SymlinkManager {
	return &SymlinkManager{
		symlinkDirs: symlinkDirs,
	}
}

// CreateSymlink creates a symlink at the target location pointing to the source.
// It checks for existing files to prevent overwriting.
func (sm *SymlinkManager) CreateSymlink(source, target string) error {
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("collision detected: target %s already exists", target)
	}

	err := os.Symlink(source, target)
	if err != nil {
		return fmt.Errorf("failed to create symlink from %s to %s: %v", source, target, err)
	}

	return nil
}

// IsSymlinkAllowed checks if the symlink can be created in the specified directory.
func (sm *SymlinkManager) IsSymlinkAllowed(dir string) bool {
	for _, allowedDir := range sm.symlinkDirs {
		if dir == allowedDir {
			return true
		}
	}
	return false
}
