package security

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PathMapperOption is a function type that modifies a PathMapper's configuration.
type PathMapperOption func(*PathMapper)

// WithBaseTransformDir sets the base directory for transformed paths.
func WithBaseTransformDir(dir string) PathMapperOption {
	return func(pm *PathMapper) {
		if dir != "" {
			pm.baseTransformDir = dir
		}
	}
}

// WithCustomMapping adds a custom path mapping.
func WithCustomMapping(source, target string) PathMapperOption {
	return func(pm *PathMapper) {
		if source != "" && target != "" {
			pm.systemDirs[source] = target
		}
	}
}

// WithSymlinkDir adds a directory to the list of directories where symlinks are allowed.
func WithSymlinkDir(dir string) PathMapperOption {
	return func(pm *PathMapper) {
		if dir != "" {
			pm.symlinkDirs = append(pm.symlinkDirs, dir)
		}
	}
}

// WithVerboseLogging enables verbose logging for path operations.
func WithVerboseLogging(verbose bool) PathMapperOption {
	return func(pm *PathMapper) {
		pm.verbose = verbose
	}
}

// PathMapper handles secure transformation of installation paths by redirecting
// operations targeting sensitive system directories to safer alternatives.
type PathMapper struct {
	// Map of system directories to their secure alternatives
	systemDirs map[string]string

	// Directories where symlinks are allowed to be created
	symlinkDirs []string

	// Base directory for transformed paths (default: /opt)
	baseTransformDir string

	// Whether to enable verbose logging
	verbose bool

	// Function used for logging
	logFunc func(format string, args ...interface{}) (int, error)
}

// NewPathMapper creates a configured PathMapper with default settings and applies
// the provided options to customize its behavior.
func NewPathMapper(opts ...PathMapperOption) *PathMapper {
	pm := &PathMapper{
		systemDirs: map[string]string{
			"/bin":     "/opt/bin",
			"/etc":     "/opt/etc",
			"/var":     "/opt/var",
			"/usr":     "/opt/usr",
			"/lib":     "/opt/lib",
			"/lib64":   "/opt/lib64",
			"/sbin":    "/opt/sbin",
			"/home":    "/opt/home",
			"/share":   "/opt/share",
			"/include": "/opt/include",
		},
		symlinkDirs: []string{
			"/etc/systemd/system",
			"/etc/init.d",
			"/usr/share/applications",
			"/usr/share/icons",
			"/usr/share/man",
			"/usr/local/bin",
			"/usr/bin",
			"/bin",
		},
		baseTransformDir: "/opt",
		verbose:          false,
		logFunc:          fmt.Printf,
	}

	// Apply configuration options
	for _, opt := range opts {
		opt(pm)
	}

	return pm
}

// SetLogger sets the function used for logging.
func (pm *PathMapper) SetLogger(logFunc func(format string, args ...interface{}) (int, error)) {
	if logFunc != nil {
		pm.logFunc = logFunc
	}
}

// log logs a message if verbose logging is enabled.
func (pm *PathMapper) log(format string, args ...interface{}) {
	if pm.verbose {
		pm.logFunc(format, args...)
	}
}

// IsTransformedPath checks if a path has already been transformed.
func (pm *PathMapper) IsTransformedPath(path string) bool {
	if path == "" {
		return false
	}

	// Normalize the path first
	norm := filepath.Clean(path)

	// Check if the path starts with the base transform directory
	return strings.HasPrefix(norm, pm.baseTransformDir)
}

// IsSystemPath checks if a path is in a system directory that needs transformation.
func (pm *PathMapper) IsSystemPath(path string) bool {
	if path == "" {
		return false
	}

	norm := filepath.Clean(path)

	for sysDir := range pm.systemDirs {
		if norm == sysDir || strings.HasPrefix(norm, sysDir+"/") {
			return true
		}
	}

	return false
}

// TransformPath maps a system path to its secure equivalent.
// Returns:
// - transformed path
// - whether a symlink should be created
// - error if the path cannot be safely transformed
func (pm *PathMapper) TransformPath(path string) (string, bool, error) {
	if path == "" {
		return "", false, fmt.Errorf("cannot transform empty path")
	}

	// Normalize the path first
	normPath := filepath.Clean(path)

	// If the path is already transformed, return it as is
	if pm.IsTransformedPath(normPath) {
		pm.log("Path already transformed: %s", normPath)
		return normPath, false, nil
	}

	// Try to find a matching system directory prefix
	transformed := false
	transformedPath := normPath

	for sysDir, secureDir := range pm.systemDirs {
		if normPath == sysDir || strings.HasPrefix(normPath, sysDir+"/") {
			// Replace the system directory prefix with the secure equivalent
			transformedPath = strings.Replace(normPath, sysDir, secureDir, 1)
			transformed = true
			pm.log("Transformed path: %s -> %s", normPath, transformedPath)
			break
		}
	}

	if !transformed {
		// If no transformation rule matched, return an error
		return "", false, fmt.Errorf("no transformation rule matched for path: %s", path)
	}

	// Check if a symlink should be created for this path
	createSymlink := pm.shouldCreateSymlink(normPath)

	return transformedPath, createSymlink, nil
}

// shouldCreateSymlink determines if a symlink should be created for the given path.
func (pm *PathMapper) shouldCreateSymlink(path string) bool {
	for _, dir := range pm.symlinkDirs {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			pm.log("Symlink required for path: %s", path)
			return true
		}
	}
	return false
}

// GetTransformedRoot returns the base directory for transformed paths.
func (pm *PathMapper) GetTransformedRoot() string {
	return pm.baseTransformDir
}

// GetSystemDirMappings returns a copy of the system directory mappings.
func (pm *PathMapper) GetSystemDirMappings() map[string]string {
	// Return a copy to prevent modification of internal state
	mappings := make(map[string]string, len(pm.systemDirs))
	for k, v := range pm.systemDirs {
		mappings[k] = v
	}
	return mappings
}

// GetSymlinkDirs returns a copy of the directories where symlinks are allowed.
func (pm *PathMapper) GetSymlinkDirs() []string {
	// Return a copy to prevent modification of internal state
	dirs := make([]string, len(pm.symlinkDirs))
	copy(dirs, pm.symlinkDirs)
	return dirs
}

// AddSystemDirMapping adds or updates a system directory mapping.
func (pm *PathMapper) AddSystemDirMapping(sourceDir, targetDir string) {
	if sourceDir != "" && targetDir != "" {
		pm.systemDirs[sourceDir] = targetDir
	}
}

// AddSymlinkDir adds a directory to the list of directories where symlinks are allowed.
func (pm *PathMapper) AddSymlinkDir(dir string) {
	if dir != "" {
		pm.symlinkDirs = append(pm.symlinkDirs, dir)
	}
}
