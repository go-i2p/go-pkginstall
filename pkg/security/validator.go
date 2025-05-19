package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SecurityPolicy defines rules for path validation
type SecurityPolicy struct {
	ForbiddenPaths    []string // Paths that should never be accessed
	RestrictedPaths   []string // Paths that require special permissions
	AllowedExtensions []string // Allowed file extensions
	MaxPathLength     int      // Maximum allowed path length
	DisallowDotDot    bool     // Whether to disallow ".." in paths
}

// DefaultSecurityPolicy returns the default security policy
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		ForbiddenPaths: []string{
			"/bin", "/sbin", "/usr/bin", "/usr/sbin",
			"/boot", "/proc", "/sys", "/dev",
		},
		RestrictedPaths: []string{
			"/etc/passwd", "/etc/shadow", "/etc/sudoers",
			"/etc/ssh", "/etc/ssl/private",
		},
		AllowedExtensions: []string{
			// Allow common file types
			".txt", ".conf", ".service", ".socket", ".target", ".sh",
			".xml", ".json", ".yml", ".yaml", ".desktop", ".png", ".svg",
			".jpg", ".jpeg", ".gif", ".md", ".html", ".css", ".js",
		},
		MaxPathLength:  4096,
		DisallowDotDot: true,
	}
}

// ValidationResult contains the result of a validation check
type ValidationResult struct {
	Valid   bool
	Message string
	Errors  []error
}

// Validator provides methods for validating paths and package creation compliance.
type Validator struct {
	policy         *SecurityPolicy
	logFunc        func(string, ...interface{})
	transformedDir string // Root directory for transformed paths
	verbose        bool
}

// ValidatorOption is a function that modifies a Validator
type ValidatorOption func(*Validator)

// WithPolicy sets a custom security policy
func WithPolicy(policy *SecurityPolicy) ValidatorOption {
	return func(v *Validator) {
		v.policy = policy
	}
}

// WithLogger sets a custom logging function
func WithLogger(logFunc func(string, ...interface{})) ValidatorOption {
	return func(v *Validator) {
		v.logFunc = logFunc
	}
}

// WithVerbose enables verbose logging
func WithVerbose(verbose bool) ValidatorOption {
	return func(v *Validator) {
		v.verbose = verbose
	}
}

// WithTransformedDir sets the root directory for transformed paths
func WithTransformedDir(dir string) ValidatorOption {
	return func(v *Validator) {
		v.transformedDir = dir
	}
}

// NewValidator creates a new instance of Validator with optional configuration.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		policy:         DefaultSecurityPolicy(),
		transformedDir: "/opt",
		logFunc:        func(format string, args ...interface{}) { fmt.Printf(format+"\n", args...) },
		verbose:        false,
	}

	// Apply options
	for _, opt := range opts {
		opt(v)
	}

	return v
}

// log writes messages to the configured log function if verbose is enabled
func (v *Validator) log(format string, args ...interface{}) {
	if v.verbose {
		v.logFunc(format, args...)
	}
}

// ValidatePath checks if the provided path is compliant with security policies.
// It returns an error if the path is invalid or if it violates any security rules.
func (v *Validator) ValidatePath(path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	// Path must be absolute
	if !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}

	// Check path length
	if len(path) > v.policy.MaxPathLength {
		return fmt.Errorf("path exceeds maximum length of %d characters", v.policy.MaxPathLength)
	}

	// Normalize the path (clean up any . or .. segments)
	cleanPath := filepath.Clean(path)

	// Verify the path wasn't changed substantially by cleaning
	// This helps catch paths with excessive dot segments like /etc/../../../etc/passwd
	if cleanPath != path && v.policy.DisallowDotDot {
		// Some slight differences are acceptable (like trailing slashes), so check if dots were involved
		if strings.Contains(path, "..") {
			return fmt.Errorf("path contains forbidden '..' sequences: %s", path)
		}
	}

	// Check for forbidden paths
	for _, forbiddenPath := range v.policy.ForbiddenPaths {
		if cleanPath == forbiddenPath || strings.HasPrefix(cleanPath, forbiddenPath+"/") {
			return fmt.Errorf("path access forbidden: %s", path)
		}
	}

	// Check for restricted paths
	for _, restrictedPath := range v.policy.RestrictedPaths {
		if cleanPath == restrictedPath || strings.HasPrefix(cleanPath, restrictedPath+"/") {
			v.log("Warning: Accessing restricted path: %s", path)
			// We don't return an error here, just log a warning
		}
	}

	// Check if this path is within the transformed directory structure
	if strings.HasPrefix(cleanPath, v.transformedDir) {
		// This is already a transformed path, which is allowed
		return nil
	}

	// At this point, the path should be scheduled for transformation
	// We'll still validate further aspects

	// File extension check for non-directories
	// Skip this check if the path looks like a directory (ends with /)
	if !strings.HasSuffix(cleanPath, "/") {
		ext := filepath.Ext(cleanPath)
		if ext != "" {
			validExt := false
			for _, allowedExt := range v.policy.AllowedExtensions {
				if ext == allowedExt {
					validExt = true
					break
				}
			}

			if !validExt {
				v.log("Warning: File has potentially unsafe extension: %s", ext)
				// We don't fail here, just log a warning
			}
		}
	}

	return nil
}

// ValidatePathTraversal provides an in-depth check for path traversal attempts
// with comprehensive detection of encoding variations and evasion techniques.
func (v *Validator) ValidatePathTraversal(path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	// Normalize path for consistent checking
	normalizedPath := filepath.Clean(path)

	// Basic path traversal check
	if strings.Contains(normalizedPath, "..") {
		// Check if .. is actually used for traversal
		parts := strings.Split(normalizedPath, "/")
		for i, part := range parts {
			if part == ".." && i > 0 {
				return errors.New("path traversal detected: contains '..' patterns")
			}
		}
	}

	// Check for various encoded path traversal attempts
	encodedDotDot := []string{
		// Basic URL encoding
		"%2e%2e", "%2E%2E",
		// Double encoding
		"%252e%252e", "%252E%252E",
		// Mixed encoding
		"%2e.", ".%2e", "%2e%2e%2f", "%2E%2E%2F",
		// Path separator encoding
		"..%2f", "..%2F", ".%2f.", "%2e/", "/%2e%2e",
		// Alternate encodings
		"%c0%ae%c0%ae", // overlong UTF-8 encoding
		"%c0%ae.", ".%c0%ae",
	}

	for _, encoded := range encodedDotDot {
		if strings.Contains(path, encoded) {
			return fmt.Errorf("encoded path traversal attempt detected: contains '%s'", encoded)
		}
	}

	// Check for unicode/backslash path traversal
	unicodeDotDot := []string{
		// Backslash variants
		"..\\", "\\..\\", "\\../", "/..\\",
		// Unicode alternatives
		"．．/", "..／", "．．／", // Unicode fullwidth periods
		"..\\u2215", "..\\u2044", // Unicode division slash
	}

	for _, unicode := range unicodeDotDot {
		if strings.Contains(path, unicode) {
			return fmt.Errorf("unicode path traversal attempt detected: contains '%s'", unicode)
		}
	}

	// Check for excessive slashes which could be normalized by the system
	if strings.Contains(path, "//") {
		// Extract the path segments and ensure they don't contain traversal
		segments := strings.FieldsFunc(path, func(r rune) bool {
			return r == '/'
		})

		for _, segment := range segments {
			if segment == ".." {
				return errors.New("path traversal detected with multiple slashes")
			}
		}
	}

	// Check for null byte injection which could truncate paths in some systems
	if strings.Contains(path, "\x00") {
		return errors.New("null byte detected in path")
	}

	// Check for unusual path elements that might be interpreted specially
	unusualElements := []string{
		"~", // Home directory reference
		"$", // Environment variable expansion
		"`", // Command substitution in some contexts
	}

	for _, element := range unusualElements {
		if strings.Contains(path, element) {
			v.log("Warning: Path contains potentially problematic element: %s", element)
			// Don't fail but log a warning as these might be legitimate in some contexts
		}
	}

	return nil
}

// ValidateSymlink checks if a symlink from source to target is allowed
func (v *Validator) ValidateSymlink(source, target string) error {
	// First validate both paths
	if err := v.ValidatePath(source); err != nil {
		return fmt.Errorf("invalid symlink source: %w", err)
	}

	if err := v.ValidatePath(target); err != nil {
		return fmt.Errorf("invalid symlink target: %w", err)
	}

	// Ensure the target is not a forbidden path
	for _, forbiddenPath := range v.policy.ForbiddenPaths {
		if target == forbiddenPath || strings.HasPrefix(target, forbiddenPath+"/") {
			return fmt.Errorf("symlink target points to forbidden path: %s", target)
		}
	}

	// If target already exists, prevent overwriting
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("symlink target already exists: %s", target)
	}

	// Check if the symlink would create a cycle
	if strings.HasPrefix(target, source) {
		return fmt.Errorf("symlink would create a cycle: %s -> %s", source, target)
	}

	return nil
}

// ValidatePackageFile checks if a file is allowed in a Debian package
func (v *Validator) ValidatePackageFile(path string, isDir bool) *ValidationResult {
	result := &ValidationResult{
		Valid:   true,
		Message: "File validation passed",
		Errors:  []error{},
	}

	// Validate path first
	if err := v.ValidatePath(path); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		result.Message = "Path validation failed"
		return result
	}

	// Check for potentially dangerous file patterns if not a directory
	if !isDir {
		// Check for executable scripts
		if strings.HasSuffix(path, ".sh") || strings.HasSuffix(path, ".bash") ||
			strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".pl") {
			v.log("Warning: Package contains executable script: %s", path)
			// We don't fail validation, just log a warning
		}

		// Check for setuid/setgid files (actual permissions will be checked elsewhere)
		if regexp.MustCompile(`\.(sh|bash|py|pl|rb)$`).MatchString(path) {
			v.log("Warning: Package contains script that could potentially be setuid/setgid: %s", path)
		}
	}

	return result
}

// ValidatePackage performs comprehensive validation of a Debian package structure
func (v *Validator) ValidatePackage(packageDir string) error {
	// Check if the package directory exists
	info, err := os.Stat(packageDir)
	if err != nil {
		return fmt.Errorf("package directory error: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("package path is not a directory: %s", packageDir)
	}

	// Check for required DEBIAN directory and control file
	debianDir := filepath.Join(packageDir, "DEBIAN")
	controlFile := filepath.Join(debianDir, "control")

	if _, err := os.Stat(debianDir); os.IsNotExist(err) {
		return errors.New("DEBIAN directory missing from package")
	}

	if _, err := os.Stat(controlFile); os.IsNotExist(err) {
		return errors.New("control file missing from package")
	}

	// Check all files in the package
	var invalidFiles []string
	err = filepath.Walk(packageDir, func(path string, info os.FileInfo, err error) error {
		// Skip the DEBIAN directory itself in validation
		if path == debianDir {
			return nil
		}

		// Get relative path from package directory for validation
		relPath, err := filepath.Rel(packageDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Skip the package root
		if relPath == "." {
			return nil
		}

		// If this is the DEBIAN directory contents, apply special rules
		if strings.HasPrefix(relPath, "DEBIAN/") {
			// Only specific files are allowed in DEBIAN directory
			validDebianFiles := map[string]bool{
				"control": true, "preinst": true, "postinst": true,
				"prerm": true, "postrm": true, "conffiles": true,
				"shlibs": true, "triggers": true,
			}

			baseName := filepath.Base(relPath)
			if !validDebianFiles[baseName] && !info.IsDir() {
				invalidFiles = append(invalidFiles, relPath)
				v.log("Invalid file in DEBIAN directory: %s", relPath)
			}

			return nil
		}

		// For regular package files, get the absolute path for validation
		absPath := filepath.Join("/", relPath)
		result := v.ValidatePackageFile(absPath, info.IsDir())

		if !result.Valid {
			invalidFiles = append(invalidFiles, relPath)
			for _, err := range result.Errors {
				v.log("Invalid package file (%s): %v", relPath, err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking package directory: %w", err)
	}

	if len(invalidFiles) > 0 {
		return fmt.Errorf("package contains %d invalid files", len(invalidFiles))
	}

	return nil
}

// WarnAboutHome warns if an application attempts to place files in /opt/home.
func (v *Validator) WarnAboutHome(path string) {
	if strings.HasPrefix(path, "/opt/home") {
		v.log("Warning: Placing files in /opt/home may not comply with standards")
	}
}
