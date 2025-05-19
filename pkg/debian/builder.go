package debian

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-i2p/go-pkginstall/pkg/security"
	"github.com/go-i2p/go-pkginstall/pkg/symlink"
)

// Builder is responsible for building Debian packages with enhanced security controls.
type Builder struct {
	Package          *Package // Package metadata
	SourceDir        string   // Directory containing files to package
	OutputDir        string   // Directory where the .deb file will be created
	BuildDir         string   // Temporary directory for building the package
	PathMapper       *security.PathMapper
	PathValidator    *security.Validator
	SymlinkProcessor *symlink.SymlinkProcessor

	PreservePerms bool              // Whether to preserve file permissions (default: false)
	Verbose       bool              // Whether to output verbose logging
	ExcludeDirs   []string          // Directories to exclude from packaging
	Conflicts     []string          // List of packages this package conflicts with
	Provides      []string          // List of packages this package provides
	Scripts       map[string]string // Map of maintainer scripts (postinst, prerm, etc.)
}

// NewBuilder creates a new Builder instance with the specified package and directories.
func NewBuilder(pkg *Package, sourceDir, outputDir string) (*Builder, error) {
	if pkg == nil {
		return nil, fmt.Errorf("package metadata cannot be nil")
	}

	if sourceDir == "" || outputDir == "" {
		return nil, fmt.Errorf("source and output directories cannot be empty")
	}

	// Ensure the source directory exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("source directory does not exist: %s", sourceDir)
	}

	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create a temporary build directory
	buildDir, err := os.MkdirTemp("", "pkginstall-build-")
	if err != nil {
		return nil, fmt.Errorf("failed to create build directory: %w", err)
	}

	symlinkDirs := []string{
		"/etc/systemd/system",
		"/etc/init.d",
		"/usr/share/applications",
		// Add other directories as needed
	}
	symlinkManager := symlink.NewSymlinkManager(symlinkDirs)

	builder := &Builder{
		Package:   pkg,
		SourceDir: sourceDir,
		OutputDir: outputDir,
		BuildDir:  buildDir,
		PathMapper: security.NewPathMapper(
			security.WithVerboseLogging(false),
		),
		PathValidator: security.NewValidator(
			security.WithTransformedDir("/opt"),
			security.WithVerbose(false),
		),
		PreservePerms: false,
		Verbose:       false,
		ExcludeDirs:   []string{},
		Scripts:       make(map[string]string),
	}
	builder.SymlinkProcessor = symlink.NewSymlinkProcessor(builder.PathMapper, symlinkManager, builder.PathValidator, false)
	return builder, nil
}

// log outputs a message if verbose logging is enabled
func (b *Builder) log(format string, args ...interface{}) {
	if b.Verbose {
		log.Printf(format, args...)
	}
}

// SetMaintainerScript sets a maintainer script (preinst, postinst, prerm, postrm)
// with comprehensive security validation to prevent unsafe operations.
func (b *Builder) SetMaintainerScript(scriptName, content string) error {
	validScripts := map[string]bool{
		"preinst":  true,
		"postinst": true,
		"prerm":    true,
		"postrm":   true,
	}

	if _, ok := validScripts[scriptName]; !ok {
		return fmt.Errorf("invalid maintainer script name: %s", scriptName)
	}

	// Create script validator with appropriate security level
	scriptValidator := security.NewScriptValidator(
		security.WithSecurityLevel(security.SecurityLevelMedium),
		security.WithPathMapper(b.PathMapper),
		security.WithScriptVerbose(b.Verbose),
	)

	// Validate the script content
	validationResult, err := scriptValidator.ValidateScript(scriptName, content)
	if err != nil {
		return fmt.Errorf("script validation error: %w", err)
	}

	// Log warnings even if the script is valid
	for _, warning := range validationResult.Warnings {
		if b.Verbose {
			b.log("Script warning: %s", warning)
		}
	}

	// If validation failed, return error with details
	if !validationResult.Valid {
		errMsg := fmt.Sprintf("Script validation failed for %s. %s",
			scriptName, scriptValidator.GetRiskAssessment(validationResult))

		// Add specific errors to the message
		if len(validationResult.Errors) > 0 {
			errMsg += "\nSpecific issues:"
			for _, err := range validationResult.Errors {
				errMsg += "\n- " + err
			}
		}

		return fmt.Errorf(errMsg)
	}

	// Store the script if it passed validation
	b.Scripts[scriptName] = content

	// Log risk assessment in verbose mode
	if b.Verbose {
		b.log("Script validation passed: %s", scriptValidator.GetRiskAssessment(validationResult))
	}

	return nil
}

// AddExcludeDir adds a directory to exclude from packaging
func (b *Builder) AddExcludeDir(dir string) {
	b.ExcludeDirs = append(b.ExcludeDirs, dir)
}

// SetConflicts sets packages that conflict with this package
func (b *Builder) SetConflicts(conflicts []string) {
	b.Conflicts = conflicts
}

// SetProvides sets packages that this package provides
func (b *Builder) SetProvides(provides []string) {
	b.Provides = provides
}

// Clean removes temporary build files
func (b *Builder) Clean() error {
	if b.BuildDir != "" {
		return os.RemoveAll(b.BuildDir)
	}
	return nil
}

// createDebianDir creates the DEBIAN directory structure
func (b *Builder) createDebianDir() error {
	debianDir := filepath.Join(b.BuildDir, "DEBIAN")
	if err := os.MkdirAll(debianDir, 0755); err != nil {
		return fmt.Errorf("failed to create DEBIAN directory: %w", err)
	}

	// Generate control file
	controlPath := filepath.Join(debianDir, "control")
	controlContent := b.generateControlFile()

	if err := os.WriteFile(controlPath, []byte(controlContent), 0644); err != nil {
		return fmt.Errorf("failed to write control file: %w", err)
	}

	// Write maintainer scripts
	for scriptName, content := range b.Scripts {
		scriptPath := filepath.Join(debianDir, scriptName)
		if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to write %s script: %w", scriptName, err)
		}
	}

	return nil
}

// generateControlFile creates the control file content based on package metadata
func (b *Builder) generateControlFile() string {
	var controlLines []string

	// Required fields
	controlLines = append(controlLines, fmt.Sprintf("Package: %s", b.Package.Name))
	controlLines = append(controlLines, fmt.Sprintf("Version: %s", b.Package.Version))
	controlLines = append(controlLines, fmt.Sprintf("Architecture: %s", b.Package.Architecture))
	controlLines = append(controlLines, fmt.Sprintf("Maintainer: %s", b.Package.Maintainer))
	controlLines = append(controlLines, fmt.Sprintf("Description: %s", b.Package.Description))

	// Optional fields
	if b.Package.Section != "" {
		controlLines = append(controlLines, fmt.Sprintf("Section: %s", b.Package.Section))
	}

	if b.Package.Priority != "" {
		controlLines = append(controlLines, fmt.Sprintf("Priority: %s", b.Package.Priority))
	}

	if len(b.Package.Depends) > 0 {
		controlLines = append(controlLines, fmt.Sprintf("Depends: %s", strings.Join(b.Package.Depends, ", ")))
	}

	if len(b.Conflicts) > 0 {
		controlLines = append(controlLines, fmt.Sprintf("Conflicts: %s", strings.Join(b.Conflicts, ", ")))
	}

	if len(b.Provides) > 0 {
		controlLines = append(controlLines, fmt.Sprintf("Provides: %s", strings.Join(b.Provides, ", ")))
	}

	// Add timestamp
	controlLines = append(controlLines, fmt.Sprintf("Installed-Size: %d", b.calculateInstalledSize()))
	controlLines = append(controlLines, fmt.Sprintf("Homepage: https://github.com/go-i2p/go-pkginstall"))

	return strings.Join(controlLines, "\n") + "\n"
}

// calculateInstalledSize estimates the installed size in KB
func (b *Builder) calculateInstalledSize() int {
	var size int64
	filepath.Walk(b.SourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() {
			size += info.Size()
		}

		return nil
	})

	// Convert to KB and round up
	return int((size + 1023) / 1024)
}

// copyFiles copies files from source to build directory with secure path transformation
func (b *Builder) copyFiles() error {
	return filepath.Walk(b.SourceDir, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip excluded directories
		for _, excludeDir := range b.ExcludeDirs {
			if strings.HasPrefix(srcPath, excludeDir) {
				return nil
			}
		}

		// Get relative path from source directory
		relPath, err := filepath.Rel(b.SourceDir, srcPath)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Skip the root directory
		if relPath == "." {
			return nil
		}

		// Convert to absolute path for transformation
		absPath := filepath.Join("/", relPath)

		// Transform the path for security
		transformedPath, needsSymlink, err := b.PathMapper.TransformPath(absPath)
		if err != nil {
			// Log warning but continue if path cannot be transformed
			if b.Verbose {
				log.Printf("Warning: Could not transform path %s: %v", absPath, err)
			}
			transformedPath = absPath
		}

		// Validate the path for security
		if err := b.PathValidator.ValidatePath(transformedPath); err != nil {
			return fmt.Errorf("path validation failed for %s: %w", transformedPath, err)
		}

		// Path traversal validation
		if err := b.PathValidator.ValidatePathTraversal(transformedPath); err != nil {
			return fmt.Errorf("path traversal check failed for %s: %w", transformedPath, err)
		}

		// Record symlink requirement if needed
		if needsSymlink {
			if err := b.SymlinkProcessor.ProcessPath(absPath, transformedPath); err != nil {
				if b.Verbose {
					log.Printf("Warning: Failed to process symlink for %s: %v", absPath, err)
				}
				// Continue with the build process even if symlink processing fails
			}
		}

		// Create the target path in the build directory
		targetPath := filepath.Join(b.BuildDir, transformedPath)

		if info.IsDir() {
			// Create directory
			if err := os.MkdirAll(targetPath, info.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		} else {
			// Create parent directory if it doesn't exist
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", targetPath, err)
			}

			// Copy file
			srcFile, err := os.Open(srcPath)
			if err != nil {
				return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
			}
			defer srcFile.Close()

			targetFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create target file %s: %w", targetPath, err)
			}
			defer targetFile.Close()

			if _, err := io.Copy(targetFile, srcFile); err != nil {
				return fmt.Errorf("failed to copy file content from %s to %s: %w", srcPath, targetPath, err)
			}

			// Set file permissions
			mode := info.Mode()
			if !b.PreservePerms {
				// Default permissions: rw-r--r--
				mode = 0644
				// Make executable files executable by all
				if mode&0100 != 0 {
					mode = 0755
				}
			}

			if err := os.Chmod(targetPath, mode); err != nil {
				return fmt.Errorf("failed to set permissions on %s: %w", targetPath, err)
			}
		}

		return nil
	})
}

// Build compiles the package from source and generates the .deb file.
// It returns the full path to the created .deb file.
func (b *Builder) Build() (string, error) {
	defer b.Clean()

	// Validate package metadata
	if err := b.Package.Validate(); err != nil {
		return "", fmt.Errorf("package validation failed: %w", err)
	}

	// Create DEBIAN directory structure
	if err := b.createDebianDir(); err != nil {
		return "", err
	}

	// Copy files with secure path transformation
	if err := b.copyFiles(); err != nil {
		return "", err
	}

	// Process symlinks if any were detected during file copying
	if b.SymlinkProcessor.GetQueuedSymlinkCount() > 0 {
		if b.Verbose {
			log.Printf("Creating %d symlinks", b.SymlinkProcessor.GetQueuedSymlinkCount())
		}

		// Create a special script to handle symlinks during package installation
		if err := b.createSymlinkScript(); err != nil {
			return "", fmt.Errorf("failed to create symlink script: %w", err)
		}
	}

	if err := b.PathValidator.ValidatePackage(b.BuildDir); err != nil {
		return "", fmt.Errorf("package validation failed: %w", err)
	}

	// Generate output file name
	outputFileName := fmt.Sprintf("%s_%s_%s.deb",
		b.Package.Name,
		b.Package.Version,
		b.Package.Architecture)
	outputPath := filepath.Join(b.OutputDir, outputFileName)

	// Build the package using dpkg-deb
	cmdArgs := []string{"--build", "--root-owner-group", b.BuildDir, outputPath}
	if b.Verbose {
		log.Printf("Running: dpkg-deb %s", strings.Join(cmdArgs, " "))
	}

	cmd := exec.Command("dpkg-deb", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to build package: %w", err)
	}

	return outputPath, nil
}

// BuildWithTimeout runs the Build method with a timeout.
// It returns the path to the created .deb file or an error.
func (b *Builder) BuildWithTimeout(timeout time.Duration) (string, error) {
	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		path, err := b.Build()
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- path
	}()

	select {
	case path := <-resultCh:
		return path, nil
	case err := <-errCh:
		return "", err
	case <-time.After(timeout):
		// Clean up on timeout
		b.Clean()
		return "", fmt.Errorf("package build timed out after %v", timeout)
	}
}

// createSymlinkScript creates a postinst script that will create necessary symlinks during package installation
func (b *Builder) createSymlinkScript() error {
	symlinks := b.SymlinkProcessor.GetQueuedSymlinks()
	if len(symlinks) == 0 {
		return nil
	}

	// Create the postinst script content
	var scriptContent strings.Builder
	scriptContent.WriteString("#!/bin/sh\n\n")
	scriptContent.WriteString("# This script was generated by go-pkginstall to create necessary symlinks\n\n")
	scriptContent.WriteString("set -e\n\n")

	for _, symlink := range symlinks {
		scriptContent.WriteString(fmt.Sprintf("# %s\n", symlink.Description))
		scriptContent.WriteString(fmt.Sprintf("mkdir -p $(dirname '%s')\n", symlink.Target))
		scriptContent.WriteString(fmt.Sprintf("if [ ! -e '%s' ]; then\n", symlink.Target))
		scriptContent.WriteString(fmt.Sprintf("    ln -sf '%s' '%s'\n", symlink.Source, symlink.Target))
		scriptContent.WriteString(fmt.Sprintf("else\n"))
		scriptContent.WriteString(fmt.Sprintf("    echo \"Warning: File '%s' already exists, not creating symlink\"\n", symlink.Target))
		scriptContent.WriteString(fmt.Sprintf("fi\n\n"))
	}

	// Set the maintainer script
	return b.SetMaintainerScript("postinst", scriptContent.String())
}
