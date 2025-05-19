package symlink

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-i2p/go-pkginstall/pkg/security"
)

// SymlinkRequest represents a request to create a symlink
type SymlinkRequest struct {
	Source      string // The secure source path
	Target      string // The system target path
	Description string // Description of what this symlink is for
}

// SymlinkProcessor integrates path transformation with symlink creation
// It tracks paths that need symlinks during the build process and creates
// them at the appropriate time, with comprehensive error handling and security validation.
type SymlinkProcessor struct {
	pathMapper     *security.PathMapper
	symlinkManager *SymlinkManager
	validator      *security.Validator
	symlinkQueue   []SymlinkRequest
	queueMutex     sync.Mutex
	verbose        bool
	dryRun         bool
	logFunc        func(format string, args ...interface{}) (int, error)
}

// NewSymlinkProcessor creates a new SymlinkProcessor with the provided dependencies
func NewSymlinkProcessor(
	pathMapper *security.PathMapper,
	symlinkManager *SymlinkManager,
	validator *security.Validator,
	verbose bool,
) *SymlinkProcessor {
	return &SymlinkProcessor{
		pathMapper:     pathMapper,
		symlinkManager: symlinkManager,
		validator:      validator,
		symlinkQueue:   make([]SymlinkRequest, 0),
		verbose:        verbose,
		dryRun:         false,
		logFunc:        fmt.Printf,
	}
}

// SetLogger allows customizing the logging function
func (p *SymlinkProcessor) SetLogger(logFunc func(format string, args ...interface{}) (int, error)) {
	p.logFunc = logFunc
}

// SetDryRun enables or disables dry run mode (no actual symlinks created)
func (p *SymlinkProcessor) SetDryRun(dryRun bool) {
	p.dryRun = dryRun
}

// QueueSymlink adds a symlink to the queue for later processing
func (p *SymlinkProcessor) QueueSymlink(request SymlinkRequest) error {
	// Validate both source and target paths
	if err := p.validator.ValidatePath(request.Source); err != nil {
		return fmt.Errorf("invalid source path %s: %w", request.Source, err)
	}
	if err := p.validator.ValidatePath(request.Target); err != nil {
		return fmt.Errorf("invalid target path %s: %w", request.Target, err)
	}

	// Check if the symlink is allowed for this target directory
	if err := p.validator.ValidateSymlink(request.Source, request.Target); err != nil {
		return fmt.Errorf("symlink validation failed: %w", err)
	}

	p.queueMutex.Lock()
	defer p.queueMutex.Unlock()

	// Check for duplicate targets to avoid conflicts
	for _, existing := range p.symlinkQueue {
		if existing.Target == request.Target {
			return fmt.Errorf("duplicate symlink target: %s", request.Target)
		}
	}

	p.symlinkQueue = append(p.symlinkQueue, request)
	if p.verbose {
		p.logFunc("Queued symlink: %s -> %s (%s)\n", request.Source, request.Target, request.Description)
	}
	return nil
}

// ProcessPath examines a path, determines if it needs a symlink, and queues it if necessary
func (p *SymlinkProcessor) ProcessPath(originalPath string, transformedPath string) error {
	// Check if the path needs a symlink
	needsSymlink := false
	if transformedPath == "" {
		var err error
		transformedPath, needsSymlink, err = p.pathMapper.TransformPath(originalPath)
		if err != nil {
			return fmt.Errorf("failed to transform path %s: %w", originalPath, err)
		}
	} else {
		var err error
		_, needsSymlink, err = p.pathMapper.TransformPath(originalPath)
		if err != nil {
			return fmt.Errorf("failed to transform path %s: %w", originalPath, err)
		}
	}

	if needsSymlink {
		// Queue the symlink creation
		return p.QueueSymlink(SymlinkRequest{
			Source:      transformedPath,
			Target:      originalPath,
			Description: "Automatically detected during build",
		})
	}
	return nil
}

// ProcessQueuedSymlinks creates all queued symlinks
func (p *SymlinkProcessor) ProcessQueuedSymlinks() error {
	p.queueMutex.Lock()
	defer p.queueMutex.Unlock()

	if len(p.symlinkQueue) == 0 {
		if p.verbose {
			p.logFunc("No symlinks to process\n")
		}
		return nil
	}

	if p.verbose {
		p.logFunc("Processing %d queued symlinks\n", len(p.symlinkQueue))
	}

	var errs []error
	for _, request := range p.symlinkQueue {
		if err := p.createSymlink(request); err != nil {
			errs = append(errs, err)
			if p.verbose {
				p.logFunc("Error creating symlink %s -> %s: %v\n",
					request.Source, request.Target, err)
			}
		}
	}

	// Clear the queue after processing
	p.symlinkQueue = make([]SymlinkRequest, 0)

	if len(errs) > 0 {
		return fmt.Errorf("failed to create %d symlinks", len(errs))
	}

	return nil
}

// createSymlink creates a single symlink, ensuring parent directories exist
func (p *SymlinkProcessor) createSymlink(request SymlinkRequest) error {
	if p.dryRun {
		p.logFunc("[DRY RUN] Would create symlink: %s -> %s\n", request.Source, request.Target)
		return nil
	}

	// Create parent directory if it doesn't exist
	parentDir := filepath.Dir(request.Target)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
	}

	// Create the symlink
	if p.verbose {
		p.logFunc("Creating symlink: %s -> %s\n", request.Source, request.Target)
	}

	return p.symlinkManager.CreateSymlink(request.Source, request.Target)
}

// GetQueuedSymlinkCount returns the number of symlinks in the queue
func (p *SymlinkProcessor) GetQueuedSymlinkCount() int {
	p.queueMutex.Lock()
	defer p.queueMutex.Unlock()
	return len(p.symlinkQueue)
}

// GetQueuedSymlinks returns a copy of the symlink queue
func (p *SymlinkProcessor) GetQueuedSymlinks() []SymlinkRequest {
	p.queueMutex.Lock()
	defer p.queueMutex.Unlock()

	// Return a copy to avoid race conditions
	result := make([]SymlinkRequest, len(p.symlinkQueue))
	copy(result, p.symlinkQueue)
	return result
}
