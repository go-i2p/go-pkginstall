package debian

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-i2p/go-pkginstall/pkg/config"
	"github.com/spf13/cobra"
)

const (
	defaultTimeout = 10 * time.Minute
	defaultArch    = "amd64"
)

// BuildOptions contains all options for the build command
type BuildOptions struct {
	// Package metadata
	PackageName  string
	Version      string
	Maintainer   string
	Description  string
	Architecture string
	Section      string
	Priority     string
	Depends      []string
	Conflicts    []string
	Provides     []string
	ConfigFile   string

	// Build options
	SourceDir        string
	OutputDir        string
	PreservePerms    bool
	Verbose          bool
	ExcludeDirs      []string
	MaintainerScript string

	// Security options
	DisableSymlinks        bool
	StrictMode             bool
	IgnoreScriptValidation bool
}

// NewBuildCommand creates a new cobra command for building Debian packages
func NewBuildCommand() *cobra.Command {
	options := &BuildOptions{
		Architecture: getDefaultArchitecture(),
		Priority:     "optional",
		Section:      "utils",
		OutputDir:    ".",
		SourceDir:    ".",
	}

	cmd := &cobra.Command{
		Use:   "build [flags]",
		Short: "Build a Debian package from source directory",
		Long: `Build a Debian package with enhanced security features.

This command creates a .deb package from the specified source directory,
applying security controls to prevent filesystem modifications outside of 
allowed paths. System paths are automatically transformed to secure 
alternatives, and symlinks are created only when necessary.

Examples:
  pkginstall build --name myapp --version 1.0.0 --source ./build
  pkginstall build --config myapp.yaml --verbose
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBuildCommand(options)
		},
	}

	// Package metadata flags
	cmd.Flags().StringVarP(&options.PackageName, "name", "n", "", "Package name (required)")
	cmd.Flags().StringVarP(&options.Version, "version", "v", "", "Package version (required)")
	cmd.Flags().StringVarP(&options.Maintainer, "maintainer", "m", "", "Package maintainer (required)")
	cmd.Flags().StringVarP(&options.Description, "description", "d", "", "Package description")
	cmd.Flags().StringVar(&options.Architecture, "arch", options.Architecture, "Package architecture")
	cmd.Flags().StringVar(&options.Section, "section", options.Section, "Package section")
	cmd.Flags().StringVar(&options.Priority, "priority", options.Priority, "Package priority")
	cmd.Flags().StringSliceVar(&options.Depends, "depends", nil, "Package dependencies (comma-separated)")
	cmd.Flags().StringSliceVar(&options.Conflicts, "conflicts", nil, "Package conflicts (comma-separated)")
	cmd.Flags().StringSliceVar(&options.Provides, "provides", nil, "Packages this package provides (comma-separated)")
	cmd.Flags().StringVar(&options.ConfigFile, "config", "", "Configuration file path")

	// Build options flags
	cmd.Flags().StringVarP(&options.SourceDir, "source", "s", options.SourceDir, "Source directory containing files to package")
	cmd.Flags().StringVarP(&options.OutputDir, "output", "o", options.OutputDir, "Output directory for the generated .deb file")
	cmd.Flags().BoolVarP(&options.PreservePerms, "preserve-perms", "p", false, "Preserve file permissions")
	cmd.Flags().BoolVarP(&options.Verbose, "verbose", "V", false, "Enable verbose output")
	cmd.Flags().StringSliceVar(&options.ExcludeDirs, "exclude", nil, "Directories to exclude from packaging (comma-separated)")
	cmd.Flags().StringVar(&options.MaintainerScript, "script", "", "Path to maintainer script file (postinst, preinst, etc.)")

	// Security options flags
	cmd.Flags().BoolVar(&options.DisableSymlinks, "disable-symlinks", false, "Disable automatic symlink creation")
	cmd.Flags().BoolVar(&options.StrictMode, "strict", false, "Enable strict security validation")
	cmd.Flags().BoolVar(&options.IgnoreScriptValidation, "ignore-script-validation", false,
		"Ignore script validation failures (NOT RECOMMENDED)")

	// Mark required flags
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("version")
	cmd.MarkFlagRequired("maintainer")

	return cmd
}

// runBuildCommand executes the build command with the specified options
func runBuildCommand(options *BuildOptions) error {
	// Load configuration from file if specified
	if options.ConfigFile != "" {
		cfg, err := config.LoadConfig(options.ConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Override options with values from config file if they're not set via flags
		if options.PackageName == "" {
			options.PackageName = cfg.PackageName
		}
		if options.Version == "" {
			options.Version = cfg.Version
		}
		if options.Maintainer == "" {
			options.Maintainer = cfg.Maintainer
		}
		if options.Description == "" {
			options.Description = cfg.Description
		}
		if options.Architecture == getDefaultArchitecture() {
			options.Architecture = cfg.Architecture
		}
		if options.Section == "utils" {
			options.Section = cfg.Section
		}
		if options.Priority == "optional" {
			options.Priority = cfg.Priority
		}
	}

	// Validate required options
	if options.PackageName == "" {
		return fmt.Errorf("package name is required")
	}
	if options.Version == "" {
		return fmt.Errorf("package version is required")
	}
	if options.Maintainer == "" {
		return fmt.Errorf("package maintainer is required")
	}

	// Normalize and validate paths
	sourceDir, err := validatePath(options.SourceDir, true)
	if err != nil {
		return fmt.Errorf("invalid source directory: %w", err)
	}

	outputDir, err := validatePath(options.OutputDir, false)
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}

	// Description defaults to package name if not specified
	if options.Description == "" {
		options.Description = options.PackageName
	}

	// Create package metadata
	pkg := NewPackage(
		options.PackageName,
		options.Version,
		options.Architecture,
		options.Maintainer,
		options.Description,
		options.Section,
		options.Priority,
		options.Depends,
	)

	// Create builder
	builder, err := NewBuilder(pkg, sourceDir, outputDir)
	if err != nil {
		return fmt.Errorf("failed to create builder: %w", err)
	}

	// Configure builder
	builder.PreservePerms = options.PreservePerms
	builder.Verbose = options.Verbose

	// Add excluded directories
	for _, excludeDir := range options.ExcludeDirs {
		builder.AddExcludeDir(excludeDir)
	}

	// Set conflicts and provides
	if len(options.Conflicts) > 0 {
		builder.SetConflicts(options.Conflicts)
	}
	if len(options.Provides) > 0 {
		builder.SetProvides(options.Provides)
	}

	if options.MaintainerScript != "" {
		scriptContent, scriptName, err := loadMaintainerScript(options.MaintainerScript)
		if err != nil {
			return fmt.Errorf("failed to load maintainer script: %w", err)
		}

		err = builder.SetMaintainerScript(scriptName, scriptContent)
		if err != nil {
			// Check if this is a validation error
			if strings.Contains(err.Error(), "Script validation failed") {
				if options.IgnoreScriptValidation {
					// If the user has chosen to ignore validation, log a warning but continue
					fmt.Printf("WARNING: Script validation issues were detected but ignored due to --ignore-script-validation flag.\n")
					fmt.Printf("Issues: %v\n", err)

					// Force set the script bypassing validation
					builder.Scripts[scriptName] = scriptContent
				} else {
					// Provide guidance on how to bypass if needed
					return fmt.Errorf("%w\n\nTo bypass script validation, use the --ignore-script-validation flag (not recommended)", err)
				}
			} else {
				// Regular error setting script
				return fmt.Errorf("failed to set maintainer script: %w", err)
			}
		}
	}

	// Build the package with timeout
	if options.Verbose {
		fmt.Printf("Building package %s_%s...\n", options.PackageName, options.Version)
	}

	outputPath, err := builder.BuildWithTimeout(defaultTimeout)
	if err != nil {
		return fmt.Errorf("package build failed: %w", err)
	}

	fmt.Printf("Successfully created package: %s\n", outputPath)
	return nil
}

// loadMaintainerScript reads a maintainer script file and determines its type
func loadMaintainerScript(path string) (string, string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("failed to read script file: %w", err)
	}

	// Determine script type from file name
	base := filepath.Base(path)
	scriptName := ""

	switch {
	case strings.HasPrefix(base, "preinst"):
		scriptName = "preinst"
	case strings.HasPrefix(base, "postinst"):
		scriptName = "postinst"
	case strings.HasPrefix(base, "prerm"):
		scriptName = "prerm"
	case strings.HasPrefix(base, "postrm"):
		scriptName = "postrm"
	default:
		return "", "", fmt.Errorf("unknown maintainer script type: %s", base)
	}

	return string(content), scriptName, nil
}

// validatePath checks if a path exists and returns its absolute path
func validatePath(path string, mustExist bool) (string, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Check if the path exists (only if required)
	if mustExist {
		info, err := os.Stat(absPath)
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist: %s", absPath)
		}
		if err != nil {
			return "", fmt.Errorf("failed to access path: %w", err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("path is not a directory: %s", absPath)
		}
	}

	return absPath, nil
}

// getDefaultArchitecture returns the default architecture based on the current system
func getDefaultArchitecture() string {
	arch := runtime.GOARCH
	// Map Go architecture names to Debian architecture names
	switch arch {
	case "386":
		return "i386"
	case "amd64":
		return "amd64"
	case "arm":
		return "armhf"
	case "arm64":
		return "arm64"
	default:
		return arch
	}
}
