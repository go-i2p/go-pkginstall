package symlink

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/go-i2p/go-pkginstall/pkg/security"
	"github.com/spf13/cobra"
)

// CommandOptions contains options for the symlink command
type CommandOptions struct {
	// General options
	Verbose bool
	DryRun  bool

	// Create command options
	Source      string
	Target      string
	Description string
	Force       bool

	// List command options
	Format string

	// Validate command options
	StrictMode bool
}

// NewSymlinkCommand creates a new command for managing symlinks
func NewSymlinkCommand() *cobra.Command {
	options := &CommandOptions{
		Format: "table",
	}

	cmd := &cobra.Command{
		Use:   "symlink",
		Short: "Manage secure symlinks for packages",
		Long: `Manage symlinks with enhanced security features.

This command allows creating, listing, and validating symlinks while applying
security controls to prevent unsafe system modifications. It ensures symlinks
follow the security model, never overwrite existing files, and maintain a
clean audit trail.

Examples:
  pkginstall symlink create --source /opt/myapp/service.conf --target /etc/systemd/system/myapp.service
  pkginstall symlink list
  pkginstall symlink validate --strict /etc/systemd/system/myapp.service
`,
	}

	// Add global flags
	cmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", false, "Enable verbose output")
	cmd.PersistentFlags().BoolVarP(&options.DryRun, "dry-run", "n", false, "Show what would be done without making changes")

	// Add subcommands
	cmd.AddCommand(newCreateCommand(options))
	cmd.AddCommand(newListCommand(options))
	cmd.AddCommand(newValidateCommand(options))

	return cmd
}

// newCreateCommand creates a subcommand for creating symlinks
func newCreateCommand(options *CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a symlink with security validation",
		Long: `Create a symlink with comprehensive security validation.

This command creates a symlink from source to target, ensuring that:
1. The target path undergoes security validation
2. No existing files are overwritten
3. Parent directories are created if needed
4. All operations follow the security model

Examples:
  pkginstall symlink create --source /opt/myapp/bin/myapp --target /usr/local/bin/myapp
  pkginstall symlink create --source /opt/myapp/myapp.service --target /etc/systemd/system/myapp.service
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreateCommand(options)
		},
	}

	// Add create-specific flags
	cmd.Flags().StringVarP(&options.Source, "source", "s", "", "Source file path (required)")
	cmd.Flags().StringVarP(&options.Target, "target", "t", "", "Target symlink path (required)")
	cmd.Flags().StringVarP(&options.Description, "description", "d", "", "Description of the symlink purpose")
	cmd.Flags().BoolVarP(&options.Force, "force", "f", false, "Force creation even if target exists (will remove existing file)")

	// Mark required flags
	cmd.MarkFlagRequired("source")
	cmd.MarkFlagRequired("target")

	return cmd
}

// newListCommand creates a subcommand for listing symlinks
func newListCommand(options *CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List planned or created symlinks",
		Long: `List symlinks that have been queued or created.

This command displays information about symlinks that have been
registered with the symlink processor, including their source,
target, and security validation status.

Examples:
  pkginstall symlink list
  pkginstall symlink list --format json
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListCommand(options)
		},
	}

	// Add list-specific flags
	cmd.Flags().StringVarP(&options.Format, "format", "f", "table", "Output format (table, json, yaml)")

	return cmd
}

// newValidateCommand creates a subcommand for validating symlinks
func newValidateCommand(options *CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [target_path]",
		Short: "Validate a symlink against security policies",
		Long: `Validate an existing or planned symlink against security policies.

This command checks if a symlink follows the security model,
ensuring it doesn't bypass security restrictions or point to
forbidden locations.

Examples:
  pkginstall symlink validate /etc/systemd/system/myapp.service
  pkginstall symlink validate --strict /usr/local/bin/myapp
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options.Target = args[0]
			return runValidateCommand(options)
		},
	}

	// Add validate-specific flags
	cmd.Flags().BoolVarP(&options.StrictMode, "strict", "S", false, "Enable strict validation mode")

	return cmd
}

// runCreateCommand handles the symlink creation logic
func runCreateCommand(options *CommandOptions) error {
	// Normalize paths to absolute
	source, err := filepath.Abs(options.Source)
	if err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}

	target, err := filepath.Abs(options.Target)
	if err != nil {
		return fmt.Errorf("invalid target path: %w", err)
	}

	// Create dependencies
	pathMapper := security.NewPathMapper(
		security.WithVerboseLogging(options.Verbose),
	)
	validator := security.NewValidator(
		security.WithVerbose(options.Verbose),
	)

	// Determine allowed symlink directories from PathMapper
	symlinkDirs := pathMapper.GetSymlinkDirs()
	manager := NewSymlinkManager(symlinkDirs)
	processor := NewSymlinkProcessor(pathMapper, manager, validator, options.Verbose)
	processor.SetDryRun(options.DryRun)

	// Validate that the source file exists
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("source file error: %w", err)
	}

	// Validate that the target path is in an allowed location
	if err := validator.ValidatePath(target); err != nil {
		return fmt.Errorf("target path validation failed: %w", err)
	}

	// Check for path traversal attempts
	if err := validator.ValidatePathTraversal(target); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	// Get symlink description
	description := options.Description
	if description == "" {
		description = fmt.Sprintf("Symlink from %s to %s", source, target)
	}

	// Check if target already exists
	if _, err := os.Lstat(target); err == nil {
		if !options.Force {
			return fmt.Errorf("target path already exists: %s (use --force to override)", target)
		}
		// Remove existing target if force is specified
		if !options.DryRun {
			if err := os.Remove(target); err != nil {
				return fmt.Errorf("failed to remove existing target: %w", err)
			}
			if options.Verbose {
				fmt.Printf("Removed existing target: %s\n", target)
			}
		} else {
			fmt.Printf("[DRY RUN] Would remove existing target: %s\n", target)
		}
	}

	// Create parent directory if needed
	parentDir := filepath.Dir(target)
	if !options.DryRun {
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}
	} else {
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			fmt.Printf("[DRY RUN] Would create directory: %s\n", parentDir)
		}
	}

	// Create symlink request
	request := SymlinkRequest{
		Source:      source,
		Target:      target,
		Description: description,
	}

	// Queue the symlink
	if err := processor.QueueSymlink(request); err != nil {
		return fmt.Errorf("failed to queue symlink: %w", err)
	}

	// Process the queued symlink
	if err := processor.ProcessQueuedSymlinks(); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	// Success message
	if !options.DryRun {
		fmt.Printf("Successfully created symlink: %s -> %s\n", target, source)
		// Add metadata about the file
		if sourceInfo.IsDir() {
			fmt.Printf("Source is a directory\n")
		} else {
			fmt.Printf("Source is a file (%d bytes)\n", sourceInfo.Size())
		}
	} else {
		fmt.Printf("[DRY RUN] Would create symlink: %s -> %s\n", target, source)
	}

	return nil
}

// runListCommand handles the symlink listing logic
func runListCommand(options *CommandOptions) error {
	// Create a dummy processor to demonstrate functionality
	// In a real implementation, this would access a persistent storage
	// of symlinks or scan the filesystem
	pathMapper := security.NewPathMapper(
		security.WithVerboseLogging(options.Verbose),
	)
	validator := security.NewValidator(
		security.WithVerbose(options.Verbose),
	)
	manager := NewSymlinkManager(pathMapper.GetSymlinkDirs())
	processor := NewSymlinkProcessor(pathMapper, manager, validator, options.Verbose)

	// Get existing symlinks - in a real implementation, this might scan specific directories
	// or read from a database of created symlinks
	existingSymlinks, err := findExistingSymlinks(pathMapper.GetSymlinkDirs())
	if err != nil {
		fmt.Printf("Warning: Error scanning for existing symlinks: %v\n", err)
		// Continue execution to show queued symlinks, if any
	}

	// Get queued symlinks
	queuedSymlinks := processor.GetQueuedSymlinks()

	// Display based on format
	switch strings.ToLower(options.Format) {
	case "table":
		printSymlinksTable(existingSymlinks, queuedSymlinks, options.Verbose)
	case "json":
		printSymlinksJSON(existingSymlinks, queuedSymlinks)
	case "yaml":
		printSymlinksYAML(existingSymlinks, queuedSymlinks)
	default:
		return fmt.Errorf("unknown output format: %s", options.Format)
	}

	return nil
}

// runValidateCommand handles the symlink validation logic
func runValidateCommand(options *CommandOptions) error {
	// Normalize path to absolute
	target, err := filepath.Abs(options.Target)
	if err != nil {
		return fmt.Errorf("invalid target path: %w", err)
	}

	// Create dependencies
	pathMapper := security.NewPathMapper(
		security.WithVerboseLogging(options.Verbose),
	)
	validator := security.NewValidator(
		security.WithVerbose(options.Verbose),
		security.WithTransformedDir("/opt"),
	)

	// Check if the target exists
	fileInfo, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf("target path error: %w", err)
	}

	// Check if it's a symlink
	if fileInfo.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("target is not a symlink: %s", target)
	}

	// Read the symlink target
	source, err := os.Readlink(target)
	if err != nil {
		return fmt.Errorf("failed to read symlink: %w", err)
	}

	// If the source is relative, make it absolute
	if !filepath.IsAbs(source) {
		source = filepath.Join(filepath.Dir(target), source)
	}

	fmt.Printf("Validating symlink: %s -> %s\n", target, source)

	// Validate the target path
	if err := validator.ValidatePath(target); err != nil {
		fmt.Printf("⚠️ Target path validation failed: %v\n", err)
		if options.StrictMode {
			return fmt.Errorf("strict validation failed: %w", err)
		}
	} else {
		fmt.Printf("✅ Target path validation passed\n")
	}

	// Validate the source path
	if err := validator.ValidatePath(source); err != nil {
		fmt.Printf("⚠️ Source path validation failed: %v\n", err)
		if options.StrictMode {
			return fmt.Errorf("strict validation failed: %w", err)
		}
	} else {
		fmt.Printf("✅ Source path validation passed\n")
	}

	// Check path traversal
	if err := validator.ValidatePathTraversal(target); err != nil {
		fmt.Printf("❌ Security validation failed: %v\n", err)
		return fmt.Errorf("security validation failed: %w", err)
	} else {
		fmt.Printf("✅ Security validation passed\n")
	}

	// Check if the source file exists
	if _, err := os.Stat(source); err != nil {
		fmt.Printf("⚠️ Source file does not exist: %v\n", err)
	} else {
		fmt.Printf("✅ Source file exists\n")
	}

	// Check if the symlink is pointing to a transformed path
	if pathMapper.IsTransformedPath(source) {
		fmt.Printf("✅ Symlink points to a secure transformed path\n")
	} else if pathMapper.IsSystemPath(source) {
		fmt.Printf("⚠️ Symlink points to a system path (potentially unsafe)\n")
		if options.StrictMode {
			return fmt.Errorf("strict validation failed: symlink points to a system path")
		}
	}

	fmt.Printf("Validation complete: symlink appears to be valid\n")
	return nil
}

// findExistingSymlinks scans specified directories for symlinks
func findExistingSymlinks(dirs []string) ([]SymlinkRequest, error) {
	var symlinks []SymlinkRequest

	for _, dir := range dirs {
		// Skip directories that don't exist
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip files with errors
			}

			if info.Mode()&os.ModeSymlink == 0 {
				return nil // Skip non-symlinks
			}

			// Read the symlink target
			target, err := os.Readlink(path)
			if err != nil {
				return nil // Skip unreadable symlinks
			}

			// If the target is relative, make it absolute
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}

			symlinks = append(symlinks, SymlinkRequest{
				Source:      target,
				Target:      path,
				Description: "Existing symlink",
			})

			return nil
		})

		if err != nil {
			return symlinks, err
		}
	}

	return symlinks, nil
}

// printSymlinksTable prints symlinks in a table format
func printSymlinksTable(existing, queued []SymlinkRequest, verbose bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "TYPE\tTARGET\tSOURCE\tDESCRIPTION")
	fmt.Fprintln(w, "----\t------\t------\t-----------")

	for _, s := range existing {
		fmt.Fprintf(w, "Existing\t%s\t%s\t%s\n", s.Target, s.Source, s.Description)
	}

	for _, s := range queued {
		fmt.Fprintf(w, "Queued\t%s\t%s\t%s\n", s.Target, s.Source, s.Description)
	}

	w.Flush()

	fmt.Printf("\nTotal: %d existing, %d queued symlinks\n", len(existing), len(queued))
}

// printSymlinksJSON prints symlinks in JSON format
func printSymlinksJSON(existing, queued []SymlinkRequest) {
	// Simple JSON output for demonstration
	fmt.Println("{")
	fmt.Println("  \"existing\": [")
	for i, s := range existing {
		fmt.Printf("    {\"target\": \"%s\", \"source\": \"%s\", \"description\": \"%s\"}",
			s.Target, s.Source, s.Description)
		if i < len(existing)-1 {
			fmt.Println(",")
		} else {
			fmt.Println("")
		}
	}
	fmt.Println("  ],")
	fmt.Println("  \"queued\": [")
	for i, s := range queued {
		fmt.Printf("    {\"target\": \"%s\", \"source\": \"%s\", \"description\": \"%s\"}",
			s.Target, s.Source, s.Description)
		if i < len(queued)-1 {
			fmt.Println(",")
		} else {
			fmt.Println("")
		}
	}
	fmt.Println("  ]")
	fmt.Println("}")
}

// printSymlinksYAML prints symlinks in YAML format
func printSymlinksYAML(existing, queued []SymlinkRequest) {
	fmt.Println("existing:")
	for _, s := range existing {
		fmt.Printf("  - target: %s\n    source: %s\n    description: %s\n",
			s.Target, s.Source, s.Description)
	}
	fmt.Println("queued:")
	for _, s := range queued {
		fmt.Printf("  - target: %s\n    source: %s\n    description: %s\n",
			s.Target, s.Source, s.Description)
	}
}
