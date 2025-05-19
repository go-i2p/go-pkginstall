package compat

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-i2p/go-pkginstall/pkg/debian"
	"github.com/spf13/cobra"
)

// CheckinstallFlags contains all the flags supported by the original Checkinstall
type CheckinstallFlags struct {
	// Package metadata flags
	PackageName    string
	Version        string
	Release        string
	Maintainer     string
	PkgGroup       string
	Architecture   string
	Summary        string
	License        string
	Provides       string
	Requires       string
	Description    string
	DescriptionPak string

	// Installation flags
	InstallPrefix       string
	DocDir              string
	DefaultDocs         bool
	StripExecutables    bool
	KeepBuildFiles      bool
	BackupConfiguration bool
	FStrans             bool

	// File-related flags
	Include       []string
	Exclude       []string
	ExcludeFile   string
	ExcludeDocsf  string
	InstalledFile string

	// Behavior flags
	NoStrip       bool
	NoSign        bool
	Reset         bool
	Interactive   bool
	ShowHelp      bool
	ShowVersion   bool
	Debug         bool
	ReviewInstall bool
	AcceptPak     bool
	Type          string
}

// CheckinstallBuilderOptions maps Checkinstall flags to go-pkginstall build options
func (f *CheckinstallFlags) ToBuilderOptions() *debian.BuildOptions {
	// Convert Checkinstall flags to go-pkginstall build options
	buildOpts := &debian.BuildOptions{
		PackageName:   f.PackageName,
		Version:       f.Version,
		Maintainer:    f.Maintainer,
		Description:   f.Description,
		Architecture:  f.Architecture,
		Section:       f.PkgGroup,
		OutputDir:     ".",
		SourceDir:     ".",
		PreservePerms: !f.StripExecutables,
		Verbose:       f.Debug,
	}

	// Set source directory to current directory if not specified
	if f.InstallPrefix != "" {
		buildOpts.SourceDir = f.InstallPrefix
	}

	// Convert comma-separated provides to slice
	if f.Provides != "" {
		buildOpts.Provides = strings.Split(f.Provides, ",")
	}

	// Convert comma-separated requires to depends
	if f.Requires != "" {
		buildOpts.Depends = strings.Split(f.Requires, ",")
	}

	// Handle excludes
	if len(f.Exclude) > 0 {
		buildOpts.ExcludeDirs = f.Exclude
	}

	// Set security options based on Checkinstall's FStrans flag
	buildOpts.DisableSymlinks = !f.FStrans
	buildOpts.StrictMode = false // Less strict by default for compatibility

	return buildOpts
}

// NewCheckinstallCommand creates a command that provides compatibility with Checkinstall
func NewCheckinstallCommand() *cobra.Command {
	flags := &CheckinstallFlags{
		DefaultDocs: true,
		FStrans:     true,     // Enable filesystem translation by default
		Type:        "debian", // Default to debian packages
	}

	cmd := &cobra.Command{
		Use:   "checkinstall [flags] [-- command [arg1 [arg2 [...]]]]",
		Short: "Checkinstall compatibility mode",
		Long: `This command provides compatibility with the original Checkinstall tool.
It allows you to use familiar Checkinstall command-line options while
benefiting from enhanced security features provided by go-pkginstall.

Usage:
  pkginstall checkinstall [flags] [-- command]

Example:
  pkginstall checkinstall -D --pkgname=myapp --pkgversion=1.0 -- make install
  pkginstall checkinstall --install=no --fstrans=no -D`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheckinstall(cmd, args, flags)
		},
		// Preserve original Checkinstall behavior for help
		SilenceUsage:  false,
		SilenceErrors: false,
	}

	// Add Checkinstall metadata flags
	cmd.Flags().StringVarP(&flags.PackageName, "pkgname", "n", "", "Package name")
	cmd.Flags().StringVarP(&flags.Version, "pkgversion", "v", "1.0", "Package version")
	cmd.Flags().StringVarP(&flags.Release, "pkgrelease", "r", "1", "Package release number")
	cmd.Flags().StringVarP(&flags.Maintainer, "maintainer", "m", "", "Package maintainer")
	cmd.Flags().StringVarP(&flags.PkgGroup, "pkggroup", "g", "utils", "Package group/section")
	cmd.Flags().StringVarP(&flags.Architecture, "arch", "a", "", "Package architecture")
	cmd.Flags().StringVarP(&flags.Summary, "pkgsummary", "s", "", "Package summary")
	cmd.Flags().StringVarP(&flags.License, "license", "l", "", "Package license")
	cmd.Flags().StringVar(&flags.Provides, "provides", "", "Package provides (comma-separated)")
	cmd.Flags().StringVar(&flags.Requires, "requires", "", "Package requires/depends (comma-separated)")
	cmd.Flags().StringVarP(&flags.Description, "pkgdescription", "d", "", "Package description")
	cmd.Flags().StringVar(&flags.DescriptionPak, "dpkgdescription", "", "Debian package description file")

	// Add installation flags
	cmd.Flags().StringVar(&flags.InstallPrefix, "install-prefix", "", "Installation prefix")
	cmd.Flags().StringVar(&flags.DocDir, "docdir", "", "Documentation directory")
	cmd.Flags().BoolVar(&flags.DefaultDocs, "deldoc", true, "Delete doc-pak directory after package creation")
	cmd.Flags().BoolVar(&flags.StripExecutables, "strip", false, "Strip executables")
	cmd.Flags().BoolVar(&flags.KeepBuildFiles, "keep", false, "Keep build files")
	cmd.Flags().BoolVar(&flags.BackupConfiguration, "backup", true, "Backup configuration files")
	cmd.Flags().BoolVar(&flags.FStrans, "fstrans", true, "Enable filesystem translation (security feature)")

	// Add file-related flags
	cmd.Flags().StringArrayVar(&flags.Include, "include", nil, "Include files/directories")
	cmd.Flags().StringArrayVar(&flags.Exclude, "exclude", nil, "Exclude files/directories")
	cmd.Flags().StringVar(&flags.ExcludeFile, "exclude-file", "", "File containing exclusion patterns")
	cmd.Flags().StringVar(&flags.ExcludeDocsf, "excludedocs", "", "File containing excluded docs")
	cmd.Flags().StringVar(&flags.InstalledFile, "inspect", "", "Inspect an already-installed package")

	// Add behavior flags
	cmd.Flags().BoolVar(&flags.NoStrip, "stripso", false, "Strip shared libraries")
	cmd.Flags().BoolVar(&flags.NoSign, "nosign", true, "Do not sign package")
	cmd.Flags().BoolVarP(&flags.Reset, "reset", "R", false, "Reset all options to default")
	cmd.Flags().BoolVarP(&flags.Interactive, "interactive", "i", true, "Interactive mode")
	cmd.Flags().BoolVarP(&flags.ShowHelp, "help", "h", false, "Show help message")
	cmd.Flags().BoolVar(&flags.ShowVersion, "version", false, "Show version information")
	cmd.Flags().BoolVar(&flags.Debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.ReviewInstall, "review-install", true, "Review installation")
	cmd.Flags().BoolVar(&flags.AcceptPak, "accept", false, "Accept default answers")

	// Add package type flags (mimic original Checkinstall's behavior)
	cmd.Flags().StringVarP(&flags.Type, "type", "t", "debian", "Package type (determined by -D/-R/-S flags)")
	cmd.Flags().BoolP("debian", "D", false, "Create Debian package (default)")
	cmd.Flags().BoolP("rpm", "R", false, "Create RPM package (unsupported)")
	cmd.Flags().BoolP("slackware", "S", false, "Create Slackware package (unsupported)")

	// Add install flag (legacy behavior simulation)
	install := cmd.Flags().String("install", "yes", "Install the package after creation (yes/no)")

	// Hook to modify flags based on the install flag
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		// Handle legacy --install=no flag (just creates the package without installing)
		if strings.ToLower(*install) == "no" {
			fmt.Println("Note: Package will be created but not installed (--install=no)")
			// No need to change behavior as go-pkginstall doesn't install by default
		}

		// Check for unsupported package types
		if cmd.Flags().Changed("rpm") || cmd.Flags().Changed("slackware") {
			fmt.Println("Warning: Only Debian packages are supported in go-pkginstall.")
			fmt.Println("The package will be created as a Debian package regardless of -R or -S flags.")
		}
	}

	return cmd
}

// runCheckinstall processes Checkinstall command and arguments
func runCheckinstall(cmd *cobra.Command, args []string, flags *CheckinstallFlags) error {
	// Show version if requested
	if flags.ShowVersion {
		fmt.Println("go-pkginstall version 1.0.0 (compatible with Checkinstall)")
		fmt.Println("Enhanced security replacement for Checkinstall")
		return nil
	}

	// Process install command if provided after --
	installCommand := []string{}
	for i, arg := range args {
		if arg == "--" && i < len(args)-1 {
			installCommand = args[i+1:]
			args = args[:i]
			break
		}
	}

	// Set default maintainer if not provided
	if flags.Maintainer == "" {
		user := os.Getenv("USER")
		if user == "" {
			user = "unknown"
		}
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "localhost"
		}
		flags.Maintainer = fmt.Sprintf("%s <%s@%s>", user, user, hostname)
	}

	// Set default package name if not provided
	if flags.PackageName == "" {
		if len(installCommand) > 0 {
			// Use the first word of the install command as package name
			flags.PackageName = filepath.Base(installCommand[0])
		} else {
			// Use current directory name as package name
			cwd, err := os.Getwd()
			if err == nil {
				flags.PackageName = filepath.Base(cwd)
			} else {
				flags.PackageName = "unnamed-package"
			}
		}
		// Clean up the package name (remove invalid characters)
		flags.PackageName = sanitizePackageName(flags.PackageName)
	}

	// Handle exclusion file if provided
	if flags.ExcludeFile != "" {
		excludePatterns, err := readExcludeFile(flags.ExcludeFile)
		if err != nil {
			return fmt.Errorf("failed to read exclude file: %w", err)
		}
		flags.Exclude = append(flags.Exclude, excludePatterns...)
	}

	// Convert Checkinstall flags to go-pkginstall build options
	buildOpts := flags.ToBuilderOptions()

	// Print summary in debug mode
	if flags.Debug {
		fmt.Println("Checkinstall compatibility mode:")
		fmt.Printf("  Package name: %s\n", flags.PackageName)
		fmt.Printf("  Version: %s\n", flags.Version)
		fmt.Printf("  Maintainer: %s\n", flags.Maintainer)
		if len(installCommand) > 0 {
			fmt.Printf("  Install command: %s\n", strings.Join(installCommand, " "))
		}
	}

	// Run the install command if provided
	if len(installCommand) > 0 {
		if flags.Debug {
			fmt.Printf("Executing: %s\n", strings.Join(installCommand, " "))
		}

		// Run the specified install command
		if err := runInstallCommand(installCommand, flags.Debug); err != nil {
			return fmt.Errorf("installation command failed: %w", err)
		}
	}

	// Create a builder and build the package
	builder, err := debian.NewBuilder(
		debian.NewPackage(
			buildOpts.PackageName,
			buildOpts.Version,
			buildOpts.Architecture,
			buildOpts.Maintainer,
			buildOpts.Description,
			buildOpts.Section,
			"optional",
			buildOpts.Depends,
		),
		buildOpts.SourceDir,
		buildOpts.OutputDir,
	)

	if err != nil {
		return fmt.Errorf("failed to create package builder: %w", err)
	}

	// Configure builder with options
	builder.PreservePerms = buildOpts.PreservePerms
	builder.Verbose = buildOpts.Verbose
	for _, exclude := range buildOpts.ExcludeDirs {
		builder.AddExcludeDir(exclude)
	}

	if len(buildOpts.Provides) > 0 {
		builder.SetProvides(buildOpts.Provides)
	}

	// Build the package
	outputPath, err := builder.Build()
	if err != nil {
		return fmt.Errorf("package build failed: %w", err)
	}

	fmt.Printf("Package created: %s\n", outputPath)

	return nil
}

// sanitizePackageName cleans a string to make it a valid Debian package name
func sanitizePackageName(name string) string {
	// Replace invalid characters with hyphens
	invalidChars := []string{" ", ".", ",", ":", ";", "!", "?", "(", ")", "[", "]", "{", "}", "<", ">", "@", "#", "$", "%", "^", "&", "*", "+", "=", "|", "\\", "/"}
	result := name

	for _, char := range invalidChars {
		result = strings.ReplaceAll(result, char, "-")
	}

	// Convert to lowercase
	result = strings.ToLower(result)

	// Ensure it starts with a letter or number
	if len(result) > 0 && !isAlphanumeric(rune(result[0])) {
		result = "pkg-" + result
	}

	return result
}

// isAlphanumeric checks if a character is a letter or number
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// readExcludeFile reads a file containing patterns to exclude
func readExcludeFile(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var patterns []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	return patterns, nil
}

// runInstallCommand executes the installation command
func runInstallCommand(args []string, debug bool) error {
	if len(args) == 0 {
		return fmt.Errorf("no installation command provided")
	}

	// Create a command with the provided arguments
	command := args[0]
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	// Start the command
	cmd := execCommand(command, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the command
	if debug {
		fmt.Printf("Executing command: %s %s\n", command, strings.Join(cmdArgs, " "))
	}

	return cmd.Run()
}

// execCommand is a wrapper around exec.Command for testing
var execCommand = func(command string, args ...string) *ExecCmd {
	return &ExecCmd{
		Path: command,
		Args: append([]string{command}, args...),
	}
}

// ExecCmd is a simple interface around exec.Cmd for testing
type ExecCmd struct {
	Path   string
	Args   []string
	Stdin  interface{}
	Stdout interface{}
	Stderr interface{}
}

// Run executes the command
func (c *ExecCmd) Run() error {
	// For now, return an error indicating external commands aren't supported
	// In a real implementation, this would use exec.Command
	return fmt.Errorf("external command execution not implemented")
}

// EnsureCompatibility checks if the environment is compatible with Checkinstall
func EnsureCompatibility() error {
	// Check for required tools
	requiredCommands := []string{"dpkg-deb"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command not found: %s", cmd)
		}
	}

	return nil
}
