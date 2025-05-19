package main

import (
	"log"
	"os"

	"github.com/go-i2p/go-pkginstall/pkg/compat"
	"github.com/go-i2p/go-pkginstall/pkg/debian"
	"github.com/go-i2p/go-pkginstall/pkg/symlink"
	"github.com/spf13/cobra"
)

func main() {
	// Initialize the root command
	var rootCmd = &cobra.Command{
		Use:   "pkginstall",
		Short: "A secure replacement for Checkinstall",
		Long:  `pkginstall is a command-line utility for creating Debian packages with enhanced security features.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Placeholder for command execution logic
			log.Println("Executing pkginstall...")
		},
	}

	/*	// Load configuration
		if cfg, err := config.LoadConfig(""); err != nil {
			log.Fatalf("Error loading configuration: %v", err)
		} else {
			if err := cfg.Validate(); err != nil {
				log.Fatalf("Invalid configuration: %v", err)
			}
			log.Printf("Loaded configuration: %+v", cfg)
		}*/

	// Register subcommands
	rootCmd.AddCommand(debian.NewBuildCommand())
	rootCmd.AddCommand(symlink.NewSymlinkCommand())
	rootCmd.AddCommand(compat.NewCheckinstallCommand())

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
		os.Exit(1)
	}
}
