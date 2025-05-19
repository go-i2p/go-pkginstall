package debian

import (
	"fmt"
)

// Package represents a Debian package with its metadata and attributes.
type Package struct {
	Name         string
	Version      string
	Architecture string
	Maintainer   string
	Description  string
	Section      string
	Priority     string
	Depends      []string
}

// NewPackage creates a new Package instance with the provided metadata.
func NewPackage(name, version, architecture, maintainer, description, section, priority string, depends []string) *Package {
	return &Package{
		Name:         name,
		Version:      version,
		Architecture: architecture,
		Maintainer:   maintainer,
		Description:  description,
		Section:      section,
		Priority:     priority,
		Depends:      depends,
	}
}

// Validate checks if the package metadata is valid.
func (p *Package) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if p.Version == "" {
		return fmt.Errorf("package version cannot be empty")
	}
	// Additional validation rules can be added here
	return nil
}
