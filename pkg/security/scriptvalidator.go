package security

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// ScriptSecurityLevel defines the level of security checking for maintainer scripts
type ScriptSecurityLevel int

const (
	// SecurityLevelLow performs basic validation only
	SecurityLevelLow ScriptSecurityLevel = iota
	// SecurityLevelMedium performs moderate validation
	SecurityLevelMedium
	// SecurityLevelHigh performs strict validation
	SecurityLevelHigh
)

// ScriptValidationResult contains the result of script validation
type ScriptValidationResult struct {
	Valid        bool
	Warnings     []string
	Errors       []string
	RiskLevel    int // 0-10 scale where 10 is highest risk
	DetailedInfo map[string]interface{}
}

// ScriptValidatorOption is a function that modifies a ScriptValidator
type ScriptValidatorOption func(*ScriptValidator)

// WithSecurityLevel sets the security level for script validation
func WithSecurityLevel(level ScriptSecurityLevel) ScriptValidatorOption {
	return func(sv *ScriptValidator) {
		sv.securityLevel = level
	}
}

// WithPathMapper provides a PathMapper for path validation in scripts
func WithPathMapper(pm *PathMapper) ScriptValidatorOption {
	return func(sv *ScriptValidator) {
		sv.pathMapper = pm
	}
}

// WithAdditionalDangerousPatterns adds custom dangerous patterns to check
func WithAdditionalDangerousPatterns(patterns []string) ScriptValidatorOption {
	return func(sv *ScriptValidator) {
		sv.dangerousPatterns = append(sv.dangerousPatterns, patterns...)
	}
}

// WithScriptVerbose enables verbose logging for script validation
func WithScriptVerbose(verbose bool) ScriptValidatorOption {
	return func(sv *ScriptValidator) {
		sv.verbose = verbose
	}
}

// ScriptValidator provides validation for maintainer scripts
type ScriptValidator struct {
	securityLevel     ScriptSecurityLevel
	pathMapper        *PathMapper
	dangerousPatterns []string
	dangerousCommands map[string]int // Command -> risk level
	protectedPaths    []string
	allowedCommands   map[string]bool
	shellInterpreters []string
	verbose           bool
	logFunc           func(format string, args ...interface{})
}

// NewScriptValidator creates a new validator for maintainer scripts
func NewScriptValidator(opts ...ScriptValidatorOption) *ScriptValidator {
	sv := &ScriptValidator{
		securityLevel: SecurityLevelMedium,
		dangerousPatterns: []string{
			`rm\s+(-[rf]+\s+)?/`,                // rm with root paths
			`chmod\s+([0-7]+\s+)?/`,             // chmod of root paths
			`chown\s+([^/]+\s+)?/`,              // chown of root paths
			`wget\s+.+\s+\|\s+([ba])?sh`,        // piping wget to shell
			`curl\s+.+\s+\|\s+([ba])?sh`,        // piping curl to shell
			`sudo`,                              // sudo usage
			`su\s+(-[a-z]+\s+)?root`,            // su to root
			`eval\s+["']`,                       // eval usage
			`exec\s+[0-9]+`,                     // exec usage with file descriptors
			`set(uid|gid)`,                      // setuid/setgid mentions
			`>\s*/etc/`,                         // writing to /etc
			`>>\s*/etc/`,                        // appending to /etc
			`apt(-get)?\s+(install|remove)`,     // package installation
			`dpkg\s+(-i|--install)`,             // dpkg installation
			`update-alternatives`,               // changing system alternatives
			`/etc/init.d/`,                      // init script manipulation
			`systemctl\s+(enable|disable|mask)`, // systemd service manipulation
		},
		dangerousCommands: map[string]int{
			"rm":          7,
			"chmod":       6,
			"chown":       6,
			"wget":        5,
			"curl":        5,
			"dd":          8,
			"mkfs":        9,
			"mount":       7,
			"umount":      5,
			"apt":         6,
			"apt-get":     6,
			"dpkg":        5,
			"sudo":        9,
			"su":          9,
			"init":        10,
			"systemctl":   6,
			"service":     6,
			"useradd":     7,
			"usermod":     7,
			"groupadd":    6,
			"sysctl":      8,
			"iptables":    7,
			"update-rc.d": 6,
		},
		protectedPaths: []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/sbin",
			"/lib",
			"/lib64",
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/boot",
			"/dev",
			"/proc",
			"/sys",
			"/var/run",
			"/var/lock",
		},
		allowedCommands: map[string]bool{
			"echo":   true,
			"touch":  true,
			"mkdir":  true,
			"ln":     true,
			"cp":     true,
			"mv":     true,
			"sleep":  true,
			"cat":    true,
			"printf": true,
			"test":   true,
			"[":      true,
		},
		shellInterpreters: []string{
			"#!/bin/sh",
			"#!/bin/bash",
			"#!/usr/bin/env sh",
			"#!/usr/bin/env bash",
		},
		verbose: false,
		logFunc: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(sv)
	}

	return sv
}

// log outputs messages when verbose mode is enabled
func (sv *ScriptValidator) log(format string, args ...interface{}) {
	if sv.verbose {
		sv.logFunc(format, args...)
	}
}

// ValidateScript checks if a maintainer script is safe and complies with security policies
func (sv *ScriptValidator) ValidateScript(scriptName, content string) (*ScriptValidationResult, error) {
	result := &ScriptValidationResult{
		Valid:        true,
		Warnings:     []string{},
		Errors:       []string{},
		RiskLevel:    0,
		DetailedInfo: make(map[string]interface{}),
	}

	// Check if content is empty
	if strings.TrimSpace(content) == "" {
		result.Warnings = append(result.Warnings, "Script content is empty")
		return result, nil
	}

	// Check for proper shebang
	hasValidShebang := false
	for _, interpreter := range sv.shellInterpreters {
		if strings.HasPrefix(content, interpreter) {
			hasValidShebang = true
			break
		}
	}

	if !hasValidShebang {
		result.Warnings = append(result.Warnings, "Script does not start with a valid shell interpreter line (shebang)")
	}

	// Scan script line by line
	lineNumber := 0
	pathModifications := []string{}
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Skip empty lines and comments
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check for dangerous patterns
		for _, pattern := range sv.dangerousPatterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(line) {
				message := fmt.Sprintf("Line %d: Potentially dangerous pattern: %s", lineNumber, pattern)
				result.Warnings = append(result.Warnings, message)
				result.RiskLevel += 2
				sv.log(message)
			}
		}

		// Check for dangerous commands with path operations
		for cmd, riskLevel := range sv.dangerousCommands {
			re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, cmd))
			if re.MatchString(line) {
				message := fmt.Sprintf("Line %d: Potentially risky command: %s", lineNumber, cmd)
				result.Warnings = append(result.Warnings, message)
				result.RiskLevel += riskLevel / 3 // Scale down the risk
				sv.log(message)

				// Further analyze if the command operates on system paths
				for _, path := range sv.protectedPaths {
					if strings.Contains(line, path) {
						message := fmt.Sprintf("Line %d: Command operates on protected path: %s", lineNumber, path)
						result.Errors = append(result.Errors, message)
						result.RiskLevel += riskLevel / 2
						sv.log(message)

						// Track paths being modified
						pathModifications = append(pathModifications, path)
					}
				}
			}
		}

		// Extract paths from the line and validate them
		if sv.pathMapper != nil {
			paths := extractPaths(line)
			for _, path := range paths {
				// Skip variables and dynamic paths
				if strings.Contains(path, "$") || strings.Contains(path, "`") {
					continue
				}

				_, needsSymlink, err := sv.pathMapper.TransformPath(path)
				if err != nil {
					// Path couldn't be transformed
					message := fmt.Sprintf("Line %d: Path cannot be transformed: %s", lineNumber, path)
					result.Warnings = append(result.Warnings, message)
					sv.log(message)
				} else if needsSymlink {
					// Path would need a symlink - this is potentially risky
					message := fmt.Sprintf("Line %d: Path would require symlink: %s", lineNumber, path)
					result.Warnings = append(result.Warnings, message)
					sv.log(message)
				}
			}
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning script: %w", err)
	}

	// Add path modifications to detailed info
	result.DetailedInfo["path_modifications"] = pathModifications

	// Determine validation result based on security level
	switch sv.securityLevel {
	case SecurityLevelLow:
		// Only fail on critical errors
		if len(result.Errors) > 3 || result.RiskLevel > 8 {
			result.Valid = false
		}
	case SecurityLevelMedium:
		// Fail on significant errors or high risk
		if len(result.Errors) > 0 || result.RiskLevel > 6 {
			result.Valid = false
		}
	case SecurityLevelHigh:
		// Strict validation - fail on any errors or warnings
		if len(result.Errors) > 0 || len(result.Warnings) > 3 || result.RiskLevel > 4 {
			result.Valid = false
		}
	}

	return result, nil
}

// extractPaths extracts file paths from a command line
func extractPaths(line string) []string {
	var paths []string

	// Path extraction regex
	re := regexp.MustCompile(`(?:^|\s+)(/[^\s;|><"']+)`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) > 1 {
			paths = append(paths, match[1])
		}
	}

	return paths
}

// IsScriptAllowed determines if a script should be allowed based on validation results
func (sv *ScriptValidator) IsScriptAllowed(result *ScriptValidationResult) bool {
	return result.Valid
}

// GetRiskAssessment provides a human-readable assessment of the script risk
func (sv *ScriptValidator) GetRiskAssessment(result *ScriptValidationResult) string {
	var riskLevel string

	switch {
	case result.RiskLevel < 3:
		riskLevel = "Low"
	case result.RiskLevel < 7:
		riskLevel = "Medium"
	default:
		riskLevel = "High"
	}

	return fmt.Sprintf("Risk Assessment: %s (Score: %d/10)\n"+
		"Warnings: %d, Errors: %d\n"+
		"Valid: %v",
		riskLevel, result.RiskLevel,
		len(result.Warnings), len(result.Errors),
		result.Valid)
}
