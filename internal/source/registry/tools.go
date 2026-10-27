package registry

import (
	"path/filepath"
	"strings"

	"toktrail-collector/internal/source/adapter"
)

// ToolSpec defines a supported developer tool and its default local source configuration.
type ToolSpec struct {
	Tool           string   // Canonical tool name, e.g. "Codex", "Claude Code"
	Aliases        []string // Case-insensitive matching aliases
	Source         string   // Collector adapter source identifier
	DefaultSubpath []string // Path segments relative to user home directory
}

var supportedTools = []ToolSpec{
	{
		Tool:           "Codex",
		Aliases:        []string{"codex"},
		Source:         adapter.CodexJSONLSource,
		DefaultSubpath: []string{".codex", "sessions"},
	},
	{
		Tool:           "Claude Code",
		Aliases:        []string{"claude code", "claude-code", "claudecode"},
		Source:         adapter.ClaudeCodeJSONLSource,
		DefaultSubpath: []string{".claude", "projects"},
	},
	{
		Tool:           "DeepSeek Harness",
		Aliases:        []string{"deepseek harness", "deepseek-harness", "deepseekharness", "dsh"},
		Source:         adapter.DeepSeekHarnessSource,
		DefaultSubpath: []string{".dsh", "sessions"},
	},
}

// SupportedTools returns the registered tool specifications.
func SupportedTools() []ToolSpec {
	out := make([]ToolSpec, len(supportedTools))
	copy(out, supportedTools)
	return out
}

// LookupTool finds a registered tool definition by name.
// Matching is case-insensitive, trimmed, and normalizes hyphens/spaces.
func LookupTool(name string) (ToolSpec, bool) {
	clean := strings.ToLower(strings.TrimSpace(name))
	if clean == "" {
		return ToolSpec{}, false
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(clean, "-", ""), " ", "")

	for _, spec := range supportedTools {
		if strings.ToLower(spec.Tool) == clean {
			return spec, true
		}
		for _, alias := range spec.Aliases {
			if strings.ToLower(alias) == clean {
				return spec, true
			}
		}
		compactSpec := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(spec.Tool), "-", ""), " ", "")
		if compactSpec == compact {
			return spec, true
		}
	}
	return ToolSpec{}, false
}

// ResolveDefaultInput returns the absolute default input directory path
// for this tool, anchored at homeDir.
func (t ToolSpec) ResolveDefaultInput(homeDir string) string {
	parts := append([]string{homeDir}, t.DefaultSubpath...)
	return filepath.Join(parts...)
}
