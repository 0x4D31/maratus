package extract

import (
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

type shellDirectoryContext struct {
	working int
	home    int
}

func (state *textVariableState) directoryContext(graph *behavior.Graph, scope string) shellDirectoryContext {
	if state.shellDirectories == nil {
		state.shellDirectories = map[string]shellDirectoryContext{}
	}
	current, exists := state.shellDirectories[scope]
	if !exists && len(state.shellDirectories) >= maxTextTrackedVariables {
		state.markOmitted("shell working-directory context limit reached; relative resource correlation remains unresolved")
		return shellDirectoryContext{}
	}
	if current.working == 0 {
		current.working = graph.NewDirectoryContext()
	}
	if current.home == 0 {
		current.home = graph.NewDirectoryContext()
	}
	state.shellDirectories[scope] = current
	return current
}

func (state *textVariableState) invalidateDirectoryContext(scope string, working, home bool) {
	if state.shellDirectories == nil {
		return
	}
	current, exists := state.shellDirectories[scope]
	if !exists {
		return
	}
	if working {
		current.working = 0
	}
	if home {
		current.home = 0
	}
	state.shellDirectories[scope] = current
}

// A tilde prefix is expanded only when the whole prefix is unquoted. This
// deliberately does not resolve HOME, passwd entries or the analyst's machine.
func shellWordExpandsHome(raw string) bool {
	if !strings.HasPrefix(raw, "~") {
		return false
	}
	for _, char := range raw {
		if char == '/' {
			return true
		}
		if char == '\\' || char == '\'' || char == '"' {
			return false
		}
	}
	return true
}

func shellPathInterpretations(fields, raw []string) map[string]behavior.FilePathInterpretation {
	if len(fields) != len(raw) {
		return nil
	}
	result := make(map[string]behavior.FilePathInterpretation, len(fields))
	for i, field := range fields {
		mode := behavior.FilePathLiteral
		if shellWordExpandsHome(raw[i]) {
			mode = behavior.FilePathUnknown
			// Named users and shell-specific ~+/~- forms require different
			// host state. Only the current HOME prefix is modeled here.
			if raw[i] == "~" || strings.HasPrefix(raw[i], "~/") {
				mode = behavior.FilePathHomeRelative
			}
		}
		if prior, exists := result[field]; exists && prior != mode {
			mode = behavior.FilePathUnknown
		}
		result[field] = mode
	}
	return result
}

func annotateShellPathContexts(graph *behavior.Graph, start int, context shellDirectoryContext, fields, raw []string) {
	modes := shellPathInterpretations(fields, raw)
	for i := start; i < len(graph.Operations); i++ {
		operation := &graph.Operations[i]
		if operation.WorkingDirectoryContext != 0 || operation.HomeDirectoryContext != 0 {
			// An inner shell has its own state. Do not replace it with the
			// caller's state when annotating the enclosing statement range.
			continue
		}
		operation.WorkingDirectoryContext = context.working
		operation.HomeDirectoryContext = context.home
		for j := range operation.ResourceBindings {
			binding := &operation.ResourceBindings[j]
			if binding.Resource.Kind == behavior.ResourceFile {
				binding.FilePathInterpretation = modes[binding.Resource.Value]
			}
		}
	}
}

func shellDirectoryEffects(fields []string) (working, home bool) {
	normalized, err := normalizeCommandFieldsChecked(fields)
	if err != nil || len(normalized) == 0 {
		return true, true
	}
	tool := normalized[0]
	switch tool {
	case "cd", "pushd", "popd":
		return true, false
	case "source", ".", "eval", "builtin":
		return true, true
	case "export", "readonly", "typeset", "declare", "local", "unset":
		for _, field := range normalized[1:] {
			if field == "HOME" || strings.HasPrefix(field, "HOME=") {
				return false, true
			}
		}
		return false, false
	}
	if strings.Contains(tool, "/") || sharedShellCommandTool(tool) {
		return false, false
	}
	// Closed command profiles cannot change their parent's directory or HOME.
	// An unknown bare name may instead name a shell function with those effects.
	switch filepath.Base(tool) {
	case "curl", "wget", "cp", "mv", "chmod", "sh", "bash", "zsh", "python", "python3", "node", "deno", "osascript", "launchctl", "security", "dscl", "installer", "xattr", "spctl", "screencapture", "pbpaste", "open", "zip", "unzip", "tar", "ditto", "echo", "printf", "cat", "tee", "true", "false", ":", "pwd", "test", "[":
		return false, false
	default:
		return true, true
	}
}

// Directory-changing commands need state analysis even when they emit no
// operation. Keep this gate bounded like the semantic command visitor; syntax
// failures enter the analyzer so it can invalidate context conservatively.
func shellDirectoryStateRelevant(line string) bool {
	commands := 0
	relevant := false
	visitCommands(line, func(command string) bool {
		commands++
		if commands > maxShellStatementsPerLine {
			relevant = true
			return false
		}
		fields, err := shellCommandFields(command)
		if err != nil {
			relevant = true
			return false
		}
		if len(fields) == 0 {
			return true
		}
		// A closing brace is a source boundary, not a command invocation.
		if len(fields) == 1 && fields[0] == "}" {
			return true
		}
		working, home := shellDirectoryEffects(fields)
		if working || home {
			relevant = true
			return false
		}
		return true
	})
	return relevant
}
