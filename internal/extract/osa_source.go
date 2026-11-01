package extract

import (
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const maxOSASourceDepth = 64

type osaSourceBlock struct {
	kind       string
	name       string
	parent     artifact.Content
	content    artifact.Content
	opaque     bool
	scopeIndex int
}

// This is a bounded statement/context profile, not an AppleScript compiler.
// Handlers and branches retain separate scopes and unknown reachability. Tell,
// script-object and terminology contexts cannot establish this host's Standard
// Additions receiver and therefore remain observational.
func extractAppleScriptSource(graph *behavior.Graph, content artifact.Content, lines []string) {
	var stack []osaSourceBlock
	current := content
	budget := newTextDerivedBudget()
	addPartialCoverageOnce(graph, content.NodeID, "applescript-statement-analysis", "bounded direct command expressions are modeled; handler calls, block feasibility, application terminology and complete AppleScript syntax are not resolved")
	for n, raw := range lines {
		if graph.WorkLimitReached() || budget.exhausted {
			graph.MarkWorkOmitted()
			break
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		for _, active := range stack {
			graph.Scopes[active.scopeIndex].LineEnd = n + 1
		}
		if lower == "end" || strings.HasPrefix(lower, "end ") {
			if len(stack) == 0 {
				break
			}
			last := stack[len(stack)-1]
			closing := strings.TrimSpace(strings.TrimPrefix(lower, "end"))
			if closing != "" && closing != last.kind && closing != strings.ToLower(last.name) {
				break
			}
			current = last.parent
			stack = stack[:len(stack)-1]
			continue
		}
		// Alternate clauses use sibling scopes, preventing resource joins
		// between different branches of one source construct.
		if lower == "else" || strings.HasPrefix(lower, "else if ") || lower == "on error" || strings.HasPrefix(lower, "on error ") {
			if len(stack) == 0 {
				break
			}
			last := &stack[len(stack)-1]
			if (strings.HasPrefix(lower, "else") && last.kind != "if") || (strings.HasPrefix(lower, "on error") && last.kind != "try") {
				break
			}
			last.content.ScopeID = osaSourceScope(graph, last.parent, "branch", line, n+1)
			last.content.Function = ""
			if last.content.ScopeID == "" {
				break
			}
			last.scopeIndex = len(graph.Scopes) - 1
			current = last.content
			continue
		}
		kind, name, opaque := "", "", false
		switch {
		case strings.HasPrefix(lower, "on ") || strings.HasPrefix(lower, "to "):
			kind = "handler"
			name = functionName(strings.TrimSpace(line[strings.IndexByte(line, ' ')+1:]))
			if name == "" {
				return
			}
		case strings.HasPrefix(lower, "if ") && strings.HasSuffix(lower, " then"):
			kind = "if"
		case lower == "repeat" || strings.HasPrefix(lower, "repeat "):
			kind = "repeat"
		case lower == "try":
			kind = "try"
		case lower == "script" || strings.HasPrefix(lower, "script "):
			kind, opaque = "script", true
		case strings.HasPrefix(lower, "tell "):
			kind, opaque = "tell", true
		case strings.HasPrefix(lower, "using terms from "):
			kind, opaque = "using terms from", true
		}
		if kind != "" {
			if len(stack) >= maxOSASourceDepth {
				addPartialCoverageOnce(graph, content.NodeID, "applescript-statement-analysis", "AppleScript context depth budget exceeded; remaining statement semantics were not inferred")
				break
			}
			child := contentWithExecutionContext(current, unknownExecutionContext())
			child.Function = ""
			scopeKind := "block"
			if kind == "handler" {
				scopeKind, child.Function = "function", name
			}
			child.ScopeID = osaSourceScope(graph, current, scopeKind, name, n+1)
			if child.ScopeID == "" {
				break
			}
			if len(stack) > 0 && stack[len(stack)-1].opaque {
				opaque = true
			}
			stack = append(stack, osaSourceBlock{kind: kind, name: name, parent: current, content: child, opaque: opaque, scopeIndex: len(graph.Scopes) - 1})
			current = child
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].opaque {
			continue
		}
		statement := appleScriptCommandStatement(line)
		_, shell := appleScriptCommandArgument(statement, "do shell script")
		_, location := appleScriptCommandArgument(statement, "open location")
		if !shell && !location && !appleScriptHiddenAnswerDialog(statement) {
			continue
		}
		evidence := addLineEvidence(graph, current, n+1, "applescript-statement", raw)
		analyzeAppleScriptLineBudget(graph, current, line, n+1, executionContextForContent(current), evidence, budget.line())
	}
	addTextDerivedCoverageOnce(graph, content, budget)
}

func osaSourceScope(graph *behavior.Graph, parent artifact.Content, kind, name string, line int) string {
	function := ""
	if kind == "function" {
		function = name
	}
	if name == "" {
		name = fmt.Sprintf("%s@%d", kind, line)
	}
	return graph.AddScope(behavior.Scope{NodeID: parent.NodeID, ParentID: parent.ScopeID, Kind: kind, Name: name, Function: function, LineStart: line, LineEnd: line, SourceRole: parent.Role, Architecture: parent.Architecture})
}
