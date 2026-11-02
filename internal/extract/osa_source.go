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
func extractAppleScriptSource(graph *behavior.Graph, content artifact.Content, lines []string, asciiOperandsOnly bool) {
	var stack []osaSourceBlock
	current := content
	budget := newTextDerivedBudget()
	bindings := newOSAStringBindings(lines)
	bindings.asciiOnly = asciiOperandsOnly
	defer bindings.coverage(graph, content)
	if asciiOperandsOnly {
		addPartialCoverageOnce(graph, content.NodeID, "osa-source-encoding", "AppleScript text encoding is unresolved; only ASCII string operands are resolved and encoding-dependent values remain unknown")
	}
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
		lower := osaHeaderText(line)
		for _, active := range stack {
			graph.Scopes[active.scopeIndex].LineEnd = n + 1
		}
		if lower == "end" || strings.HasPrefix(lower, "end ") {
			bindings.clear()
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
			bindings.clear()
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
			header := strings.TrimSpace(line[2:]) // both "on" and "to" are two bytes
			name = functionName(header)
			if name == "" || (name[0] >= '0' && name[0] <= '9') || (len(header) > len(name) && !strings.ContainsRune(" \t(", rune(header[len(name)]))) {
				addPartialCoverageOnce(graph, content.NodeID, "applescript-statement-analysis", "a handler name was outside the bounded ASCII identifier grammar; remaining statement contexts were not inferred")
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
			bindings.clear()
			if len(stack) >= maxOSASourceDepth {
				addPartialCoverageOnce(graph, content.NodeID, "applescript-statement-analysis", "AppleScript context depth budget exceeded; remaining statement semantics were not inferred")
				break
			}
			child := contentWithExecutionContext(current, unknownExecutionContext())
			child.Function = ""
			scopeKind := "block"
			if kind == "handler" {
				scopeKind, child.Function = "function", name
				if content.Function != "" && len(content.SupportingEvidenceIDs) > 0 {
					opaque = true
					addPartialCoverageOnce(graph, content.NodeID, "osa-derived-handler-context", "a nested handler in scoped derived OSA source cannot inherit another function's causal evidence; its body remained observational")
				}
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
		dialog := appleScriptHiddenAnswerDialog(statement)
		closedRequest := false
		if shell || location || dialog {
			evidence := addLineEvidence(graph, current, n+1, "applescript-statement", raw)
			if evidence == "" {
				graph.MarkWorkOmitted()
				break
			}
			closedRequest = analyzeAppleScriptLineBudget(graph, current, line, n+1, executionContextForContent(current), evidence, budget.line(), bindings)
		}
		if name, expression, assigned := osaStringAssignment(line); assigned {
			bindings.retain(graph, current, name, expression, raw, n+1, closedRequest)
		} else if (!shell && !location) || dialog {
			bindings.clear()
		}
		if prefix := (osaLiteralExpression{source: line}); prefix.word("return") {
			current = contentWithExecutionContext(current, unknownExecutionContext())
		}
	}
	addTextDerivedCoverageOnce(graph, content, budget)
}

// Normalization is confined to the header-match view. Operands and source
// evidence always use the original line.
func osaHeaderText(line string) string {
	var out strings.Builder
	out.Grow(len(line))
	space := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ' ' || c == '\t' {
			space = out.Len() > 0
			continue
		}
		if space {
			out.WriteByte(' ')
			space = false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out.WriteByte(c)
	}
	return out.String()
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
