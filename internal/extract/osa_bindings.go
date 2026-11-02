package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxOSAStringBindings     = 128
	maxOSAStringBindingBytes = 256 << 10
	maxOSAStringProofs       = 32
)

type osaResolvedString struct {
	value       string
	evidenceIDs []string
}

type osaStringBindings struct {
	values    map[string]osaResolvedString
	seen      map[string]bool
	blocked   map[string]bool
	bytes     int
	work      int64
	disabled  bool
	limited   bool
	asciiOnly bool
}

func newOSAStringBindings(lines []string) *osaStringBindings {
	state := &osaStringBindings{values: map[string]osaResolvedString{}, seen: map[string]bool{}, blocked: map[string]bool{}}
	// Properties/globals can outlive a run and have different handler lookup
	// rules. This local-text profile never substitutes their initializers.
	for _, line := range lines {
		p := osaLiteralExpression{source: strings.TrimSpace(line)}
		property := p.word("property")
		if !property && !p.word("global") {
			continue
		}
		for {
			name := osaBindingIdentifier(&p)
			if name == "" {
				state.disabled = true
				break
			}
			state.blocked[name] = true
			if len(state.blocked) > maxOSAStringBindings {
				state.disabled = true
				return state
			}
			p.space()
			if property || p.pos == len(p.source) {
				break
			}
			if p.source[p.pos] != ',' {
				state.disabled = true
				break
			}
			p.pos++
		}
	}
	return state
}

func osaBindingIdentifier(p *osaLiteralExpression) string {
	p.space()
	start := p.pos
	for p.pos < len(p.source) && isIdentifierByte(p.source[p.pos]) {
		p.pos++
	}
	if p.pos == start || p.pos-start > maxTextVariableNameBytes || p.source[start] >= '0' && p.source[start] <= '9' {
		return ""
	}
	return strings.ToLower(p.source[start:p.pos])
}

func osaStringAssignment(line string) (string, string, bool) {
	p := osaLiteralExpression{source: line}
	if !p.word("set") {
		return "", "", false
	}
	name := osaBindingIdentifier(&p)
	if name == "" || !p.word("to") {
		return "", "", false
	}
	return name, strings.TrimSpace(line[p.pos:]), true
}

func (s *osaStringBindings) clear() {
	clear(s.values)
	s.bytes = 0
}

func (s *osaStringBindings) lookup(name string) (osaResolvedString, bool) {
	if s == nil || s.disabled || s.limited || s.blocked[name] {
		return osaResolvedString{}, false
	}
	value, ok := s.values[name]
	if !ok {
		return osaResolvedString{}, false
	}
	if int64(len(value.value)) > maxTextVariableExpansionWorkBytes-s.work {
		s.limited = true
		return osaResolvedString{}, false
	}
	s.work += int64(len(value.value))
	return value, true
}

func (s *osaStringBindings) retain(graph *behavior.Graph, content artifact.Content, name, expression, raw string, line int, closedRequest bool) {
	value, proofs, exact := resolveAppleScriptStringExpression(expression, s)
	if !exact {
		if closedRequest {
			// A closed Standard Additions request has an unknown return
			// value, but does not assign other run/handler-local text names.
			s.bytes -= len(s.values[name].value)
			delete(s.values, name)
			return
		}
		// An unsupported RHS may call code or use references. Do not keep
		// other local values across an unmodeled mutation context.
		s.clear()
		return
	}
	if s.disabled || s.limited || s.blocked[name] {
		delete(s.values, name)
		return
	}
	switch name {
	case "result", "it", "me", "my", "parent", "applescript", "true", "false", "missing", "quoted":
		return
	}
	key := content.ScopeID + "\x00" + name
	bytes := s.bytes - len(s.values[name].value) + len(value)
	if (!s.seen[key] && len(s.seen) >= maxOSAStringBindings) || bytes > maxOSAStringBindingBytes || len(proofs) >= maxOSAStringProofs {
		s.limited = true
		s.clear()
		return
	}
	evidence := addLineEvidence(graph, content, line, "applescript-string-binding", raw)
	if evidence == "" {
		graph.MarkWorkOmitted()
		s.clear()
		return
	}
	s.seen[key] = true
	s.values[name] = osaResolvedString{value: value, evidenceIDs: mergeEvidenceIDs(append(proofs, evidence)...)}
	s.bytes = bytes
}

func (s *osaStringBindings) coverage(graph *behavior.Graph, content artifact.Content) {
	if s.disabled || len(s.blocked) > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "applescript-string-bindings", "global/property identifiers or ambiguous declarations were excluded from local string resolution; persistent values and cross-handler lookup were not inferred")
	}
	if s.limited {
		addPartialCoverageOnce(graph, content.NodeID, "applescript-string-bindings", "local string binding count, value, provenance or expansion-work budget reached; further binding-dependent arguments remained unresolved")
	}
}
