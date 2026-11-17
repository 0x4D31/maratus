package extract

import (
	"fmt"
	"strings"
)

const (
	maxTextTrackedVariables             = 4096
	maxTextTrackedRequestVariables      = 1024
	maxTextVariableNameBytes            = 256
	maxTextVariableValueBytes           = 16 << 10
	maxTextVariableValueTotalBytes      = 4 << 20
	maxTextRequestDestinationsPerVar    = 32
	maxTextRequestEvidencePerVar        = 64
	maxTextRequestDestinationBytes      = 16 << 10
	maxTextRequestValueTotalBytes       = 1 << 20
	maxTextVariableSubstitutionsPerLine = 256
	maxTextVariableExpandedLineBytes    = 1 << 20
	maxTextVariableExpansionWorkBytes   = 32 << 20
	maxTextStringExpressionParts        = 512
	maxTextStringExpressionDepth        = 32
	maxTextStringExpressionArguments    = 256
)

type shellVariableKey struct{ scope, name string }
type textRequestKey struct{ scope, name string }

type textVariableState struct {
	shellOrigins     map[shellVariableKey]string
	shellDirectories map[string]shellDirectoryContext
	usedShellOrigins []string
	globals          map[string]string
	locals           map[string]map[string]string
	requestEvidence  map[textRequestKey][]string
	requestGlobal    map[string][]string
	requestLocals    map[string]map[string][]string
	unknownGlobal    map[string]bool
	unknownLocals    map[string]map[string]bool

	bindings        int
	valueBytes      int64
	requestBindings int
	requestBytes    int64
	expansionWork   int64
	limited         bool
	limitDetail     string
	omittedDetail   string
}

func newTextVariableState() *textVariableState {
	return &textVariableState{
		globals:         make(map[string]string),
		shellOrigins:    make(map[shellVariableKey]string),
		locals:          make(map[string]map[string]string),
		requestGlobal:   make(map[string][]string),
		requestEvidence: make(map[textRequestKey][]string),
		requestLocals:   make(map[string]map[string][]string),
		unknownGlobal:   make(map[string]bool),
		unknownLocals:   make(map[string]map[string]bool),
	}
}

type textVariableView struct {
	scope        string
	localOnly    bool
	state        *textVariableState
	local        map[string]string
	unknownLocal map[string]bool
}

type textRequestVariableView struct {
	state *textVariableState
	scope string
	local map[string][]string
}

func (s *textVariableState) variables(scope string) textVariableView {
	return textVariableView{scope: scope, state: s, local: s.locals[scope], unknownLocal: s.unknownLocals[scope]}
}

func (s *textVariableState) requestVariables(scope string) textRequestVariableView {
	return textRequestVariableView{state: s, scope: scope, local: s.requestLocals[scope]}
}

func (s *textVariableState) setVariable(scope, name, value string) bool {
	if s.limited {
		return false
	}
	if len(name) > maxTextVariableNameBytes {
		s.markLimited(fmt.Sprintf("variable name exceeded %d bytes", maxTextVariableNameBytes))
		return false
	}
	if len(value) > maxTextVariableValueBytes {
		s.markOmitted(fmt.Sprintf("variable value exceeded %d bytes", maxTextVariableValueBytes))
		// Do not let a previously retained value survive an oversized
		// reassignment. The binding becomes unknown, while analysis can safely
		// continue with later independent lines.
		s.invalidateVariable(scope, name)
		return false
	}
	target := s.globals
	unknown := s.unknownGlobal
	if scope != "" {
		target = s.locals[scope]
		if target == nil {
			target = make(map[string]string)
			s.locals[scope] = target
		}
		unknown = s.unknownLocals[scope]
		if unknown == nil {
			unknown = make(map[string]bool)
			s.unknownLocals[scope] = unknown
		}
	}
	old, exists := target[name]
	exists = exists || unknown[name]
	if !exists && s.bindings >= maxTextTrackedVariables {
		s.markLimited(fmt.Sprintf("tracked variable limit %d reached", maxTextTrackedVariables))
		return false
	}
	newBytes := s.valueBytes - int64(len(old)) + int64(len(value))
	if newBytes > maxTextVariableValueTotalBytes {
		s.markLimited(fmt.Sprintf("retained variable value limit %d bytes reached", maxTextVariableValueTotalBytes))
		return false
	}
	if !exists {
		s.bindings++
	}
	target[name] = value
	delete(unknown, name)
	s.valueBytes = newBytes
	return true
}

func (s *textVariableState) invalidateVariable(scope, name string) bool {
	delete(s.shellOrigins, shellVariableKey{scope, name})
	if s.limited {
		return false
	}
	if len(name) > maxTextVariableNameBytes {
		s.markLimited(fmt.Sprintf("variable name exceeded %d bytes", maxTextVariableNameBytes))
		return false
	}
	target := s.globals
	unknown := s.unknownGlobal
	if scope != "" {
		target = s.locals[scope]
		if target == nil {
			target = make(map[string]string)
			s.locals[scope] = target
		}
		unknown = s.unknownLocals[scope]
		if unknown == nil {
			unknown = make(map[string]bool)
			s.unknownLocals[scope] = unknown
		}
	}
	old, known := target[name]
	exists := known || unknown[name]
	if !exists && s.bindings >= maxTextTrackedVariables {
		s.markLimited(fmt.Sprintf("tracked variable limit %d reached", maxTextTrackedVariables))
		return false
	}
	if !exists {
		s.bindings++
	}
	if known {
		s.valueBytes -= int64(len(old))
		delete(target, name)
	}
	unknown[name] = true
	return true
}

func (s *textVariableState) setRequestVariable(scope, name string, destinations []string, evidenceIDs ...string) bool {
	if s.limited {
		return false
	}
	if len(name) > maxTextVariableNameBytes {
		s.markLimited(fmt.Sprintf("request variable name exceeded %d bytes", maxTextVariableNameBytes))
		return false
	}
	if len(destinations) > maxTextRequestDestinationsPerVar {
		s.markLimited(fmt.Sprintf("request destination limit %d per variable reached", maxTextRequestDestinationsPerVar))
		return false
	}
	var destinationBytes int64
	for _, destination := range destinations {
		if len(destination) > maxTextRequestDestinationBytes {
			s.markLimited(fmt.Sprintf("request destination exceeded %d bytes", maxTextRequestDestinationBytes))
			return false
		}
		destinationBytes += int64(len(destination))
	}
	if len(evidenceIDs) > maxTextRequestEvidencePerVar {
		s.markOmitted(fmt.Sprintf("request proof exceeded %d evidence records", maxTextRequestEvidencePerVar))
		s.clearRequestVariable(scope, name)
		return false
	}
	target := s.requestGlobal
	if scope != "" {
		target = s.requestLocals[scope]
		if target == nil {
			target = make(map[string][]string)
			s.requestLocals[scope] = target
		}
	}
	old, exists := target[name]
	if !exists && s.requestBindings >= maxTextTrackedRequestVariables {
		s.markLimited(fmt.Sprintf("tracked request variable limit %d reached", maxTextTrackedRequestVariables))
		return false
	}
	oldBytes := int64(0)
	for _, destination := range old {
		oldBytes += int64(len(destination))
	}
	newBytes := s.requestBytes - oldBytes + destinationBytes
	if newBytes > maxTextRequestValueTotalBytes {
		s.markLimited(fmt.Sprintf("retained request destination limit %d bytes reached", maxTextRequestValueTotalBytes))
		return false
	}
	if !exists {
		s.requestBindings++
	}
	target[name] = append([]string(nil), destinations...)
	s.requestEvidence[textRequestKey{scope, name}] = mergeEvidenceIDs(evidenceIDs...)
	s.requestBytes = newBytes
	return true
}

func (s *textVariableState) clearRequestVariable(scope, name string) {
	delete(s.requestEvidence, textRequestKey{scope, name})
	target := s.requestGlobal
	if scope != "" {
		target = s.requestLocals[scope]
	}
	old, exists := target[name]
	if !exists {
		return
	}
	for _, destination := range old {
		s.requestBytes -= int64(len(destination))
	}
	s.requestBindings--
	delete(target, name)
}

func (s *textVariableState) chargeExpansionWork(amount int64) bool {
	if s.limited {
		return false
	}
	if amount < 0 || amount > maxTextVariableExpansionWorkBytes-s.expansionWork {
		s.markLimited(fmt.Sprintf("variable expansion work limit %d bytes reached", maxTextVariableExpansionWorkBytes))
		return false
	}
	s.expansionWork += amount
	return true
}

func (s *textVariableState) markLimited(detail string) {
	if s.limited {
		return
	}
	s.limited = true
	s.limitDetail = detail
}

func (s *textVariableState) markOmitted(detail string) {
	if s.omittedDetail == "" {
		s.omittedDetail = detail
	}
}

func (s *textVariableState) coverageDetail() string {
	if s.limitDetail == "" {
		return "text variable analysis limit reached; remaining lines were not analyzed"
	}
	return "text variable analysis partial: " + s.limitDetail + "; remaining lines were not analyzed"
}

func (s *textVariableState) omittedCoverageDetail() string {
	if s.omittedDetail == "" {
		return ""
	}
	return "text variable analysis partial: " + s.omittedDetail + "; affected variable semantics were not inferred"
}

func lookupTextVariable(values any, name string) (string, bool) {
	switch vars := values.(type) {
	case textVariableView:
		if vars.unknownLocal[name] {
			return "", false
		}
		if value, ok := vars.local[name]; ok {
			return value, true
		}
		if vars.localOnly {
			return "", false
		}
		if vars.state.unknownGlobal[name] {
			return "", false
		}
		value, ok := vars.state.globals[name]
		return value, ok
	case *textVariableView:
		if vars == nil {
			return "", false
		}
		return lookupTextVariable(*vars, name)
	case map[string]string:
		value, ok := vars[name]
		return value, ok
	default:
		return "", false
	}
}

func textVariableCount(values any) int {
	switch vars := values.(type) {
	case textVariableView:
		return len(vars.state.globals) + len(vars.local)
	case *textVariableView:
		if vars == nil {
			return 0
		}
		return textVariableCount(*vars)
	case map[string]string:
		return len(vars)
	default:
		return 0
	}
}

func textVariableBudget(values any) *textVariableState {
	switch vars := values.(type) {
	case textVariableView:
		return vars.state
	case *textVariableView:
		if vars != nil {
			return vars.state
		}
	}
	return nil
}

func lookupTextRequestVariable(values any, name string) ([]string, bool) {
	switch vars := values.(type) {
	case textRequestVariableView:
		if value, ok := vars.local[name]; ok {
			return value, true
		}
		if vars.scope != "" {
			return nil, false
		}
		value, ok := vars.state.requestGlobal[name]
		return value, ok
	case *textRequestVariableView:
		if vars == nil {
			return nil, false
		}
		return lookupTextRequestVariable(*vars, name)
	case map[string][]string:
		value, ok := vars[name]
		return value, ok
	default:
		return nil, false
	}
}

func lookupTextRequestEvidence(values any, name string) []string {
	if view, ok := values.(textRequestVariableView); ok && view.state != nil {
		return view.state.requestEvidence[textRequestKey{view.scope, name}]
	}
	return nil
}

func textRequestVariableCount(values any) int {
	switch vars := values.(type) {
	case textRequestVariableView:
		if vars.scope != "" {
			return len(vars.local)
		}
		return len(vars.state.requestGlobal) + len(vars.local)
	case *textRequestVariableView:
		if vars == nil {
			return 0
		}
		return textRequestVariableCount(*vars)
	case map[string][]string:
		return len(vars)
	default:
		return 0
	}
}

func expandTextSimpleVariables(language, line string, vars any) string {
	if line == "" || textVariableCount(vars) == 0 {
		return line
	}
	budget := textVariableBudget(vars)
	if budget != nil && !budget.chargeExpansionWork(int64(len(line))) {
		return line
	}
	replaceIdentifiers := language == "python" || language == "javascript" || language == "jxa" || language == "applescript"
	var out strings.Builder
	out.Grow(len(line))
	changed := false
	substitutions := 0
	var shellQuote byte
	appendReplacement := func(name, value string) bool {
		if language == "shell" {
			// Parameter expansion does not reparse the value as shell syntax.
			// Keep literal quote/operator bytes from manufacturing commands.
			if shellQuote == '"' {
				value = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "`", "\\`").Replace(value)
			} else if strings.ContainsAny(value, " \t\r\n\\\"'`;|&()<>*?[]{}~#$") {
				if budget != nil {
					budget.markOmitted("unquoted shell expansion requires unsupported field splitting or metacharacter handling")
				}
				return false
			} else if value != "" {
				// Expanded words never become reserved words or assignment
				// names during shell parsing. Retain that lexical boundary.
				value = "'" + value + "'"
			}
		}
		if budget != nil {
			if substitutions >= maxTextVariableSubstitutionsPerLine {
				budget.markLimited(fmt.Sprintf("variable substitution limit %d reached on one line", maxTextVariableSubstitutionsPerLine))
				return false
			}
			if !budget.chargeExpansionWork(int64(len(value))) {
				return false
			}
			if int64(out.Len()+len(value)) > maxTextVariableExpandedLineBytes {
				budget.markLimited(fmt.Sprintf("expanded line limit %d bytes reached", maxTextVariableExpandedLineBytes))
				return false
			}
		}
		if language == "shell" {
			if view, ok := vars.(textVariableView); ok {
				view.retainShellOrigin(name)
			}
		}
		out.WriteString(value)
		substitutions++
		changed = true
		return true
	}
	for i := 0; i < len(line); {
		if language == "shell" {
			if line[i] == '\\' && shellQuote != '\'' && i+1 < len(line) {
				out.WriteString(line[i : i+2])
				i += 2
				continue
			}
			if shellQuote == '\'' {
				if line[i] == '\'' {
					shellQuote = 0
				}
				out.WriteByte(line[i])
				i++
				continue
			}
			if line[i] == '"' || line[i] == '\'' && shellQuote == 0 {
				if shellQuote == line[i] {
					shellQuote = 0
				} else {
					shellQuote = line[i]
				}
				out.WriteByte(line[i])
				i++
				continue
			}
		}
		if line[i] == '$' {
			if i+2 < len(line) && line[i+1] == '{' {
				end := i + 2
				for end < len(line) && isIdentifierByte(line[end]) {
					end++
				}
				if end > i+2 && end < len(line) && line[end] == '}' {
					if value, ok := lookupTextVariable(vars, line[i+2:end]); ok {
						if !appendReplacement(line[i+2:end], value) {
							return line
						}
						i = end + 1
						continue
					}
				}
			} else if i+1 < len(line) && identifierStartByte(line[i+1]) {
				end := i + 2
				for end < len(line) && isIdentifierByte(line[end]) {
					end++
				}
				if value, ok := lookupTextVariable(vars, line[i+1:end]); ok {
					if !appendReplacement(line[i+1:end], value) {
						return line
					}
					i = end
					continue
				}
			}
		}
		if replaceIdentifiers && identifierStartByte(line[i]) {
			end := i + 1
			for end < len(line) && isIdentifierByte(line[end]) {
				end++
			}
			if value, ok := lookupTextVariable(vars, line[i:end]); ok {
				if !appendReplacement(line[i:end], value) {
					return line
				}
				i = end
				continue
			}
			out.WriteString(line[i:end])
			i = end
			continue
		}
		out.WriteByte(line[i])
		i++
		if budget != nil && changed && out.Len() > maxTextVariableExpandedLineBytes {
			budget.markLimited(fmt.Sprintf("expanded line limit %d bytes reached", maxTextVariableExpandedLineBytes))
			return line
		}
	}
	if !changed {
		return line
	}
	return out.String()
}

func expandTextFormatPlaceholders(value string, vars any) string {
	if value == "" || textVariableCount(vars) == 0 || !strings.Contains(value, "{") {
		return value
	}
	budget := textVariableBudget(vars)
	if budget != nil && !budget.chargeExpansionWork(int64(len(value))) {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	changed := false
	substitutions := 0
	for i := 0; i < len(value); {
		if value[i] == '{' && i+2 < len(value) && identifierStartByte(value[i+1]) {
			end := i + 2
			for end < len(value) && isIdentifierByte(value[end]) {
				end++
			}
			if end < len(value) && value[end] == '}' {
				if replacement, ok := lookupTextVariable(vars, value[i+1:end]); ok {
					if budget != nil {
						if substitutions >= maxTextVariableSubstitutionsPerLine {
							budget.markLimited(fmt.Sprintf("format substitution limit %d reached on one value", maxTextVariableSubstitutionsPerLine))
							return value
						}
						if !budget.chargeExpansionWork(int64(len(replacement))) {
							return value
						}
						if out.Len()+len(replacement) > maxTextVariableExpandedLineBytes {
							budget.markLimited(fmt.Sprintf("expanded value limit %d bytes reached", maxTextVariableExpandedLineBytes))
							return value
						}
					}
					out.WriteString(replacement)
					substitutions++
					changed = true
					i = end + 1
					continue
				}
			}
		}
		out.WriteByte(value[i])
		i++
		if budget != nil && changed && out.Len() > maxTextVariableExpandedLineBytes {
			budget.markLimited(fmt.Sprintf("expanded value limit %d bytes reached", maxTextVariableExpandedLineBytes))
			return value
		}
	}
	if !changed {
		return value
	}
	return out.String()
}

func identifierStartByte(ch byte) bool {
	return ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func (view textVariableView) retainShellOrigin(name string) {
	scope := ""
	if _, local := view.local[name]; local {
		scope = view.scope
	}
	id := view.state.shellOrigins[shellVariableKey{scope, name}]
	if id == "" {
		return
	}
	for _, old := range view.state.usedShellOrigins {
		if old == id {
			return
		}
	}
	view.state.usedShellOrigins = append(view.state.usedShellOrigins, id)
}
