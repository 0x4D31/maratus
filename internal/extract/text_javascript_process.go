package extract

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	reJSImportChildProcess        = regexp.MustCompile(`^\s*import\s*\{([^{}\n]{1,1000})\}\s*from\s*["'](?:node:)?child_process["']\s*;?\s*$`)
	reJSRequireChildProcess       = regexp.MustCompile(`^\s*(?:const|let|var)\s*\{([^{}\n]{1,1000})\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*;?\s*$`)
	reJSImportChildProcessModule  = regexp.MustCompile(`^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s+from\s+["'](?:node:)?child_process["']\s*;?\s*$`)
	reJSRequireChildProcessModule = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*;?\s*$`)
)

const (
	maxJavaScriptProcessBindings       = 16
	maxJavaScriptProcessStatementBytes = 512 << 10
	javaScriptProcessModuleBinding     = "module"
)

// javaScriptProcessBindings is a closed source-order binding tracker, not a
// JavaScript evaluator. Only exact child_process declarations and calls are
// retained. Any other use of a retained name invalidates it before later calls
// can be promoted.
type javaScriptProcessBindings struct {
	scopes         map[string]map[string]string
	proofs         map[string]map[string][]javaScriptCommandProof
	prescan        javaScriptCommandPrescan
	command        javaScriptCommandState
	count          int
	limited        bool
	limitDetail    string
	prescanLimited bool
	hiddenBinding  bool
}

type javaScriptProcessCall struct {
	method string
	text   string
	offset int
	proofs []javaScriptCommandProof
}

type javaScriptProcessResolution struct {
	invocation     embeddedInvocation
	proofs         []javaScriptCommandProof
	candidate      bool
	incomplete     bool
	multiple       bool
	unmodeledOuter bool
}

func newJavaScriptProcessBindings(lines []string) javaScriptProcessBindings {
	prescan := prescanJavaScriptCommands(lines)
	return javaScriptProcessBindings{
		scopes:         map[string]map[string]string{},
		proofs:         map[string]map[string][]javaScriptCommandProof{},
		prescan:        prescan,
		command:        newJavaScriptCommandState(prescan),
		prescanLimited: prescan.limited,
		limitDetail:    prescan.limitDetail,
		hiddenBinding:  prescan.hiddenBinding,
	}
}

func (bindings *javaScriptProcessBindings) observeAndResolve(_ string, _ string, lineNo int) javaScriptProcessResolution {
	if bindings == nil || bindings.limited {
		return javaScriptProcessResolution{}
	}
	var result javaScriptProcessResolution
	for _, retained := range bindings.prescan.byLine[lineNo] {
		statement := strings.TrimSpace(retained.text)
		if statement == "" {
			continue
		}
		function := retained.scopeKey
		declared := bindings.observeDeclaration(statement, retained.evidenceText, function, lineNo, retained.bindingProofs)
		if len(bindings.prescan.processAll) > 0 || len(bindings.scopes[function]) > 0 {
			bindings.command.observe(statement, function, lineNo)
		}
		if !declared {
			bindings.invalidateUnsupportedUses(statement, function)
		}
		calls := bindings.boundCalls(statement, function)
		if len(calls) == 0 {
			if bindings.hasUnmodeledOuterCall(statement, function, lineNo) {
				result.unmodeledOuter = true
			}
			continue
		}
		if len(calls) > 1 || result.candidate {
			result.multiple = true
		}
		if result.candidate {
			continue
		}
		result.candidate = true
		call := calls[0]
		invocation, proofs, ok := bindings.command.resolveInvocation(call.method, call.text, function)
		if !ok {
			result.incomplete = true
			continue
		}
		result.invocation = invocation
		result.proofs = mergeJavaScriptCommandProofs(call.proofs, proofs)
	}
	return result
}

func (bindings *javaScriptProcessBindings) observeDeclaration(line, evidenceText, function string, lineNo int, extraProofs []javaScriptCommandProof) bool {
	declarations, recognized := javaScriptProcessDeclarations(line)
	if recognized && bindings.prescan.dynamicScopes[function] {
		bindings.hiddenBinding = true
		for name := range declarations {
			bindings.invalidate(function, name)
		}
		return true
	}
	if recognized &&
		javaScriptProcessDeclarationRequiresRuntime(line) &&
		!bindings.prescan.runtimeSafe[function] {
		bindings.hiddenBinding = true
		for name := range declarations {
			bindings.invalidate(function, name)
		}
		return true
	}
	for name, kind := range declarations {
		if bindings.prescan.hiddenUses[function][name] {
			bindings.hiddenBinding = true
			bindings.invalidate(function, name)
			continue
		}
		if kind == "" {
			bindings.invalidate(function, name)
			continue
		}
		proof := javaScriptCommandProof{
			scopeKey: function,
			line:     lineNo,
			kind:     "javascript-child-process-binding",
			value:    evidenceText,
		}
		bindings.add(function, name, kind, mergeJavaScriptCommandProofs(extraProofs, []javaScriptCommandProof{proof})...)
	}
	return recognized
}

func (bindings *javaScriptProcessBindings) add(function, name, kind string, bindingProofs ...javaScriptCommandProof) {
	if bindings == nil || bindings.limited || !javaScriptIdentifier(name) {
		return
	}
	scope := bindings.scopes[function]
	if scope == nil {
		scope = map[string]string{}
		bindings.scopes[function] = scope
	}
	if scope[name] != "" {
		bindings.invalidate(function, name)
		return
	}
	if bindings.count >= maxJavaScriptProcessBindings {
		bindings.markLimited(fmt.Sprintf("child_process binding limit %d reached; additional bindings and later calls were not correlated", maxJavaScriptProcessBindings))
		return
	}
	scope[name] = kind
	proofs := bindings.proofs[function]
	if proofs == nil {
		proofs = map[string][]javaScriptCommandProof{}
		bindings.proofs[function] = proofs
	}
	proofs[name] = mergeJavaScriptCommandProofs(nil, bindingProofs)
	bindings.count++
}

func (bindings *javaScriptProcessBindings) invalidateUnsupportedUses(line, function string) {
	if bindings == nil || line == "" {
		return
	}
	scope := bindings.scopes[function]
	names := make([]string, 0, len(scope))
	for name := range scope {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		positions := javaScriptIdentifierPositions(line, name)
		if len(positions) == 0 {
			continue
		}
		_, _, safe := javaScriptBoundProcessCall(line, name, scope[name])
		if !safe || len(positions) != 1 {
			bindings.invalidate(function, name)
		}
	}
}

func (bindings *javaScriptProcessBindings) invalidate(function, name string) {
	delete(bindings.scopes[function], name)
	delete(bindings.proofs[function], name)
}

func (bindings *javaScriptProcessBindings) markLimited(detail string) {
	if bindings == nil || bindings.limited {
		return
	}
	bindings.limited = true
	bindings.limitDetail = detail
}

func (bindings javaScriptProcessBindings) coverageDetail() string {
	if bindings.limitDetail != "" {
		return bindings.limitDetail
	}
	return fmt.Sprintf("child_process binding limit %d reached; additional bindings and later calls were not correlated", maxJavaScriptProcessBindings)
}

func javaScriptProcessDeclarations(line string) (map[string]string, bool) {
	declarations := map[string]string{}
	var declaration string
	for _, grammar := range []*regexp.Regexp{reJSImportChildProcess, reJSRequireChildProcess} {
		match := grammar.FindStringSubmatch(line)
		if len(match) == 2 {
			declaration = match[1]
			break
		}
	}
	if declaration != "" {
		for _, item := range strings.Split(declaration, ",") {
			method, name := javaScriptProcessBinding(item)
			if name != "" {
				declarations[name] = method
			}
		}
		return declarations, true
	}

	for _, grammar := range []*regexp.Regexp{reJSImportChildProcessModule, reJSRequireChildProcessModule} {
		match := grammar.FindStringSubmatch(line)
		if len(match) == 2 {
			declarations[match[1]] = javaScriptProcessModuleBinding
			return declarations, true
		}
	}
	return declarations, false
}

func javaScriptProcessBinding(item string) (method, name string) {
	item = strings.TrimSpace(item)
	if item == "" || len(item) > 128 {
		return "", ""
	}
	parts := strings.Fields(item)
	switch {
	case len(parts) == 1:
		method, name = parts[0], parts[0]
	case len(parts) == 3 && parts[1] == "as":
		method, name = parts[0], parts[2]
	case strings.Count(item, ":") == 1:
		pair := strings.SplitN(item, ":", 2)
		method, name = strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
	default:
		return "", ""
	}
	if !javaScriptIdentifier(name) {
		return "", ""
	}
	if normalized := normalizeJavaScriptProcessMethod(method); normalized != "" {
		return normalized, name
	}
	return "", name
}

func (bindings javaScriptProcessBindings) boundCalls(line, function string) []javaScriptProcessCall {
	if bindings.limited {
		return nil
	}
	scope := bindings.scopes[function]
	names := make([]string, 0, len(scope))
	for candidate := range scope {
		names = append(names, candidate)
	}
	sort.Strings(names)
	var calls []javaScriptProcessCall
	for _, candidate := range names {
		for _, candidateCall := range javaScriptBoundProcessCalls(line, candidate, scope[candidate]) {
			candidateCall.proofs = bindings.proofs[function][candidate]
			calls = append(calls, candidateCall)
		}
	}
	if function != "" {
		inheritedNames := bindings.prescan.stableProcessNames(function, bindings.command.currentLine)
		for _, candidate := range inheritedNames {
			for _, candidateCall := range javaScriptBoundProcessCalls(line, candidate, bindings.prescan.process[candidate].kind) {
				candidateCall.proofs = bindings.prescan.process[candidate].proofs
				calls = append(calls, candidateCall)
			}
		}
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].offset < calls[j].offset })
	if len(calls) > 2 {
		calls = calls[:2]
	}
	return calls
}

func (bindings javaScriptProcessBindings) hasUnmodeledOuterCall(line, function string, lineNo int) bool {
	if function == "" || bindings.limited {
		return false
	}
	return bindings.prescan.hasBlockedProcessCall(line, function, lineNo)
}

func javaScriptBoundProcessCall(line, identifier, binding string) (method, call string, ok bool) {
	calls := javaScriptBoundProcessCalls(line, identifier, binding)
	if len(calls) == 0 {
		return "", "", false
	}
	return calls[0].method, calls[0].text, true
}

func javaScriptBoundProcessCalls(line, identifier, binding string) []javaScriptProcessCall {
	if binding == javaScriptProcessModuleBinding {
		return moduleJavaScriptProcessCalls(line, identifier)
	}
	if !javaScriptIdentifier(identifier) {
		return nil
	}
	var calls []javaScriptProcessCall
	for _, start := range javaScriptIdentifierPositions(line, identifier) {
		previous := previousJavaScriptSignificantByte(line, start)
		if previous == '.' || previous == '/' {
			continue
		}
		open := skipJavaScriptSpace(line, start+len(identifier))
		if open < len(line) && line[open] == '(' {
			content, close, exact := exactJavaScriptCallContent(line, open, maxJavaScriptProcessStatementBytes)
			if !exact {
				continue
			}
			if next := skipJavaScriptSpace(line, close+1); next < len(line) && line[next] == '{' {
				// A shorthand object/class method declaration is not an
				// invocation of a same-named destructured binding.
				continue
			}
			calls = append(calls, javaScriptProcessCall{
				method: binding,
				text:   content,
				offset: start,
			})
			if len(calls) == 2 {
				return calls
			}
		}
	}
	return calls
}

func moduleJavaScriptProcessCalls(line, module string) []javaScriptProcessCall {
	if !javaScriptIdentifier(module) {
		return nil
	}
	var calls []javaScriptProcessCall
	for _, start := range javaScriptIdentifierPositions(line, module) {
		previous := previousJavaScriptSignificantByte(line, start)
		if previous == '.' || previous == '/' {
			continue
		}
		esbuildWrapper := previous == ',' && exactEsbuildZeroCommaPrefix(line, start)
		if previous == ',' && !esbuildWrapper {
			continue
		}
		cursor := skipJavaScriptSpace(line, start+len(module))
		if cursor >= len(line) || line[cursor] != '.' {
			continue
		}
		cursor = skipJavaScriptSpace(line, cursor+1)
		methodStart := cursor
		if methodStart >= len(line) || !javaScriptIdentifierStartByte(line[methodStart]) {
			continue
		}
		cursor++
		for cursor < len(line) && javaScriptIdentifierByte(line[cursor]) {
			cursor++
		}
		method := normalizeJavaScriptProcessMethod(line[methodStart:cursor])
		if method == "" {
			continue
		}
		open := skipJavaScriptSpace(line, cursor)
		if esbuildWrapper {
			if open >= len(line) || line[open] != ')' {
				continue
			}
			open = skipJavaScriptSpace(line, open+1)
		}
		if open < len(line) && line[open] == '(' {
			content, close, exact := exactJavaScriptCallContent(line, open, maxJavaScriptProcessStatementBytes)
			if !exact {
				continue
			}
			if next := skipJavaScriptSpace(line, close+1); next < len(line) && line[next] == '{' {
				continue
			}
			calls = append(calls, javaScriptProcessCall{
				method: method,
				text:   content,
				offset: start,
			})
			if len(calls) == 2 {
				return calls
			}
		}
	}
	return calls
}

// exactEsbuildZeroCommaPrefix accepts only esbuild's unbound-call wrapper
// `(0, module.method)(...)`. Arbitrary comma expressions, computed properties,
// optional chaining, and .call/.apply forms remain outside the closed grammar.
func exactEsbuildZeroCommaPrefix(line string, identifierStart int) bool {
	index := identifierStart - 1
	for index >= 0 && (line[index] == ' ' || line[index] == '\t') {
		index--
	}
	if index < 0 || line[index] != ',' {
		return false
	}
	index--
	for index >= 0 && (line[index] == ' ' || line[index] == '\t') {
		index--
	}
	if index < 0 || line[index] != '0' {
		return false
	}
	index--
	for index >= 0 && (line[index] == ' ' || line[index] == '\t') {
		index--
	}
	if index < 0 || line[index] != '(' {
		return false
	}
	if strings.TrimSpace(line[:index]) != "" {
		return false
	}
	return true
}

func normalizeJavaScriptProcessMethod(method string) string {
	switch method {
	case "exec":
		return "exec"
	case "execSync":
		return "execsync"
	case "spawn":
		return "spawn"
	case "spawnSync":
		return "spawnsync"
	case "execFile":
		return "execfile"
	case "execFileSync":
		return "execfilesync"
	default:
		return ""
	}
}

func javaScriptIdentifierPositions(line, identifier string) []int {
	if !javaScriptIdentifier(identifier) {
		return nil
	}
	var positions []int
	var quote byte
	escaped := false
	for index := 0; index < len(line); {
		char := line[index]
		if escaped {
			escaped = false
			index++
			continue
		}
		if quote != 0 {
			switch char {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
			index++
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			index++
			continue
		}
		if !javaScriptIdentifierStartByte(char) {
			index++
			continue
		}
		end := index + 1
		for end < len(line) && javaScriptIdentifierByte(line[end]) {
			end++
		}
		if line[index:end] == identifier {
			positions = append(positions, index)
		}
		index = end
	}
	return positions
}

func previousJavaScriptSignificantByte(line string, index int) byte {
	for index--; index >= 0; index-- {
		if line[index] != ' ' && line[index] != '\t' {
			return line[index]
		}
	}
	return 0
}

func skipJavaScriptSpace(line string, index int) int {
	for index < len(line) && (line[index] == ' ' || line[index] == '\t') {
		index++
	}
	return index
}

func javaScriptIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if index == 0 {
			if !javaScriptIdentifierStartByte(char) {
				return false
			}
			continue
		}
		if !javaScriptIdentifierByte(char) {
			return false
		}
	}
	return true
}

func javaScriptIdentifierStartByte(char byte) bool {
	return char == '_' || char == '$' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

func javaScriptIdentifierByte(char byte) bool {
	return javaScriptIdentifierStartByte(char) || char >= '0' && char <= '9'
}
