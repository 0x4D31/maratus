package extract

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	javaScriptAnalysisTargetPlatform            = "darwin"
	maxJavaScriptCommandModuleBindings          = 16
	maxJavaScriptCommandIdentifiersPerStatement = 4096
	maxJavaScriptCommandScalars                 = 128
	maxJavaScriptCommandValueBytes              = 16 << 10
	maxJavaScriptCommandValueTotalBytes         = 256 << 10
	maxJavaScriptCommandExpressionDepth         = 8
	maxJavaScriptCommandInterpolations          = 32
	maxJavaScriptCommandProofs                  = 32
	maxJavaScriptCommandArguments               = 64
	maxJavaScriptCommandArrayArguments          = 64
	javaScriptOSBindingDirect                   = "direct"
	javaScriptOSBindingESModuleInterop          = "es-module-interop"
	javaScriptCommandAssignmentEvidence         = "javascript-static-command-value"
	javaScriptCommandESModuleInteropEvidence    = "javascript-es-module-interop"
	javaScriptCommandOSBindingEvidence          = "javascript-os-binding"
	javaScriptCommandProcessBindingEvidence     = "javascript-child-process-binding"
)

var (
	reJSImportOSDefault = regexp.MustCompile(`^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s+from\s+["'](?:node:)?os["']\s*;?\s*$`)
	reJSImportOSModule  = regexp.MustCompile(`^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s+from\s+["'](?:node:)?os["']\s*;?\s*$`)
	reJSRequireOSModule = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*require\s*\(\s*["'](?:node:)?os["']\s*\)\s*;?\s*$`)
	reJSEsbuildOSModule = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*__toESM\s*\(\s*require\s*\(\s*["'](?:node:)?os["']\s*\)\s*\)\s*;?\s*$`)
)

type javaScriptCommandProof struct {
	scopeKey string
	line     int
	kind     string
	value    string
}

type javaScriptModuleBinding struct {
	kind   string
	proof  javaScriptCommandProof
	proofs []javaScriptCommandProof
}

type javaScriptCommandStatement struct {
	scopeKey      string
	functionName  string
	line          int
	text          string
	evidenceText  string
	bindingProofs []javaScriptCommandProof
}

type javaScriptCommandPrescan struct {
	process        map[string]javaScriptModuleBinding
	processAll     map[string]javaScriptModuleBinding
	os             map[string]javaScriptModuleBinding
	osAll          map[string]javaScriptModuleBinding
	processBlocked map[string]map[string]bool
	osBlocked      map[string]map[string]bool
	hiddenUses     map[string]map[string]bool
	hiddenWrites   map[string]map[string]bool
	runtimeSafe    map[string]bool
	dynamicScopes  map[string]bool
	index          javaScriptStructuralIndex
	byLine         map[int][]javaScriptCommandStatement
	hiddenBinding  bool
	dynamicCode    bool
	bundlePartial  bool
	bundleDetail   string
	bundleModules  []javaScriptBundleModule
	limited        bool
	limitDetail    string
}

func prescanJavaScriptCommands(lines []string) javaScriptCommandPrescan {
	index := buildJavaScriptStructuralIndex(lines)
	scan := javaScriptCommandPrescan{
		process:        map[string]javaScriptModuleBinding{},
		processAll:     map[string]javaScriptModuleBinding{},
		os:             map[string]javaScriptModuleBinding{},
		osAll:          map[string]javaScriptModuleBinding{},
		processBlocked: map[string]map[string]bool{},
		osBlocked:      map[string]map[string]bool{},
		hiddenUses:     map[string]map[string]bool{},
		hiddenWrites:   map[string]map[string]bool{},
		runtimeSafe:    map[string]bool{},
		dynamicScopes:  map[string]bool{},
		index:          index,
		byLine:         map[int][]javaScriptCommandStatement{},
	}
	if index.Disposition == javaScriptStructuralLimited ||
		index.Disposition == javaScriptStructuralMalformed {
		scan.limited = true
		scan.limitDetail = index.Detail
		return scan
	}
	statements := make([]javaScriptCommandStatement, 0, len(index.Statements))
	for _, use := range index.HiddenUses {
		hidden := scan.hiddenUses[use.ScopeKey]
		if hidden == nil {
			hidden = map[string]bool{}
			scan.hiddenUses[use.ScopeKey] = hidden
		}
		hidden[use.Name] = true
		if use.Write {
			writes := scan.hiddenWrites[use.ScopeKey]
			if writes == nil {
				writes = map[string]bool{}
				scan.hiddenWrites[use.ScopeKey] = writes
			}
			writes[use.Name] = true
		}
		if use.Name == "eval" {
			scan.dynamicScopes[use.ScopeKey] = true
			scan.dynamicCode = true
		}
	}
	for _, retained := range index.Statements {
		statement := javaScriptCommandStatement{
			scopeKey:     retained.ScopeKey,
			functionName: retained.FunctionName,
			line:         retained.StartLine,
			text:         stripJavaScriptStatementComments(retained.DirectText),
			evidenceText: retained.Text,
		}
		if javaScriptStructuralStatementUses(retained, "eval") {
			dynamic, exact := javaScriptStatementHasDirectEval(statement.text)
			if !exact {
				scan.limited = true
				scan.limitDetail = fmt.Sprintf(
					"JavaScript command identifier limit %d reached while checking dynamic code",
					maxJavaScriptCommandIdentifiersPerStatement,
				)
				return scan
			}
			if dynamic {
				scan.dynamicScopes[statement.scopeKey] = true
				scan.dynamicCode = true
			}
		}
		statements = append(statements, statement)
	}
	bundle := resolveJavaScriptBundleBindings(lines, statements)
	statements = bundle.statements
	scan.bundlePartial = bundle.partial
	scan.bundleDetail = bundle.detail
	scan.bundleModules = bundle.observations
	for _, statement := range statements {
		scan.byLine[statement.line] = append(scan.byLine[statement.line], statement)
	}
	scan.runtimeSafe[""] =
		!scan.dynamicScopes[""] &&
			javaScriptRuntimeRequireSafe(index, "")
	for _, scope := range index.Scopes {
		scan.runtimeSafe[scope.Key] =
			scan.runtimeSafe[""] &&
				!scan.dynamicScopes[scope.Key] &&
				javaScriptRuntimeRequireSafe(index, scope.Key)
	}

	duplicateProcess := map[string]bool{}
	duplicateOS := map[string]bool{}
	for _, statement := range statements {
		if statement.scopeKey != "" {
			continue
		}
		if declarations, recognized := javaScriptProcessDeclarations(statement.text); recognized {
			if scan.dynamicScopes[statement.scopeKey] {
				scan.hiddenBinding = true
				continue
			}
			if javaScriptProcessDeclarationRequiresRuntime(statement.text) &&
				!scan.runtimeSafe[statement.scopeKey] {
				scan.hiddenBinding = true
				continue
			}
			for name, kind := range declarations {
				if _, exists := scan.processAll[name]; !exists && len(scan.processAll) >= maxJavaScriptCommandModuleBindings {
					scan.limited = true
					scan.limitDetail = fmt.Sprintf("JavaScript command module binding limit %d reached; module binding inheritance was disabled", maxJavaScriptCommandModuleBindings)
					return scan
				}
				binding := javaScriptModuleBinding{
					kind: kind,
					proof: javaScriptCommandProof{
						line:  statement.line,
						kind:  javaScriptCommandProcessBindingEvidence,
						value: statement.evidenceText,
					},
				}
				binding.proofs = mergeJavaScriptCommandProofs(statement.bindingProofs, []javaScriptCommandProof{binding.proof})
				if _, exists := scan.processAll[name]; exists {
					duplicateProcess[name] = true
				} else {
					scan.processAll[name] = binding
				}
			}
		}
		if name, kind, ok := javaScriptOSDeclaration(statement.text); ok {
			if scan.dynamicScopes[statement.scopeKey] {
				scan.hiddenBinding = true
				continue
			}
			if javaScriptOSDeclarationRequiresRuntime(statement.text) &&
				!scan.runtimeSafe[statement.scopeKey] {
				scan.hiddenBinding = true
				continue
			}
			var interopProof javaScriptCommandProof
			if kind == javaScriptOSBindingESModuleInterop {
				var proven bool
				interopProof, proven =
					javaScriptCanonicalESModuleInteropBefore(
						index,
						statement.line,
					)
				if !proven {
					scan.hiddenBinding = true
					continue
				}
			}
			if _, exists := scan.osAll[name]; !exists && len(scan.osAll) >= maxJavaScriptCommandModuleBindings {
				scan.limited = true
				scan.limitDetail = fmt.Sprintf("JavaScript os module binding limit %d reached; target-platform resolution was disabled", maxJavaScriptCommandModuleBindings)
				return scan
			}
			binding := javaScriptModuleBinding{
				kind: kind,
				proof: javaScriptCommandProof{
					line:  statement.line,
					kind:  javaScriptCommandOSBindingEvidence,
					value: statement.evidenceText,
				},
			}
			binding.proofs = mergeJavaScriptCommandProofs(statement.bindingProofs, []javaScriptCommandProof{binding.proof})
			if interopProof.kind != "" {
				binding.proofs = mergeJavaScriptCommandProofs(
					[]javaScriptCommandProof{interopProof},
					binding.proofs,
				)
			}
			if _, exists := scan.osAll[name]; exists {
				duplicateOS[name] = true
			} else {
				scan.osAll[name] = binding
			}
		}
	}
	for name, binding := range scan.processAll {
		if !duplicateProcess[name] && !scan.hiddenUses[""][name] {
			scan.process[name] = binding
		} else if scan.hiddenUses[""][name] {
			scan.hiddenBinding = true
		}
	}
	for name, binding := range scan.osAll {
		if !duplicateOS[name] && !scan.hiddenUses[""][name] {
			scan.os[name] = binding
		} else if scan.hiddenUses[""][name] {
			scan.hiddenBinding = true
		}
	}

	for _, statement := range statements {
		scan.validateProcessUses(statement)
		scan.validateOSUses(statement)
	}
	for scope, hidden := range scan.hiddenUses {
		if scope == "" {
			continue
		}
		for name := range hidden {
			if _, ok := scan.processAll[name]; ok {
				scan.hiddenBinding = true
			}
			if _, ok := scan.osAll[name]; ok {
				scan.hiddenBinding = true
			}
		}
	}
	return scan
}

func javaScriptStructuralStatementUses(
	statement javaScriptStructuralStatement,
	name string,
) bool {
	for _, use := range statement.Uses {
		if use.Name == name {
			return true
		}
	}
	return false
}

func javaScriptStatementHasDirectEval(statement string) (bool, bool) {
	occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
		statement,
		maxJavaScriptProcessStatementBytes,
		maxJavaScriptCommandIdentifiersPerStatement,
	)
	if !exact {
		return false, false
	}
	for _, occurrence := range occurrences {
		if occurrence.Reference &&
			occurrence.Name == "eval" &&
			exactJavaScriptDirectCallAt(statement, occurrence) {
			return true, true
		}
	}
	return false, true
}

func javaScriptRuntimeRequireSafe(
	index javaScriptStructuralIndex,
	scope string,
) bool {
	for _, hidden := range index.HiddenUses {
		if hidden.ScopeKey == scope &&
			hidden.Name == "require" &&
			hidden.UnsafeRuntime {
			return false
		}
	}
	for _, retained := range index.Statements {
		if retained.ScopeKey != scope {
			continue
		}
		occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
			retained.DirectText,
			maxJavaScriptProcessStatementBytes,
			maxJavaScriptCommandIdentifiersPerStatement,
		)
		if !exact {
			return false
		}
		for _, occurrence := range occurrences {
			if !occurrence.Reference || occurrence.Name != "require" {
				continue
			}
			if !exactJavaScriptRuntimeRequireCallAt(
				retained.DirectText,
				occurrence,
			) {
				return false
			}
		}
	}
	if scope == "" {
		for _, candidate := range index.Scopes {
			if candidate.Name == "require" {
				return false
			}
		}
	}
	return true
}

func javaScriptProcessDeclarationRequiresRuntime(statement string) bool {
	return reJSRequireChildProcess.MatchString(statement) ||
		reJSRequireChildProcessModule.MatchString(statement)
}

func javaScriptOSDeclarationRequiresRuntime(statement string) bool {
	return reJSRequireOSModule.MatchString(statement) ||
		reJSEsbuildOSModule.MatchString(statement)
}

func javaScriptCanonicalESModuleInteropBefore(
	index javaScriptStructuralIndex,
	line int,
) (javaScriptCommandProof, bool) {
	const canonical = `var__toESM=(mod,isNodeMode,target)=>(target=mod!=null?__create(__getProtoOf(mod)):{},__copyProps(isNodeMode||!mod||!mod.__esModule?__defProp(target,"default",{value:mod,enumerable:true}):target,mod));`
	proofStatement := -1
	for _, statement := range index.Statements {
		if statement.ScopeKey != "" || statement.StartLine >= line {
			continue
		}
		if compactJavaScriptStatement(statement.Text) != canonical {
			continue
		}
		if proofStatement >= 0 {
			return javaScriptCommandProof{}, false
		}
		proofStatement = statement.StartLine
	}
	if proofStatement < 0 {
		return javaScriptCommandProof{}, false
	}
	for _, scope := range index.Scopes {
		if scope.Name == "__toESM" {
			return javaScriptCommandProof{}, false
		}
	}
	for _, hidden := range index.HiddenUses {
		if hidden.ScopeKey == "" && hidden.Name == "__toESM" {
			return javaScriptCommandProof{}, false
		}
	}
	var proof javaScriptCommandProof
	for _, statement := range index.Statements {
		if statement.ScopeKey != "" {
			continue
		}
		if statement.StartLine == proofStatement &&
			compactJavaScriptStatement(statement.Text) == canonical {
			proof = javaScriptCommandProof{
				line:  statement.StartLine,
				kind:  javaScriptCommandESModuleInteropEvidence,
				value: statement.Text,
			}
			continue
		}
		occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
			statement.DirectText,
			maxJavaScriptProcessStatementBytes,
			maxJavaScriptCommandIdentifiersPerStatement,
		)
		if !exact {
			return javaScriptCommandProof{}, false
		}
		for _, occurrence := range occurrences {
			if !occurrence.Reference || occurrence.Name != "__toESM" {
				continue
			}
			if occurrence.Write ||
				!exactJavaScriptDirectCallAt(
					statement.DirectText,
					occurrence,
				) {
				return javaScriptCommandProof{}, false
			}
		}
	}
	return proof, proof.kind != ""
}

func exactJavaScriptDirectCallAt(
	source string,
	occurrence javaScriptIdentifierOccurrence,
) bool {
	open := skipJavaScriptSpace(source, occurrence.Offset+len(occurrence.Name))
	if open >= len(source) || source[open] != '(' {
		return false
	}
	_, _, exact := exactJavaScriptCallContent(
		source,
		open,
		maxJavaScriptProcessStatementBytes,
	)
	return exact
}

func compactJavaScriptStatement(statement string) string {
	return strings.Map(func(char rune) rune {
		switch char {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			return -1
		default:
			return char
		}
	}, stripJavaScriptStatementComments(statement))
}

func (scan *javaScriptCommandPrescan) validateProcessUses(statement javaScriptCommandStatement) {
	for name, binding := range scan.processAll {
		positions, exact := javaScriptReferencePositions(statement.text, name)
		if !exact {
			scan.limited = true
			scan.limitDetail = fmt.Sprintf(
				"JavaScript command identifier limit %d reached; binding correlation was disabled",
				maxJavaScriptCommandIdentifiersPerStatement,
			)
			return
		}
		if len(positions) == 0 {
			continue
		}
		if declarations, recognized := javaScriptProcessDeclarations(statement.text); recognized &&
			statement.scopeKey == "" && declarations[name] == binding.kind {
			continue
		}
		calls := javaScriptBoundProcessCalls(statement.text, name, binding.kind)
		if len(positions) == 1 && len(calls) == 1 {
			continue
		}
		if statement.scopeKey == "" {
			delete(scan.process, name)
			continue
		}
		scan.markBlocked(scan.processBlocked, statement.scopeKey, name)
	}
}

func (scan *javaScriptCommandPrescan) validateOSUses(statement javaScriptCommandStatement) {
	for name, binding := range scan.osAll {
		positions, exact := javaScriptReferencePositions(statement.text, name)
		if !exact {
			scan.limited = true
			scan.limitDetail = fmt.Sprintf(
				"JavaScript command identifier limit %d reached; os binding correlation was disabled",
				maxJavaScriptCommandIdentifiersPerStatement,
			)
			return
		}
		if len(positions) == 0 {
			continue
		}
		if declared, kind, ok := javaScriptOSDeclaration(statement.text); ok &&
			statement.scopeKey == "" && declared == name && kind == binding.kind {
			continue
		}
		if len(positions) == 1 && exactJavaScriptOSPlatformCall(statement.text, name, binding.kind) {
			continue
		}
		if statement.scopeKey == "" {
			delete(scan.os, name)
			continue
		}
		scan.markBlocked(scan.osBlocked, statement.scopeKey, name)
	}
}

func javaScriptReferencePositions(text, name string) ([]int, bool) {
	occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
		text,
		maxJavaScriptProcessStatementBytes,
		maxJavaScriptCommandIdentifiersPerStatement,
	)
	if !exact {
		return nil, false
	}
	var positions []int
	for _, occurrence := range occurrences {
		if occurrence.Reference && occurrence.Name == name {
			positions = append(positions, occurrence.Offset)
		}
	}
	return positions, true
}

func (scan *javaScriptCommandPrescan) markBlocked(target map[string]map[string]bool, scope, name string) {
	blocked := target[scope]
	if blocked == nil {
		blocked = map[string]bool{}
		target[scope] = blocked
	}
	blocked[name] = true
}

func (scan javaScriptCommandPrescan) stableProcessNames(scope string, line int) []string {
	if scan.limited ||
		scan.dynamicScopes[""] ||
		scan.dynamicScopes[scope] {
		return nil
	}
	names := make([]string, 0, len(scan.process))
	for name, binding := range scan.process {
		if !scan.processBlocked[scope][name] &&
			!scan.hiddenUses[scope][name] &&
			binding.proof.line > 0 &&
			binding.proof.line < line {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (scan javaScriptCommandPrescan) hasBlockedProcessCall(line, scope string, lineNo int) bool {
	for name, binding := range scan.processAll {
		if len(javaScriptBoundProcessCalls(line, name, binding.kind)) == 0 {
			continue
		}
		stable := scan.process[name]
		if scan.limited || stable.kind == "" || stable.proof.line <= 0 ||
			stable.proof.line >= lineNo ||
			scan.processBlocked[scope][name] ||
			scan.hiddenUses[scope][name] {
			return true
		}
	}
	return false
}

func javaScriptOSDeclaration(line string) (string, string, bool) {
	for _, grammar := range []*regexp.Regexp{reJSImportOSDefault, reJSImportOSModule, reJSRequireOSModule} {
		if match := grammar.FindStringSubmatch(line); len(match) == 2 {
			return match[1], javaScriptOSBindingDirect, true
		}
	}
	if match := reJSEsbuildOSModule.FindStringSubmatch(line); len(match) == 2 {
		return match[1], javaScriptOSBindingESModuleInterop, true
	}
	return "", "", false
}

func exactJavaScriptOSPlatformCall(line, name, kind string) bool {
	direct := name + ".platform()"
	if strings.Contains(line, direct) {
		return true
	}
	return kind == javaScriptOSBindingESModuleInterop &&
		strings.Contains(line, name+".default.platform()")
}

type javaScriptCommandValue struct {
	value  string
	proofs []javaScriptCommandProof
}

type javaScriptCommandState struct {
	prescan      javaScriptCommandPrescan
	globals      map[string]javaScriptCommandValue
	locals       map[string]map[string]javaScriptCommandValue
	unknown      map[string]bool
	localUnknown map[string]map[string]bool
	count        int
	valueBytes   int
	currentLine  int
	limited      bool
	limitDetail  string
}

func newJavaScriptCommandState(prescan javaScriptCommandPrescan) javaScriptCommandState {
	return javaScriptCommandState{
		prescan:      prescan,
		globals:      map[string]javaScriptCommandValue{},
		locals:       map[string]map[string]javaScriptCommandValue{},
		unknown:      map[string]bool{},
		localUnknown: map[string]map[string]bool{},
	}
}

func (state *javaScriptCommandState) observe(statement, scope string, line int) {
	if state == nil {
		return
	}
	state.currentLine = line
	if !state.invalidateObservedWrites(statement, scope) {
		return
	}
	name, expression, possible := simpleJavaScriptCommandAssignment(statement)
	if !possible {
		return
	}
	value, proofs, ok := state.resolveExpression(expression, scope, 0)
	if !ok {
		state.invalidate(scope, name)
		return
	}
	proofs = mergeJavaScriptCommandProofs(proofs, []javaScriptCommandProof{{
		scopeKey: scope,
		line:     line,
		kind:     javaScriptCommandAssignmentEvidence,
		value:    statement,
	}})
	if len(proofs) > maxJavaScriptCommandProofs {
		state.markLimited(fmt.Sprintf("JavaScript command provenance limit %d reached", maxJavaScriptCommandProofs))
		state.invalidate(scope, name)
		return
	}
	state.set(scope, name, javaScriptCommandValue{value: value, proofs: proofs})
}

// simpleJavaScriptCommandAssignment recognizes one bare identifier write. It
// deliberately rejects destructuring, multiple declarators, member writes,
// update operators, and assignment expressions nested in another expression.
func simpleJavaScriptCommandAssignment(statement string) (name, expression string, possible bool) {
	statement = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	if statement == "" {
		return "", "", false
	}
	for _, keyword := range []string{"const", "let", "var"} {
		prefix := keyword + " "
		if !strings.HasPrefix(statement, prefix) {
			continue
		}
		rest := strings.TrimSpace(statement[len(prefix):])
		index := strings.IndexByte(rest, '=')
		if index <= 0 || strings.Contains(rest[:index], ",") {
			return "", "", false
		}
		name = strings.TrimSpace(rest[:index])
		expression = strings.TrimSpace(rest[index+1:])
		if !javaScriptIdentifier(name) || expression == "" {
			return "", "", false
		}
		return name, expression, true
	}
	index := strings.IndexByte(statement, '=')
	if index <= 0 || index+1 < len(statement) && (statement[index+1] == '=' || statement[index+1] == '>') {
		return "", "", false
	}
	if index > 0 && strings.ContainsRune("!<>+-*/%&|^?", rune(statement[index-1])) {
		return "", "", false
	}
	name = strings.TrimSpace(statement[:index])
	expression = strings.TrimSpace(statement[index+1:])
	if !javaScriptIdentifier(name) || expression == "" {
		return "", "", false
	}
	return name, expression, true
}

func (state *javaScriptCommandState) set(scope, name string, value javaScriptCommandValue) {
	if state == nil || !javaScriptIdentifier(name) {
		return
	}
	if len(value.value) > maxJavaScriptCommandValueBytes {
		state.markLimited(fmt.Sprintf("JavaScript command scalar exceeded %d bytes", maxJavaScriptCommandValueBytes))
		state.invalidate(scope, name)
		return
	}
	target := state.globals
	unknown := state.unknown
	if scope != "" {
		target = state.locals[scope]
		if target == nil {
			target = map[string]javaScriptCommandValue{}
			state.locals[scope] = target
		}
		unknown = state.localUnknown[scope]
		if unknown == nil {
			unknown = map[string]bool{}
			state.localUnknown[scope] = unknown
		}
	}
	old, exists := target[name]
	if !exists && !unknown[name] && state.count >= maxJavaScriptCommandScalars {
		state.markLimited(fmt.Sprintf("JavaScript command scalar limit %d reached", maxJavaScriptCommandScalars))
		return
	}
	newBytes := state.valueBytes - len(old.value) + len(value.value)
	if newBytes > maxJavaScriptCommandValueTotalBytes {
		state.markLimited(fmt.Sprintf("JavaScript command scalar byte limit %d reached", maxJavaScriptCommandValueTotalBytes))
		state.invalidate(scope, name)
		return
	}
	if !exists && !unknown[name] {
		state.count++
	}
	target[name] = value
	delete(unknown, name)
	state.valueBytes = newBytes
}

func (state *javaScriptCommandState) invalidate(scope, name string) {
	if state == nil || !javaScriptIdentifier(name) {
		return
	}
	target := state.globals
	unknown := state.unknown
	if scope != "" {
		target = state.locals[scope]
		unknown = state.localUnknown[scope]
	}
	if old, ok := target[name]; ok {
		state.valueBytes -= len(old.value)
		delete(target, name)
		if unknown == nil {
			unknown = map[string]bool{}
			if scope == "" {
				state.unknown = unknown
			} else {
				state.localUnknown[scope] = unknown
			}
		}
		unknown[name] = true
	}
}

func (state *javaScriptCommandState) lookup(scope, name string) (javaScriptCommandValue, bool) {
	if state == nil || !javaScriptIdentifier(name) {
		return javaScriptCommandValue{}, false
	}
	if state.prescan.hiddenWrites[scope][name] ||
		state.prescan.dynamicScopes[scope] {
		return javaScriptCommandValue{}, false
	}
	if scope != "" {
		if state.localUnknown[scope][name] {
			return javaScriptCommandValue{}, false
		}
		if value, ok := state.locals[scope][name]; ok {
			return value, true
		}
		// Function execution is deferred and may observe module mutations that
		// this bounded source-order model cannot prove. Initial command
		// recovery therefore never inherits module scalar values into a
		// function; Fast-Draft-shaped chains use exact function-local scalars.
		return javaScriptCommandValue{}, false
	}
	if state.unknown[name] {
		return javaScriptCommandValue{}, false
	}
	value, ok := state.globals[name]
	return value, ok
}

func (state *javaScriptCommandState) invalidateObservedWrites(statement, scope string) bool {
	if state == nil {
		return false
	}
	occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
		statement,
		maxJavaScriptProcessStatementBytes,
		maxJavaScriptCommandIdentifiersPerStatement,
	)
	if !exact {
		state.markLimited(fmt.Sprintf(
			"JavaScript command identifier limit %d reached or statement syntax was unsupported",
			maxJavaScriptCommandIdentifiersPerStatement,
		))
		state.invalidateScope(scope)
		return false
	}
	for _, occurrence := range occurrences {
		if occurrence.Write {
			state.invalidate(scope, occurrence.Name)
		}
	}
	return true
}

func (state *javaScriptCommandState) invalidateScope(scope string) {
	if state == nil {
		return
	}
	if scope == "" {
		for name := range state.globals {
			state.invalidate("", name)
		}
		return
	}
	for name := range state.locals[scope] {
		state.invalidate(scope, name)
	}
}

func (state *javaScriptCommandState) markLimited(detail string) {
	if state == nil || state.limited {
		return
	}
	state.limited = true
	state.limitDetail = detail
}

func (state *javaScriptCommandState) resolveInvocation(method, call, scope string) (embeddedInvocation, []javaScriptCommandProof, bool) {
	arguments, exact := splitJavaScriptArgumentsExact(call, maxJavaScriptProcessStatementBytes, maxJavaScriptCommandArguments)
	if !exact {
		state.markLimited(fmt.Sprintf("JavaScript process argument limit %d reached", maxJavaScriptCommandArguments))
		return embeddedInvocation{}, nil, false
	}
	if len(arguments) == 0 {
		return embeddedInvocation{}, nil, false
	}
	unresolved := func(executable string, proofs []javaScriptCommandProof) (embeddedInvocation, []javaScriptCommandProof, bool) {
		if state.limited {
			return embeddedInvocation{}, nil, false
		}
		api := map[string]string{"exec": "exec", "execsync": "execSync", "spawn": "spawn", "spawnsync": "spawnSync", "execfile": "execFile", "execfilesync": "execFileSync"}[method]
		if api == "" {
			return embeddedInvocation{}, nil, false
		}
		return embeddedInvocation{processAttempt: true, executableOnly: executable, argumentsUnresolved: true, api: api}, proofs, true
	}
	executable, proofs, ok := state.resolveExpression(arguments[0], scope, 0)
	if !ok || executable == "" {
		if javaScriptPartialArgumentIdentifier(strings.TrimSpace(arguments[0])) {
			return unresolved("", nil)
		}
		return embeddedInvocation{}, nil, false
	}
	switch method {
	case "exec", "execsync":
		return embeddedInvocation{shellCommand: executable}, proofs, true
	case "spawn", "spawnsync", "execfile", "execfilesync":
		argv := []string{executable}
		if len(arguments) > 1 {
			second := strings.TrimSpace(arguments[1])
			switch {
			case strings.HasPrefix(second, "["):
				values, argumentProofs, resolved := state.resolveArray(second, scope)
				if !resolved {
					if javaScriptPartialArgv(second) {
						return unresolved(executable, proofs)
					}
					return embeddedInvocation{}, nil, false
				}
				argv = append(argv, values...)
				proofs = mergeJavaScriptCommandProofs(proofs, argumentProofs)
			case second == "undefined" || strings.HasPrefix(second, "{"):
				// An omitted argv or an options object does not add arguments.
			default:
				if javaScriptPartialArgumentIdentifier(second) {
					return unresolved(executable, proofs)
				}
				return embeddedInvocation{}, nil, false
			}
		}
		return embeddedInvocation{argv: argv}, proofs, true
	default:
		return embeddedInvocation{}, nil, false
	}
}

func javaScriptPartialArgumentIdentifier(value string) bool {
	return javaScriptIdentifier(value) && !javaScriptSyntaxKeyword(value) && value != "undefined"
}

// Admit only closed literal/identifier arrays for partial argv. An unsupported
// expression must not turn malformed source into a process claim.
func javaScriptPartialArgv(expression string) bool {
	if len(expression) < 2 || expression[0] != '[' || expression[len(expression)-1] != ']' {
		return false
	}
	parts, exact := splitJavaScriptArgumentsExact(expression[1:len(expression)-1], maxJavaScriptCommandValueBytes, maxJavaScriptCommandArrayArguments)
	if !exact {
		return false
	}
	for _, part := range parts {
		if _, literal := exactJavaScriptQuotedLiteral(strings.TrimSpace(part)); !literal && !javaScriptPartialArgumentIdentifier(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func (state *javaScriptCommandState) resolveArray(expression, scope string) ([]string, []javaScriptCommandProof, bool) {
	expression = strings.TrimSpace(expression)
	if len(expression) < 2 || expression[0] != '[' || expression[len(expression)-1] != ']' {
		return nil, nil, false
	}
	body := strings.TrimSpace(expression[1 : len(expression)-1])
	if body == "" {
		return nil, nil, true
	}
	parts, exact := splitJavaScriptArgumentsExact(body, maxJavaScriptCommandValueBytes, maxJavaScriptCommandArrayArguments)
	if !exact {
		state.markLimited(fmt.Sprintf("JavaScript process argv limit %d reached", maxJavaScriptCommandArrayArguments))
		return nil, nil, false
	}
	values := make([]string, 0, len(parts))
	var proofs []javaScriptCommandProof
	for _, part := range parts {
		value, itemProofs, ok := state.resolveExpression(part, scope, 0)
		if !ok {
			return nil, nil, false
		}
		values = append(values, value)
		proofs = mergeJavaScriptCommandProofs(proofs, itemProofs)
		if len(proofs) > maxJavaScriptCommandProofs {
			state.markLimited(fmt.Sprintf("JavaScript command provenance limit %d reached", maxJavaScriptCommandProofs))
			return nil, nil, false
		}
	}
	return values, proofs, true
}

func (state *javaScriptCommandState) resolveExpression(expression, scope string, depth int) (string, []javaScriptCommandProof, bool) {
	expression = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expression), ";"))
	if expression == "" {
		return "", nil, false
	}
	if len(expression) > maxJavaScriptCommandValueBytes {
		state.markLimited(fmt.Sprintf("JavaScript command expression exceeded %d bytes", maxJavaScriptCommandValueBytes))
		return "", nil, false
	}
	if depth >= maxJavaScriptCommandExpressionDepth {
		state.markLimited(fmt.Sprintf("JavaScript command expression depth limit %d reached", maxJavaScriptCommandExpressionDepth))
		return "", nil, false
	}
	if expression[0] == '`' {
		if value, proofs, ok := state.resolveTemplate(expression, scope, depth+1); ok {
			return value, proofs, true
		}
	}
	if expression[0] == '\'' || expression[0] == '"' {
		if value, ok := exactJavaScriptQuotedLiteral(expression); ok {
			return value, nil, true
		}
	}
	if javaScriptIdentifier(expression) {
		value, ok := state.lookup(scope, expression)
		return value.value, append([]javaScriptCommandProof(nil), value.proofs...), ok
	}
	if value, proofs, ok := state.resolveOSPlatform(expression, scope); ok {
		return value, proofs, true
	}
	if condition, left, right, ok := splitJavaScriptCommandTernary(expression); ok {
		selected, conditionProofs, decided := state.resolveEqualityCondition(condition, scope, depth+1)
		if !decided {
			return "", nil, false
		}
		branch := right
		if selected {
			branch = left
		}
		value, branchProofs, resolved := state.resolveExpression(branch, scope, depth+1)
		if !resolved {
			return "", nil, false
		}
		return value, mergeJavaScriptCommandProofs(conditionProofs, branchProofs), true
	}
	if parts, ok := splitJavaScriptStaticConcatenation(expression); ok {
		var out strings.Builder
		var proofs []javaScriptCommandProof
		for _, part := range parts {
			value, partProofs, resolved := state.resolveExpression(part, scope, depth+1)
			if !resolved || out.Len() > maxJavaScriptCommandValueBytes-len(value) {
				if resolved {
					state.markLimited(fmt.Sprintf("JavaScript command value exceeded %d bytes", maxJavaScriptCommandValueBytes))
				}
				return "", nil, false
			}
			out.WriteString(value)
			proofs = mergeJavaScriptCommandProofs(proofs, partProofs)
			if len(proofs) > maxJavaScriptCommandProofs {
				state.markLimited(fmt.Sprintf("JavaScript command provenance limit %d reached", maxJavaScriptCommandProofs))
				return "", nil, false
			}
		}
		return out.String(), proofs, true
	}
	// Calls other than a proven os.platform(), computed properties, optional
	// chaining, coercion, and arbitrary expressions remain outside this closed
	// resolver. Concatenation is admitted only when every top-level operand is
	// already an exact retained string.
	return "", nil, false
}

// splitJavaScriptStaticConcatenation recognizes only top-level binary +
// operators. It does not evaluate JavaScript coercion: callers must prove
// every operand is an exact string literal or retained string scalar. Nested
// calls, numeric expressions, ++, +=, and malformed delimiters fail closed.
func splitJavaScriptStaticConcatenation(expression string) ([]string, bool) {
	if len(expression) == 0 || len(expression) > maxJavaScriptCommandValueBytes {
		return nil, false
	}
	var parts []string
	start := 0
	quote := byte(0)
	escaped := false
	paren, bracket, brace := 0, 0, 0
	for index := 0; index < len(expression); index++ {
		char := expression[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			bracket++
		case ']':
			bracket--
		case '{':
			brace++
		case '}':
			brace--
		case '+':
			if paren != 0 || bracket != 0 || brace != 0 {
				continue
			}
			if index == 0 || index+1 >= len(expression) || expression[index-1] == '+' || expression[index+1] == '+' || expression[index+1] == '=' {
				return nil, false
			}
			part := strings.TrimSpace(expression[start:index])
			if part == "" {
				return nil, false
			}
			parts = append(parts, part)
			if len(parts) > maxJavaScriptCommandArrayArguments {
				return nil, false
			}
			start = index + 1
		}
		if paren < 0 || bracket < 0 || brace < 0 {
			return nil, false
		}
	}
	if quote != 0 || paren != 0 || bracket != 0 || brace != 0 || len(parts) == 0 {
		return nil, false
	}
	last := strings.TrimSpace(expression[start:])
	if last == "" {
		return nil, false
	}
	parts = append(parts, last)
	return parts, true
}

func exactJavaScriptQuotedLiteral(expression string) (string, bool) {
	expression = strings.TrimSpace(expression)
	if len(expression) < 2 {
		return "", false
	}
	quote := expression[0]
	if quote != '\'' && quote != '"' || expression[len(expression)-1] != quote {
		return "", false
	}
	var out strings.Builder
	for index := 1; index < len(expression)-1; index++ {
		char := expression[index]
		if char == '\n' || char == '\r' {
			return "", false
		}
		if char == quote {
			return "", false
		}
		if char != '\\' {
			out.WriteByte(char)
			continue
		}
		index++
		if index >= len(expression)-1 {
			return "", false
		}
		switch expression[index] {
		case '\\', '\'', '"', '/':
			out.WriteByte(expression[index])
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte('\v')
		case '0':
			if index+1 < len(expression)-1 && expression[index+1] >= '0' && expression[index+1] <= '9' {
				return "", false
			}
			out.WriteByte(0)
		default:
			// Hex, Unicode, legacy octal, line continuations, identity
			// escapes, and malformed escapes remain outside this closed
			// decoder rather than being interpreted with another
			// language's rules.
			return "", false
		}
		if out.Len() > maxJavaScriptCommandValueBytes {
			return "", false
		}
	}
	return out.String(), true
}

func (state *javaScriptCommandState) resolveTemplate(expression, scope string, depth int) (string, []javaScriptCommandProof, bool) {
	if len(expression) < 2 || expression[0] != '`' || expression[len(expression)-1] != '`' {
		return "", nil, false
	}
	body := expression[1 : len(expression)-1]
	var out strings.Builder
	var proofs []javaScriptCommandProof
	interpolations := 0
	for index := 0; index < len(body); {
		if body[index] == '\\' {
			if index+1 >= len(body) {
				return "", nil, false
			}
			switch body[index+1] {
			case '\\', '`', '$':
				out.WriteByte(body[index+1])
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			default:
				return "", nil, false
			}
			index += 2
			continue
		}
		if strings.HasPrefix(body[index:], "${") {
			end := strings.IndexByte(body[index+2:], '}')
			if end < 0 {
				return "", nil, false
			}
			end += index + 2
			name := strings.TrimSpace(body[index+2 : end])
			if !javaScriptIdentifier(name) {
				return "", nil, false
			}
			value, ok := state.lookup(scope, name)
			if !ok {
				return "", nil, false
			}
			interpolations++
			if interpolations > maxJavaScriptCommandInterpolations {
				state.markLimited(fmt.Sprintf("JavaScript template interpolation limit %d reached", maxJavaScriptCommandInterpolations))
				return "", nil, false
			}
			if out.Len() > maxJavaScriptCommandValueBytes-len(value.value) {
				state.markLimited(fmt.Sprintf("JavaScript command value exceeded %d bytes", maxJavaScriptCommandValueBytes))
				return "", nil, false
			}
			out.WriteString(value.value)
			proofs = mergeJavaScriptCommandProofs(proofs, value.proofs)
			index = end + 1
			continue
		}
		if out.Len() >= maxJavaScriptCommandValueBytes {
			state.markLimited(fmt.Sprintf("JavaScript command value exceeded %d bytes", maxJavaScriptCommandValueBytes))
			return "", nil, false
		}
		out.WriteByte(body[index])
		index++
	}
	return out.String(), proofs, true
}

func (state *javaScriptCommandState) resolveOSPlatform(expression, scope string) (string, []javaScriptCommandProof, bool) {
	for name, binding := range state.prescan.os {
		if state.prescan.osBlocked[scope][name] ||
			state.prescan.hiddenUses[scope][name] ||
			binding.proof.line <= 0 ||
			binding.proof.line >= state.currentLine {
			continue
		}
		direct := name + ".platform()"
		interop := name + ".default.platform()"
		if expression == direct || binding.kind == javaScriptOSBindingESModuleInterop && expression == interop {
			return javaScriptAnalysisTargetPlatform, append(
				[]javaScriptCommandProof(nil),
				binding.proofs...,
			), true
		}
	}
	return "", nil, false
}

func splitJavaScriptCommandTernary(expression string) (condition, left, right string, ok bool) {
	question := -1
	colon := -1
	var quote byte
	escaped := false
	depth := 0
	for index := 0; index < len(expression); index++ {
		char := expression[index]
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		switch char {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '?':
			if depth == 0 {
				if index+1 < len(expression) && expression[index+1] == '?' {
					return "", "", "", false
				}
				if question >= 0 {
					return "", "", "", false
				}
				question = index
			}
		case ':':
			if depth == 0 && question >= 0 {
				if colon >= 0 {
					return "", "", "", false
				}
				colon = index
			}
		}
	}
	if question <= 0 || colon <= question+1 || colon+1 >= len(expression) {
		return "", "", "", false
	}
	return strings.TrimSpace(expression[:question]), strings.TrimSpace(expression[question+1 : colon]), strings.TrimSpace(expression[colon+1:]), true
}

func (state *javaScriptCommandState) resolveEqualityCondition(condition, scope string, depth int) (bool, []javaScriptCommandProof, bool) {
	index := strings.Index(condition, "===")
	if index <= 0 || strings.Contains(condition[index+3:], "===") {
		return false, nil, false
	}
	left := strings.TrimSpace(condition[:index])
	right := strings.TrimSpace(condition[index+3:])
	leftValue, leftProofs, leftOK := state.resolveExpression(left, scope, depth)
	rightValue, rightProofs, rightOK := state.resolveExpression(right, scope, depth)
	if !leftOK || !rightOK {
		return false, nil, false
	}
	return leftValue == rightValue, mergeJavaScriptCommandProofs(leftProofs, rightProofs), true
}

func mergeJavaScriptCommandProofs(groups ...[]javaScriptCommandProof) []javaScriptCommandProof {
	var out []javaScriptCommandProof
	seen := map[string]bool{}
	for _, group := range groups {
		for _, proof := range group {
			if proof.kind == "" || proof.line <= 0 {
				continue
			}
			key := fmt.Sprintf("%s\x00%d\x00%s\x00%s", proof.scopeKey, proof.line, proof.kind, proof.value)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, proof)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		if out[i].scopeKey != out[j].scopeKey {
			return out[i].scopeKey < out[j].scopeKey
		}
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		return out[i].value < out[j].value
	})
	return out
}

func addJavaScriptCommandProofEvidence(
	graph *behavior.Graph,
	moduleContent artifact.Content,
	lineContent artifact.Content,
	scopeKey string,
	proofs []javaScriptCommandProof,
) ([]string, bool) {
	if len(proofs) > maxJavaScriptCommandProofs {
		return nil, false
	}
	ids := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		proofContent := moduleContent
		switch proof.scopeKey {
		case "":
			// The module binding belongs to the retained program scope.
		case scopeKey:
			proofContent = lineContent
		default:
			return nil, false
		}
		id := addLineEvidence(graph, proofContent, proof.line, proof.kind, proof.value)
		if id == "" {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, len(ids) > 0
}
