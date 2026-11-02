package extract

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/grafana/sobek/ast"
)

const javaScriptASTAnalysisArea = "javascript-ast-analysis"

const maxJavaScriptLeadingIIFEBytes = 64 << 10

func requiresJavaScriptASTFrontend(prescan javaScriptCommandPrescan) bool {
	if prescan.index.Disposition == javaScriptStructuralLimited || prescan.index.Disposition == javaScriptStructuralMalformed {
		return false
	}
	// Keep the established interop and static-value adapter together until the
	// AST frontend supports its complete helper and scalar proof chain.
	for _, binding := range prescan.osAll {
		if binding.kind == javaScriptOSBindingESModuleInterop {
			return false
		}
	}
	for _, statement := range prescan.byLineStatements() {
		text := strings.TrimSpace(statement.text)
		if len(text) > len("import") && strings.HasPrefix(text, "import") && strings.ContainsRune(" \t\r\n{*\"'", rune(text[len("import")])) {
			return false
		}
	}
	if prescan.index.Disposition == javaScriptStructuralUnsupported {
		return true
	}
	for _, statements := range prescan.byLine {
		if !sameJavaScriptStatementScope(statements) {
			return true
		}
	}
	return false
}

// extractJavaScriptASTSource handles syntax outside the line-oriented frontend.
// Selection is based on syntax, never on how many operations a sample produced.
// Only stable CommonJS namespace calls enter the shared operation vocabulary.
// No JavaScript runtime, module resolution, or second rule evaluator is used.
func extractJavaScriptASTSource(graph *behavior.Graph, content artifact.Content, source string) {
	extractJavaScriptASTSourceAt(graph, content, source, 0, true)
}

func extractJavaScriptASTSourceAt(graph *behavior.Graph, content artifact.Content, source string, lineBase int, allowLeadingIIFE bool) {
	operationStart := len(graph.Operations)
	doc, err := parseJavaScriptAST(source, false)
	if err != nil {
		doc, err = parseJavaScriptAST(source, true)
	}
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, javaScriptASTAnalysisArea, err.Error()+"; source semantics were not inferred")
		return
	}
	bindings, err := inventoryJavaScriptASTBindings(doc)
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, javaScriptASTAnalysisArea, err.Error()+"; source semantics were not inferred")
		return
	}
	state := javaScriptASTExtraction{graph: graph, content: content, doc: doc, scopes: map[int]string{}, lines: javaScriptASTLineOffsets(source), lineBase: lineBase}
	state.values = newJavaScriptASTValues(bindings)
	addPartialCoverageOnce(graph, content.NodeID, javaScriptASTAnalysisArea,
		"AST frontend retained bounded CommonJS namespace calls; named imports, destructured aliases, interop wrappers, helper argument propagation, control-flow feasibility and a complete call graph are not modeled; unresolved resources remain unknown")
	if len(doc.unlocated) > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "javascript-ast-source-locations", "some parser nodes lacked verified source spans; those nodes were not used as call or binding evidence")
	}
	if len(bindings.dynamic) > 0 || bindings.runtimeMutated {
		addPartialCoverageOnce(graph, content.NodeID, "javascript-ast-dynamic-identity", "dynamic code construction, eval use or a changed runtime loader prevented binding promotion in affected scopes; dynamic code was not decoded or executed")
	}
	if len(bindings.invalidModules) > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "javascript-ast-module-identity", "namespace mutation or an opaque namespace escape invalidated affected shared module identities")
	}
	calls := 0
	fetchSafe := bindings.builtinFetchSafe()
	for _, located := range doc.nodes {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		call, ok := located.node.(*ast.CallExpression)
		if !ok || !located.spanKnown || located.span.end-located.span.start > maxJavaScriptAPICallBytes {
			continue
		}
		if identifier, ok := call.Callee.(*ast.Identifier); ok && identifier.Name.String() == "fetch" && fetchSafe && bindings.lookup(located.scope, "fetch") == nil && state.exactIdentifier(identifier) {
			if len(call.ArgumentList) != 1 {
				continue
			}
			if _, spread := call.ArgumentList[0].(*ast.SpreadElement); spread {
				continue
			}
			value, proof, resolved := state.stringValue(call.ArgumentList[0], located.scope, located.span.start)
			if !resolved || !exactJavaScriptHTTPURL(value) {
				value = ""
			}
			calls++
			if calls > maxJavaScriptAPICalls {
				addPartialCoverageOnce(graph, content.NodeID, javaScriptASTAnalysisArea, fmt.Sprintf("AST API call budget of %d reached; later calls were omitted", maxJavaScriptAPICalls))
				break
			}
			state.fetch(located, call, value, proof)
			continue
		}
		dot, ok := call.Callee.(*ast.DotExpression)
		if !ok {
			continue
		}
		name, ok := dot.Left.(*ast.Identifier)
		if !ok {
			continue
		}
		binding, ok := bindings.namespace(located.scope, name.Name.String(), located.span.start)
		if !ok || !state.exactIdentifier(name) || !state.exactIdentifier(&dot.Identifier) {
			continue
		}
		method := dot.Identifier.Name.String()
		spec, known := lookupJavaScriptAPISpec(binding.namespace, method)
		process := binding.namespace == "child_process" && javaScriptASTProcessArity(method, len(call.ArgumentList))
		if !known && !process {
			continue
		}
		if known && (len(call.ArgumentList) < spec.minArgs || len(call.ArgumentList) > spec.maxArgs) {
			continue
		}
		spread := false
		for _, arg := range call.ArgumentList {
			if _, ok := arg.(*ast.SpreadElement); ok {
				spread = true
			}
		}
		if spread {
			continue
		}
		if known && spec.callback && !javaScriptASTCallback(call.ArgumentList[len(call.ArgumentList)-1]) {
			continue
		}
		calls++
		if calls > maxJavaScriptAPICalls {
			addPartialCoverageOnce(graph, content.NodeID, javaScriptASTAnalysisArea, fmt.Sprintf("AST API call budget of %d reached; later calls were omitted", maxJavaScriptAPICalls))
			break
		}
		callContent, ok := state.scopeContent(located.scope)
		if !ok {
			continue
		}
		bindingContent, ok := state.scopeContent(doc.nodes[binding.declaration].scope)
		if !ok {
			continue
		}
		proof := []string{
			state.evidence(callContent, call, "javascript-api-call"),
			state.evidence(bindingContent, binding.identifier, "javascript-module-binding-name"),
			state.evidence(bindingContent, binding.initializer, "javascript-module-binding-initializer"),
		}
		if proof[0] == "" || proof[1] == "" || proof[2] == "" {
			continue
		}
		if process {
			state.process(callContent, call, located.scope, located.span, method, name.Name.String(), proof)
			continue
		}
		resources := make([]behavior.ResourceBinding, 0, len(spec.resources))
		unresolved := false
		for _, resourceSpec := range spec.resources {
			value := resourceSpec.fixed
			var valueProof []string
			if resourceSpec.index >= 0 {
				value, valueProof, _ = state.stringValue(call.ArgumentList[resourceSpec.index], located.scope, located.span.start)
				if merged, retained := mergeJavaScriptASTValueEvidence(proof, valueProof); retained {
					proof = merged
				} else {
					value, valueProof = "", nil
					addPartialCoverageOnce(graph, content.NodeID, "javascript-ast-value-analysis", "causal value evidence exceeded retained bounds; affected resources remain unknown")
				}
			}
			resource := behavior.NewResource(resourceSpec.kind, value)
			if resourceSpec.kind == behavior.ResourceFile && value != "" {
				resource = classifiedFileResource(value)
			}
			if resourceSpec.kind == behavior.ResourceURL {
				if !exactJavaScriptHTTPURL(value) {
					resource = behavior.NewResource(behavior.ResourceURL, "")
				}
			}
			if resource.Value == "" {
				unresolved = true
			}
			resources = append(resources, behavior.Bind(resourceSpec.role, resource, valueProof...))
		}
		resourceState := "exact-static"
		if unresolved {
			resourceState = "unresolved"
		}
		kind := spec.kind
		if spec.module == "axios" && (spec.method == "post" || spec.method == "put" || spec.method == "patch") && len(call.ArgumentList) >= 2 {
			kind = behavior.OperationNetworkUpload
		}
		operationID := graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: callContent.ScopeID, SourceFunction: callContent.Function,
			Kind: kind, ResourceBindings: resources, EvidenceIDs: proof, Support: behavior.SupportCorroborated,
			Execution: executionContextForContent(callContent), Line: state.line(located.span.start),
			Qualifiers: map[string]string{"api": spec.module + "." + method, "api_identity": javaScriptAPIIdentityQualifier(spec.module), "module_binding": name.Name.String(), "resource_binding": resourceState},
		})
		if operationID != "" && isNetworkOperationKind(kind) {
			observation := networkImplementationObservation(operationID, callContent, "javascript", proof[0])
			observation.APIOrTool = spec.module + "." + method
			observation.EvidenceIDs = proof
			graph.AddNetworkImplementation(observation)
		}
	}
	state.valueCoverage()
	if !allowLeadingIIFE || len(graph.Operations) != operationStart {
		return
	}
	start, end, ok := javaScriptLeadingIIFERegion(doc)
	if !ok || content.ByteOffsetBase < 0 || int64(end) > math.MaxInt64-content.ByteOffsetBase {
		return
	}
	regionContent := content
	regionContent.ByteOffsetBase += int64(start)
	regionLineBase := state.line(start) - 1
	extractJavaScriptASTSourceAt(graph, regionContent, source[start:end], regionLineBase, false)
}

// A leading zero-argument IIFE is a bounded lexical region whose namespace
// bindings are local to the wrapper. When whole-file alias invalidation would
// otherwise discard every operation, analyze that region under the same
// per-content identity boundary used for separately retained modules. This does
// not establish scheduling or execution; emitted operations keep their normal
// static connectivity. Restricting the fallback to the first executable
// statement avoids splitting arbitrary functions or later program regions.
func javaScriptLeadingIIFERegion(doc *javaScriptASTDocument) (int, int, bool) {
	for _, statement := range doc.program.Body {
		expression, ok := statement.(*ast.ExpressionStatement)
		if !ok {
			if _, empty := statement.(*ast.EmptyStatement); empty {
				continue
			}
			return 0, 0, false
		}
		if _, directive := expression.Expression.(*ast.StringLiteral); directive {
			continue
		}
		call, ok := expression.Expression.(*ast.CallExpression)
		if !ok || len(call.ArgumentList) != 0 {
			return 0, 0, false
		}
		switch call.Callee.(type) {
		case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		default:
			return 0, 0, false
		}
		start, end, known := javaScriptASTSourceSpan(statement, doc.program.File.Base(), len(doc.source))
		if !known || start == 0 || doc.source[start-1] != '(' || end-start+1 > maxJavaScriptLeadingIIFEBytes {
			return 0, 0, false
		}
		return start - 1, end, true
	}
	return 0, 0, false
}

func (bindings *javaScriptASTBindings) builtinFetchSafe() bool {
	if bindings.runtimeMutated || len(bindings.dynamic) > 0 {
		return false
	}
	for _, located := range bindings.doc.nodes {
		switch node := located.node.(type) {
		case *ast.DotExpression:
			if node.Identifier.Name.String() == "fetch" {
				return false
			}
		case *ast.BracketExpression:
			if javaScriptASTLiteralString(node.Member) == "fetch" {
				return false
			}
		case *ast.Identifier:
			name := node.Name.String()
			if (name == "globalThis" || name == "global" || name == "window" || name == "self") && bindings.lookup(located.scope, name) == nil {
				return false
			}
			if name != "fetch" || bindings.lookup(located.scope, name) != nil {
				continue
			}
			if located.parent < 0 {
				return false
			}
			call, ok := bindings.doc.nodes[located.parent].node.(*ast.CallExpression)
			if !ok || call.Callee != node {
				return false
			}
		}
	}
	return true
}

func (state *javaScriptASTExtraction) fetch(located javaScriptASTNode, call *ast.CallExpression, value string, proof []string) {
	content, ok := state.scopeContent(located.scope)
	if !ok {
		return
	}
	evidence := state.evidence(content, call, "javascript-api-call")
	if evidence == "" {
		return
	}
	var destination []string
	resourceBinding := "unresolved"
	if value != "" {
		destination = []string{value}
		resourceBinding = "exact-static"
	}
	bindings := networkOperationBindings(behavior.OperationNetworkConnect, destination, "", "")
	for i := range bindings {
		bindings[i].EvidenceIDs = append([]string(nil), proof...)
	}
	proof = append([]string{evidence}, proof...)
	operationID := state.graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, SourceFunction: content.Function,
		Kind: behavior.OperationNetworkConnect, ResourceBindings: bindings,
		Qualifiers:  map[string]string{"api": "fetch", "api_identity": "unshadowed-runtime-builtin-and-exact-call", "resource_binding": resourceBinding},
		EvidenceIDs: proof, Support: behavior.SupportCorroborated, Execution: executionContextForContent(content), Line: state.line(located.span.start),
	})
	if operationID == "" {
		return
	}
	observation := networkImplementationObservation(operationID, content, "javascript", evidence)
	observation.APIOrTool = "fetch"
	observation.HTTPImplementation = "WHATWG fetch runtime implementation"
	observation.EvidenceIDs = proof
	state.graph.AddNetworkImplementation(observation)
}

type javaScriptASTExtraction struct {
	graph         *behavior.Graph
	content       artifact.Content
	doc           *javaScriptASTDocument
	scopes        map[int]string
	lines         []int
	lineBase      int
	values        *javaScriptASTValues
	valueEvidence map[javaScriptASTValueProof]string
}

func (state *javaScriptASTExtraction) line(offset int) int {
	return state.lineBase + sort.Search(len(state.lines), func(i int) bool { return state.lines[i] > offset })
}

func (state *javaScriptASTExtraction) absoluteOffset(offset int) int64 {
	return state.content.ByteOffsetBase + int64(offset)
}

func (state *javaScriptASTExtraction) functionName(scope int) string {
	lexical := state.doc.scopes[scope]
	if lexical.kind != "function" {
		return ""
	}
	if !strings.HasPrefix(lexical.function, "function@") {
		return lexical.function
	}
	return fmt.Sprintf("function@%d", state.absoluteOffset(lexical.span.start))
}

func javaScriptASTLineOffsets(source string) []int {
	lines := []int{0}
	for offset, char := range source {
		switch char {
		case '\r':
			lines = append(lines, offset+1)
		case '\n':
			if offset > 0 && source[offset-1] == '\r' {
				lines[len(lines)-1] = offset + 1
			} else {
				lines = append(lines, offset+1)
			}
		case '\u2028', '\u2029':
			lines = append(lines, offset+3)
		}
	}
	return lines
}

func (state *javaScriptASTExtraction) exactIdentifier(node *ast.Identifier) bool {
	start, end, known := javaScriptASTSourceSpan(node, state.doc.program.File.Base(), len(state.doc.source))
	return known && state.doc.source[start:end] == node.Name.String()
}

func (state *javaScriptASTExtraction) scopeContent(scope int) (artifact.Content, bool) {
	content := state.content
	lexical := state.doc.scopes[scope]
	// The body block is the function's own operation scope. Nested lexical
	// blocks retain separate scopes, preventing cross-branch resource joins.
	if lexical.kind == "block" && lexical.parent >= 0 && state.doc.scopes[lexical.parent].kind == "function" {
		return state.scopeContent(lexical.parent)
	}
	if scope == 0 && content.ScopeID != "" {
		return content, true
	}
	if _, exists := state.scopes[scope]; !exists {
		lexical := state.doc.scopes[scope]
		if !lexical.spanKnown {
			return content, false
		}
		parentID := content.ScopeID
		if scope > 0 {
			parent, ok := state.scopeContent(lexical.parent)
			if !ok {
				return content, false
			}
			parentID = parent.ScopeID
		}
		kind, name := lexical.kind, fmt.Sprintf("%s@%d", lexical.kind, state.absoluteOffset(lexical.span.start))
		function := state.functionName(scope)
		state.scopes[scope] = state.graph.AddScope(behavior.Scope{
			NodeID: content.NodeID, ParentID: parentID, Kind: kind, Name: name, Function: function,
			LineStart: state.line(lexical.span.start), LineEnd: state.line(lexical.span.end), SourceRole: content.Role,
		})
	}
	content.ScopeID = state.scopes[scope]
	content.Function = ""
	if scope > 0 {
		content.ExecutionConnectivity = string(behavior.ConnectivityUnknown)
		content.ExecutionRootIDs = nil
		content.InvokedTargetIDs = nil
	}
	content.Function = state.functionName(scope)
	return content, content.ScopeID != ""
}

func (state *javaScriptASTExtraction) evidence(content artifact.Content, node ast.Node, kind string) string {
	start, end, known := javaScriptASTSourceSpan(node, state.doc.program.File.Base(), len(state.doc.source))
	if !known {
		return ""
	}
	return state.graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, ScopeID: content.ScopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
		Function: content.Function, Line: state.line(start), Offset: state.absoluteOffset(start), OffsetKnown: true,
		Method: "javascript-ast", Kind: kind, Value: compactTextEvidenceValue(state.doc.source[start:end]),
	})
}

func javaScriptASTLiteralString(expression ast.Expression) string {
	if literal, ok := expression.(*ast.StringLiteral); ok && len(literal.Value) <= 2*maxJavaScriptCommandValueBytes+2 {
		value, valid := javaScriptASTUTF8String(literal.Value)
		if valid && len(value) <= maxJavaScriptCommandValueBytes {
			return value
		}
	}
	return ""
}

func javaScriptASTCallback(expression ast.Expression) bool {
	switch expression.(type) {
	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral, *ast.Identifier:
		return true
	}
	return false
}

func javaScriptASTProcessArity(method string, count int) bool {
	switch method {
	case "execFile":
		return count >= 1 && count <= 4
	case "execSync":
		return count >= 1 && count <= 2
	case "exec", "spawn", "spawnSync", "execFileSync":
		return count >= 1 && count <= 3
	}
	return false
}

func (state *javaScriptASTExtraction) process(content artifact.Content, call *ast.CallExpression, scope int, span javaScriptASTSpan, method, binding string, proof []string) {
	// Only complete proved strings/arrays enter the existing command grammar.
	// Unknown expressions and selection-changing options remain unresolved.
	commandState := newJavaScriptCommandState(javaScriptCommandPrescan{})
	start, end := int(call.LeftParenthesis)-state.doc.program.File.Base()+1, int(call.RightParenthesis)-state.doc.program.File.Base()
	if start < span.start || end < start || end > span.end {
		return
	}
	arguments := state.doc.source[start:end]
	if resolved, causal, ok := state.invocationArguments(call, scope, span.start); ok {
		if merged, retained := mergeJavaScriptASTValueEvidence(proof, causal); retained {
			arguments, proof = resolved, merged
		}
	}
	invocation, _, exact := commandState.resolveInvocation(strings.ToLower(method), arguments, "")
	if exact && !invocation.processAttempt {
		commandContent := content
		commandContent.SupportingEvidenceIDs = append(append([]string(nil), content.SupportingEvidenceIDs...), proof...)
		before := state.graph.CaptureGraphRange()
		if invocation.shellCommand != "" {
			AnalyzeShellLine(state.graph, commandContent, invocation.shellCommand, state.line(span.start), executionContextForContent(content), proof[0])
		} else {
			analyzeShellFields(state.graph, commandContent, invocation.argv, state.line(span.start), executionContextForContent(content), proof[0], 0, nil)
		}
		if !state.graph.CorroborateRange(before, proof) {
			addPartialCoverageOnce(state.graph, content.NodeID, javaScriptASTAnalysisArea, "causal command evidence exceeded retained bounds; affected derived facts were weakened or discarded")
			return
		}
		if len(state.graph.Operations) > before.OperationStart {
			return
		}
	}
	qualifiers := map[string]string{"api": "child_process." + method, "api_identity": "stable-javascript-binding-and-exact-call", "module_binding": binding, "argument_coverage": "unresolved", "unresolved_arguments": "dynamic or unsupported argv", "unresolved_executable": "dynamic or unsupported expression"}
	for key, value := range invocation.qualifiers {
		qualifiers[key] = value
	}
	// A literal argument remains useful even when options prevent proving
	// executable selection. It is not an executable resource or shell action.
	if literal, causal, known := state.stringValue(call.ArgumentList[0], scope, span.start); known && literal != "" {
		key := "executable_argument"
		if method == "exec" || method == "execSync" {
			key = "command_argument"
		}
		if merged, retained := mergeJavaScriptASTValueEvidence(proof, causal); retained {
			qualifiers[key], proof = literal, merged
		}
	}
	executable := invocation.executableOnly
	if executable != "" {
		qualifiers["argument_coverage"] = "executable-only"
		delete(qualifiers, "unresolved_executable")
	}
	bindings := behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, executable)))
	if exact && !invocation.processAttempt {
		// A closed command outside the shell vocabulary still proves the
		// process API request. Preserve it without inventing PATH resolution
		// or an operation for the unrecognized command's downstream behavior.
		value := invocation.shellCommand
		qualifiers["argument_coverage"], qualifiers["argument_encoding"] = "exact-command", "shell-command"
		if value == "" {
			encoded, _ := json.Marshal(invocation.argv[1:])
			value = string(encoded)
			qualifiers["argument_coverage"], qualifiers["argument_encoding"] = "exact-argv", "json-array"
		}
		delete(qualifiers, "unresolved_arguments")
		qualifiers["unresolved_executable"] = "runtime command resolution"
		bindings = append(bindings, behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, value), proof...))
	}
	state.graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, SourceFunction: content.Function,
		Kind: behavior.OperationProcessExecute, ResourceBindings: bindings,
		Qualifiers: qualifiers, EvidenceIDs: proof, Support: behavior.SupportCorroborated,
		Execution: executionContextForContent(content), Line: state.line(span.start),
	})
}
