package extract

import (
	"sort"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/grafana/sobek/ast"
)

type jxaShellReceiver struct {
	initial    ast.Node
	initialEnd int
	setting    ast.Node
	readyAt    int
	invalid    bool
}

// JXA uses the shared syntax parser, not Node module semantics. This profile
// admits direct program-level calls on a stable current-application receiver.
// Receiver aliases, escapes, other member uses, nested calls, and dynamic
// namespace access invalidate the proof instead of guessing host behavior.
func extractJXAShellCalls(graph *behavior.Graph, content artifact.Content, source string) {
	doc, err := parseJavaScriptAST(source, false)
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, "jxa-standard-additions", err.Error())
		return
	}
	bindings, err := inventoryJavaScriptASTBindings(doc)
	if err != nil {
		addPartialCoverageOnce(graph, content.NodeID, "jxa-standard-additions", err.Error())
		return
	}
	state := javaScriptASTExtraction{graph: graph, content: content, doc: doc, scopes: map[int]string{}, lines: []int{0}}
	for i, c := range source {
		if c == '\n' {
			state.lines = append(state.lines, i+1)
		}
	}
	receivers := map[*javaScriptASTBinding]*jxaShellReceiver{}
	allowedFactory := map[*ast.Identifier]bool{}
	factorySafe := len(bindings.dynamic) == 0 && bindings.lookup(0, "Application") == nil
	for _, located := range doc.nodes {
		call, ok := located.node.(*ast.CallExpression)
		if !ok || len(call.ArgumentList) != 0 || located.scope != 0 || !located.spanKnown {
			continue
		}
		dot, ok := call.Callee.(*ast.DotExpression)
		if !ok || dot.Identifier.Name.String() != "currentApplication" || !state.exactIdentifier(&dot.Identifier) {
			continue
		}
		name, ok := dot.Left.(*ast.Identifier)
		if !ok || name.Name.String() != "Application" || !state.exactIdentifier(name) {
			continue
		}
		// Only a complete simple declaration initializer proves this receiver.
		if located.parent < 0 {
			continue
		}
		declaration, ok := doc.nodes[located.parent].node.(*ast.Binding)
		if !ok || declaration.Initializer != call {
			continue
		}
		identifier, ok := declaration.Target.(*ast.Identifier)
		if !ok {
			continue
		}
		binding := bindings.lookup(0, identifier.Name.String())
		if binding == nil || binding.invalid || binding.initializer != call {
			continue
		}
		receivers[binding] = &jxaShellReceiver{initial: call, initialEnd: located.span.end}
		allowedFactory[name] = true
	}
	for _, located := range doc.nodes {
		switch node := located.node.(type) {
		case *ast.ThisExpression:
			factorySafe = false
		case *ast.DotExpression:
			if node.Identifier.Name.String() == "constructor" {
				factorySafe = false
			}
		case *ast.BracketExpression:
			if property := javaScriptASTLiteralString(node.Member); property == "" || property == "constructor" {
				factorySafe = false
			}
		}
		name, ok := located.node.(*ast.Identifier)
		if !ok || bindings.declarations[name] {
			continue
		}
		if name.Name.String() == "Application" && !allowedFactory[name] {
			factorySafe = false
		}
		if name.Name.String() == "globalThis" || name.Name.String() == "global" {
			factorySafe = false
		}
		receiver := receivers[bindings.lookup(located.scope, name.Name.String())]
		if receiver == nil {
			continue
		}
		if located.parent < 0 || located.scope != 0 || !state.exactIdentifier(name) {
			receiver.invalid = true
			continue
		}
		parent := doc.nodes[located.parent]
		dot, ok := parent.node.(*ast.DotExpression)
		if !ok || dot.Left != name || !state.exactIdentifier(&dot.Identifier) || parent.parent < 0 {
			receiver.invalid = true
			continue
		}
		consumer := doc.nodes[parent.parent]
		direct := consumer.parent >= 0
		if direct {
			_, direct = doc.nodes[consumer.parent].node.(*ast.ExpressionStatement)
		}
		if dot.Identifier.Name.String() == "includeStandardAdditions" {
			assignment, ok := consumer.node.(*ast.AssignExpression)
			if ok && direct && assignment.Left == dot && assignment.Operator.String() == "=" && consumer.spanKnown && consumer.span.start >= receiver.initialEnd {
				value, literal := assignment.Right.(*ast.BooleanLiteral)
				if literal && value.Value && receiver.setting == nil {
					receiver.setting, receiver.readyAt = assignment, consumer.span.end
					continue
				}
			}
		} else if dot.Identifier.Name.String() == "doShellScript" {
			if call, ok := consumer.node.(*ast.CallExpression); ok && direct && call.Callee == dot {
				continue
			}
		}
		receiver.invalid = true
	}
	addPartialCoverageOnce(graph, content.NodeID, "jxa-standard-additions", "only stable program-level current-application Standard Additions shell calls are modeled; other receivers, nested contexts and unresolved expressions remain partial")
	// currentApplication wrappers are not proved independent mutable objects.
	// An escaped or changed wrapper cannot leave another wrapper trusted.
	for _, receiver := range receivers {
		if receiver.invalid {
			factorySafe = false
		}
	}
	if !factorySafe {
		return
	}
	// Parser traversal order is structural; explicit source ordering avoids
	// relying on reflection field order for emitted facts.
	var calls []javaScriptASTNode
	for _, located := range doc.nodes {
		if _, ok := located.node.(*ast.CallExpression); !ok {
			continue
		}
		if len(calls) >= maxJavaScriptAPICalls {
			addPartialCoverageOnce(graph, content.NodeID, "jxa-standard-additions", "the bounded JXA call inventory was exceeded; shell calls were not inferred")
			return
		}
		calls = append(calls, located)
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].span.start < calls[j].span.start })
	for _, located := range calls {
		call, ok := located.node.(*ast.CallExpression)
		if !ok || !located.spanKnown || located.scope != 0 || len(call.ArgumentList) != 1 {
			continue
		}
		dot, ok := call.Callee.(*ast.DotExpression)
		if !ok || dot.Identifier.Name.String() != "doShellScript" {
			continue
		}
		name, ok := dot.Left.(*ast.Identifier)
		if !ok {
			continue
		}
		receiver := receivers[bindings.lookup(0, name.Name.String())]
		if receiver == nil || receiver.invalid || receiver.setting == nil || located.span.start < receiver.readyAt {
			continue
		}
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			break
		}
		argument, exact := call.ArgumentList[0].(*ast.StringLiteral)
		command := ""
		if exact && len(argument.Value.String()) <= maxOSAExpressionBytes {
			command = argument.Value.String()
		}
		initial := state.evidence(content, receiver.initial, "jxa-current-application")
		setting := state.evidence(content, receiver.setting, "jxa-standard-additions-enabled")
		proof := state.evidence(content, call, "jxa-shell-call")
		if initial == "" || setting == "" || proof == "" {
			continue
		}
		line := state.line(located.span.start)
		callContent := content
		callContent.SupportingEvidenceIDs = append(append([]string(nil), content.SupportingEvidenceIDs...), initial, setting)
		addOSAShellInvocation(graph, callContent, command, line, executionContextForContent(content), proof)
	}
}
