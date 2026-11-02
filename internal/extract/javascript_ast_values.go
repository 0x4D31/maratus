package extract

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/grafana/sobek/ast"
	"github.com/grafana/sobek/unistring"
)

type javaScriptASTValueProof struct {
	node  ast.Node
	scope int
}

type javaScriptASTString struct {
	value  string
	proofs []javaScriptASTValueProof
}

// This is a closed string transformer over the syntax inventory, not a
// JavaScript evaluator. It never resolves calls, objects, mutable arrays,
// coercions, environment values, or values captured by another function.
type javaScriptASTValues struct {
	bindings            *javaScriptASTBindings
	cache               map[*javaScriptASTBinding]javaScriptASTString
	bytes               int
	work                int64
	limited             bool
	encodingUnsupported bool
}

func javaScriptASTUTF8String(value unistring.String) (string, bool) {
	units := value.AsUtf16()
	for i := 1; i < len(units); i++ {
		unit := units[i]
		if unit < 0xd800 || unit > 0xdfff {
			continue
		}
		if unit >= 0xdc00 || i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
			return "", false
		}
		i++
	}
	text := value.String()
	return text, utf8.ValidString(text)
}

func newJavaScriptASTValues(bindings *javaScriptASTBindings) *javaScriptASTValues {
	return &javaScriptASTValues{bindings: bindings, cache: map[*javaScriptASTBinding]javaScriptASTString{}}
}

func (v *javaScriptASTValues) charge(bytes int) bool {
	if v.limited || int64(bytes)+1 > maxTextVariableExpansionWorkBytes-v.work {
		v.limited = true
		return false
	}
	v.work += int64(bytes) + 1
	return true
}

func (v *javaScriptASTValues) resolve(expression ast.Expression, scope, useOffset, depth int) (javaScriptASTString, bool) {
	if expression == nil || depth > maxJavaScriptCommandExpressionDepth || v.limited {
		if depth > maxJavaScriptCommandExpressionDepth {
			v.limited = true
		}
		return javaScriptASTString{}, false
	}
	doc := v.bindings.doc
	start, end, known := javaScriptASTSourceSpan(expression, doc.program.File.Base(), len(doc.source))
	if !known || !v.charge(end-start) {
		return javaScriptASTString{}, false
	}
	result := javaScriptASTString{proofs: []javaScriptASTValueProof{{expression, scope}}}
	join := func(part javaScriptASTString) bool {
		if len(part.value) > maxJavaScriptCommandValueBytes-len(result.value) {
			v.limited = true
			return false
		}
		result.value += part.value
		for _, proof := range part.proofs {
			duplicate := false
			for _, prior := range result.proofs {
				if prior.node == proof.node && prior.scope == proof.scope {
					duplicate = true
					break
				}
			}
			if !duplicate {
				if len(result.proofs) >= maxJavaScriptCommandProofs {
					v.limited = true
					return false
				}
				result.proofs = append(result.proofs, proof)
			}
		}
		return true
	}
	switch node := expression.(type) {
	case *ast.StringLiteral:
		if len(node.Value) > 2*maxJavaScriptCommandValueBytes+2 {
			v.limited = true
			return javaScriptASTString{}, false
		}
		var valid bool
		result.value, valid = javaScriptASTUTF8String(node.Value)
		if !valid {
			v.encodingUnsupported = true
			return javaScriptASTString{}, false
		}
	case *ast.Identifier:
		if doc.source[start:end] != node.Name.String() || v.bindings.runtimeMutated {
			return javaScriptASTString{}, false
		}
		for current := scope; current >= 0; current = doc.scopes[current].parent {
			if v.bindings.dynamic[current] {
				return javaScriptASTString{}, false
			}
		}
		binding := v.bindings.lookup(scope, node.Name.String())
		if binding == nil || binding.invalid || binding.initializer == nil {
			return javaScriptASTString{}, false
		}
		declaration := doc.nodes[binding.declaration]
		// Lexical strings and function-local vars cannot be changed through
		// a global-object alias. A top-level var needs a host-specific proof.
		_, lexical := declaration.node.(*ast.LexicalDeclaration)
		_, variable := declaration.node.(*ast.VariableStatement)
		localVariable := variable && v.bindings.functionScope(declaration.scope) > 0
		if (!lexical && !localVariable) || !declaration.spanKnown || v.bindings.functionScope(scope) != v.bindings.functionScope(declaration.scope) {
			return javaScriptASTString{}, false
		}
		ancestor := scope
		for ancestor >= 0 && ancestor != declaration.scope {
			ancestor = doc.scopes[ancestor].parent
		}
		_, initializedAt, located := javaScriptASTSourceSpan(binding.initializer, doc.program.File.Base(), len(doc.source))
		if ancestor < 0 || !located || initializedAt > useOffset {
			return javaScriptASTString{}, false
		}
		value, cached := v.cache[binding]
		if !cached {
			value, known = v.resolve(binding.initializer, declaration.scope, int(binding.identifier.Idx)-doc.program.File.Base(), depth+1)
			if !known {
				return javaScriptASTString{}, false
			}
			value.proofs = append(value.proofs, javaScriptASTValueProof{declaration.node, declaration.scope})
			if len(value.proofs) > maxJavaScriptCommandProofs || len(v.cache) >= maxJavaScriptCommandScalars || len(value.value) > maxJavaScriptCommandValueTotalBytes-v.bytes {
				v.limited = true
				return javaScriptASTString{}, false
			}
			v.cache[binding] = value
			v.bytes += len(value.value)
		}
		if !join(value) {
			return javaScriptASTString{}, false
		}
	case *ast.BinaryExpression:
		if node.Operator.String() != "+" {
			return javaScriptASTString{}, false
		}
		for _, operand := range []ast.Expression{node.Left, node.Right} {
			value, ok := v.resolve(operand, scope, useOffset, depth+1)
			if !ok || !join(value) {
				return javaScriptASTString{}, false
			}
		}
	case *ast.TemplateLiteral:
		if node.Tag != nil || len(node.Expressions) > maxJavaScriptCommandInterpolations || len(node.Elements) != len(node.Expressions)+1 {
			return javaScriptASTString{}, false
		}
		for i, element := range node.Elements {
			if element == nil || !element.Valid {
				return javaScriptASTString{}, false
			}
			if len(element.Parsed) > 2*maxJavaScriptCommandValueBytes+2 {
				v.limited = true
				return javaScriptASTString{}, false
			}
			part, valid := javaScriptASTUTF8String(element.Parsed)
			if !valid {
				v.encodingUnsupported = true
				return javaScriptASTString{}, false
			}
			if !join(javaScriptASTString{value: part}) {
				return javaScriptASTString{}, false
			}
			if i < len(node.Expressions) {
				value, ok := v.resolve(node.Expressions[i], scope, useOffset, depth+1)
				if !ok || !join(value) {
					return javaScriptASTString{}, false
				}
			}
		}
	default:
		return javaScriptASTString{}, false
	}
	if len(result.value) > maxJavaScriptCommandValueBytes || !v.charge(len(result.value)) {
		v.limited = true
		return javaScriptASTString{}, false
	}
	return result, true
}

func (state *javaScriptASTExtraction) stringValue(expression ast.Expression, scope, offset int) (string, []string, bool) {
	if literal, ok := expression.(*ast.StringLiteral); ok {
		_, _, known := javaScriptASTSourceSpan(literal, state.doc.program.File.Base(), len(state.doc.source))
		if len(literal.Value) > 2*maxJavaScriptCommandValueBytes+2 {
			if state.values != nil {
				state.values.limited = true
			}
			return "", nil, false
		}
		value, valid := javaScriptASTUTF8String(literal.Value)
		if !valid && state.values != nil {
			state.values.encodingUnsupported = true
		}
		if !known || !valid || len(value) > maxJavaScriptCommandValueBytes {
			return "", nil, false
		}
		// The call evidence already contains this complete literal. Preserve
		// existing literal coverage without spending a new binding budget.
		return value, nil, true
	}
	if state.values == nil {
		return "", nil, false
	}
	value, ok := state.values.resolve(expression, scope, offset, 0)
	if !ok {
		return "", nil, false
	}
	useContent, known := state.scopeContent(scope)
	if !known {
		return "", nil, false
	}
	for _, origin := range value.proofs {
		content, known := state.scopeContent(origin.scope)
		if !known || content.Function != "" && (content.ScopeID != useContent.ScopeID || content.Function != useContent.Function) {
			addPartialCoverageOnce(state.graph, state.content.NodeID, "javascript-ast-value-context", "a lexical value required incompatible function/block evidence contexts; its operand remains unknown")
			return "", nil, false
		}
	}
	proof := make([]string, 0, len(value.proofs))
	for _, origin := range value.proofs {
		if id := state.valueEvidence[origin]; id != "" {
			proof = append(proof, id)
			continue
		}
		if len(state.valueEvidence) >= maxJavaScriptAPICalls*maxJavaScriptCommandProofs {
			state.values.limited = true
			return "", nil, false
		}
		content, known := state.scopeContent(origin.scope)
		if !known {
			return "", nil, false
		}
		id := state.evidence(content, origin.node, "javascript-static-value")
		if id == "" {
			state.graph.MarkWorkOmitted()
			addPartialCoverageOnce(state.graph, state.content.NodeID, "javascript-ast-value-analysis", "value evidence could not be retained within graph bounds; its operand remains unknown")
			return "", nil, false
		}
		if state.valueEvidence == nil {
			state.valueEvidence = map[javaScriptASTValueProof]string{}
		}
		state.valueEvidence[origin] = id
		proof = append(proof, id)
	}
	return value.value, proof, true
}

func mergeJavaScriptASTValueEvidence(base, extra []string) ([]string, bool) {
	result := append([]string(nil), base...)
	for _, id := range extra {
		found := false
		for _, prior := range result {
			found = found || prior == id
		}
		if !found {
			if id == "" || len(result) >= maxJavaScriptCommandProofs+3 {
				return base, false
			}
			result = append(result, id)
		}
	}
	return result, true
}

func encodeJavaScriptASTArgument(value any) (string, bool) {
	var out strings.Builder
	encoder := json.NewEncoder(&out)
	// This is an internal literal for the shared argument parser, not HTML.
	// Escaping '&', '<', or '>' would require an unrelated Unicode decoder.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", false
	}
	return strings.TrimSuffix(out.String(), "\n"), true
}

// Requote only complete proved strings and literal arrays. Other argument
// syntax is preserved for the existing invocation recognizer to reject or
// model conservatively; no unknown value is serialized as an empty string.
func (state *javaScriptASTExtraction) invocationArguments(call *ast.CallExpression, scope, offset int) (string, []string, bool) {
	var args, proof []string
	for _, argument := range call.ArgumentList {
		start, end, known := javaScriptASTSourceSpan(argument, state.doc.program.File.Base(), len(state.doc.source))
		if !known {
			return "", nil, false
		}
		text := state.doc.source[start:end]
		if value, ids, ok := state.stringValue(argument, scope, offset); ok {
			if encoded, known := encodeJavaScriptASTArgument(value); known {
				text, proof = encoded, append(proof, ids...)
			}
		} else if array, ok := argument.(*ast.ArrayLiteral); ok && len(array.Value) <= maxJavaScriptCommandArrayArguments {
			values := []string{}
			var ids []string
			complete := true
			for _, element := range array.Value {
				value, causal, ok := state.stringValue(element, scope, offset)
				if !ok {
					complete = false
					break
				}
				values, ids = append(values, value), append(ids, causal...)
			}
			if complete {
				if encoded, known := encodeJavaScriptASTArgument(values); known {
					text, proof = encoded, append(proof, ids...)
				}
			}
		}
		args = append(args, text)
	}
	proof, known := mergeJavaScriptASTValueEvidence(nil, proof)
	if !known || len(proof) > maxJavaScriptCommandProofs || len(strings.Join(args, ",")) > maxJavaScriptAPICallBytes {
		addPartialCoverageOnce(state.graph, state.content.NodeID, "javascript-ast-value-analysis", "resolved command values or causal evidence exceeded retained bounds; arguments remain unresolved")
		return "", nil, false
	}
	return strings.Join(args, ","), proof, true
}
