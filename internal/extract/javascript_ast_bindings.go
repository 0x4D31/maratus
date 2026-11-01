package extract

import (
	"fmt"
	"strings"

	"github.com/grafana/sobek/ast"
)

const maxJavaScriptASTBindings = 262144

type javaScriptASTBindingKey struct {
	scope int
	name  string
}
type javaScriptASTBinding struct {
	key           javaScriptASTBindingKey
	declaration   int
	identifier    *ast.Identifier
	initializer   ast.Expression
	namespace     string
	invalid       bool
	initializedAt int
}
type javaScriptASTBindings struct {
	doc            *javaScriptASTDocument
	bindings       map[javaScriptASTBindingKey]*javaScriptASTBinding
	dynamic        map[int]bool
	invalidModules map[string]bool
	declarations   map[*ast.Identifier]bool
	runtimeMutated bool
}

func (state *javaScriptASTBindings) functionScope(scope int) int {
	for scope > 0 {
		kind := state.doc.scopes[scope].kind
		if kind == "function" || kind == "static-block" {
			break
		}
		scope = state.doc.scopes[scope].parent
	}
	return scope
}

func (state *javaScriptASTBindings) lookup(scope int, name string) *javaScriptASTBinding {
	for scope >= 0 {
		if binding := state.bindings[javaScriptASTBindingKey{scope, name}]; binding != nil {
			return binding
		}
		scope = state.doc.scopes[scope].parent
	}
	return nil
}

func (state *javaScriptASTBindings) declare(scope int, target ast.Expression, node int, initializer ast.Expression) error {
	var names []*ast.Identifier
	var collect func(ast.Expression)
	collect = func(value ast.Expression) {
		switch value := value.(type) {
		case *ast.Identifier:
			names = append(names, value)
		case *ast.ArrayPattern:
			for _, element := range value.Elements {
				collect(element)
			}
			collect(value.Rest)
		case *ast.ObjectPattern:
			for _, property := range value.Properties {
				switch property := property.(type) {
				case *ast.PropertyShort:
					names = append(names, &property.Name)
				case *ast.PropertyKeyed:
					collect(property.Value)
				}
			}
			collect(value.Rest)
		case *ast.AssignExpression:
			collect(value.Left)
		case *ast.Binding:
			collect(value.Target)
		case *ast.SpreadElement:
			collect(value.Expression)
		}
	}
	collect(target)
	for _, name := range names {
		state.declarations[name] = true
		key := javaScriptASTBindingKey{scope, name.Name.String()}
		if previous := state.bindings[key]; previous != nil {
			previous.invalid = true
			continue
		}
		if len(state.bindings) >= maxJavaScriptASTBindings {
			return fmt.Errorf("JavaScript AST distinct binding budget exceeded")
		}
		init := initializer
		if _, simple := target.(*ast.Identifier); !simple {
			init = nil
		}
		start, end, known := javaScriptASTSourceSpan(name, state.doc.program.File.Base(), len(state.doc.source))
		invalid := !known || state.doc.source[start:end] != name.Name.String()
		state.bindings[key] = &javaScriptASTBinding{key: key, declaration: node, identifier: name, initializer: init, invalid: invalid}
	}
	return nil
}

func inventoryJavaScriptASTBindings(doc *javaScriptASTDocument) (*javaScriptASTBindings, error) {
	state := &javaScriptASTBindings{doc: doc, bindings: map[javaScriptASTBindingKey]*javaScriptASTBinding{}, dynamic: map[int]bool{}, invalidModules: map[string]bool{}, declarations: map[*ast.Identifier]bool{}}
	for i, located := range doc.nodes {
		scope := located.scope
		var err error
		declareList := func(list []*ast.Binding, varScope bool) {
			if varScope {
				scope = state.functionScope(scope)
			}
			for _, binding := range list {
				if err == nil {
					err = state.declare(scope, binding.Target, i, binding.Initializer)
				}
			}
		}
		switch node := located.node.(type) {
		case *ast.VariableStatement:
			declareList(node.List, true)
		case *ast.LexicalDeclaration:
			declareList(node.List, false)
		case *ast.ForLoopInitializerVarDeclList:
			declareList(node.List, true)
		case *ast.ForLoopInitializerLexicalDecl:
			declareList(node.LexicalDeclaration.List, false)
		case *ast.ForIntoVar:
			err = state.declare(state.functionScope(scope), node.Binding.Target, i, nil)
		case *ast.ForDeclaration:
			err = state.declare(scope, node.Target, i, nil)
		case *ast.ParameterList:
			for _, parameter := range node.List {
				if err == nil {
					err = state.declare(scope, parameter.Target, i, nil)
				}
			}
			if err == nil {
				err = state.declare(scope, node.Rest, i, nil)
			}
		case *ast.CatchStatement:
			err = state.declare(scope, node.Parameter, i, nil)
		case *ast.FunctionDeclaration:
			if node.Function.Name != nil {
				err = state.declare(scope, node.Function.Name, i, nil)
				// Sloppy-script Annex B can also expose a block function as a
				// var binding. Block that outer identity rather than choosing a
				// strictness-dependent interpretation.
				if outer := state.functionScope(scope); err == nil && outer != scope {
					err = state.declare(outer, node.Function.Name, i, nil)
				}
			}
		case *ast.FunctionLiteral:
			if node.Name != nil {
				err = state.declare(scope, node.Name, i, nil)
			}
		case *ast.ClassDeclaration:
			if node.Class.Name != nil {
				err = state.declare(scope, node.Class.Name, i, nil)
			}
		case *ast.ClassLiteral:
			if node.Name != nil {
				err = state.declare(scope, node.Name, i, nil)
			}
		case *ast.ImportDeclaration:
			if clause := node.ImportClause; clause != nil {
				if clause.ImportedDefaultBinding != nil {
					err = state.declare(scope, clause.ImportedDefaultBinding, i, nil)
				}
				if clause.NameSpaceImport != nil && err == nil {
					err = state.declare(scope, &ast.Identifier{Name: clause.NameSpaceImport.ImportedBinding}, i, nil)
				}
				if clause.NamedImports != nil {
					for _, item := range clause.NamedImports.ImportsList {
						if err != nil {
							break
						}
						name := item.Alias
						if name == "" {
							name = item.IdentifierName
						}
						err = state.declare(scope, &ast.Identifier{Name: name}, i, nil)
					}
				}
			}
		case *ast.WithStatement:
			state.dynamic[state.functionScope(scope)] = true
		}
		if err != nil {
			return nil, err
		}
	}
	for _, binding := range state.bindings {
		if binding.invalid || state.lookup(binding.key.scope, "require") != nil {
			continue
		}
		conditional := false
		for parent := doc.nodes[binding.declaration].parent; parent >= 0; parent = doc.nodes[parent].parent {
			switch doc.nodes[parent].node.(type) {
			case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
				parent = -1
			case *ast.IfStatement, *ast.ForStatement, *ast.ForInStatement, *ast.ForOfStatement, *ast.WhileStatement, *ast.DoWhileStatement, *ast.SwitchStatement:
				conditional = true
			}
			if parent < 0 {
				break
			}
		}
		if conditional {
			continue
		}
		call, ok := binding.initializer.(*ast.CallExpression)
		if !ok || len(call.ArgumentList) != 1 {
			continue
		}
		loader, ok := call.Callee.(*ast.Identifier)
		if !ok || loader.Name.String() != "require" {
			continue
		}
		start, end, known := javaScriptASTSourceSpan(loader, doc.program.File.Base(), len(doc.source))
		if !known || doc.source[start:end] != "require" {
			continue
		}
		literal, ok := call.ArgumentList[0].(*ast.StringLiteral)
		if !ok {
			continue
		}
		_, end, known = javaScriptASTSourceSpan(call, doc.program.File.Base(), len(doc.source))
		if !known {
			continue
		}
		binding.initializedAt = end
		module := strings.TrimPrefix(literal.Value.String(), "node:")
		switch module {
		case "child_process", "fs", "fs/promises", "os", "path", "http", "https", "crypto", "dns", "dns/promises", "net", "tls", "zlib":
			binding.namespace = module
		}
	}
	state.invalidate()
	return state, nil
}

func (state *javaScriptASTBindings) invalidate() {
	root := func(expression ast.Expression) *ast.Identifier {
		for depth := 0; depth < maxJavaScriptSyntaxNesting; depth++ {
			switch value := expression.(type) {
			case *ast.Identifier:
				return value
			case *ast.DotExpression:
				expression = value.Left
			case *ast.BracketExpression:
				expression = value.Left
			default:
				return nil
			}
		}
		return nil
	}
	var mutate func(ast.Expression, int)
	mutate = func(expression ast.Expression, scope int) {
		switch target := expression.(type) {
		case *ast.ArrayPattern:
			for _, element := range target.Elements {
				mutate(element, scope)
			}
			mutate(target.Rest, scope)
			return
		case *ast.ObjectPattern:
			for _, property := range target.Properties {
				switch property := property.(type) {
				case *ast.PropertyShort:
					mutate(&property.Name, scope)
				case *ast.PropertyKeyed:
					mutate(property.Value, scope)
				}
			}
			mutate(target.Rest, scope)
			return
		case *ast.AssignExpression:
			mutate(target.Left, scope)
			return
		}
		identifier := root(expression)
		if identifier == nil {
			return
		}
		binding := state.lookup(scope, identifier.Name.String())
		if binding == nil {
			if identifier.Name.String() == "require" {
				state.runtimeMutated = true
			}
			if identifier.Name.String() == "globalThis" || identifier.Name.String() == "global" {
				member := expression
				for member != identifier {
					switch value := member.(type) {
					case *ast.DotExpression:
						if value.Left == identifier && value.Identifier.Name.String() == "require" {
							state.runtimeMutated = true
						}
						member = value.Left
					case *ast.BracketExpression:
						property := javaScriptASTLiteralString(value.Member)
						if value.Left == identifier && (property == "" || property == "require") {
							state.runtimeMutated = true
						}
						member = value.Left
					default:
						member = identifier
					}
				}
			}
			return
		}
		if expression == identifier {
			binding.invalid = true
		} else if binding.namespace != "" {
			state.invalidateModule(binding.namespace)
		}
	}
	for _, located := range state.doc.nodes {
		switch node := located.node.(type) {
		case *ast.AssignExpression:
			mutate(node.Left, located.scope)
		case *ast.ForIntoExpression:
			mutate(node.Expression, located.scope)
		case *ast.UnaryExpression:
			if op := node.Operator.String(); op == "++" || op == "--" || op == "delete" {
				mutate(node.Operand, located.scope)
			}
		case *ast.CallExpression:
			if identifier, ok := node.Callee.(*ast.Identifier); ok && identifier.Name.String() == "eval" && state.lookup(located.scope, "eval") == nil {
				state.dynamic[state.functionScope(located.scope)] = true
			}
		case *ast.PropertyShort:
			if !state.declarations[&node.Name] {
				if binding := state.lookup(located.scope, node.Name.Name.String()); binding != nil && binding.namespace != "" {
					state.invalidateModule(binding.namespace)
				}
			}
		case *ast.Identifier:
			if state.declarations[node] {
				continue
			}
			if located.parent >= 0 {
				if property, ok := state.doc.nodes[located.parent].node.(*ast.PropertyKeyed); ok && !property.Computed && property.Key == node {
					continue
				}
			}
			if state.lookup(located.scope, node.Name.String()) == nil {
				if node.Name.String() == "Function" {
					read := false
					if located.parent >= 0 {
						parent := state.doc.nodes[located.parent].node
						if unary, ok := parent.(*ast.UnaryExpression); ok && unary.Operator.String() == "typeof" {
							read = true
						}
						if dot, ok := parent.(*ast.DotExpression); ok && dot.Left == node && dot.Identifier.Name.String() == "prototype" {
							read = true
							for ancestor := located.parent; ancestor >= 0; ancestor = state.doc.nodes[ancestor].parent {
								switch member := state.doc.nodes[ancestor].node.(type) {
								case *ast.DotExpression:
									if member.Identifier.Name.String() == "constructor" {
										read = false
									}
								case *ast.BracketExpression:
									property := javaScriptASTLiteralString(member.Member)
									if property == "" || property == "constructor" {
										read = false
									}
								default:
									ancestor = -1
								}
								if ancestor < 0 {
									break
								}
							}
						}
					}
					if !read {
						state.dynamic[state.functionScope(located.scope)] = true
					}
				}
				if node.Name.String() == "eval" {
					call, direct := (*ast.CallExpression)(nil), false
					if located.parent >= 0 {
						call, direct = state.doc.nodes[located.parent].node.(*ast.CallExpression)
					}
					if !direct || call.Callee != node {
						state.dynamic[state.functionScope(located.scope)] = true
					}
				}
			}
			binding := state.lookup(located.scope, node.Name.String())
			if binding == nil || binding.namespace == "" {
				continue
			}
			if located.parent >= 0 {
				parent := state.doc.nodes[located.parent]
				if property, ok := parent.node.(*ast.PropertyKeyed); ok && !property.Computed && property.Key == node {
					continue
				}
				// A member read consumes a property, not the namespace object.
				// Writes through either spelling are handled separately above.
				if dot, ok := parent.node.(*ast.DotExpression); ok && dot.Left == node && located.spanKnown {
					continue
				}
				if bracket, ok := parent.node.(*ast.BracketExpression); ok && bracket.Left == node && located.spanKnown {
					continue
				}
				if assignment, ok := parent.node.(*ast.AssignExpression); ok && assignment.Left == node {
					continue
				}
			}
			state.invalidateModule(binding.namespace)
		}
	}
}

func (state *javaScriptASTBindings) invalidateModule(module string) {
	state.invalidModules[module] = true
	// These namespaces expose the same mutable object through both spellings.
	switch module {
	case "fs":
		state.invalidModules["fs/promises"] = true
	case "dns":
		state.invalidModules["dns/promises"] = true
	}
}

func (state *javaScriptASTBindings) namespace(scope int, name string, offset int) (*javaScriptASTBinding, bool) {
	if state.runtimeMutated {
		return nil, false
	}
	for current := scope; current >= 0; current = state.doc.scopes[current].parent {
		if state.dynamic[current] {
			return nil, false
		}
	}
	binding := state.lookup(scope, name)
	if binding == nil || binding.invalid || binding.namespace == "" || state.invalidModules[binding.namespace] {
		return nil, false
	}
	declaration := state.doc.nodes[binding.declaration]
	if !declaration.spanKnown || binding.initializedAt > offset {
		return nil, false
	}
	// A var declaration can be visible outside its initializing block. Source
	// order alone cannot prove that a conditional initializer was reached.
	ancestor := scope
	for ancestor >= 0 && ancestor != declaration.scope {
		ancestor = state.doc.scopes[ancestor].parent
	}
	if ancestor < 0 {
		return nil, false
	}
	return binding, true
}
