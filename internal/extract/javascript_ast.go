package extract

import (
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/grafana/sobek/ast"
	"github.com/grafana/sobek/parser"
)

const maxJavaScriptASTNodes = 1 << 20 // at most 64 MiB of located-node payload

type javaScriptASTSpan struct{ start, end int }
type javaScriptASTScope struct {
	parent    int
	kind      string
	function  string
	span      javaScriptASTSpan
	spanKnown bool
}
type javaScriptASTNode struct {
	node          ast.Node
	parent, scope int
	span          javaScriptASTSpan
	spanKnown     bool
}
type javaScriptASTDocument struct {
	source    string
	program   *ast.Program
	nodes     []javaScriptASTNode
	scopes    []javaScriptASTScope
	unlocated []int
}

// parseJavaScriptAST never loads source maps or modules and never instantiates
// a runtime. Syntax and budget failures discard the complete inventory. Nodes
// whose source spans cannot be validated remain explicitly unlocated.
func parseJavaScriptAST(source string, module bool) (*javaScriptASTDocument, error) {
	if len(source) > maxJavaScriptStructuralBytes || !utf8.ValidString(source) {
		return nil, fmt.Errorf("JavaScript AST input exceeds its byte bound or is not UTF-8")
	}
	tokens := 0
	_, valid := scanJavaScriptSyntax(source, 0, len(source), 0, func(javaScriptSyntaxEvent) bool { tokens++; return tokens <= maxJavaScriptStructuralTokens })
	if !valid {
		return nil, fmt.Errorf("JavaScript AST lexical preflight was incomplete or exceeded its token/depth budget")
	}
	options := []parser.Option{parser.WithDisableSourceMaps}
	if module {
		options = append(options, parser.IsModule)
	}
	program, err := parser.ParseFile(nil, "", source, 0, options...)
	if err != nil {
		return nil, fmt.Errorf("JavaScript AST syntax is unsupported or malformed")
	}
	doc := &javaScriptASTDocument{source: source, program: program, scopes: []javaScriptASTScope{{parent: -1, kind: "program", span: javaScriptASTSpan{0, len(source)}, spanKnown: true}}}
	seen := map[uintptr]bool{}
	scopeNodes := []int{-1}
	var walk func(reflect.Value, int, int, int) error
	walk = func(value reflect.Value, parent, scope, depth int) error {
		if !value.IsValid() {
			return nil
		}
		if depth > maxJavaScriptSyntaxNesting*4 {
			return fmt.Errorf("JavaScript AST traversal depth exceeded")
		}
		if value.Kind() == reflect.Interface {
			if value.IsNil() {
				return nil
			}
			return walk(value.Elem(), parent, scope, depth)
		}
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return nil
			}
			key := value.Pointer()
			if seen[key] {
				return nil
			}
			seen[key] = true
			if node, ok := value.Interface().(ast.Node); ok {
				if len(doc.nodes) >= maxJavaScriptASTNodes {
					return fmt.Errorf("JavaScript AST node budget exceeded")
				}
				kind := ""
				switch node.(type) {
				case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
					kind = "function"
				case *ast.BlockStatement:
					kind = "block"
				case *ast.CaseStatement:
					kind = "branch"
				case *ast.CatchStatement:
					kind = "catch"
				case *ast.ForStatement, *ast.ForInStatement, *ast.ForOfStatement, *ast.SwitchStatement:
					kind = "block"
				case *ast.ClassLiteral:
					kind = "class"
				case *ast.ClassStaticBlock:
					kind = "static-block"
				}
				// Operation contexts must also distinguish branches without
				// braces. They add no declarations to JavaScript name lookup.
				if kind == "" && parent >= 0 {
					switch owner := doc.nodes[parent].node.(type) {
					case *ast.IfStatement:
						if node == owner.Consequent || node == owner.Alternate {
							kind = "branch"
						}
					case *ast.ConditionalExpression:
						if node == owner.Consequent || node == owner.Alternate {
							kind = "branch"
						}
					case *ast.BinaryExpression:
						if node == owner.Right && (owner.Operator.String() == "&&" || owner.Operator.String() == "||" || owner.Operator.String() == "??") {
							kind = "branch"
						}
					case *ast.WhileStatement:
						if node == owner.Body {
							kind = "branch"
						}
					case *ast.DoWhileStatement:
						if node == owner.Body {
							kind = "branch"
						}
					}
				}
				if kind != "" {
					doc.scopes = append(doc.scopes, javaScriptASTScope{parent: scope, kind: kind})
					scopeNodes = append(scopeNodes, len(doc.nodes))
					scope = len(doc.scopes) - 1
				}
				doc.nodes = append(doc.nodes, javaScriptASTNode{node: node, parent: parent, scope: scope})
				parent = len(doc.nodes) - 1
			}
			return walk(value.Elem(), parent, scope, depth+1)
		}
		switch value.Kind() {
		case reflect.Struct:
			for i := 0; i < value.NumField(); i++ {
				name := value.Type().Field(i).Name
				// Parser caches and source metadata are not lexical children.
				if name == "DeclarationList" || name == "ImportEntries" || name == "ExportEntries" || name == "File" || name == "Source" {
					continue
				}
				if value.Field(i).CanInterface() {
					if err := walk(value.Field(i), parent, scope, depth+1); err != nil {
						return err
					}
				}
			}
		case reflect.Slice:
			if value.Type().Elem().Kind() == reflect.Uint8 {
				return nil
			}
			for i := 0; i < value.Len(); i++ {
				if err := walk(value.Index(i), parent, scope, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(reflect.ValueOf(program.Body), -1, 0, 0); err != nil {
		return nil, err
	}
	// Idx methods may recurse through expression children. Establish the AST
	// depth bound first, before invoking them on attacker-controlled trees.
	for i := range doc.nodes {
		node := doc.nodes[i].node
		start, end, located := javaScriptASTSourceSpan(node, program.File.Base(), len(source))
		if !located {
			doc.unlocated = append(doc.unlocated, i)
			continue
		}
		if identifier, ok := node.(*ast.Identifier); ok && source[start:end] != identifier.Name.String() {
			doc.unlocated = append(doc.unlocated, i)
			continue
		}
		doc.nodes[i].span = javaScriptASTSpan{start, end}
		doc.nodes[i].spanKnown = true
	}
	for i := 1; i < len(doc.scopes); i++ {
		doc.scopes[i].span = doc.nodes[scopeNodes[i]].span
		doc.scopes[i].spanKnown = doc.nodes[scopeNodes[i]].spanKnown
		if doc.scopes[i].kind == "function" {
			doc.scopes[i].function = fmt.Sprintf("function@%d", doc.scopes[i].span.start)
			if function, ok := doc.nodes[scopeNodes[i]].node.(*ast.FunctionLiteral); ok && function.Name != nil {
				start, end, known := javaScriptASTSourceSpan(function.Name, program.File.Base(), len(source))
				if known && source[start:end] == function.Name.Name.String() {
					doc.scopes[i].function = function.Name.Name.String()
				}
			}
		}
	}
	return doc, nil
}

func javaScriptASTSourceSpan(node ast.Node, base, length int) (start, end int, known bool) {
	// Upstream span accessors are not total for every valid syntax node (for
	// example an empty fallthrough case). Treat such metadata as unavailable.
	defer func() {
		if recover() != nil {
			start, end, known = 0, 0, false
		}
	}()
	start, end = int(node.Idx0())-base, int(node.Idx1())-base
	known = start >= 0 && end >= start && end <= length
	return
}
