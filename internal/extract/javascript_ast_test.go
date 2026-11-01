package extract

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/grafana/sobek/ast"
)

func TestJavaScriptASTPreservesSpansAndScopes(t *testing.T) {
	source := `; (function(){try{var cp=require("child_process"),fs=require("fs");function run(value){cp.exec(value);}run(command);}catch(error){}})();const español=1;async function load(){return import("module");}`
	doc, err := parseJavaScriptAST(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.scopes) < 5 {
		t.Fatalf("missing nested scopes: %#v", doc.scopes)
	}
	bindings, calls := 0, 0
	for _, located := range doc.nodes {
		if located.parent >= len(doc.nodes) || located.scope >= len(doc.scopes) {
			t.Fatal("dangling structural reference")
		}
		text := ""
		if located.spanKnown {
			text = source[located.span.start:located.span.end]
		}
		switch located.node.(type) {
		case *ast.Binding:
			bindings++
		case *ast.CallExpression:
			if text == `cp.exec(value)` {
				calls++
			}
		}
	}
	if bindings < 3 || calls != 1 {
		t.Fatalf("missing exact declarations/calls: bindings=%d calls=%d", bindings, calls)
	}
	for i, scope := range doc.scopes {
		if i > 0 && (scope.parent < 0 || scope.parent >= i) {
			t.Fatalf("invalid scope parent: %#v", scope)
		}
	}
}

func TestJavaScriptASTRejectsMalformedOrOverBudgetSource(t *testing.T) {
	for _, source := range []string{`function broken( {`, "const bad=\xff;", strings.Repeat("(", maxJavaScriptSyntaxNesting+1) + "value" + strings.Repeat(")", maxJavaScriptSyntaxNesting+1), strings.Repeat("x", maxJavaScriptStructuralBytes+1), strings.Repeat("a+", 1000) + "a;"} {
		if doc, err := parseJavaScriptAST(source, false); err == nil || doc != nil {
			t.Fatalf("invalid/budget-exhausted source retained an AST: %d bytes", len(source))
		}
	}
}

func TestJavaScriptASTDisablesSourceMaps(t *testing.T) {
	for _, suffix := range []string{"file:///nonexistent/private.map", "https://example.invalid/source.map", "data:application/json;base64,not-valid"} {
		if _, err := parseJavaScriptAST("const value=1;\n//# sourceMappingURL="+suffix, false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJavaScriptASTUsesExplicitModuleGrammar(t *testing.T) {
	source := `import * as cp from "node:child_process"; export function run(){cp.exec(command);}`
	if _, err := parseJavaScriptAST(source, true); err != nil {
		t.Fatal(err)
	}
	if doc, err := parseJavaScriptAST(source, false); err == nil || doc != nil {
		t.Fatal("module syntax silently accepted as script")
	}
}

func TestJavaScriptASTDoesNotGuessMissingImportOffset(t *testing.T) {
	doc, err := parseJavaScriptAST(`import("module");`, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.unlocated) == 0 {
		t.Fatal("pinned parser's missing import position was silently guessed")
	}
	for _, i := range doc.unlocated {
		if doc.nodes[i].spanKnown {
			t.Fatal("unlocated node was marked exact")
		}
	}
}

func TestJavaScriptASTNodePayloadBudget(t *testing.T) {
	if size := unsafe.Sizeof(javaScriptASTNode{}); size > 64 || size*maxJavaScriptASTNodes > 64<<20 {
		t.Fatalf("AST inventory payload budget exceeded: node=%d", size)
	}
}

func TestJavaScriptASTHandlesEmptyFallthroughCaseSpans(t *testing.T) {
	doc, err := parseJavaScriptAST(`switch(value){case 1:case 2:run();}`, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.unlocated) == 0 {
		t.Fatal("unsupported upstream empty-case metadata was not disclosed")
	}
	found := false
	for _, node := range doc.nodes {
		if node.spanKnown && doc.source[node.span.start:node.span.end] == "run()" {
			found = true
		}
	}
	if !found {
		t.Fatal("unlocated case discarded independently located call")
	}
}

func TestJavaScriptASTDoesNotUseDecodedIdentifierAsSourceSpan(t *testing.T) {
	doc, err := parseJavaScriptAST(`var \u0063p = require("child_process");`, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, located := range doc.nodes {
		if identifier, ok := located.node.(*ast.Identifier); ok && identifier.Name.String() == "cp" {
			found = true
			if located.spanKnown {
				t.Fatal("decoded escaped name was presented as exact source")
			}
		}
	}
	if !found {
		t.Fatal("missing escaped identifier")
	}
}

func FuzzJavaScriptAST(f *testing.F) {
	for _, source := range []string{"const value=1;", `switch(value){case 1:case 2:run();}`, `import("module");`, "(()=>{let x; x=value;})()"} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1<<20 {
			return
		}
		doc, err := parseJavaScriptAST(source, false)
		if err != nil {
			if doc != nil {
				t.Fatal("failed parse retained partial inventory")
			}
			return
		}
		if _, err := inventoryJavaScriptASTBindings(doc); err != nil {
			return
		}
		for _, node := range doc.nodes {
			if node.spanKnown && (node.span.start < 0 || node.span.end < node.span.start || node.span.end > len(source)) {
				t.Fatal("invalid located span")
			}
		}
	})
}
