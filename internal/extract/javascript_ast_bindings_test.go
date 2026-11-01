package extract

import (
	"testing"

	"github.com/grafana/sobek/ast"
)

func TestJavaScriptASTNamespaceBindingScopes(t *testing.T) {
	tests := []struct {
		name, source string
		module       bool
		want         int
	}{
		{"comma declarations", `var cp=require("child_process"),fs=require("fs");cp.exec(command);`, false, 1},
		{"member read is not object escape", `const cp=require("child_process");const method=cp.exec;cp.exec(command);`, false, 1},
		{"guard member read", `const cp=require("child_process");if(cp.exec){cp.exec(command);}`, false, 1},
		{"Function prototype read", `const cp=require("child_process");const bind=Function.prototype.call.bind;cp.exec(command);`, false, 1},
		{"Function typeof read", `const cp=require("child_process");typeof Function;cp.exec(command);`, false, 1},
		{"Function constructor call", `const cp=require("child_process");Function(code)();cp.exec(command);`, false, 0},
		{"Function prototype constructor call", `const cp=require("child_process");Function.prototype.constructor(code)();cp.exec(command);`, false, 0},
		{"indirect eval", `const cp=require("child_process");(0,eval)(code);cp.exec(command);`, false, 0},
		{"prefix closure and try", `(function(){try{var cp=require("child_process");function run(){cp.exec(command);}run();}catch(error){}})();other();`, false, 1},
		{"block shadow", `const cp=require("child_process");{let cp=other;cp.exec(command);}cp.exec(command);`, false, 1},
		{"require parameter", `function run(require){var cp=require("child_process");cp.exec(command);}`, false, 0},
		{"default parameter", `function run(cp=require("child_process")){cp.exec(command);}`, false, 0},
		{"hoisted var shadow", `const cp=require("child_process");function run(){cp.exec(command);var cp;}`, false, 0},
		{"sloppy block function replacement", `var cp=require("child_process");if(flag){function cp(){}}cp.exec(command);`, false, 0},
		{"late comma initializer", `var first=cp.exec(command),cp=require("child_process");`, false, 0},
		{"rebound namespace", `let cp=require("child_process");cp=other;cp.exec(command);`, false, 0},
		{"rebound runtime loader", `require=fake;const cp=require("child_process");cp.exec(command);`, false, 0},
		{"global runtime loader replacement", `globalThis.require=fake;const cp=require("child_process");cp.exec(command);`, false, 0},
		{"computed global loader replacement", `global[key]=fake;const cp=require("child_process");cp.exec(command);`, false, 0},
		{"unrelated global assignment", `globalThis.inert=1;const cp=require("child_process");cp.exec(command);`, false, 1},
		{"member mutation", `const cp=require("child_process"),other=require("child_process");other.exec=fake;cp.exec(command);`, false, 0},
		{"object escape", `const cp=require("child_process");capture({cp});cp.exec(command);`, false, 0},
		{"dynamic scope", `const cp=require("child_process");function run(){eval(code);cp.exec(command);}`, false, 0},
		{"unrelated eval scope", `const cp=require("child_process");function other(){eval(code);}function run(){cp.exec(command);}`, false, 1},
		{"catch shadow", `const cp=require("child_process");try{}catch(cp){cp.exec(command);}cp.exec(command);`, false, 1},
		{"destructured require parameter", `function run({loader:require}){const cp=require("child_process");cp.exec(command);}`, false, 0},
		{"static block var isolation", `class Example{static{var cp=require("child_process");}static{cp.exec(command);}}`, false, 0},
		{"import shadow", `import require from "loader";const cp=require("child_process");cp.exec(command);`, true, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc, err := parseJavaScriptAST(test.source, test.module)
			if err != nil {
				t.Fatal(err)
			}
			state, err := inventoryJavaScriptASTBindings(doc)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, located := range doc.nodes {
				call, ok := located.node.(*ast.CallExpression)
				if !ok || !located.spanKnown {
					continue
				}
				dot, ok := call.Callee.(*ast.DotExpression)
				if !ok || dot.Identifier.Name.String() != "exec" {
					continue
				}
				name, ok := dot.Left.(*ast.Identifier)
				if !ok {
					continue
				}
				if binding, ok := state.namespace(located.scope, name.Name.String(), located.span.start); ok && binding.namespace == "child_process" {
					count++
				}
			}
			if count != test.want {
				t.Fatalf("proven calls=%d want=%d", count, test.want)
			}
		})
	}
}

func TestJavaScriptASTPromiseNamespaceMutationInvalidatesSharedObject(t *testing.T) {
	for _, module := range []string{"fs", "dns"} {
		source := `const root=require("` + module + `"),promise=require("` + module + `/promises");root.promises.method=fake;`
		doc, err := parseJavaScriptAST(source, false)
		if err != nil {
			t.Fatal(err)
		}
		state, err := inventoryJavaScriptASTBindings(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := state.namespace(0, "promise", len(source)); ok {
			t.Fatal("shared promise namespace survived a mutation through its parent")
		}
	}
}
