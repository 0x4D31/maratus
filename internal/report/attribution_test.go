package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

// All payloads are inert source fixtures. InspectPath must never execute them.
func TestPackageTargetAttributionRejectsDecoys(t *testing.T) {
	for _, command := range []string{
		`node 'decoy.js --version'`,
		`node ' decoy.js '`,
		`node '"decoy.js"'`,
		`cd sub; node decoy.js`,
		`sh -c 'cd sub; node decoy.js'`,
		`node -r decoy.js --eval '0'`,
		`node -r ./decoy.js --version`,
		`npm --prefix other run helper`,
		`npm run helper --prefix other`,
		`pnpm --filter other run helper`,
		`env -Csub node decoy.js`,
		`sudo -Dsub node decoy.js`,
		`sudo -Rsub node decoy.js`,
		`sudo --chroot=sub node decoy.js`,
		`env -S '-Csub node decoy.js'`,
		`env -0 node decoy.js`,
		`env --null node decoy.js`,
		`bash -o noexec decoy.js`,
		`bash -o noexec -c 'node decoy.js'`,
		`bash --rcfile=./fixture.rc decoy.js`,
		`bash --init-file=./fixture.rc decoy.js`,
	} {
		t.Run(command, func(t *testing.T) {
			root := t.TempDir()
			manifest, err := json.Marshal(map[string]any{"scripts": map[string]string{"postinstall": command, "helper": "node ./decoy.js"}})
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "package.json"), string(manifest))
			writeFile(t, filepath.Join(root, "decoy.js"), `fetch("https://attribution-decoy.invalid/");`)
			writeFile(t, filepath.Join(root, "sub", "decoy.js"), `console.log("inert");`)
			rep, err := InspectPath(root, artifact.Options{IncludeUnreferenced: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range rep.InvokedTargets {
				for _, node := range rep.ArtifactNodes {
					if node.ID == target.NodeID && (node.LogicalPath == "decoy.js" || strings.HasSuffix(node.LogicalPath, "/decoy.js") && !strings.HasSuffix(node.LogicalPath, "/sub/decoy.js")) {
						t.Fatalf("command %q selected the decoy: %#v", command, target)
					}
				}
			}
			assertNoConnectedDestination(t, rep, "https://attribution-decoy.invalid/")
			assertStableReportEncoding(t, rep)
		})
	}
}

func TestPackageTargetDoesNotPromoteDormantFunction(t *testing.T) {
	for _, called := range []bool{false, true} {
		t.Run(map[bool]string{false: "dormant", true: "direct call"}[called], func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "package.json"), `{"scripts":{"postinstall":"python3 ./entry.py"}}`)
			source := "import requests\ndef helper():\n requests.get(\"https://helper.invalid/\")\n"
			if called {
				source += "helper()\n"
			}
			writeFile(t, filepath.Join(root, "entry.py"), source)
			rep, err := InspectPath(root, artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			connected := false
			for _, op := range rep.Operations {
				for _, binding := range op.ResourceBindings {
					if binding.Resource.Value == "https://helper.invalid/" && op.Execution.Connectivity == behavior.ConnectivityConnected {
						connected = true
					}
				}
			}
			if connected != called {
				t.Fatalf("helper connected = %v, called = %v", connected, called)
			}
			assertStableReportEncoding(t, rep)
		})
	}
}

func TestInlinePythonBase64DoesNotExecuteInertOrInvalidWrappers(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`import os; os.system("curl https://base64-decoy.invalid/")`))
	call := `exec(base64.b64decode("` + encoded + `"))`
	for _, source := range []string{
		"# " + call,
		`'''` + call + `'''`,
		`print('` + call + `')`,
		"def dormant():\n import base64\n " + call,
		"import base64; base64 = fake; " + call,
		" import base64; " + call,
		`import base64; exec(base64.b64decode("` + base64.StdEncoding.EncodeToString([]byte("import os; os.system(\"curl https://base64-decoy.invalid/\");\xff")) + `"))`,
		"import base64; EXEC(base64.b64decode(\"" + encoded + "\"))",
		`import base64; exec(base64.b64decode("` + strings.TrimRight(encoded, "=") + `"))`,
	} {
		t.Run(source, func(t *testing.T) {
			rep, err := InspectInline([]byte("python3 -c '"+strings.ReplaceAll(source, "'", "'\"'\"'")+"'"), "shell", artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			for _, feature := range rep.Features {
				if feature.Key == "python.base64_decoded_script" {
					t.Fatalf("inert/invalid wrapper decoded: %q", source)
				}
			}
			assertNoConnectedDestination(t, rep, "https://base64-decoy.invalid/")
			assertStableReportEncoding(t, rep)
		})
	}
}

func TestPackageQuotedTargetsRemainExactAndDeterministic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"scripts":{"postinstall":"node --require './space dir/preload.cjs' './space dir/entry.js'"}}`)
	writeFile(t, filepath.Join(root, "space dir", "preload.cjs"), `fetch("https://preload-positive.invalid/");`)
	writeFile(t, filepath.Join(root, "space dir", "entry.js"), `fetch("https://entry-positive.invalid/"); function dormant() { fetch("https://dormant-negative.invalid/"); }`)
	first, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"https://preload-positive.invalid/", "https://entry-positive.invalid/"} {
		connected := false
		for _, operation := range first.Operations {
			for _, binding := range operation.ResourceBindings {
				if binding.Resource.Value == destination && operation.Execution.Connectivity == behavior.ConnectivityConnected {
					connected = true
				}
			}
		}
		if !connected {
			t.Fatalf("exact quoted target lost its connected behavior: %s", destination)
		}
	}
	assertNoConnectedDestination(t, first, "https://dormant-negative.invalid/")
	assertStableReportEncoding(t, first)
	var a, b bytes.Buffer
	if err := WriteJSON(&a, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("quoted target reports are not deterministic")
	}
}

func TestVSCodeEntrypointDoesNotTrimDeclaredFilename(t *testing.T) {
	for _, entry := range []string{" entry.js ", `"entry.js"`} {
		root := t.TempDir()
		manifest, err := json.Marshal(map[string]any{"engines": map[string]string{"vscode": "*"}, "main": entry})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, "package.json"), string(manifest))
		writeFile(t, filepath.Join(root, "entry.js"), `fetch("https://vscode-decoy.invalid/")`)
		rep, err := InspectPath(root, artifact.Options{IncludeUnreferenced: true})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConnectedDestination(t, rep, "https://vscode-decoy.invalid/")
		assertStableReportEncoding(t, rep)
	}
}

func TestInlinePythonNormalizationPreservesDormantScopes(t *testing.T) {
	for _, source := range []string{
		"def dormant():\n import os; os.system(\"curl https://scope-decoy.invalid/\")",
		"def dormant(): import os; os.system(\"curl https://scope-decoy.invalid/\")",
		" import os; os.system(\"curl https://scope-decoy.invalid/\")",
	} {
		t.Logf("source: %q", source)
		rep, err := InspectInline([]byte("python3 -c '"+source+"'"), "shell", artifact.Options{})
		if err != nil {
			t.Fatal(err)
		}
		assertNoConnectedDestination(t, rep, "https://scope-decoy.invalid/")
		assertStableReportEncoding(t, rep)
	}
}

func assertNoConnectedDestination(t *testing.T, rep Report, destination string) {
	t.Helper()
	for _, op := range rep.Operations {
		for _, binding := range op.ResourceBindings {
			if binding.Resource.Value == destination && op.Execution.Connectivity == behavior.ConnectivityConnected {
				t.Fatalf("decoy destination was connected: %#v", op)
			}
		}
	}
}

func TestNamedShellNoexecDoesNotPromoteInlineBehavior(t *testing.T) {
	rep, err := InspectInline([]byte(`bash -o noexec -c 'curl https://noexec-decoy.invalid/'`), "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoConnectedDestination(t, rep, "https://noexec-decoy.invalid/")
	assertStableReportEncoding(t, rep)
}

func TestInvalidBashLongOptionDoesNotPromoteInlineBehavior(t *testing.T) {
	for _, option := range []string{"--rcfile=./fixture.rc", "--init-file=./fixture.rc"} {
		t.Run(option, func(t *testing.T) {
			rep, err := InspectInline([]byte("bash "+option+" -c 'curl https://bash-option-decoy.invalid/'"), "shell", artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			assertNoConnectedDestination(t, rep, "https://bash-option-decoy.invalid/")
			assertStableReportEncoding(t, rep)
		})
	}
}
