package report

import (
	"path/filepath"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptASTReportKeepsDormantScopeAndRoundTrips(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"scripts":{"postinstall":"node ./entry.js"}}`)
	writeFile(t, filepath.Join(root, "entry.js"), `const os=require("os"); os.hostname(); function dormant(value){const cp=require("child_process"); cp.execSync(value);} function* unused(value){yield value;}`)
	rep, err := InspectPath(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, operation := range rep.Operations {
		if operation.Qualifiers["api"] != "child_process.execSync" {
			continue
		}
		found = true
		if operation.SourceFunction != "dormant" || operation.Execution.Connectivity != behavior.ConnectivityUnknown || len(operation.Execution.ExecutionRootIDs) != 0 {
			t.Fatalf("dormant helper acquired host activation: %#v", operation)
		}
	}
	if !found {
		t.Fatal("missing modeled helper operation")
	}
	assertStableReportEncoding(t, rep)
}
