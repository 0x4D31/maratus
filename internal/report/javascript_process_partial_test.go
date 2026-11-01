package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestJavaScriptUnknownCommandReportPreservesOnlyProcessPrimitive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.js")
	if err := os.WriteFile(path, []byte("const cp = require('child_process');\ncp.exec(command);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InspectPath(path, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Operations) != 1 || rep.Operations[0].Kind != behavior.OperationProcessExecute || rep.Operations[0].RequiredResource().Value != "" || len(rep.Capabilities) != 0 {
		t.Fatalf("unknown command lost its primitive or gained concrete capabilities: %#v", rep)
	}
	assertReportReferencesValid(t, rep)
	assertStableReportEncoding(t, rep)
}
