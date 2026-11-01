package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tauriTestExecutable() []byte {
	return append(testThinMachO(), []byte(
		"/.cargo/registry/src/example/tauri-1.6.8/src/app.rs\x00"+
			"/.cargo/registry/src/example/tauri-runtime-wry-0.14.8/src/lib.rs\x00"+
			"__TAURI_INVOKE_KEY__")...)
}

func TestArchivedTauriAppAttributesDeclaredExecutable(t *testing.T) {
	result := inspectArchiveEntries(t, map[string][]byte{
		"Payload/Fixture.app/Contents/Info.plist":    []byte(appInfoPlist("Fixture")),
		"Payload/Fixture.app/Contents/MacOS/Fixture": tauriTestExecutable(),
	})
	var carrier *Node
	for index := range result.Graph.Nodes {
		node := &result.Graph.Nodes[index]
		if strings.HasSuffix(node.LogicalPath, "/Contents/MacOS/Fixture") {
			carrier = node
			break
		}
	}
	if carrier == nil || carrier.PackagingTechnology != "Tauri" || len(carrier.PackagingEvidence) != 3 {
		t.Fatalf("Tauri carrier = %#v", carrier)
	}
	if carrier.AnalyzeStatus != "partial" || !strings.Contains(carrier.CoverageDetail, "asset-table extraction") {
		t.Fatalf("Tauri extraction gap was not explicit: %#v", carrier)
	}
	for _, evidence := range carrier.PackagingEvidence {
		if evidence.Offset < 0 || evidence.Kind == "" || evidence.Value == "" {
			t.Fatalf("invalid Tauri evidence: %#v", evidence)
		}
	}
}

func TestFilesystemTauriAppAttributesDeclaredExecutable(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Fixture.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(appInfoPlist("Fixture")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "Fixture"), tauriTestExecutable(), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := InspectPath(app, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, node := range result.Graph.Nodes {
		if strings.HasSuffix(node.LogicalPath, "/Contents/MacOS/Fixture") && node.PackagingTechnology == "Tauri" && len(node.PackagingEvidence) == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("filesystem Tauri carrier was not attributed: %#v", result.Graph.Nodes)
	}
}

func TestRecognizeTauriExecutableRequiresIndependentRuntimeProofs(t *testing.T) {
	proofs := []string{
		"/.cargo/registry/src/example/tauri-1.6.8/src/app.rs",
		"/.cargo/registry/src/example/tauri-runtime-wry-0.14.8/src/lib.rs",
		"__TAURI_INVOKE_KEY__",
	}
	for omitted := range proofs {
		var data string
		for index, proof := range proofs {
			if index != omitted {
				data += proof + "\x00"
			}
		}
		members := []appBundleMember{{relativePath: "Contents/MacOS/Fixture", data: []byte(data), kind: "macho", available: true}}
		if evidence, ok := recognizeTauriExecutable(members, "Fixture"); ok {
			t.Fatalf("Tauri recognized with proof %q omitted: %#v", proofs[omitted], evidence)
		}
	}
}

func TestRecognizeTauriExecutableRejectsDecoyAndNonMachOCarriers(t *testing.T) {
	proof := []byte("/.cargo/registry/src/example/tauri-1.6/src/app.rs\x00" +
		"/.cargo/registry/src/example/tauri-runtime-wry-latest/src/lib.rs\x00" +
		"__TAURI_INVOKE_KEY__")
	tests := []appBundleMember{
		{relativePath: "Contents/Resources/Fixture", data: proof, kind: "macho", available: true},
		{relativePath: "Contents/MacOS/Fixture", data: proof, kind: "text", available: true},
		{relativePath: "Contents/MacOS/Fixture", data: proof, kind: "macho", available: false},
	}
	for _, member := range tests {
		if evidence, ok := recognizeTauriExecutable([]appBundleMember{member}, "Fixture"); ok {
			t.Fatalf("decoy Tauri carrier accepted: member=%#v evidence=%#v", member, evidence)
		}
	}
}

func TestRecognizeTauriExecutableRejectsVersionStringsOutsideCargoRegistry(t *testing.T) {
	data := []byte("/vendor/tauri-1.6.8/src/app.rs\x00" +
		"/vendor/tauri-runtime-wry-0.14.8/src/lib.rs\x00" +
		"__TAURI_INVOKE_KEY__")
	members := []appBundleMember{{relativePath: "Contents/MacOS/Fixture", data: data, kind: "macho", available: true}}
	if evidence, ok := recognizeTauriExecutable(members, "Fixture"); ok {
		t.Fatalf("non-registry Tauri version strings were accepted: %#v", evidence)
	}
}
