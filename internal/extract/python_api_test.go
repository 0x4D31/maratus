package extract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func pythonAPIExtract(source string) behavior.Graph {
	var graph behavior.Graph
	ExtractText(&graph, artifact.Content{
		NodeID: "node-python-api", LogicalPath: "fixture.py", PhysicalPath: "/private/test/fixture.py",
		Kind: "script", MediaType: "text/plain", SemanticLanguage: "python", Data: []byte(source),
	})
	return graph
}

func pythonAPIOperation(graph behavior.Graph, kind behavior.OperationKind, role behavior.ResourceRole, value string) (behavior.ModeledOperation, bool) {
	for _, operation := range graph.Operations {
		if operation.Kind != kind {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Role == role && binding.Resource.Value == value {
				return operation, true
			}
		}
	}
	return behavior.ModeledOperation{}, false
}

func pythonAPIOperationsByKind(graph behavior.Graph, kind behavior.OperationKind) []behavior.ModeledOperation {
	var operations []behavior.ModeledOperation
	for _, operation := range graph.Operations {
		if operation.Kind == kind {
			operations = append(operations, operation)
		}
	}
	return operations
}

func TestPythonSourceAPIsUseSharedOperationsAndExactResources(t *testing.T) {
	graph := pythonAPIExtract(`import glob
import os as operating_system
import platform
import pwd
import shutil
import socket

def inspect_host():
    glob.glob("/Users/alice/Library/Application Support/*", recursive=True)
    operating_system.access("/Users/alice/Documents", operating_system.R_OK)
    operating_system.chmod("/tmp/stage", 0o700)
    operating_system.listdir("/Users/alice/Documents")
    operating_system.path.exists(path="/Users/alice/Library/Keychains/login.keychain-db")
    operating_system.makedirs(name="/tmp/stage", exist_ok=True)
    shutil.copy(src="/Users/alice/.ssh/id_ed25519", dst="/tmp/stage/key")
    socket.getaddrinfo(host="collector.example.invalid", port=443)
    pwd.getpwuid(501)
    platform.system()
`)

	wants := []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileEnumerate, behavior.ResourceRoleSource, "/Users/alice/Library/Application Support/*"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/Users/alice/Documents"},
		{behavior.OperationFilePermissionModify, behavior.ResourceRoleTarget, "/tmp/stage"},
		{behavior.OperationFileEnumerate, behavior.ResourceRoleSource, "/Users/alice/Documents"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/Users/alice/Library/Keychains/login.keychain-db"},
		{behavior.OperationDirectoryCreate, behavior.ResourceRoleTarget, "/tmp/stage"},
		{behavior.OperationFileCopy, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519"},
		{behavior.OperationFileCopy, behavior.ResourceRoleLocalOutput, "/tmp/stage/key"},
		{behavior.OperationNameResolve, behavior.ResourceRoleSource, "collector.example.invalid"},
		{behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, "local users"},
		{behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, "macOS system and hardware"},
	}
	for _, want := range wants {
		operation, ok := pythonAPIOperation(graph, want.kind, want.role, want.value)
		if !ok {
			t.Errorf("missing %s %s=%q: %#v", want.kind, want.role, want.value, graph.Operations)
			continue
		}
		if operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) != 2 {
			t.Errorf("operation lacks call+binding corroboration: %#v", operation)
		}
		if operation.SourceFunction != "inspect_host" || operation.Qualifiers["api_identity"] != "stable-python-import-and-exact-qualified-call" {
			t.Errorf("operation lost source scope or identity proof: %#v", operation)
		}
	}

	var sawImportEvidence bool
	for _, evidence := range graph.Evidence {
		if evidence.Method == "python-source-binding" && evidence.Kind == "python-import-binding" && evidence.Line >= 1 && evidence.Line <= 6 && evidence.OffsetKnown {
			sawImportEvidence = true
		}
	}
	if !sawImportEvidence {
		t.Fatalf("stable import evidence was not retained: %#v", graph.Evidence)
	}
}

func TestPythonSourceAPIsUseDocumentedDefaultDirectory(t *testing.T) {
	graph := pythonAPIExtract("import os\nos.listdir()\nos.scandir()\n")
	for _, kind := range []behavior.OperationKind{behavior.OperationFileEnumerate} {
		if _, ok := pythonAPIOperation(graph, kind, behavior.ResourceRoleSource, "."); !ok {
			t.Fatalf("documented current-directory default missing: %#v", graph.Operations)
		}
	}
}

func TestPythonSourceAPIsCoverNeutralOpenMetadataAndTruncatePrimitives(t *testing.T) {
	graph := pythonAPIExtract(`import os
os.open("/tmp/input", os.O_RDONLY)
os.readlink("/tmp/link")
os.path.realpath("/tmp/item", strict=True)
os.truncate("/tmp/output", 0)
`)
	for _, want := range []struct {
		kind  behavior.OperationKind
		role  behavior.ResourceRole
		value string
	}{
		{behavior.OperationFileOpen, behavior.ResourceRoleSource, "/tmp/input"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/tmp/link"},
		{behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "/tmp/item"},
		{behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput, "/tmp/output"},
	} {
		operation, ok := pythonAPIOperation(graph, want.kind, want.role, want.value)
		if !ok || operation.Support != behavior.SupportCorroborated || operation.Qualifiers["resource_binding"] != "exact-static" {
			t.Errorf("missing exact neutral Python API operation %#v: %#v", want, graph.Operations)
		}
	}
}

func TestPythonArchiveExtractionUsesSharedOperationAndExactLineage(t *testing.T) {
	for name, source := range map[string]string{
		"shutil": `import shutil as archive_tools
archive_tools.unpack_archive("/tmp/stage.zip", extract_dir="/tmp/stage")
`,
		"zipfile": `import zipfile as archive_format
archive_format.ZipFile("/tmp/stage.zip", mode="r").extractall("/tmp/stage")
`,
		"tarfile": `import tarfile
tarfile.open("/tmp/stage.tgz", mode="r:gz").extractall(path="/tmp/stage")
`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			operation, ok := pythonAPIOperation(graph, behavior.OperationArchiveExtract, behavior.ResourceRoleSource, map[string]string{
				"shutil": "/tmp/stage.zip", "zipfile": "/tmp/stage.zip", "tarfile": "/tmp/stage.tgz",
			}[name])
			if !ok || operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) != 2 {
				t.Fatalf("archive extraction lacks exact call/import lineage: %#v", graph.Operations)
			}
			sourceBinding, _ := operation.FirstBinding(behavior.ResourceRoleSource)
			if !sourceBinding.Resource.HasClassification(behavior.ResourceClassArchive) {
				t.Fatalf("archive input lacks typed classification: %#v", sourceBinding)
			}
			target, ok := operation.FirstBinding(behavior.ResourceRoleLocalOutput)
			if !ok || target.Resource.Value != "/tmp/stage" {
				t.Fatalf("archive destination binding = %#v", target)
			}
		})
	}
}

func TestPythonArchiveExtractionRetainsUnresolvedResourcesWithoutFabrication(t *testing.T) {
	graph := pythonAPIExtract(`import zipfile as _zf
_zf.ZipFile(archive_path).extractall(destination())
`)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationArchiveExtract {
		t.Fatalf("exact dynamic extraction chain was not retained once: %#v", graph.Operations)
	}
	source, sourceOK := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	target, targetOK := graph.Operations[0].FirstBinding(behavior.ResourceRoleLocalOutput)
	if !sourceOK || !targetOK || source.Resource.Value != "" || target.Resource.Value != "" {
		t.Fatalf("dynamic extraction resources were fabricated: %#v", graph.Operations[0])
	}
	if graph.Operations[0].Qualifiers["source_binding"] != "unresolved" || graph.Operations[0].Qualifiers["destination_binding"] != "unresolved" {
		t.Fatalf("dynamic extraction limits are not explicit: %#v", graph.Operations[0].Qualifiers)
	}
}

func TestPythonArchiveExtractionUsesWorkingDirectoryOnlyWhenDestinationIsOmitted(t *testing.T) {
	graph := pythonAPIExtract(`import zipfile
zipfile.ZipFile("/tmp/stage.zip").extractall()
`)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationArchiveExtract {
		t.Fatalf("default-destination extraction was not retained once: %#v", graph.Operations)
	}
	target, ok := graph.Operations[0].FirstBinding(behavior.ResourceRoleLocalOutput)
	if !ok || target.Resource.Value != "." || graph.Operations[0].Qualifiers["destination_binding"] != "runtime-working-directory" {
		t.Fatalf("omitted extraction destination was not modeled as working directory: operation=%#v", graph.Operations[0])
	}
}

func TestPythonArchiveExtractionUsesTopLevelBindingAtCallTime(t *testing.T) {
	for name, source := range map[string]string{
		"later cleanup": `import zipfile as archive_format
archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
del archive_format
`,
		"explicit reimport": `import zipfile as archive_format
del archive_format
import zipfile as archive_format
archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
		"unrelated function body": `import zipfile as archive_format
def helper(value):
    return value
archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
	} {
		t.Run(name, func(t *testing.T) {
			first := pythonAPIExtract(source)
			second := pythonAPIExtract(source)
			operation, ok := pythonAPIOperation(first, behavior.OperationArchiveExtract, behavior.ResourceRoleSource, "/tmp/stage.zip")
			if !ok || len(operation.EvidenceIDs) != 2 {
				t.Fatalf("source-ordered module binding was not retained: operations=%#v coverage=%#v", first.Operations, first.Coverage)
			}
			if !reflect.DeepEqual(first.Operations, second.Operations) || !reflect.DeepEqual(first.Evidence, second.Evidence) {
				t.Fatal("source-ordered binding result is nondeterministic")
			}
		})
	}
}

func TestPythonArchiveExtractionUsesOrderedBindingInsideContiguousSuite(t *testing.T) {
	for name, source := range map[string]string{
		"conditional package stage": `if should_unpack:
    import zipfile as archive_format
    archive_format.ZipFile(stage_path).extractall(stage_dir)
    del archive_format
`,
		"function local import": `def unpack(stage_path, stage_dir):
    import zipfile as archive_format
    archive_format.ZipFile(stage_path).extractall(stage_dir)
    del archive_format
`,
		"nested descendant suite": `if should_unpack:
    import tarfile as archive_format
    if destination_ready:
        archive_format.open(stage_path).extractall(stage_dir)
`,
	} {
		t.Run(name, func(t *testing.T) {
			first := pythonAPIExtract(source)
			second := pythonAPIExtract(source)
			operations := pythonAPIOperationsByKind(first, behavior.OperationArchiveExtract)
			if len(operations) != 1 || len(operations[0].EvidenceIDs) != 2 {
				t.Fatalf("contiguous ordered binding was not retained: operations=%#v coverage=%#v", first.Operations, first.Coverage)
			}
			if operations[0].Execution.Connectivity != behavior.ConnectivityUnknown ||
				len(operations[0].Execution.ExecutionRootIDs) != 0 ||
				len(operations[0].Execution.InvokedTargetIDs) != 0 {
				t.Fatalf("conditional source behavior was promoted beyond UNKNOWN execution: %#v", operations[0])
			}
			if !reflect.DeepEqual(first.Operations, second.Operations) || !reflect.DeepEqual(first.Evidence, second.Evidence) {
				t.Fatal("ordered binding result is nondeterministic")
			}
		})
	}
}

func TestPythonArchiveExtractionOrderedBindingStopsAtSuiteBoundary(t *testing.T) {
	for name, source := range map[string]string{
		"sibling conditional": `if first_condition:
    import zipfile as archive_format
if second_condition:
    archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
		"else suite": `if first_condition:
    import zipfile as archive_format
else:
    archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
		"local shadow of global": `import zipfile as archive_format
def unpack():
    archive_format = facade
    archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			if operations := pythonAPIOperationsByKind(graph, behavior.OperationArchiveExtract); len(operations) != 0 {
				t.Fatalf("ordered binding crossed an ambiguous suite or shadow: %#v", operations)
			}
		})
	}
}

func TestPythonSharedAPIsUseTheSameOrderedBindingProof(t *testing.T) {
	source := `if collect:
    import shutil as filesystem
    filesystem.copy("/Users/alice/.ssh/id_ed25519", "/tmp/stage/key")
`
	graph := pythonAPIExtract(source)
	operation, ok := pythonAPIOperation(graph, behavior.OperationFileCopy, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519")
	if !ok {
		t.Fatalf("shared API table did not receive the ordered binding proof: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
	if operation.Support != behavior.SupportCorroborated ||
		operation.Execution.Connectivity != behavior.ConnectivityUnknown ||
		len(operation.EvidenceIDs) != 2 {
		t.Fatalf("ordered shared API proof changed support, reachability, or lineage: %#v", operation)
	}
}

func TestPythonSharedAPIsRejectOrderedBindingAcrossSiblingSuite(t *testing.T) {
	source := `if prepare:
    import shutil as filesystem
if collect:
    filesystem.copy("/Users/alice/.ssh/id_ed25519", "/tmp/stage/key")
`
	graph := pythonAPIExtract(source)
	if operation, ok := pythonAPIOperation(graph, behavior.OperationFileCopy, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519"); ok {
		t.Fatalf("shared API binding crossed sibling conditional suites: %#v", operation)
	}
}

func TestPythonOrderedBindingTabIndentIsExplicitlyUnsupported(t *testing.T) {
	graph := pythonAPIExtract("if collect:\n\timport shutil as filesystem\n\tfilesystem.copy(\"/a\", \"/b\")\n")
	if operation, ok := pythonAPIOperation(graph, behavior.OperationFileCopy, behavior.ResourceRoleSource, "/a"); ok {
		t.Fatalf("tab-indented ordered binding was promoted: %#v", operation)
	}
	if !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("tab-indented ordered binding gap lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonArchiveExtractionTimelineDoesNotCrossFunctionOrConditionalAmbiguity(t *testing.T) {
	for name, source := range map[string]string{
		"function global lookup": `import zipfile as archive_format
def unpack():
    archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
del archive_format
`,
		"indented conditional write": `import zipfile as archive_format
if condition:
    archive_format = facade
archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
		"unsupported import boundary": `import zipfile as archive_format
import (future)
archive_format.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")
`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationArchiveExtract {
					t.Fatalf("ambiguous module binding crossed a control-flow boundary: %#v", operation)
				}
			}
		})
	}
}

func TestPythonArchiveExtractionOrderedBindingBudgetIsExplicit(t *testing.T) {
	var source strings.Builder
	for index := 0; index <= maxPythonAPIOrderedBindingEvents/2; index++ {
		source.WriteString("import zipfile as archive_format\n")
		source.WriteString("del archive_format\n")
	}
	source.WriteString("import zipfile as archive_format\n")
	source.WriteString("archive_format.ZipFile(\"/tmp/stage.zip\").extractall(\"/tmp/stage\")\n")
	graph := pythonAPIExtract(source.String())
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationArchiveExtract {
			t.Fatalf("operation crossed an exhausted binding timeline: %#v", operation)
		}
	}
	if !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("binding timeline budget lacks explicit partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonArchiveExtractionRejectsCloseNegativesAndMalformedChains(t *testing.T) {
	for name, source := range map[string]string{
		"missing import":          `zipfile.ZipFile("/tmp/stage.zip").extractall("/tmp/stage")`,
		"write mode":              "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\", mode=\"w\").extractall(\"/tmp/stage\")",
		"constructor only":        "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\")",
		"different method":        "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").namelist()",
		"trailing statement":      "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").extractall(\"/tmp/stage\"); cleanup()",
		"unknown constructor key": "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\", imaginary=True).extractall(\"/tmp/stage\")",
		"duplicate path":          "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").extractall(\"/tmp/stage\", path=\"/tmp/other\")",
		"starred members":         "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").extractall(*options)",
		"malformed constructor":   "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\"].extractall(\"/tmp/stage\")",
		"malformed method":        "import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").extractall(\"/tmp/stage\"",
		"tar file object only":    "import tarfile\ntarfile.open(name=None, fileobj=stream).extractall(\"/tmp/stage\")",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source + "\n")
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationArchiveExtract {
					t.Fatalf("unsupported archive chain became extraction: %#v", operation)
				}
			}
		})
	}
}

func TestPythonArchiveExtractionCallBudgetIsExplicit(t *testing.T) {
	graph := pythonAPIExtract("import zipfile\nzipfile.ZipFile(\"/tmp/stage.zip\").extractall(\"" + strings.Repeat("a", maxPythonAPICallBytes) + "\")\n")
	if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("archive extraction call budget was not enforced honestly: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestPythonBuiltinOpenReadRequiresUnshadowedExactCallChain(t *testing.T) {
	graph := pythonAPIExtract(`def collect():
    return open("/Users/alice/.ssh/id_ed25519", mode="rb").read()
`)
	operation, ok := pythonAPIOperation(graph, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519")
	if !ok || operation.Support != behavior.SupportCorroborated || operation.Qualifiers["api_identity"] != "unshadowed-builtin-and-exact-call-chain" || !operation.RequiredResource().HasClassification(behavior.ResourceClassSSHPrivateKey) {
		t.Fatalf("exact builtin open/read operation = %#v; all operations=%#v", operation, graph.Operations)
	}

	for name, source := range map[string]string{
		"assigned shadow":    "open = facade\nopen(\"/Users/alice/.ssh/id_ed25519\").read()\n",
		"parameter shadow":   "def collect(open):\n    open(\"/Users/alice/.ssh/id_ed25519\").read()\n",
		"method lookalike":   "facade.open(\"/Users/alice/.ssh/id_ed25519\").read()\n",
		"spaced method":      "facade . open(\"/Users/alice/.ssh/id_ed25519\").read()\n",
		"literal only":       "message = 'open(\"/Users/alice/.ssh/id_ed25519\").read()'\n",
		"dynamic path":       "open(path).read()\n",
		"no read terminal":   "open(\"/Users/alice/.ssh/id_ed25519\")\n",
		"member lookalike":   "open(\"/Users/alice/.ssh/id_ed25519\").readable()\n",
		"duplicate argument": "open(\"/Users/alice/.ssh/id_ed25519\", file=\"/tmp/other\").read()\n",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pythonAPIExtract(source)
			if _, found := pythonAPIOperation(candidate, behavior.OperationFileRead, behavior.ResourceRoleSource, "/Users/alice/.ssh/id_ed25519"); found {
				t.Fatalf("unsupported builtin-open shape became file read: %#v", candidate.Operations)
			}
		})
	}
}

func TestPythonSourceAPIRejectsUnstableOrInvalidCalls(t *testing.T) {
	tests := map[string]string{
		"missing import":          `os.remove("/tmp/a")`,
		"import after call":       "os.remove(\"/tmp/a\")\nimport os\n",
		"rebound module":          "import os\nos = facade\nos.remove(\"/tmp/a\")\n",
		"parameter shadow":        "import os\ndef f(os):\n    os.remove(\"/tmp/a\")\n",
		"method replacement":      "import os\nos.remove = fake\nos.remove(\"/tmp/a\")\n",
		"dynamic namespace":       "import os\nglobals()\nos.remove(\"/tmp/a\")\n",
		"wildcard namespace":      "import os\nfrom facade import *\nos.remove(\"/tmp/a\")\n",
		"wrong fixed arity":       "import platform\nplatform.system(\"unexpected\")\n",
		"too few arguments":       "import shutil\nshutil.copy(\"/tmp/a\")\n",
		"too many arguments":      "import os\nos.getenv(\"A\", \"B\", \"C\")\n",
		"starred arguments":       "import os\npaths = [\"/tmp/a\"]\nos.remove(*paths)\n",
		"duplicate keyword":       "import shutil\nshutil.copy(src=\"/tmp/a\", src=\"/tmp/b\", dst=\"/tmp/c\")\n",
		"positional after key":    "import shutil\nshutil.copy(src=\"/tmp/a\", \"/tmp/b\")\n",
		"unknown keyword":         "import os\nos.remove(path=\"/tmp/a\", imaginary=True)\n",
		"keyword-only positional": "import os\nos.remove(\"/tmp/a\", 7)\n",
		"positional-only keyword": "import pwd\npwd.getpwuid(uid=501)\n",
		"malformed delimiters":    "import os\nos.remove(\"/tmp/a\"]\n",
		"from import":             "from os import remove\nremove(\"/tmp/a\")\n",
		"string and comment":      "import os\ntext = 'os.remove(\\\"/tmp/a\\\")'\n# os.remove(\"/tmp/b\")\n",
		"triple-string import":    "'''\nimport os\n'''\nos.remove(\"/tmp/a\")\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if name == "alias" {
				lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
				bindings := scanPythonStableAPIBindings(lines, nil)
				bindingName, canonical, observed, proven := pythonNetworkCallBinding(lines[1], 2, &bindings)
				if bindingName != "client" || canonical != `requests.get("https://exact.example.invalid/p")` || !observed || !proven {
					t.Fatalf("stable network alias resolution = name=%q canonical=%q observed=%t proven=%t bindings=%#v", bindingName, canonical, observed, proven, bindings.bindings)
				}
			}
			graph := pythonAPIExtract(source)
			if len(graph.Operations) != 0 {
				t.Fatalf("unsupported call became an operation: %#v", graph.Operations)
			}
		})
	}
}

func TestPythonSourceAPIDuplicatePositionalAndKeywordResourceIsRejected(t *testing.T) {
	graph := pythonAPIExtract("import shutil\nshutil.copy(\"/tmp/a\", \"/tmp/b\", src=\"/tmp/c\")\n")
	if len(graph.Operations) != 0 {
		t.Fatalf("duplicate positional/keyword resource became an operation: %#v", graph.Operations)
	}
}

func TestPythonSourceAPIBindingBudgetIsExplicit(t *testing.T) {
	var source strings.Builder
	for index := 0; index <= maxPythonAPIBindings; index++ {
		fmt.Fprintf(&source, "import os as operating%d\n", index)
	}
	fmt.Fprintf(&source, "operating%d.remove(\"/tmp/a\")\n", maxPythonAPIBindings)
	graph := pythonAPIExtract(source.String())
	if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("binding budget was not enforced honestly: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestPythonSourceAPICallCountBudgetIsExplicit(t *testing.T) {
	var line strings.Builder
	line.WriteString("import os\n")
	for index := 0; index <= maxPythonAPICallsPerLine; index++ {
		fmt.Fprintf(&line, "os.remove(\"/tmp/%d\");", index)
	}
	line.WriteByte('\n')
	graph := pythonAPIExtract(line.String())
	count := 0
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationFileDelete {
			count++
		}
	}
	if count > maxPythonAPICallsPerLine || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("call budget was not enforced honestly: count=%d coverage=%#v", count, graph.Coverage)
	}
}

func TestPythonSourceAPICallByteBudgetIsExplicit(t *testing.T) {
	source := "import os\nos.remove(\"" + strings.Repeat("a", maxPythonAPICallBytes) + "\")\n"
	graph := pythonAPIExtract(source)
	if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("call-byte budget was not enforced honestly: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestPythonSourceAPIBenignControlRemainsNeutral(t *testing.T) {
	graph := pythonAPIExtract(`import os
import platform

def inventory_cache(cache):
    if os.path.exists(cache):
        return os.listdir(cache)
    return platform.python_version()
`)
	if _, ok := pythonAPIOperation(graph, behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, ""); !ok {
		t.Fatalf("dynamic benign path should remain a neutral operation with unresolved resource: %#v", graph.Operations)
	}
	if _, ok := pythonAPIOperation(graph, behavior.OperationFileEnumerate, behavior.ResourceRoleSource, ""); !ok {
		t.Fatalf("dynamic benign enumeration should remain visible without fabricated resource: %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationFileMetadataQuery && operation.Kind != behavior.OperationFileEnumerate && operation.Kind != behavior.OperationSystemInfoQuery {
			t.Fatalf("benign control acquired unrelated semantics: %#v", operation)
		}
	}
}

func TestPythonSourceAPIUnknownConcatenationDoesNotFabricatePath(t *testing.T) {
	graph := pythonAPIExtract("import os\ndef inspect(user):\n    os.path.exists(\"/Users/\" + user + \"/Library/Keychains/login.keychain-db\")\n")
	operation, ok := pythonAPIOperation(graph, behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource, "")
	if !ok || operation.Qualifiers["resource_binding"] != "unresolved" {
		t.Fatalf("unknown path component was not retained honestly: %#v", graph.Operations)
	}
	for _, binding := range operation.ResourceBindings {
		if strings.Contains(binding.Resource.Value, "/Users//") {
			t.Fatalf("unknown user component was silently deleted: %#v", operation)
		}
	}
}

func TestPythonNetworkRequiresStableModuleIdentityBeforeCall(t *testing.T) {
	tests := map[string]string{
		"missing import": `requests.get("https://unbound.example.invalid/p")`,
		"import after call": `requests.get("https://early.example.invalid/p")
import requests`,
		"rebound module": `import requests
requests = fixture
requests.get("https://rebound.example.invalid/p")`,
		"parameter shadow": `import requests
def collect(requests):
    requests.get("https://shadowed.example.invalid/p")`,
		"spread arguments": `import requests
requests.get("https://spread.example.invalid/p", *options)`,
		"duplicate keyword": `import requests
requests.get("https://duplicate.example.invalid/p", url="https://other.example.invalid/p")`,
		"malformed call": `import requests
requests.get("https://malformed.example.invalid/p"`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source + "\n")
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationNetworkConnect || operation.Kind == behavior.OperationNetworkDownload || operation.Kind == behavior.OperationNetworkUpload {
					t.Fatalf("unproved Python API identity became network behavior: %#v", operation)
				}
			}
			if !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
				t.Fatalf("unproved network call lacks explicit partial coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonNetworkRetainsImportAndCallLineage(t *testing.T) {
	for name, source := range map[string]string{
		"canonical": "import requests\nrequests.get(\"https://exact.example.invalid/p\")\n",
		"alias":     "import requests as client\nclient.get(\"https://exact.example.invalid/p\")\n",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			operation, ok := pythonAPIOperation(graph, behavior.OperationNetworkConnect, behavior.ResourceRoleRemoteDestination, "https://exact.example.invalid/p")
			if !ok || operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) < 2 {
				t.Fatalf("identity-proven request lacks import/call lineage: %#v", graph.Operations)
			}
		})
	}
}

func TestPythonMemberBindingTargetsInvalidateAPIIdentity(t *testing.T) {
	for _, mutation := range []string{
		"API, other = fake, None",
		"(API) = fake",
		"[API, other] = [fake, None]",
		"other = API = fake",
		"for API in replacements:\n    pass",
		"with context() as API:\n    pass",
		"del (API)",
		"MODULE.__dict__[\"MEMBER\"] = fake",
	} {
		for _, api := range []string{"os.remove", "requests.get", "subprocess.run"} {
			t.Run(api+"/"+mutation, func(t *testing.T) {
				parts := strings.Split(api, ".")
				statement := strings.NewReplacer("API", api, "MODULE", parts[0], "MEMBER", parts[1]).Replace(mutation)
				source := "import " + parts[0] + "\n" + statement + "\n" + api + "(\"https://unit.invalid/payload\")\n"
				graph := pythonAPIExtract(source)
				if len(graph.Operations) != 0 {
					t.Fatalf("mutated API acquired original semantics: %#v", graph.Operations)
				}
			})
		}
	}
}

func TestPythonMemberReadsPreserveAPIIdentity(t *testing.T) {
	for _, read := range []string{
		"alias = os.remove",
		"same = os.remove == other",
		"check(value=os.remove)",
		"values = [os.remove for value in items]",
		"with context() as handle: check(os.remove)",
	} {
		t.Run(read, func(t *testing.T) {
			graph := pythonAPIExtract("import os\n" + read + "\nos.remove(\"/tmp/a\")\n")
			if len(pythonAPIOperationsByKind(graph, behavior.OperationFileDelete)) != 1 {
				t.Fatalf("ordinary member read invalidated API: %#v", graph.Operations)
			}
		})
	}
}
