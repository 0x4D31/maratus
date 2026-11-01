package extract

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonWheelPTHCreatesConditionalSiteStartupRoot(t *testing.T) {
	pth := []byte("# path configuration is inert\nsrc\nimport subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("execution roots = %#v, want one Python site-startup root", graph.ExecutionRoots)
	}
	root := graph.ExecutionRoots[0]
	if root.Kind != "python-site-startup" || root.Name != "startup.pth" || root.Interpreter != "python" ||
		root.DeclarationNodeID != "node-pth" || root.StartNodeID != "node-pth" || len(root.EvidenceIDs) != 6 {
		t.Fatalf("unexpected Python site-startup root: %#v", root)
	}
	expectedEvidenceLines := map[string]int{
		"python-pth-executable-line":         3,
		"python-wheel-platform-filename-tag": 0,
		"python-wheel-version":               1,
		"python-wheel-site-layout":           3,
		"verified-python-wheel-metadata":     2,
		"verified-python-pth-member":         1,
	}
	evidenceByID := make(map[string]behavior.Evidence, len(graph.Evidence))
	for _, item := range graph.Evidence {
		evidenceByID[item.ID] = item
	}
	for _, evidenceID := range root.EvidenceIDs {
		item, ok := evidenceByID[evidenceID]
		if !ok || expectedEvidenceLines[item.Kind] != item.Line {
			t.Fatalf("root evidence is missing or mislocated: id=%q evidence=%#v", evidenceID, item)
		}
		delete(expectedEvidenceLines, item.Kind)
	}
	if len(expectedEvidenceLines) != 0 {
		t.Fatalf("root evidence kinds were not retained: %#v", expectedEvidenceLines)
	}
	feature := pythonPTHFeature(graph)
	if feature == nil || feature.Support != behavior.SupportDirect || feature.Execution.Connectivity != behavior.ConnectivityConnected ||
		!slices.Equal(feature.Execution.ExecutionRootIDs, []string{root.ID}) {
		t.Fatalf("executable .pth Feature lacks exact connected ownership: %#v", feature)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationProcessExecute); operation != nil {
		t.Fatalf("foundational .pth declaration analysis promoted arbitrary Python to an operation: %#v", operation)
	}
	if !pythonPTHCoverageContains(graph, "conditional Python site-startup root") {
		t.Fatalf("conditional runtime boundary was not disclosed: %#v", graph.Coverage)
	}
	if !pythonPTHCoverageContains(graph, "only one exact same-line subprocess.Popen") {
		t.Fatalf("unmodeled executable-line semantics were not disclosed: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHFeatureSurvivesInvalidRecordWithoutConnectivity(t *testing.T) {
	pth := []byte(pythonPTHBase64Launcher("import requests\n"+`requests.get("https://invalid-record.example/")`) + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	record := pythonPTHContent(contents, "RECORD")
	record.Data = []byte(strings.Replace(string(record.Data), pythonRecordDigest(pth), strings.Repeat("A", 43), 1))
	replacePythonPTHContent(contents, record)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("RECORD mismatch created a root: %#v", graph.ExecutionRoots)
	}
	feature := pythonPTHFeature(graph)
	if feature == nil || feature.Support != behavior.SupportDirect || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("direct executable-line Feature was lost or strengthened: %#v", feature)
	}
	operation := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke)
	if operation == nil || operation.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("exact artifact code was lost or gained installation connectivity: %#v", operation)
	}
	if network := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://invalid-record.example/"); network == nil || network.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("nested exact artifact behavior was lost or gained installation connectivity: %#v", network)
	}
	if !pythonPTHCoverageContains(graph, "digest does not match RECORD") {
		t.Fatalf("RECORD mismatch lacks stable partial coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHAmbiguousMetadataFailsClosed(t *testing.T) {
	pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	for name, mutate := range map[string]func(*artifact.Graph, []artifact.Content) []artifact.Content{
		"missing WHEEL": func(_ *artifact.Graph, contents []artifact.Content) []artifact.Content {
			out := contents[:0]
			for _, content := range contents {
				if filepathBaseForPythonPTHTest(content.LogicalPath) != "WHEEL" {
					out = append(out, content)
				}
			}
			return out
		},
		"duplicate WHEEL": func(graph *artifact.Graph, contents []artifact.Content) []artifact.Content {
			wheel := pythonPTHContent(contents, "WHEEL")
			wheel.NodeID = "node-wheel-metadata-duplicate"
			graph.Nodes = append(graph.Nodes, artifact.Node{
				ID:          wheel.NodeID,
				ParentID:    "node-wheel",
				LogicalPath: wheel.LogicalPath,
				Kind:        "text",
				MediaType:   "text/plain",
				SourceRole:  "unknown",
			})
			return append(contents, wheel)
		},
	} {
		t.Run(name, func(t *testing.T) {
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			contents = mutate(&artifacts, contents)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 0 {
				t.Fatalf("ambiguous metadata created a root: %#v", graph.ExecutionRoots)
			}
			if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("direct Feature was lost or connected: %#v", feature)
			}
			if !pythonPTHCoverageContains(graph, "one unambiguous .dist-info/WHEEL and RECORD pair") {
				t.Fatalf("ambiguous metadata lacks stable coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonWheelPTHDuplicateMemberPathFailsClosed(t *testing.T) {
	pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"first\"])\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	duplicate := pythonPTHContent(contents, "startup.pth")
	duplicate.NodeID = "node-pth-duplicate"
	duplicate.Data = []byte("import subprocess; subprocess.run([\"/bin/echo\", \"second\"])\n")
	artifacts.Nodes = append(artifacts.Nodes, artifact.Node{
		ID:          duplicate.NodeID,
		ParentID:    "node-wheel",
		LogicalPath: duplicate.LogicalPath,
		Kind:        "text",
		MediaType:   "text/plain",
		SourceRole:  "unknown",
	})
	contents = append(contents, duplicate)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("duplicate .pth identity created roots: %#v", graph.ExecutionRoots)
	}
	features := 0
	for _, feature := range graph.Features {
		if feature.Key == "python.site.pth.import-line" {
			features++
			if feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("duplicate .pth Feature gained connectivity: %#v", feature)
			}
		}
	}
	if features != 2 {
		t.Fatalf("duplicate .pth lines were not retained independently: %#v", graph.Features)
	}
	if !pythonPTHCoverageContains(graph, "duplicate wheel member path") {
		t.Fatalf("duplicate .pth identity lacks stable coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHSkippedDuplicateMemberFailsClosed(t *testing.T) {
	pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	for _, base := range []string{"startup.pth", "WHEEL", "RECORD"} {
		t.Run(base, func(t *testing.T) {
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			member := pythonPTHContent(contents, base)
			artifacts.Nodes = append(artifacts.Nodes, artifact.Node{
				ID:             "node-skipped-duplicate",
				ParentID:       "node-wheel",
				LogicalPath:    member.LogicalPath,
				Kind:           "text",
				MediaType:      "text/plain",
				SourceRole:     "unknown",
				AnalyzeStatus:  "skipped",
				CoverageDetail: "fixture skipped duplicate",
			})

			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 0 {
				t.Fatalf("skipped duplicate %s created a root: %#v", base, graph.ExecutionRoots)
			}
			if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("direct Feature was lost or connected: %#v", feature)
			}
		})
	}
}

func TestPythonWheelPTHIncompleteMemberInventoryFailsClosed(t *testing.T) {
	pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	artifacts.Nodes[0].AnalyzeStatus = "partial"
	artifacts.Nodes[0].CoverageDetail = "archive entry limit reached"

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("partial wheel inventory created a root: %#v", graph.ExecutionRoots)
	}
	if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("partial wheel lost its direct Feature or gained connectivity: %#v", feature)
	}
	if !pythonPTHCoverageContains(graph, "wheel member inventory is incomplete") {
		t.Fatalf("partial wheel lacks uniqueness coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHRejectsNonExecutableAndUnsupportedPlacements(t *testing.T) {
	t.Run("path and leading whitespace lines", func(t *testing.T) {
		pth := []byte("src\n# comment\n import subprocess; subprocess.run([\"/bin/echo\"])\nimportx demo\n")
		artifacts, contents := pythonWheelPTHFixture("editable.pth", pth, false)
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil || pythonPTHOperation(graph, behavior.OperationProcessExecute) != nil {
			t.Fatalf("non-executable .pth lines gained semantics: roots=%#v features=%#v operations=%#v", graph.ExecutionRoots, graph.Features, graph.Operations)
		}
	})

	t.Run("nested package data", func(t *testing.T) {
		pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
		artifacts, contents := pythonWheelPTHFixture("package/startup.pth", pth, false)
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 0 {
			t.Fatalf("nested package .pth became a site root: %#v", graph.ExecutionRoots)
		}
		if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
			t.Fatalf("nested executable line was lost or connected: %#v", feature)
		}
		if operation := pythonPTHOperation(graph, behavior.OperationProcessExecute); operation != nil {
			t.Fatalf("nested executable line became an operation: %#v", operation)
		}
		if !pythonPTHCoverageContains(graph, "does not install directly at a supported site root") {
			t.Fatalf("unsupported placement lacks explicit analyzed coverage: %#v", graph.Coverage)
		}
		for _, evidence := range graph.Evidence {
			if strings.HasPrefix(evidence.Kind, "python-wheel-") || evidence.Kind == "verified-python-wheel-metadata" {
				t.Fatalf("ineligible .pth placement retained orphan wheel proof evidence: %#v", evidence)
			}
		}
	})

	for _, path := range []string{".startup.pth", ".pth", "sample-1.0.data/purelib/.startup.pth"} {
		t.Run("hidden site file "+path, func(t *testing.T) {
			pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
			artifacts, contents := pythonWheelPTHFixture(path, pth, false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 0 {
				t.Fatalf("hidden .pth member became a site root: %#v", graph.ExecutionRoots)
			}
			if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("hidden executable line was lost or connected: %#v", feature)
			}
			if !pythonPTHCoverageContains(graph, "does not install directly at a supported site root") {
				t.Fatalf("hidden placement lacks explicit analyzed coverage: %#v", graph.Coverage)
			}
		})
	}

	t.Run("non-wheel archive", func(t *testing.T) {
		pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
		artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
		artifacts.Nodes[0].Kind = "zip"
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil {
			t.Fatalf("ordinary ZIP .pth gained wheel semantics: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
		}
	})
}

func TestPythonWheelPTHReportsUnsupportedMemberRepresentations(t *testing.T) {
	for name, pth := range map[string][]byte{
		"invalid UTF-8": []byte("import startup_hook # \xff\n"),
		"NUL byte":      []byte("import startup_hook\x00\n"),
	} {
		t.Run(name, func(t *testing.T) {
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			for index := range artifacts.Nodes {
				if artifacts.Nodes[index].ID == "node-pth" {
					artifacts.Nodes[index].Kind = "blob"
					artifacts.Nodes[index].MediaType = "application/octet-stream"
				}
			}
			for index := range contents {
				if contents[index].NodeID == "node-pth" {
					contents[index].Kind = "blob"
					contents[index].MediaType = "application/octet-stream"
				}
			}

			graph := Run(Context{Artifacts: &artifacts, Contents: contents})

			if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil {
				t.Fatalf("unsupported .pth decoding gained startup semantics: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
			}
			if !pythonPTHCoverageContains(graph, "locale-dependent decoding is unsupported") {
				t.Fatalf("unsupported .pth decoding lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}

	t.Run("raw-only bytes", func(t *testing.T) {
		artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte("import startup_hook\n"), false)
		for index := range contents {
			if contents[index].NodeID == "node-pth" {
				contents[index].RawFeaturesOnly = true
				contents[index].Kind = "uninterpreted-bytes"
				contents[index].MediaType = "application/octet-stream"
			}
		}
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil {
			t.Fatalf("raw-only .pth gained startup semantics: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
		}
		if !pythonPTHCoverageContains(graph, "retained only as uninterpreted bytes") {
			t.Fatalf("raw-only .pth lacks explicit adapter coverage: %#v", graph.Coverage)
		}
	})

	t.Run("unavailable bytes", func(t *testing.T) {
		artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte("import startup_hook\n"), false)
		filtered := contents[:0]
		for _, content := range contents {
			if content.NodeID != "node-pth" {
				filtered = append(filtered, content)
			}
		}
		contents = filtered
		for index := range artifacts.Nodes {
			if artifacts.Nodes[index].ID == "node-pth" {
				artifacts.Nodes[index].AnalyzeStatus = "skipped"
				artifacts.Nodes[index].CoverageDetail = "fixture byte limit"
			}
		}
		graph := Run(Context{Artifacts: &artifacts, Contents: contents})
		if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil {
			t.Fatalf("unavailable .pth gained startup semantics: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
		}
		if !pythonPTHCoverageContains(graph, "bytes were unavailable") {
			t.Fatalf("unavailable .pth lacks explicit adapter coverage: %#v", graph.Coverage)
		}
	})
}

func TestPythonWheelPTHSupportsDataSchemeSiteRoot(t *testing.T) {
	pth := []byte("import subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	artifacts, contents := pythonWheelPTHFixture("sample-1.0.data/purelib/startup.pth", pth, false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "python-site-startup" {
		t.Fatalf(".data/purelib site-root member was not modeled: %#v", graph.ExecutionRoots)
	}
}

func TestPythonWheelPTHRequiresMacOSCompatibleFilenameTag(t *testing.T) {
	pth := []byte("import startup_hook\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	const (
		oldName = "sample-1.0-py3-none-any.whl"
		newName = "sample-1.0-py3-none-win_amd64.whl"
	)
	for index := range artifacts.Nodes {
		artifacts.Nodes[index].LogicalPath = strings.Replace(artifacts.Nodes[index].LogicalPath, oldName, newName, 1)
	}
	for index := range contents {
		contents[index].LogicalPath = strings.Replace(contents[index].LogicalPath, oldName, newName, 1)
	}

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("platform-incompatible wheel filename created a macOS startup root: %#v", graph.ExecutionRoots)
	}
	if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("platform-incompatible wheel lost its direct Feature or gained connectivity: %#v", feature)
	}
	if !pythonPTHCoverageContains(graph, "outer wheel filename did not declare a macOS") {
		t.Fatalf("filename incompatibility lacks stable coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHRejectsWheelMetadataBody(t *testing.T) {
	pth := []byte("import startup_hook\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	wheel := pythonPTHContent(contents, "WHEEL")
	wheel.Data = []byte("Wheel-Version: 1.0\nRoot-Is-Purelib: true\n\nTag: py3-none-any\n")
	replacePythonPTHContent(contents, wheel)
	record := pythonPTHContent(contents, "RECORD")
	record.Data = []byte(
		pythonRecordLine("startup.pth", pth) +
			pythonRecordLine("sample-1.0.dist-info/WHEEL", wheel.Data) +
			"sample-1.0.dist-info/RECORD,,\n",
	)
	replacePythonPTHContent(contents, record)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("WHEEL body content created a startup root: %#v", graph.ExecutionRoots)
	}
	if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("WHEEL body case lost its direct Feature or gained connectivity: %#v", feature)
	}
	if !pythonPTHCoverageContains(graph, "content after the header block") {
		t.Fatalf("WHEEL body content lacks stable coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHRejectsInstalledDestinationCollision(t *testing.T) {
	rootData := []byte("import root_hook\n")
	dataPath := "sample-1.0.data/platlib/startup.pth"
	dataPTH := []byte("import data_hook\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", rootData, false)
	wheel := pythonPTHContent(contents, "WHEEL")
	record := pythonPTHContent(contents, "RECORD")
	recordPath := "sample-1.0.dist-info/RECORD"
	record.Data = []byte(
		pythonRecordLine("startup.pth", rootData) +
			pythonRecordLine(dataPath, dataPTH) +
			pythonRecordLine("sample-1.0.dist-info/WHEEL", wheel.Data) +
			recordPath + ",,\n",
	)
	replacePythonPTHContent(contents, record)
	logical := "sample-1.0-py3-none-any.whl!" + dataPath
	artifacts.Nodes = append(artifacts.Nodes, artifact.Node{
		ID:            "node-pth-data-scheme",
		ParentID:      "node-wheel",
		LogicalPath:   logical,
		Kind:          "text",
		MediaType:     "text/plain",
		SourceRole:    "unknown",
		AnalyzeStatus: "analyzed",
	})
	contents = append(contents, artifact.Content{
		NodeID:      "node-pth-data-scheme",
		LogicalPath: logical,
		Kind:        "text",
		MediaType:   "text/plain",
		Role:        "unknown",
		Data:        dataPTH,
	})

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("colliding installed .pth destinations created roots: %#v", graph.ExecutionRoots)
	}
	if !pythonPTHCoverageContains(graph, "same installed .pth destination") {
		t.Fatalf("installed-destination collision lacks stable coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHAcceptsTextualExecutableModeMember(t *testing.T) {
	pth := []byte("#!/usr/bin/env python\nimport subprocess; subprocess.run([\"/bin/echo\", \"ok\"])\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	for index := range artifacts.Nodes {
		if artifacts.Nodes[index].ID == "node-pth" {
			artifacts.Nodes[index].Kind = "script"
		}
	}
	for index := range contents {
		if contents[index].NodeID == "node-pth" {
			contents[index].Kind = "script"
			contents[index].Executable = true
		}
	}

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 || graph.ExecutionRoots[0].Kind != "python-site-startup" {
		t.Fatalf("textual executable-mode .pth was not modeled: %#v", graph.ExecutionRoots)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationProcessExecute); operation != nil {
		t.Fatalf("executable-mode .pth code became an operation: %#v", operation)
	}
}

func TestPythonWheelPTHHonorsExecutionRootEligibility(t *testing.T) {
	pth := []byte(pythonPTHBase64Launcher(`requests.get("https://ineligible-root.example/")`) + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, true)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 0 {
		t.Fatalf("CArchive descendant created an independent root: %#v", graph.ExecutionRoots)
	}
	if feature := pythonPTHFeature(graph); feature == nil || feature.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("ineligible carrier lost its direct Feature or gained connectivity: %#v", feature)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); operation == nil || operation.Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("ineligible carrier code was lost or gained connectivity: %#v", operation)
	}
	if !pythonPTHCoverageContains(graph, "cannot declare an independent execution root") {
		t.Fatalf("ineligible carrier lacks explicit analyzed coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHAnalyzesExactLiteralExecWithSourceLineage(t *testing.T) {
	line := `import os; os.path.exists("/tmp/sentinel") or exec('import requests\nrequests.get("https://literal-exec.example/path")')`
	artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("valid wheel lost its conditional startup root: %#v", graph.ExecutionRoots)
	}
	literalFeature := false
	for _, feature := range graph.Features {
		if feature.Key != "python.literal_exec_script" {
			continue
		}
		literalFeature = true
		if feature.Support != behavior.SupportDirect || feature.Execution.Connectivity != behavior.ConnectivityConnected ||
			!strings.Contains(feature.Value, "sha256=") || strings.Contains(feature.Value, "literal-exec.example") {
			t.Fatalf("literal-exec feature was not compact and connected: %#v", feature)
		}
	}
	if !literalFeature {
		t.Fatalf("exact literal exec stage was not retained: %#v", graph.Features)
	}
	network := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://literal-exec.example/path")
	if network == nil || network.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("literal exec network operation lacks exact startup ownership: %#v", network)
	}
	evidenceKinds := map[string]bool{}
	for _, evidenceID := range network.EvidenceIDs {
		for _, evidence := range graph.Evidence {
			if evidence.ID == evidenceID {
				evidenceKinds[evidence.Kind] = true
			}
		}
	}
	if !evidenceKinds["python-pth-executable-line"] || !evidenceKinds["python-literal-exec-script"] || !evidenceKinds["text-line"] {
		t.Fatalf("derived operation lacks its source line and derived-stage lineage: operation=%#v evidence=%#v", network, evidenceKinds)
	}
}

func TestPythonWheelPTHLiteralExecSupportsStableAliasedPythonAPIs(t *testing.T) {
	line := `import os; exec('import subprocess as _s\n_s.run(["/usr/bin/true", "--bounded"])')`
	artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	operation := pythonPTHOperation(graph, behavior.OperationProcessExecute)
	if operation == nil || operation.Execution.Connectivity != behavior.ConnectivityConnected || operation.Support != behavior.SupportCorroborated {
		t.Fatalf("stable aliased subprocess call in literal exec was not modeled: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}

func TestPythonWheelPTHLiteralExecFailsClosedOnDecoysAndAmbiguity(t *testing.T) {
	code := `requests.get("https://must-not-model.example/")`
	for name, line := range map[string]string{
		"quoted decoy":       `import os; note='exec("` + code + `")'`,
		"comment decoy":      `import os; # exec('` + code + `')`,
		"attribute call":     `import os; runner.exec('` + code + `')`,
		"dynamic argument":   `import os; exec(payload)`,
		"rebound name":       `import os; exec = print; exec('` + code + `')`,
		"multiple calls":     `import os; exec('` + code + `'); exec('` + code + `')`,
		"concatenation":      `import os; exec('requests.' + 'get("https://must-not-model.example/")')`,
		"formatted literal":  `import os; exec(f'` + code + `')`,
		"raw prefix":         `import os; exec(r'` + code + `')`,
		"triple quoted":      `import os; exec('''` + code + `''')`,
		"two call arguments": `import os; exec('` + code + `', globals())`,
	} {
		t.Run(name, func(t *testing.T) {
			artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			for _, feature := range graph.Features {
				if feature.Key == "python.literal_exec_script" {
					t.Fatalf("unsupported literal-exec shape gained a derived feature: %#v", feature)
				}
			}
			if operation := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://must-not-model.example/"); operation != nil {
				t.Fatalf("unsupported literal-exec shape gained behavior: %#v", operation)
			}
		})
	}
}

func TestPythonWheelPTHLiteralExecEnforcesPayloadBudget(t *testing.T) {
	oversized := strings.Repeat("x", maxDecodedInlineBytes+1)
	line := `import os; exec('` + oversized + `')`
	artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})
	for _, feature := range graph.Features {
		if feature.Key == "python.literal_exec_script" {
			t.Fatalf("oversized literal exec payload was retained: %#v", feature)
		}
	}
}

func TestPythonWheelPTHRunsBeforeEvidenceExhaustion(t *testing.T) {
	pth := []byte("import harmless_hook\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	for index := 0; index < 128; index++ {
		nodeID := fmt.Sprintf("node-noise-%03d", index)
		artifacts.Nodes = append(artifacts.Nodes, artifact.Node{
			ID:          nodeID,
			ParentID:    "node-wheel",
			LogicalPath: fmt.Sprintf("sample-1.0-py3-none-any.whl!noise/%03d.py", index),
			Kind:        "script",
		})
		contents = append([]artifact.Content{{
			NodeID:      nodeID,
			LogicalPath: fmt.Sprintf("sample-1.0-py3-none-any.whl!noise/%03d.py", index),
			Kind:        "script",
			MediaType:   "text/plain",
			Role:        "runtime",
			Data:        []byte(fmt.Sprintf("requests.get(\"https://noise-%03d.example/\")\n", index)),
		}}, contents...)
	}

	graph := Run(Context{
		Artifacts: &artifacts,
		Contents:  contents,
		Options:   artifact.Options{MaxEvidence: 6},
	})
	if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
		t.Fatalf("noisy wheel exhausted evidence before startup proof: roots=%#v features=%#v evidence=%#v", graph.ExecutionRoots, graph.Features, graph.Evidence)
	}
	if len(graph.Evidence) != 6 {
		t.Fatalf("retained evidence = %d, want exact startup proof budget", len(graph.Evidence))
	}
}

func TestPythonWheelPTHDecodesExactCurrentInterpreterBase64Stage(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("import requests\n" + `requests.get("https://pth-stage.example/")`))
	pth := []byte(`import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('` + encoded + `'))"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)` + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
		t.Fatalf("startup declaration was not retained: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
	}
	decodedFeature := false
	for _, feature := range graph.Features {
		if feature.Key == "python.base64_decoded_script" {
			decodedFeature = true
			if feature.Execution.Connectivity != behavior.ConnectivityConnected ||
				!slices.Equal(feature.Execution.ExecutionRootIDs, []string{graph.ExecutionRoots[0].ID}) {
				t.Fatalf("decoded feature lacks exact root ownership: %#v", feature)
			}
		}
	}
	if !decodedFeature {
		t.Fatalf("exact literal base64 stage was not retained: %#v", graph.Features)
	}
	invoke := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke)
	if invoke == nil || invoke.Execution.Connectivity != behavior.ConnectivityConnected ||
		!slices.Equal(invoke.Execution.ExecutionRootIDs, []string{graph.ExecutionRoots[0].ID}) {
		t.Fatalf("current-interpreter invocation lacks exact ownership: %#v", invoke)
	}
	arguments, ok := invoke.FirstBinding(behavior.ResourceRoleArguments)
	if !ok || !strings.Contains(arguments.Resource.Value, "sha256=") || strings.Contains(arguments.Resource.Value, encoded) {
		t.Fatalf("inline code arguments were not compactly provenance-described: %#v", invoke.ResourceBindings)
	}
	network := pythonPTHOperation(graph, behavior.OperationNetworkConnect)
	if network == nil || network.Execution.Connectivity != behavior.ConnectivityConnected ||
		network.RequiredResource().Value != "https://pth-stage.example/" {
		t.Fatalf("decoded network operation was not connected: %#v", network)
	}
	if !pythonPTHCoverageContains(graph, "unmatched nested stages remain unmodeled") {
		t.Fatalf("remaining semantic boundary lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHNestedStageRequiresEquivalentBase64AndUTF8Source(t *testing.T) {
	validSource := `requests.get("https://must-not-connect.example/")`
	urlSafeSource := validSource + " # ¾"
	urlSafe := base64.RawURLEncoding.EncodeToString([]byte(urlSafeSource))
	if !strings.ContainsAny(urlSafe, "-_") {
		t.Fatalf("test URL-safe literal lacks distinguishing alphabet bytes: %q", urlSafe)
	}
	padded := base64.StdEncoding.EncodeToString([]byte(validSource + "x"))
	unpadded := strings.TrimRight(padded, "=")
	if unpadded == padded {
		t.Fatalf("test standard Base64 literal unexpectedly required no padding: %q", padded)
	}
	invalidUTF8Source := append([]byte(validSource+" # "), 0xff)

	for name, encoded := range map[string]string{
		"URL-safe alphabet": urlSafe,
		"implicit padding":  unpadded,
		"invalid UTF-8":     base64.StdEncoding.EncodeToString(invalidUTF8Source),
	} {
		t.Run(name, func(t *testing.T) {
			pth := []byte(pythonPTHBase64LauncherEncoded(encoded) + "\n")
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})

			if invoke := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); invoke == nil {
				t.Fatalf("exact outer invocation was lost: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
			}
			if operation := pythonPTHOperation(graph, behavior.OperationNetworkConnect); operation != nil {
				t.Fatalf("unsupported nested bytes became connected behavior: %#v", operation)
			}
			for _, feature := range graph.Features {
				if feature.Key == "python.base64_decoded_script" {
					t.Fatalf("unsupported nested bytes gained a decoded-stage Feature: %#v", feature)
				}
			}
			if !pythonPTHCoverageContains(graph, "interpreter invocation was retained") {
				t.Fatalf("nested byte omission lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonWheelPTHDecodedStageDoesNotPromotePythonLexicalDecoys(t *testing.T) {
	for name, test := range map[string]struct {
		decoded        string
		coverageDetail string
	}{
		"quoted network call": {
			decoded: `note = 'requests.get("https://quoted-decoy.example/")'`,
		},
		"comment semicolon": {
			decoded: `# inert; requests.get("https://comment-decoy.example/")`,
		},
		"quoted file read": {
			decoded: `note = 'open("~/.ssh/id_rsa").read()'`,
		},
		"multiline triple-quoted": {
			decoded: "\"\"\"documentation\nrequests.get(\"https://triple-decoy.example/\")\n\"\"\"",
		},
		"unterminated triple-quoted": {
			decoded:        "\"\"\"documentation\nrequests.get(\"https://unterminated-triple-decoy.example/\")",
			coverageDetail: "unterminated triple-quoted string",
		},
		"formatted triple-quoted": {
			decoded:        "note = f'''{requests.get(\"https://formatted-triple-decoy.example/\")}'''\nrequests.get(\"https://after-formatted-triple.example/\")",
			coverageDetail: "formatted or template triple-quoted string",
		},
		"template triple-quoted": {
			decoded:        "note = t'''{requests.get(\"https://template-triple-decoy.example/\")}'''\nrequests.get(\"https://after-template-triple.example/\")",
			coverageDetail: "formatted or template triple-quoted string",
		},
	} {
		t.Run(name, func(t *testing.T) {
			pth := []byte(pythonPTHBase64Launcher(test.decoded) + "\n")
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})

			if invoke := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); invoke == nil {
				t.Fatalf("exact outer invocation was lost: operations=%#v", graph.Operations)
			}
			for _, operation := range graph.Operations {
				if operation.Kind != behavior.OperationInterpreterInvoke {
					t.Fatalf("lexical decoy became connected behavior: %#v", operation)
				}
			}
			if test.coverageDetail != "" &&
				!pythonPTHAnyCoverageContains(graph, test.coverageDetail) {
				t.Fatalf("triple-quoted omission lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonWheelPTHDecodedStageResumesAfterOrdinaryTripleQuotedConstant(t *testing.T) {
	decoded := `import requests
description = """
requests.get("https://ordinary-triple-decoy.example/")
"""
requests.get("https://after-ordinary-triple.example/")
`
	pth := []byte(pythonPTHBase64Launcher(decoded) + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if operation := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://ordinary-triple-decoy.example/"); operation != nil {
		t.Fatalf("ordinary triple-quoted decoy became connected behavior: %#v", operation)
	}
	network := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://after-ordinary-triple.example/")
	if network == nil || network.Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("analysis did not resume after proved ordinary triple-quote close: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
	if hasPartialCoverageScope(graph.Coverage, "python-multiline-string-analysis") {
		t.Fatalf("a complete ordinary triple-quoted constant should not be partial: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHDecodedStageTripleQuoteMaskingLimitFailsClosed(t *testing.T) {
	decoded := `description = """` + "\n" +
		strings.Repeat("\n", maxPythonMultilineStringLines+1) +
		`"""` + "\n" +
		`requests.get("https://after-triple-limit.example/")`
	pth := []byte(pythonPTHBase64Launcher(decoded) + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if operation := pythonPTHOperationWithResource(graph, behavior.OperationNetworkConnect, "https://after-triple-limit.example/"); operation != nil {
		t.Fatalf("source after triple-string masking limit became behavior: %#v", operation)
	}
	if !pythonPTHAnyCoverageContains(graph, "triple-quoted string masking limit reached") {
		t.Fatalf("triple-string masking bound lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHDecodedStageRejectsSourceDecodingSemantics(t *testing.T) {
	for name, test := range map[string]struct {
		decoded string
		detail  string
	}{
		"UTF-8 BOM": {
			decoded: "\ufeff" + `requests.get("https://bom-decoy.example/")`,
			detail:  "used a UTF-8 BOM",
		},
		"first-line encoding cookie": {
			decoded: "# coding: latin-1\n" + `requests.get("https://first-cookie-decoy.example/")`,
			detail:  "used a source-encoding cookie",
		},
		"second-line encoding cookie": {
			decoded: "#!/usr/bin/env python\n# -*- coding: latin-1 -*-\n" +
				`requests.get("https://second-cookie-decoy.example/")`,
			detail: "used a source-encoding cookie",
		},
	} {
		t.Run(name, func(t *testing.T) {
			pth := []byte(pythonPTHBase64Launcher(test.decoded) + "\n")
			artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})

			if invoke := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); invoke == nil {
				t.Fatalf("exact outer invocation was lost: operations=%#v", graph.Operations)
			}
			for _, operation := range graph.Operations {
				if operation.Kind != behavior.OperationInterpreterInvoke {
					t.Fatalf("unsupported source-decoding semantics became connected behavior: %#v", operation)
				}
			}
			if !pythonPTHCoverageContains(graph, test.detail) ||
				!pythonPTHCoverageContains(graph, "source-decoding semantics are unsupported") {
				t.Fatalf("source-decoding omission lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonWheelPTHDoesNotRecursivelyUsePermissiveBase64Analyzer(t *testing.T) {
	nestedSource := `requests.get("https://recursive-decoy.example/")`
	for len(nestedSource)%3 == 0 {
		nestedSource += " "
	}
	unpadded := base64.RawStdEncoding.EncodeToString([]byte(nestedSource))
	decoded := "import base64\nexec(base64.b64decode(\"" + unpadded + "\"))"
	pth := []byte(pythonPTHBase64Launcher(decoded) + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if invoke := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); invoke == nil {
		t.Fatalf("exact outer invocation was lost: operations=%#v", graph.Operations)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationNetworkConnect); operation != nil {
		t.Fatalf("permissive recursive Base64 analysis produced connected behavior: %#v", operation)
	}
	decodedFeatures := 0
	for _, feature := range graph.Features {
		if feature.Key == "python.base64_decoded_script" {
			decodedFeatures++
		}
	}
	if decodedFeatures != 1 {
		t.Fatalf("decoded-stage Features = %d, want only the exact outer stage: %#v", decodedFeatures, graph.Features)
	}
	if !pythonPTHCoverageContains(graph, "unmatched nested stages remain unmodeled") {
		t.Fatalf("recursive-stage omission lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHLiteralStageContractFailsClosed(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`requests.get("https://must-not-connect.example/")`))
	code := `"import base64; exec(base64.b64decode('` + encoded + `'))"`
	exact := `subprocess.Popen([sys.executable, "-c", ` + code + `], stdout=subprocess.DEVNULL)`
	for name, line := range map[string]string{
		"missing subprocess import": `import sys; ` + exact,
		"missing sys import":        `import subprocess; ` + exact,
		"aliased import":            `import subprocess as subprocess, sys; ` + exact,
		"rebound by later import":   `import subprocess, sys; import os as subprocess; ` + exact,
		"unsupported import item":   `import subprocess, sys, pathlib; ` + exact,
		"malformed import list":     `import subprocess,, sys; ` + exact,
		"subprocess rebound":        `import subprocess, sys; subprocess = object(); ` + exact,
		"sys rebound":               `import subprocess, sys; sys = object(); ` + exact,
		"statement before launch":   `import subprocess, sys; pass; ` + exact,
		"statement after launch":    `import subprocess, sys; ` + exact + `; pass`,
		"syntax error after launch": `import subprocess, sys; ` + exact + `; ???`,
		"duplicate separator":       `import subprocess, sys;; ` + exact,
		"quoted decoy":              `import subprocess, sys; note = '` + exact + `'`,
		"dynamic code":              `import subprocess, sys; code = "print(1)"; subprocess.Popen([sys.executable, "-c", code])`,
		"concatenated code":         `import subprocess, sys; subprocess.Popen([sys.executable, "-c", "print(" + "1)"])`,
		"format code":               `import subprocess, sys; subprocess.Popen([sys.executable, "-c", f"print({1})"])`,
		"empty argv position":       `import subprocess, sys; subprocess.Popen([sys.executable, , "-c", ` + code + `])`,
		"empty call position":       `import subprocess, sys; subprocess.Popen(, [sys.executable, "-c", ` + code + `])`,
		"shell override":            `import subprocess, sys; subprocess.Popen([sys.executable, "-c", ` + code + `], shell=True)`,
		"executable override":       `import subprocess, sys; subprocess.Popen([sys.executable, "-c", ` + code + `], executable="/bin/sh")`,
		"extra argv":                `import subprocess, sys; subprocess.Popen([sys.executable, "-c", ` + code + `, "extra"])`,
		"multiple launch calls":     `import subprocess, sys; ` + exact + `; ` + exact,
		"mismatched delimiters":     `import subprocess, sys; subprocess.Popen([sys.executable, "-c", ` + code + `)]`,
		"comment inside call":       `import subprocess, sys; subprocess.Popen([sys.executable, # comment; "-c", ` + code + `])`,
	} {
		t.Run(name, func(t *testing.T) {
			artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
				t.Fatalf("direct startup declaration was lost: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
			}
			if operation := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); operation != nil {
				t.Fatalf("unsupported or malformed launcher became an invocation: %#v", operation)
			}
			if operation := pythonPTHOperation(graph, behavior.OperationNetworkConnect); operation != nil {
				t.Fatalf("unsupported or malformed launcher reached nested behavior: %#v", operation)
			}
		})
	}
}

func TestPythonWheelPTHImportCardinalityIsBounded(t *testing.T) {
	code := `"print('bounded import grammar')"`
	call := `subprocess.Popen([sys.executable, "-c", ` + code + `])`
	items := []string{"subprocess", "sys"}
	for len(items) < maxPythonWheelPTHImportItems {
		items = append(items, "os")
	}
	exactLine := "import " + strings.Join(items, ", ") + "; " + call
	artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(exactLine+"\n"), false)
	exactGraph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if operation := pythonPTHOperation(exactGraph, behavior.OperationInterpreterInvoke); operation == nil {
		t.Fatalf("exact import-item boundary lost the supported invocation: coverage=%#v", exactGraph.Coverage)
	}

	items = append(items, "os")
	limitedLine := "import " + strings.Join(items, ", ") + "; " + call
	artifacts, contents = pythonWheelPTHFixture("startup.pth", []byte(limitedLine+"\n"), false)
	limitedGraph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if operation := pythonPTHOperation(limitedGraph, behavior.OperationInterpreterInvoke); operation != nil {
		t.Fatalf("over-limit import list became an invocation: %#v", operation)
	}
	if !pythonPTHCoverageContains(limitedGraph, "import item limit 32 reached") {
		t.Fatalf("import cardinality omission lacks explicit coverage: %#v", limitedGraph.Coverage)
	}
}

func TestPythonWheelPTHRetainsOuterInvocationWhenNestedWrapperIsUnsupported(t *testing.T) {
	for name, code := range map[string]string{
		"arbitrary literal code": `print("hello")`,
		"dynamic base64":         `import base64; exec(base64.b64decode(payload))`,
		"invalid base64":         `import base64; exec(base64.b64decode("%%%"))`,
	} {
		t.Run(name, func(t *testing.T) {
			line := `import subprocess, sys; subprocess.Popen([sys.executable, "-c", ` + fmt.Sprintf("%q", code) + `])`
			artifacts, contents := pythonWheelPTHFixture("startup.pth", []byte(line+"\n"), false)
			graph := Run(Context{Artifacts: &artifacts, Contents: contents})
			if operation := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); operation == nil {
				t.Fatalf("exact outer invocation was lost: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
			}
			if operation := pythonPTHOperation(graph, behavior.OperationNetworkConnect); operation != nil {
				t.Fatalf("unsupported nested code became behavior: %#v", operation)
			}
			if !pythonPTHCoverageContains(graph, "interpreter invocation was retained") {
				t.Fatalf("nested semantic omission lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestBoundedPythonPTHStatementsRejectsMalformedStructure(t *testing.T) {
	for name, line := range map[string]string{
		"mismatched delimiters": `import subprocess, sys; subprocess.Popen(([)])`,
		"comment in delimiters": `import subprocess, sys; subprocess.Popen([sys.executable, # remainder`,
		"unterminated quote":    `import subprocess, sys; subprocess.Popen([sys.executable, "-c])`,
		"triple quote":          `import subprocess, sys; note = """decoy"""`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, malformed := boundedPythonPTHStatements(line); !malformed {
				t.Fatalf("malformed structure was accepted: %q", line)
			}
		})
	}
	hostile := "import subprocess, sys;" + strings.Repeat("(", maxPythonWheelPTHNesting+1)
	if _, limited, _ := boundedPythonPTHStatements(hostile); !limited {
		t.Fatal("nesting limit was not enforced")
	}
}

func TestPythonWheelPTHUsesCPythonTextIOBoundaries(t *testing.T) {
	pth := []byte("import harmless\rsubprocess.run([\"/bin/echo\", \"must-not-connect\"])\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
		t.Fatalf("first executable physical line was not retained: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationProcessExecute); operation != nil {
		t.Fatalf("code after a lone-CR runtime boundary was connected to the import line: %#v", operation)
	}

	lines := parsePythonPTHLines([]byte("path\rimport second\r\nignored\nimport\tfourth"))
	if len(lines.executable) != 2 || lines.executable[0].number != 2 || lines.executable[1].number != 4 {
		t.Fatalf("universal-newline boundaries were not honored: %#v", lines.executable)
	}

	lines = parsePythonPTHLines([]byte("path\u000bimport second\u000cimport third\u0085import fourth\u2028import fifth\u2029import sixth"))
	if len(lines.executable) != 0 {
		t.Fatalf("str.splitlines-only Unicode separators manufactured executable .pth lines: %#v", lines.executable)
	}

	bomPTH := []byte("\ufeff" + pythonPTHBase64Launcher(`requests.get("https://bom-pth-decoy.example/")`) + "\n")
	artifacts, contents = pythonWheelPTHFixture("startup.pth", bomPTH, false)
	graph = Run(Context{Artifacts: &artifacts, Contents: contents})
	if len(graph.ExecutionRoots) != 0 || pythonPTHFeature(graph) != nil || len(graph.Operations) != 0 {
		t.Fatalf("a UTF-8 BOM was stripped before CPython's executable-line prefix check: roots=%#v features=%#v operations=%#v", graph.ExecutionRoots, graph.Features, graph.Operations)
	}
}

func TestPythonWheelPTHDoesNotJoinIndependentExecutableLines(t *testing.T) {
	pth := []byte("import requests; requests.get(\nimport x; \"https://must-not-join.example/\")\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 {
		t.Fatalf("executable .pth declaration root was lost: %#v", graph.ExecutionRoots)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("independently executed malformed lines were joined into behavior: %#v", graph.Operations)
	}
	if !pythonPTHCoverageContains(graph, "only one exact same-line subprocess.Popen") {
		t.Fatalf("unmodeled executable lines lack explicit semantic coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHDoesNotPromoteAPILookingStringData(t *testing.T) {
	pth := []byte(`import harmless; note = 'subprocess.run(["/bin/evil"])'; url = 'requests.get("https://inert.example/")'` + "\n")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
		t.Fatalf("site-startup declaration was not retained: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("API-looking Python string data became execution-backed operations: %#v", graph.Operations)
	}
}

func TestPythonWheelPTHReportsByteInspectionLimit(t *testing.T) {
	prefix := pythonPTHBase64Launcher(`requests.get("https://truncated-line.example/")`)
	pth := []byte(prefix + strings.Repeat(" ", maxPythonWheelPTHBytes-len(prefix)) + "x")
	artifacts, contents := pythonWheelPTHFixture("startup.pth", pth, false)

	graph := Run(Context{Artifacts: &artifacts, Contents: contents})

	if len(graph.ExecutionRoots) != 1 || pythonPTHFeature(graph) == nil {
		t.Fatalf("direct startup declaration was lost at the byte boundary: roots=%#v features=%#v", graph.ExecutionRoots, graph.Features)
	}
	if operation := pythonPTHOperation(graph, behavior.OperationInterpreterInvoke); operation != nil {
		t.Fatalf("truncated physical line invented a connected operation: %#v", operation)
	}
	if !pythonPTHCoverageContains(graph, "only the first 1048576 .pth bytes were inspected") {
		t.Fatalf("bounded .pth inspection lacks explicit coverage: %#v", graph.Coverage)
	}
}

func TestPythonWheelPTHLineInspectionLimitBlocksLiteralSemantics(t *testing.T) {
	launcher := pythonPTHBase64Launcher("import requests\n" + `requests.get("https://line-limit.example/")`)
	var source strings.Builder
	source.WriteString(launcher)
	source.WriteByte('\n')
	for line := 1; line < maxPythonWheelPTHLines; line++ {
		source.WriteString("site-path\n")
	}

	exact := []byte(source.String())
	lines := parsePythonPTHLines(exact)
	if lines.semanticsTruncated {
		t.Fatal("exact .pth line boundary was marked truncated")
	}
	artifacts, contents := pythonWheelPTHFixture("startup.pth", exact, false)
	exactGraph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if operation := pythonPTHOperation(exactGraph, behavior.OperationNetworkConnect); operation == nil {
		t.Fatalf("exact line boundary lost decoded semantics: coverage=%#v", exactGraph.Coverage)
	}

	source.WriteString("uninspected-line\n")
	limited := []byte(source.String())
	lines = parsePythonPTHLines(limited)
	if !lines.semanticsTruncated {
		t.Fatal("over-limit .pth line inventory did not block semantic promotion")
	}
	artifacts, contents = pythonWheelPTHFixture("startup.pth", limited, false)
	limitedGraph := Run(Context{Artifacts: &artifacts, Contents: contents})
	if operation := pythonPTHOperation(limitedGraph, behavior.OperationInterpreterInvoke); operation != nil {
		t.Fatalf("partially inspected .pth file became an invocation: %#v", operation)
	}
	if !pythonPTHCoverageContains(limitedGraph, "only the first 4096 .pth lines were inspected") {
		t.Fatalf("line inspection limit lacks explicit coverage: %#v", limitedGraph.Coverage)
	}
}

func TestParsePythonPTHLinesIsExactAndBounded(t *testing.T) {
	lines := parsePythonPTHLines([]byte("\ufeffimport first\nimport\tsecond\n import third\nimportx fourth\n"))
	if len(lines.executable) != 1 || lines.executable[0].number != 2 || lines.executable[0].text != "import\tsecond" {
		t.Fatalf("executable line grammar mismatch: %#v", lines.executable)
	}
	var hostile strings.Builder
	for index := 0; index <= maxPythonWheelPTHExecutableLines; index++ {
		hostile.WriteString("import x\n")
	}
	bounded := parsePythonPTHLines([]byte(hostile.String()))
	if len(bounded.executable) != maxPythonWheelPTHExecutableLines || !slices.ContainsFunc(bounded.partials, func(value string) bool {
		return strings.Contains(value, "executable .pth line limit")
	}) {
		t.Fatalf("executable-line bound failed: retained=%d partial=%q", len(bounded.executable), bounded.partials)
	}
	if !bounded.semanticsTruncated {
		t.Fatal("executable-line truncation did not block semantic promotion")
	}
}

func TestParsePythonWheelHeadersFailsClosed(t *testing.T) {
	valid := []byte("Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n")
	headers, reason := parseWheelHeaders(valid)
	if reason != "" || headers.version != "1.0" || headers.rootIsPurelib {
		t.Fatalf("valid WHEEL headers failed: headers=%#v reason=%q", headers, reason)
	}
	for name, data := range map[string]string{
		"unsupported major": "Wheel-Version: 2.0\nRoot-Is-Purelib: true\n",
		"missing layout":    "Wheel-Version: 1.0\n",
		"duplicate version": "Wheel-Version: 1.0\nWheel-Version: 1.0\nRoot-Is-Purelib: true\n",
		"invalid boolean":   "Wheel-Version: 1.0\nRoot-Is-Purelib: maybe\n",
		"malformed header":  "Wheel-Version 1.0\nRoot-Is-Purelib: true\n",
		"body content":      "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n\nTag: py3-none-any\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, reason := parseWheelHeaders([]byte(data)); reason == "" {
				t.Fatalf("malformed WHEEL metadata accepted: %q", data)
			}
		})
	}
	withoutTag, reason := parseWheelHeaders([]byte("Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"))
	if reason != "" || !withoutTag.rootIsPurelib {
		t.Fatalf("installer-relevant WHEEL metadata without Tag was rejected: headers=%#v reason=%q", withoutTag, reason)
	}
	var hostile strings.Builder
	hostile.WriteString("Wheel-Version: 1.0\nRoot-Is-Purelib: true\n")
	for index := 0; index < maxPythonWheelHeaderLines; index++ {
		hostile.WriteString("Generator: x\n")
	}
	if _, reason := parseWheelHeaders([]byte(hostile.String())); !strings.Contains(reason, "header-line limit") {
		t.Fatalf("newline-dense WHEEL metadata lacked bounded failure: %q", reason)
	}
}

func TestPythonWheelFilenameTagFailsClosed(t *testing.T) {
	for name, logical := range map[string]string{
		"missing tag":        "sample.whl",
		"windows only":       "sample-1.0-py3-none-win_amd64.whl",
		"space in tag":       "sample-1.0-evil value-none-any.whl",
		"malformed macOS":    "sample-1.0-cp314-cp314-macosx_evil.whl",
		"unknown macOS arch": "sample-1.0-cp314-cp314-macosx_15_0_notamacarch.whl",
		"missing extension":  "sample-1.0-py3-none-any",
	} {
		t.Run(name, func(t *testing.T) {
			if _, reason := pythonWheelFilenameTag(logical); reason == "" {
				t.Fatalf("malformed or platform-incompatible filename accepted: %q", logical)
			}
		})
	}
	for _, logical := range []string{
		"sample-1.0-py3-none-any.whl",
		"carrier!sample-1.0-cp314-cp314-macosx_15_0_arm64.whl",
		"sample-1.0-cp314-cp314-macosx_10_9_fat3.whl",
		"sample-1.0-py3-none-macosx_14_0_x86_64.macosx_15_0_arm64.whl",
	} {
		if _, reason := pythonWheelFilenameTag(logical); reason != "" {
			t.Fatalf("valid platform filename rejected: %q: %s", logical, reason)
		}
	}
}

func TestParsePythonWheelRecordFailsClosed(t *testing.T) {
	content := artifact.Content{Data: []byte("import hook\n")}
	path := "startup.pth"
	recordPath := "sample-1.0.dist-info/RECORD"
	valid := pythonRecordLine(path, content.Data) + recordPath + ",,\n"
	wanted := map[string]artifact.Content{path: content, recordPath: {Data: []byte(valid)}}

	proofs, ok := parsePythonWheelRecord([]byte(valid), wanted, recordPath)
	if !ok || !proofs[path].valid || !proofs[recordPath].valid {
		t.Fatalf("valid RECORD proof failed: ok=%v proofs=%#v", ok, proofs)
	}
	for name, record := range map[string]string{
		"duplicate": valid + pythonRecordLine(path, content.Data),
		"malformed": path + ",sha256=abc\n",
		"self hash": pythonRecordLine(path, content.Data) + pythonRecordLine(recordPath, []byte(valid)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parsePythonWheelRecord([]byte(record), wanted, recordPath); ok {
				t.Fatalf("malformed RECORD accepted: %q", record)
			}
		})
	}
}

func pythonWheelPTHFixture(pthPath string, pthData []byte, wrappedByCArchive bool) (artifact.Graph, []artifact.Content) {
	wheelLogical := "sample-1.0-py3-none-any.whl"
	wheelParent := ""
	nodes := []artifact.Node(nil)
	if wrappedByCArchive {
		wheelLogical = "carrier!sample-1.0-py3-none-any.whl"
		wheelParent = "node-carrier"
		nodes = append(nodes, artifact.Node{ID: "node-carrier", LogicalPath: "carrier", Kind: "carchive", AnalyzeStatus: "analyzed"})
	}
	nodes = append(nodes, artifact.Node{ID: "node-wheel", ParentID: wheelParent, LogicalPath: wheelLogical, Kind: "python-wheel", AnalyzeStatus: "analyzed"})

	wheelPath := "sample-1.0.dist-info/WHEEL"
	recordPath := "sample-1.0.dist-info/RECORD"
	wheelData := []byte("Wheel-Version: 1.0\nGenerator: maratus-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
	recordData := []byte(pythonRecordLine(pthPath, pthData) + pythonRecordLine(wheelPath, wheelData) + recordPath + ",,\n")
	members := []struct {
		id   string
		path string
		data []byte
	}{
		{id: "node-pth", path: pthPath, data: pthData},
		{id: "node-wheel-metadata", path: wheelPath, data: wheelData},
		{id: "node-record", path: recordPath, data: recordData},
	}
	sort.Slice(members, func(i, j int) bool { return members[i].path < members[j].path })
	contents := make([]artifact.Content, 0, len(members))
	for _, member := range members {
		logical := wheelLogical + "!" + member.path
		nodes = append(nodes, artifact.Node{
			ID:            member.id,
			ParentID:      "node-wheel",
			LogicalPath:   logical,
			Kind:          "text",
			MediaType:     "text/plain",
			SourceRole:    "unknown",
			AnalyzeStatus: "analyzed",
		})
		contents = append(contents, artifact.Content{
			NodeID:      member.id,
			LogicalPath: logical,
			Kind:        "text",
			MediaType:   "text/plain",
			Role:        "unknown",
			Data:        member.data,
		})
	}
	return artifact.Graph{Nodes: nodes}, contents
}

func pythonRecordLine(path string, data []byte) string {
	return fmt.Sprintf("%s,sha256=%s,%d\n", path, pythonRecordDigest(data), len(data))
}

func pythonRecordDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pythonPTHContent(contents []artifact.Content, base string) artifact.Content {
	for _, content := range contents {
		if filepathBaseForPythonPTHTest(content.LogicalPath) == base {
			return content
		}
	}
	return artifact.Content{}
}

func replacePythonPTHContent(contents []artifact.Content, replacement artifact.Content) {
	for index := range contents {
		if contents[index].NodeID == replacement.NodeID {
			contents[index] = replacement
			return
		}
	}
}

func filepathBaseForPythonPTHTest(logical string) string {
	logical = strings.ReplaceAll(logical, "!", "/")
	parts := strings.Split(logical, "/")
	return parts[len(parts)-1]
}

func pythonPTHFeature(graph behavior.Graph) *behavior.Feature {
	for index := range graph.Features {
		if graph.Features[index].Key == "python.site.pth.import-line" {
			return &graph.Features[index]
		}
	}
	return nil
}

func pythonPTHOperation(graph behavior.Graph, kind behavior.OperationKind) *behavior.ModeledOperation {
	for index := range graph.Operations {
		if graph.Operations[index].SubjectNodeID == "node-pth" && graph.Operations[index].Kind == kind {
			return &graph.Operations[index]
		}
	}
	return nil
}

func pythonPTHOperationWithResource(graph behavior.Graph, kind behavior.OperationKind, value string) *behavior.ModeledOperation {
	for index := range graph.Operations {
		operation := &graph.Operations[index]
		if operation.SubjectNodeID != "node-pth" || operation.Kind != kind {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Resource.Value == value {
				return operation
			}
		}
	}
	return nil
}

func pythonPTHCoverageContains(graph behavior.Graph, fragment string) bool {
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == pythonWheelPTHAnalysisArea && strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}

func pythonPTHAnyCoverageContains(graph behavior.Graph, fragment string) bool {
	for _, coverage := range graph.Coverage {
		if strings.Contains(coverage.Detail, fragment) {
			return true
		}
	}
	return false
}

func pythonPTHBase64Launcher(decoded string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	return pythonPTHBase64LauncherEncoded(encoded)
}

func pythonPTHBase64LauncherEncoded(encoded string) string {
	return `import subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('` + encoded + `'))"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)`
}
