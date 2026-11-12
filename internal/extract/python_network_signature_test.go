package extract

import (
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonStandardNetworkCallsRequireDocumentedSignature(t *testing.T) {
	for name, source := range map[string]string{
		"urlopen":     "import urllib.request\nurllib.request.urlopen(\"https://unit.example.invalid/data\", data=None, timeout=10, context=None)\n",
		"urlretrieve": "import urllib.request\nurllib.request.urlretrieve(\"https://unit.example.invalid/data\", filename=\"/tmp/output\", reporthook=None, data=None)\n",
		"legacy open": "import urllib2\nurllib2.urlopen(\"https://unit.example.invalid/data\", timeout=10)\n",
		"alias":       "import urllib.request as client\nclient.urlopen(url=\"https://unit.example.invalid/data\", context=context)\n",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			if len(graph.Operations) != 1 || len(graph.Operations[0].EvidenceIDs) != 2 || graph.Operations[0].Support != behavior.SupportCorroborated || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("supported network call lost context/lineage: %#v", graph.Operations)
			}
		})
	}
	for name, call := range map[string]string{
		"unknown open option":    `urllib.request.urlopen("https://unit.example.invalid/data", impossible=True)`,
		"unknown retrieve opt":   `urllib.request.urlretrieve("https://unit.example.invalid/data", "/tmp/output", impossible=True)`,
		"missing URL":            `urllib.request.urlopen(data=None)`,
		"duplicate positional":   `urllib.request.urlopen("https://unit.example.invalid/data", url="https://other.example.invalid/")`,
		"duplicate keyword":      `urllib.request.urlopen(url="https://unit.example.invalid/data", url="https://other.example.invalid/")`,
		"keyword-only context":   `urllib.request.urlopen("https://unit.example.invalid/data", None, 10, context)`,
		"too many retrieve args": `urllib.request.urlretrieve("https://unit.example.invalid/data", "/tmp/output", None, None, 5)`,
		"starred open options":   `urllib.request.urlopen("https://unit.example.invalid/data", **options)`,
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract("import urllib.request\n" + call + "\n")
			if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
				t.Fatalf("invalid stdlib signature acquired semantics or lost coverage: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
			}
		})
	}
}

func TestPythonRequestConstructionDoesNotCommunicate(t *testing.T) {
	for _, source := range []string{
		"import urllib2\nurllib2.Request(\"https://unit.example.invalid/data\")\n",
		"import urllib.request\nurllib.request.Request(\"https://unit.example.invalid/data\")\n",
		"import requests\nrequests.Request(\"GET\", \"https://unit.example.invalid/data\")\n",
		"import httpx\nhttpx.Request(\"GET\", \"https://unit.example.invalid/data\")\n",
	} {
		graph := pythonAPIExtract(source)
		if len(graph.Operations) != 0 || hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
			t.Fatalf("request construction became I/O or an invalid network call: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
		}
	}
}

func TestPythonStandardNetworkSignatureBudgetIsExplicit(t *testing.T) {
	graph := pythonAPIExtract("import urllib.request\nurllib.request.urlopen(\"https://unit.example.invalid/" + strings.Repeat("a", maxPythonAPICallBytes) + "\")\n")
	if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("oversized stdlib network call was not bounded: operations=%#v coverage=%#v", graph.Operations, graph.Coverage)
	}
}
