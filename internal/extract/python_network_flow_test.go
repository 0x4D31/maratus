package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonResponseDownloadRequiresExactContentWrite(t *testing.T) {
	for name, source := range map[string]string{
		"literal":          "r = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(b\"r.content\")",
		"wrapped response": "r = bool(requests.get(\"https://unit.invalid/payload\"))\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"other attribute":  "r = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(r.content_type)",
		"conditional body": "r = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(b\"yes\" if r.content else b\"no\")",
		"read-only file":   "r = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"rb\").write(r.content)",
		"rebound open":     "r = requests.get(\"https://unit.invalid/payload\")\nopen = custom\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"custom opener":    "r = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\", opener=custom).write(r.content)",
		"mutated content":  "r = requests.get(\"https://unit.invalid/payload\")\nr._content = b\"local\"\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"escaped response": "r = requests.get(\"https://unit.invalid/payload\")\ncustom(r)\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"inline wrapper":   "open(\"/tmp/out\", \"wb\").write(bool(requests.get(\"https://unit.invalid/payload\")))",
		"inline read-only": "open(\"/tmp/out\", \"rb\").write(requests.get(\"https://unit.invalid/payload\").content)",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract("import requests\n" + source + "\n")
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationNetworkDownload {
					t.Fatalf("unsupported response flow became download: %#v", operation)
				}
			}
			if !hasPartialCoverageScope(graph.Coverage, "python-response-write") {
				t.Fatalf("unsupported write lacks coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonResponseDownloadPreservesSupportedFlows(t *testing.T) {
	for name, source := range map[string]string{
		"split":       "import requests\nr = requests.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"with":        "import requests\nr = requests.get(\"https://unit.invalid/payload\")\nwith open(\"/tmp/out\", \"wb\") as f:f.write(r.content)",
		"inline":      "import requests\nopen(\"/tmp/out\", \"wb\").write(requests.get(\"https://unit.invalid/payload\").content)",
		"alias":       "import requests as client\nr = client.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"httpx":       "import httpx\nr = httpx.get(\"https://unit.invalid/payload\")\nopen(\"/tmp/out\", \"wb\").write(r.content)",
		"urlretrieve": "import urllib.request\nurllib.request.urlretrieve(filename=\"/tmp/out\", url=\"https://unit.invalid/payload\")",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source + "\n")
			assertTextDownloadDestination(t, graph, "/tmp/out", "https://unit.invalid/payload")
			for _, operation := range graph.Operations {
				if operation.Kind == behavior.OperationNetworkDownload && (operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) == 0) {
					t.Fatalf("download lacks supporting evidence: %#v", operation)
				}
			}
		})
	}
}

func TestPythonNetworkDestinationUsesWholeURLArgument(t *testing.T) {
	for _, call := range []string{
		`requests.get("prefix https://unit.invalid/payload suffix")`,
		`requests.get("not a URL", headers={"hint": "https://unit.invalid/payload"})`,
	} {
		graph := pythonAPIExtract("import requests\n" + call + "\n")
		for _, operation := range graph.Operations {
			for _, binding := range operation.ResourceBindings {
				if binding.Resource.Value != "" {
					t.Fatalf("URL substring became an exact operand: %#v", operation)
				}
			}
		}
	}
	for _, call := range []string{
		`requests.post(data=b"body", url="https://unit.invalid/payload?q=a&b=c")`,
		`requests.request(method="GET", url="https://unit.invalid/payload?q=a&b=c")`,
	} {
		graph := pythonAPIExtract("import requests\n" + call + "\n")
		if len(graph.Operations) != 1 {
			t.Fatalf("expected one HTTP operation: %#v", graph.Operations)
		}
		resource, ok := testOperationBinding(graph.Operations[0], behavior.ResourceRoleRemoteDestination)
		if !ok || resource.Value != "https://unit.invalid/payload?q=a&b=c" {
			t.Fatalf("selected URL changed: %#v", graph.Operations[0])
		}
	}
}

func TestPythonLocalURLDoesNotEstablishNetworkOperation(t *testing.T) {
	for _, source := range []string{
		"import urllib.request\nurllib.request.urlopen(\"file:///tmp/input\")\n",
		"import urllib.request\nurllib.request.urlopen(\"data:text/plain,control\")\n",
	} {
		graph := pythonAPIExtract(source)
		for _, operation := range graph.Operations {
			if isNetworkOperationKind(operation.Kind) {
				t.Fatalf("local URL acquired network semantics: %#v", operation)
			}
		}
		if !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
			t.Fatalf("local transport lacks coverage: %#v", graph.Coverage)
		}
	}
}

func TestPythonSplitDownloadRetainsRequestAndImportEvidence(t *testing.T) {
	for name, test := range map[string]struct {
		source string
		lines  []int
		absent int
	}{
		"split":      {"import requests\nr = requests.get(\"https://unit.invalid/p\")\nopen(\"/tmp/out\", \"wb\").write(r.content)\n", []int{1, 2, 3}, 0},
		"reassigned": {"import requests\nr = requests.get(\"https://old.invalid/p\")\nr = requests.get(\"https://unit.invalid/p\")\nopen(\"/tmp/out\", \"wb\").write(r.content)\n", []int{1, 3, 4}, 2},
		"function":   {"import requests as client\ndef collect():\n    r = client.get(\"https://unit.invalid/p\")\n    open(\"/tmp/out\", \"wb\").write(r.content)\n", []int{1, 3, 4}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(test.source)
			downloads := pythonAPIOperationsByKind(graph, behavior.OperationNetworkDownload)
			if len(downloads) != 1 {
				t.Fatalf("downloads = %#v", downloads)
			}
			lines := map[int]bool{}
			for _, id := range downloads[0].EvidenceIDs {
				for _, evidence := range graph.Evidence {
					if evidence.ID == id {
						lines[evidence.Line] = true
					}
				}
			}
			for _, line := range test.lines {
				if !lines[line] {
					t.Errorf("download lacks causal evidence from line %d: %#v", line, downloads[0])
				}
			}
			if test.absent != 0 && lines[test.absent] {
				t.Fatalf("download inherited overwritten response evidence from line %d", test.absent)
			}
		})
	}
}
