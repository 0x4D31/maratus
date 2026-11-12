package extract

import (
	"github.com/0x4D31/maratus/internal/behavior"
	"testing"
)

func TestPythonUploadRequiresSelectedPayloadArgument(t *testing.T) {
	for _, call := range []string{
		`requests.post("https://unit.invalid/?data=x")`,
		`requests.post("https://unit.invalid/", headers={"x": "data=foo"})`,
		`requests.post("https://unit.invalid/", data=None)`,
		`urllib.request.urlopen("https://unit.invalid/", data=None)`,
	} {
		graph := pythonAPIExtract("import requests\nimport urllib.request\n" + call + "\n")
		if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect {
			t.Errorf("body-free request became upload: %s: %#v", call, graph.Operations)
		}
	}
}
func TestPythonSeparateNetworkCallsCannotShareDestinationOrMethod(t *testing.T) {
	graph := pythonAPIExtract("import requests\n" + `requests.get("https://first.invalid/"); requests.post("https://second.invalid/", data=b"data")` + "\n")
	if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
		t.Fatalf("multiple network calls mixed: %#v", graph.Operations)
	}
}

func TestPythonHTTPCallsRejectUnsupportedSignatures(t *testing.T) {
	for _, call := range []string{
		`requests.post("https://unit.invalid/", impossible=True)`,
		`requests.post("https://unit.invalid/", b"one", data=b"two")`,
		`requests.request("POST", "https://unit.invalid/", b"extra")`,
		`httpx.post("https://unit.invalid/", b"extra")`,
		`httpx.get("https://unit.invalid/", data=b"extra")`,
	} {
		graph := pythonAPIExtract("import requests\nimport httpx\n" + call + "\n")
		if len(graph.Operations) != 0 || !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
			t.Errorf("invalid signature acquired I/O: %s: %#v", call, graph.Operations)
		}
	}
	for _, call := range []string{
		`requests.post("https://unit.invalid/", b"body")`,
		`requests.request("POST", "https://unit.invalid/", json={"k":"v"})`,
		`httpx.post("https://unit.invalid/", content=b"body")`,
		`urllib2.urlopen("https://unit.invalid/", b"body")`,
	} {
		graph := pythonAPIExtract("import requests\nimport httpx\nimport urllib2\n" + call + "\n")
		if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkUpload {
			t.Errorf("body argument lost: %s: %#v", call, graph.Operations)
		}
	}
}
