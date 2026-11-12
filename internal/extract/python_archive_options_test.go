package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/behavior"
)

func TestPythonArchiveExtractionSupportedOptions(t *testing.T) {
	for name, source := range map[string]string{
		"tar default file object": "import tarfile\ntarfile.open(\"/tmp/input.tar\", fileobj=None).extractall(\"/tmp/output\", members=None, numeric_owner=False, filter=\"data\")\n",
		"tar stream":              "import tarfile\ntarfile.open(\"/tmp/input.tar\", \"r|gz\", None).extractall(path=\"/tmp/output\", filter=None)\n",
		"zip byte password":       "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\", \"r\").extractall(\"/tmp/output\", members=None, pwd=b\"inert\")\n",
		"zip default password":    "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(path=\"/tmp/output\", pwd=None)\n",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			operation, ok := pythonAPIOperation(graph, behavior.OperationArchiveExtract, behavior.ResourceRoleSource, "/tmp/input.tar")
			if !ok || operation.Support != behavior.SupportCorroborated || len(operation.EvidenceIDs) != 2 || operation.Execution.Connectivity != behavior.ConnectivityUnknown {
				t.Fatalf("supported extraction lost exact API context: %#v", graph.Operations)
			}
		})
	}
	for _, mode := range []string{"r", "r:*", "r:", "r:gz", "r:bz2", "r:xz", "r:zst", "r|", "r|*", "r|gz", "r|bz2", "r|xz", "r|zst"} {
		t.Run("tar mode "+mode, func(t *testing.T) {
			if !pythonArchiveReadMode("tarfile", `"`+mode+`"`) {
				t.Fatalf("documented read mode %q rejected", mode)
			}
		})
	}
}

func TestPythonArchiveExtractionRejectsSourceAndConsumerOverrides(t *testing.T) {
	for name, source := range map[string]string{
		"file object override":     "import tarfile\ntarfile.open(\"/tmp/input.tar\", fileobj=other).extractall(\"/tmp/output\")\n",
		"positional file object":   "import tarfile\ntarfile.open(\"/tmp/input.tar\", \"r\", other).extractall(\"/tmp/output\")\n",
		"invalid tar read prefix":  "import tarfile\ntarfile.open(\"/tmp/input.tar\", mode=\"rubbish\").extractall(\"/tmp/output\")\n",
		"unknown compression":      "import tarfile\ntarfile.open(\"/tmp/input.tar\", mode=\"r:unknown\").extractall(\"/tmp/output\")\n",
		"dynamic mode":             "import tarfile\ntarfile.open(\"/tmp/input.tar\", mode=mode).extractall(\"/tmp/output\")\n",
		"zip bytes is not path":    "import zipfile\nzipfile.ZipFile(b\"/tmp/input.tar\").extractall(\"/tmp/output\")\n",
		"zip raw bytes not path":   "import zipfile\nzipfile.ZipFile(br\"/tmp/input.tar\").extractall(\"/tmp/output\")\n",
		"zip raw bytes reversed":   "import zipfile\nzipfile.ZipFile(rb\"/tmp/input.tar\").extractall(\"/tmp/output\")\n",
		"custom filter":            "import tarfile\ntarfile.open(\"/tmp/input.tar\").extractall(\"/tmp/output\", filter=redirect)\n",
		"unknown filter":           "import tarfile\ntarfile.open(\"/tmp/input.tar\").extractall(\"/tmp/output\", filter=\"unknown\")\n",
		"custom members":           "import tarfile\ntarfile.open(\"/tmp/input.tar\").extractall(\"/tmp/output\", members=other)\n",
		"empty members":            "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(\"/tmp/output\", members=[])\n",
		"string members":           "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(\"/tmp/output\", members=\"entry\")\n",
		"dynamic password":         "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(\"/tmp/output\", pwd=password)\n",
		"string password":          "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(\"/tmp/output\", pwd=\"inert\")\n",
		"non-ASCII bytes password": "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(\"/tmp/output\", pwd=b\"é\")\n",
		"invalid owner type":       "import tarfile\ntarfile.open(\"/tmp/input.tar\").extractall(\"/tmp/output\", numeric_owner=other)\n",
		"bytes destination":        "import zipfile\nzipfile.ZipFile(\"/tmp/input.tar\").extractall(b\"/tmp/output\")\n",
	} {
		t.Run(name, func(t *testing.T) {
			graph := pythonAPIExtract(source)
			if operations := pythonAPIOperationsByKind(graph, behavior.OperationArchiveExtract); len(operations) != 0 {
				t.Fatalf("unsupported source/consumer became exact extraction: %#v", operations)
			}
			if !hasPartialCoverageScope(graph.Coverage, pythonAPIBindingAnalysisArea) {
				t.Fatalf("unsupported archive profile lacks explicit coverage: %#v", graph.Coverage)
			}
		})
	}
}

func TestPythonArchiveExtractionFileLikeSourceIsNotAPathLiteral(t *testing.T) {
	graph := pythonAPIExtract("import zipfile\nzipfile.ZipFile(BytesIO(b\"/tmp/not-a-file\")).extractall(\"/tmp/output\")\n")
	operations := pythonAPIOperationsByKind(graph, behavior.OperationArchiveExtract)
	if len(operations) != 1 || operations[0].Qualifiers["source_binding"] != "unresolved" {
		t.Fatalf("file-like source did not remain unresolved: %#v", operations)
	}
	if source, ok := operations[0].FirstBinding(behavior.ResourceRoleSource); !ok || source.Resource.Value != "" {
		t.Fatalf("literal bytes inside file-like source became a pathname: %#v", source)
	}
}
