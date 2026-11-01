package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestSharedDiscoveryVocabularyAcrossShellAndNativeCalls(t *testing.T) {
	tests := []struct {
		command string
		symbol  string
		kind    behavior.OperationKind
	}{
		{"uname -a", "_uname", behavior.OperationSystemInfoQuery},
		{"whoami", "_getuid", behavior.OperationUserInfoQuery},
		{"ps aux", "_proc_listpids", behavior.OperationProcessEnumerate},
		{"find /tmp -maxdepth 1", "_readdir", behavior.OperationFileEnumerate},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			shell := behavior.Graph{}
			AnalyzeShellLine(&shell, artifact.Content{NodeID: "shell"}, test.command, 1, unknownExecutionContext(), "ev-shell")
			if len(shell.Operations) != 1 || shell.Operations[0].Kind != test.kind || shell.Operations[0].Support != behavior.SupportCorroborated {
				t.Fatalf("shell semantics = %#v", shell.Operations)
			}

			native := behavior.Graph{}
			scopeID := native.AddScope(behavior.Scope{NodeID: "native", Kind: "function", Function: "main", Name: "main", Architecture: "arm64"})
			evidenceID := native.AddEvidence(behavior.Evidence{NodeID: "native", ScopeID: scopeID, Function: "main", Arch: "arm64", Method: "fixture", Kind: "import-call", Value: test.symbol})
			addOperationFromCalledImportedSymbol(&native, artifact.Content{NodeID: "native"}, test.symbol, "arm64", evidenceID, machoFunction{Name: "main"})
			if len(native.Operations) != 1 || native.Operations[0].Kind != test.kind || native.Operations[0].Support != behavior.SupportCorroborated {
				t.Fatalf("native semantics = %#v", native.Operations)
			}
		})
	}
}

func TestNativeSourceAndMachOUseSameCollectionVocabulary(t *testing.T) {
	tests := []struct {
		line   string
		symbol string
		kind   behavior.OperationKind
	}{
		{`CGEventTapCreate(.cgSessionEventTap, .headInsertEventTap, .listenOnly, mask, callback, nil)`, "_CGEventTapCreate", behavior.OperationInputEventTapCreate},
		{`AudioQueueNewInput(&format, callback, context, nil, nil, 0, &queue);`, "_AudioQueueNewInput", behavior.OperationAudioRecordingQueueCreate},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			var source behavior.Graph
			ExtractText(&source, artifact.Content{NodeID: "source", LogicalPath: "Control.swift", Kind: "text", MediaType: "text/plain", Role: "runtime", Data: []byte(test.line)})
			if len(source.Operations) != 1 || source.Operations[0].Kind != test.kind || source.Operations[0].Support != behavior.SupportCorroborated {
				t.Fatalf("source semantics = %#v", source.Operations)
			}

			var native behavior.Graph
			scopeID := native.AddScope(behavior.Scope{NodeID: "native", Kind: "function", Function: "main", Name: "main", Architecture: "arm64"})
			evidenceID := native.AddEvidence(behavior.Evidence{NodeID: "native", ScopeID: scopeID, Function: "main", Arch: "arm64", Method: "fixture", Kind: "import-call", Value: test.symbol})
			addOperationFromCalledImportedSymbol(&native, artifact.Content{NodeID: "native"}, test.symbol, "arm64", evidenceID, machoFunction{Name: "main"})
			if len(native.Operations) != 1 || native.Operations[0].Kind != test.kind || native.Operations[0].Support != behavior.SupportCorroborated {
				t.Fatalf("Mach-O semantics = %#v", native.Operations)
			}
		})
	}
}

func TestPythonAndJavaScriptBuiltinsUseSameTypedVocabulary(t *testing.T) {
	tests := []struct {
		name       string
		python     string
		javascript string
		kind       behavior.OperationKind
		role       behavior.ResourceRole
		value      string
	}{
		{
			name: "file enumeration", python: "import os\nos.listdir(\"/Users/alice\")\n",
			javascript: "import * as fs from 'node:fs';\nfs.readdirSync('/Users/alice');\n",
			kind:       behavior.OperationFileEnumerate, role: behavior.ResourceRoleSource, value: "/Users/alice",
		},
		{
			name: "system information", python: "import platform\nplatform.system()\n",
			javascript: "import os from 'node:os';\nos.hostname();\n",
			kind:       behavior.OperationSystemInfoQuery, role: behavior.ResourceRoleSource, value: "macOS system and hardware",
		},
		{
			name: "name resolution", python: "import socket\nsocket.gethostbyname(\"example.invalid\")\n",
			javascript: "import {lookup} from 'node:dns/promises';\nlookup('example.invalid');\n",
			kind:       behavior.OperationNameResolve, role: behavior.ResourceRoleSource, value: "example.invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			python := pythonAPIExtract(test.python)
			pythonOperation, pythonOK := pythonAPIOperation(python, test.kind, test.role, test.value)
			javascript := javaScriptAPIExtract(test.javascript)
			javascriptOperation, javascriptOK := javaScriptAPIOperation(javascript, test.kind, test.role, test.value)
			if !pythonOK || !javascriptOK {
				t.Fatalf("parity operation missing: python=%#v javascript=%#v", python.Operations, javascript.Operations)
			}
			if pythonOperation.Support != behavior.SupportCorroborated || javascriptOperation.Support != behavior.SupportCorroborated {
				t.Fatalf("parity support differs: python=%#v javascript=%#v", pythonOperation, javascriptOperation)
			}
		})
	}
}

func TestNetworkConfigurationDiscoveryUsesOneTypedOperationAcrossAdapters(t *testing.T) {
	graphs := map[string]behavior.Graph{}
	graphs["shell"] = extractShellCommandFixture("/sbin/ifconfig -a")
	graphs["python"] = pythonAPIExtract("import socket\nsocket.if_nameindex()\n")
	graphs["javascript"] = javaScriptAPIExtract("import os from 'node:os';\nos.networkInterfaces();\n")

	var native behavior.Graph
	scopeID := native.AddScope(behavior.Scope{NodeID: "native", Kind: "function", Function: "main", Name: "main", Architecture: "arm64"})
	evidenceID := native.AddEvidence(behavior.Evidence{NodeID: "native", ScopeID: scopeID, Function: "main", Arch: "arm64", Method: "fixture", Kind: "import-call", Value: "_getifaddrs"})
	addOperationFromCalledImportedSymbol(&native, artifact.Content{NodeID: "native"}, "_getifaddrs", "arm64", evidenceID, machoFunction{Name: "main"})
	graphs["macho"] = native

	for name, graph := range graphs {
		var matches []behavior.ModeledOperation
		for _, operation := range graph.Operations {
			if operation.Kind == behavior.OperationNetworkConfigurationQuery {
				matches = append(matches, operation)
			}
		}
		if len(matches) != 1 || matches[0].Support != behavior.SupportCorroborated || matches[0].RequiredResource().Kind != behavior.ResourceConfiguration {
			t.Fatalf("%s network-configuration semantics = %#v", name, graph.Operations)
		}
	}
}
