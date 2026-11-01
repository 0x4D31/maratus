package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestNativeSourceProcessPrimitivesAreNotInjectionByThemselves(t *testing.T) {
	tests := map[string]string{
		"task_for_pid(mach_task_self(), pid, &task);":         "process.task-access",
		"mach_vm_read(task, address, size, &data, &count);":   "process.memory.read",
		"mach_vm_write(task, address, data, count);":          "process.memory.write",
		"thread_create_running(task, state, count, &thread);": "process.thread.create",
	}
	for line, want := range tests {
		t.Run(want+line[:4], func(t *testing.T) {
			var graph behavior.Graph
			ExtractText(&graph, artifact.Content{
				NodeID:      "node-1",
				LogicalPath: "sample.c",
				Kind:        "text",
				MediaType:   "text/plain",
				Data:        []byte(line),
			})
			if len(graph.Operations) != 1 || string(graph.Operations[0].Kind) != want || graph.Operations[0].RequiredResource().Kind != behavior.ResourceProcess {
				t.Fatalf("primitive %q produced %#v, want %s", line, graph.Operations, want)
			}
			if graph.Operations[0].Kind == "process.inject" {
				t.Fatalf("single primitive overclaimed injection: %#v", graph.Operations[0])
			}
		})
	}
}

func TestMachOCalledProcessPrimitivesAreClassifiedPrecisely(t *testing.T) {
	tests := map[string]string{
		"_task_for_pid":          "process.task-access",
		"_mach_vm_read":          "process.memory.read",
		"_mach_vm_write":         "process.memory.write",
		"_thread_create_running": "process.thread.create",
	}
	for symbol, want := range tests {
		t.Run(symbol, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1"}, symbol, "arm64", "ev-1", machoFunction{Name: "main", Reachable: true})
			if len(graph.Operations) != 1 || string(graph.Operations[0].Kind) != want || graph.Operations[0].RequiredResource().Kind != behavior.ResourceProcess {
				t.Fatalf("called symbol %q produced %#v, want %s", symbol, graph.Operations, want)
			}
		})
	}
}

func TestMachOSecurityAPIImportsRemainStructuredPossibleFeatures(t *testing.T) {
	tests := []struct {
		symbol   string
		value    string
		category string
	}{
		{"_SecItemCopyMatching", "SecItemCopyMatching", "keychain"},
		{"_execl", "execl", "process-exec"},
		{"_task_for_pid", "task_for_pid", "process-access"},
		{"_mach_vm_read", "mach_vm_read", "process-memory"},
		{"_thread_create_running", "thread_create_running", "process-thread"},
		{"_CGEventTapCreate", "CGEventTapCreate", "input-event-monitoring"},
		{"_AudioQueueNewInput", "AudioQueueNewInput", "audio-recording"},
		{"_CGDisplayCreateImage", "CGDisplayCreateImage", "screenshot"},
		{"_PasteboardCreate", "PasteboardCreate", "clipboard"},
		{"_curl_easy_perform", "curl_easy_perform", "libcurl"},
		{"_connect", "connect", "socket-connect"},
		{"_SMLoginItemSetEnabled", "SMLoginItemSetEnabled", "login-item"},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromImportedSymbol(&graph, artifact.Content{NodeID: "node-1"}, tt.symbol, "x86_64", "ev-import")
			if len(graph.Operations) != 0 {
				t.Fatalf("an imported-but-uncalled %s symbol must not become an operation: %#v", tt.value, graph.Operations)
			}
			if len(graph.Features) != 1 {
				t.Fatalf("%s import should produce one feature: %#v", tt.value, graph.Features)
			}
			feature := graph.Features[0]
			if feature.Key != "macho.security_api_import" || feature.Value != tt.value || feature.Support != behavior.SupportHeuristic {
				t.Fatalf("%s import produced the wrong feature: %#v", tt.value, feature)
			}
			if feature.Qualifiers["category"] != tt.category || feature.Architecture != "x86_64" {
				t.Fatalf("%s import produced the wrong qualifiers: %#v", tt.value, feature.Qualifiers)
			}
		})
	}
}

func TestMachOEventTapEvidenceModelsOnlyNeutralTapCreation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1"}
	addOperationFromImportedSymbol(&graph, content, "_CGEventTapCreate", "arm64", "ev-import")
	addOperationFromCalledImportedSymbol(&graph, content, "_CGEventTapCreate", "arm64", "ev-call", machoFunction{Name: "main", Reachable: true})

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationInputEventTapCreate || graph.Operations[0].RequiredResource().Kind != behavior.ResourceInputEventStream || graph.Operations[0].Support != behavior.SupportCorroborated {
		t.Fatalf("called event-tap constructor should create only a neutral tap operation: %#v", graph.Operations)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "macho.security_api_import" || graph.Features[0].Qualifiers["category"] != "input-event-monitoring" || graph.Features[0].Support != behavior.SupportHeuristic {
		t.Fatalf("event-tap import should remain one HEURISTIC neutral feature: %#v", graph.Features)
	}
}

func TestMachOCalledAudioRecordingQueueIsNeutralAndExact(t *testing.T) {
	for _, symbol := range []string{"_AudioQueueNewInput", "_AudioQueueNewInputWithDispatchQueue"} {
		t.Run(symbol, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromImportedSymbol(&graph, artifact.Content{NodeID: "node-1"}, symbol, "arm64", "ev-import")
			addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1"}, symbol, "arm64", "ev-call", machoFunction{Name: "record", Reachable: true})
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationAudioRecordingQueueCreate || graph.Operations[0].RequiredResource().Kind != behavior.ResourceAudioInput || graph.Operations[0].Qualifiers["semantic_basis"] != "exact-called-import" {
				t.Fatalf("called recording queue API produced %#v", graph.Operations)
			}
			if len(graph.Features) != 1 || graph.Features[0].Support != behavior.SupportHeuristic {
				t.Fatalf("import availability should remain a separate HEURISTIC feature: %#v", graph.Features)
			}
		})
	}
}
