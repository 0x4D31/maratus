package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

func processPrimitiveOperationKind(symbol string) (behavior.OperationKind, bool) {
	symbol = strings.TrimPrefix(symbol, "_")
	switch symbol {
	case "task_for_pid":
		return behavior.OperationProcessTaskAccess, true
	case "mach_vm_read":
		return behavior.OperationProcessMemoryRead, true
	case "mach_vm_write":
		return behavior.OperationProcessMemoryWrite, true
	case "thread_create_running":
		return behavior.OperationProcessThreadCreate, true
	default:
		return "", false
	}
}

func processPrimitiveFeatureCategory(symbol string) (string, bool) {
	symbol = strings.TrimPrefix(symbol, "_")
	switch symbol {
	case "task_for_pid":
		return "process-access", true
	case "mach_vm_read", "mach_vm_write":
		return "process-memory", true
	case "thread_create_running":
		return "process-thread", true
	default:
		return "", false
	}
}

func isProcessPrimitive(symbol string) bool {
	_, ok := processPrimitiveOperationKind(symbol)
	return ok
}

func processPrimitiveOperationKindsInText(line string) []behavior.OperationKind {
	var kinds []behavior.OperationKind
	seen := map[behavior.OperationKind]bool{}
	for _, primitive := range []string{"task_for_pid", "mach_vm_read", "mach_vm_write", "thread_create_running"} {
		if !containsDirectUnquotedCall(line, primitive) {
			continue
		}
		kind, _ := processPrimitiveOperationKind(primitive)
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	return kinds
}
