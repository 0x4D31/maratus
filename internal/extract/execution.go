package extract

import (
	"slices"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

// executionContextForContent converts the artifact-layer analysis annotation
// into the public behavior contract. Artifact discovery cannot import the
// behavior package, so it retains the closed connectivity value as a string.
func executionContextForContent(content artifact.Content) behavior.ExecutionContext {
	// Merely finding an operation inside a declared function does not prove the
	// function is called. Direct-call promotion can connect that scope later.
	if content.Function != "" {
		return unknownExecutionContext()
	}
	context := behavior.ExecutionContext{
		Connectivity:     behavior.Connectivity(content.ExecutionConnectivity),
		ExecutionRootIDs: append([]string(nil), content.ExecutionRootIDs...),
		InvokedTargetIDs: append([]string(nil), content.InvokedTargetIDs...),
	}
	normalized, err := behavior.NormalizeExecutionContext(context)
	if err != nil {
		return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
	}
	return normalized
}

func unknownExecutionContext() behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
}

func contentWithExecutionContext(content artifact.Content, context behavior.ExecutionContext) artifact.Content {
	normalized, err := behavior.NormalizeExecutionContext(context)
	if err != nil {
		normalized = unknownExecutionContext()
	}
	content.ExecutionConnectivity = string(normalized.Connectivity)
	content.ExecutionRootIDs = append([]string(nil), normalized.ExecutionRootIDs...)
	content.InvokedTargetIDs = append([]string(nil), normalized.InvokedTargetIDs...)
	return content
}

func connectedExecutionContext(rootIDs, targetIDs []string) behavior.ExecutionContext {
	context, err := behavior.NormalizeExecutionContext(behavior.ExecutionContext{
		Connectivity:     behavior.ConnectivityConnected,
		ExecutionRootIDs: rootIDs,
		InvokedTargetIDs: targetIDs,
	})
	if err != nil {
		return unknownExecutionContext()
	}
	return context
}

func executionSourceForOperation(operation behavior.ModeledOperation) behavior.EntityRef {
	context, err := behavior.NormalizeExecutionContext(operation.Execution)
	if err == nil {
		if len(context.InvokedTargetIDs) == 1 {
			return behavior.EntityRef{Kind: behavior.EntityKindInvokedTarget, ID: context.InvokedTargetIDs[0]}
		}
		if len(context.InvokedTargetIDs) == 0 && len(context.ExecutionRootIDs) == 1 {
			return behavior.EntityRef{Kind: behavior.EntityKindExecutionRoot, ID: context.ExecutionRootIDs[0]}
		}
	}
	return behavior.EntityRef{Kind: behavior.EntityKindArtifactNode, ID: operation.SubjectNodeID}
}

func mergeOperationExecution(operation *behavior.ModeledOperation, incoming behavior.ExecutionContext) bool {
	if operation == nil {
		return false
	}
	incoming, err := behavior.NormalizeExecutionContext(incoming)
	if err != nil || incoming.Connectivity != behavior.ConnectivityConnected {
		return false
	}
	current, currentErr := behavior.NormalizeExecutionContext(operation.Execution)
	if currentErr != nil || current.Connectivity != behavior.ConnectivityConnected {
		operation.Execution = incoming
		return true
	}
	merged := connectedExecutionContext(
		append(append([]string(nil), current.ExecutionRootIDs...), incoming.ExecutionRootIDs...),
		append(append([]string(nil), current.InvokedTargetIDs...), incoming.InvokedTargetIDs...),
	)
	if current.Connectivity == merged.Connectivity &&
		slices.Equal(current.ExecutionRootIDs, merged.ExecutionRootIDs) &&
		slices.Equal(current.InvokedTargetIDs, merged.InvokedTargetIDs) {
		return false
	}
	operation.Execution = merged
	return true
}

func executionContextKey(context behavior.ExecutionContext) (behavior.ExecutionKey, bool) {
	key, err := behavior.NewExecutionKey(context)
	return key, err == nil
}
