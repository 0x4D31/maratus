package report

import "github.com/0x4D31/maratus/internal/behavior"

func testConnectedExecution(rootID string, targetIDs ...string) behavior.ExecutionContext {
	if rootID == "" {
		rootID = "root-test"
	}
	return behavior.ExecutionContext{
		Connectivity:     behavior.ConnectivityConnected,
		ExecutionRootIDs: []string{rootID},
		InvokedTargetIDs: append([]string(nil), targetIDs...),
	}
}

func testUnknownExecution() behavior.ExecutionContext {
	return behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}
}
