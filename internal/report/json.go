package report

import (
	"encoding/json"
	"io"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func WriteJSON(w io.Writer, value any) error {
	value = normalizeJSONCollections(value)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func normalizeJSONCollections(value any) any {
	var report Report
	switch typed := value.(type) {
	case Report:
		report = typed
	case *Report:
		if typed == nil {
			return value
		}
		report = *typed
	default:
		return value
	}
	if report.ArtifactNodes == nil {
		report.ArtifactNodes = []artifact.Node{}
	}
	if report.Relationships == nil {
		report.Relationships = []artifact.Edge{}
	}
	if report.Scopes == nil {
		report.Scopes = []behavior.Scope{}
	}
	if report.AnalysisSelection == nil {
		report.AnalysisSelection = []behavior.AnalysisSelection{}
	}
	if report.ExecutionRoots == nil {
		report.ExecutionRoots = []behavior.ExecutionRoot{}
	}
	if report.InvokedTargets == nil {
		report.InvokedTargets = []behavior.InvokedTarget{}
	}
	if report.Capabilities == nil {
		report.Capabilities = []behavior.CapabilityMatch{}
	}
	if report.Features == nil {
		report.Features = []behavior.Feature{}
	}
	if report.Operations == nil {
		report.Operations = []behavior.ModeledOperation{}
	}
	if report.OperationRelations == nil {
		report.OperationRelations = []behavior.OperationRelation{}
	}
	if report.ArtifactProperties == nil {
		report.ArtifactProperties = []behavior.ArtifactProperty{}
	}
	if report.NetworkImplementations == nil {
		report.NetworkImplementations = []behavior.NetworkImplementationObservation{}
	}
	if report.Coverage == nil {
		report.Coverage = []behavior.Coverage{}
	}
	if report.Evidence == nil {
		report.Evidence = []behavior.Evidence{}
	}
	if report.Diagnostics == nil {
		report.Diagnostics = []string{}
	}
	return report
}
