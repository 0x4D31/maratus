package extract

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	nodePackageManifestAnalysisArea = "node-package-manifest"
	// Manifest metadata is attacker-controlled. Bound each declaration before
	// creating evidence so one otherwise valid scalar cannot consume the
	// graph's shared evidence-string budget.
	maxNodePackageManifestFeatureBytes = 4 << 10
)

type nodePackageManifestFeature struct {
	key          string
	value        string
	evidenceKind string
	qualifiers   map[string]string
	field        string
}

type nodePackageRootExportDisposition uint8

const (
	nodePackageRootExportAbsent nodePackageRootExportDisposition = iota
	nodePackageRootExportResolved
	nodePackageRootExportNotExported
	nodePackageRootExportUnsupported
	nodePackageRootExportMalformed
)

type nodePackageRootExportResult struct {
	disposition nodePackageRootExportDisposition
	value       string
	reason      string
}

func extractNodePackageManifestFeatures(graph *behavior.Graph, content artifact.Content, pkg packageJSON) {
	features := []nodePackageManifestFeature{
		{key: "package.name", value: pkg.Name, evidenceKind: "package-name", field: "name"},
		{key: "package.version", value: pkg.Version, evidenceKind: "package-version", field: "version"},
		{key: "node.package.type", value: pkg.Type, evidenceKind: "node-package-type", field: "type"},
		{
			key:          "node.package.entrypoint",
			value:        pkg.Main,
			evidenceKind: "node-package-main-entrypoint",
			qualifiers:   map[string]string{"field": "main"},
			field:        "main",
		},
	}

	export := parseNodePackageRootExport(pkg.Exports)
	switch export.disposition {
	case nodePackageRootExportResolved:
		features = append(features, nodePackageManifestFeature{
			key:          "node.package.entrypoint",
			value:        export.value,
			evidenceKind: "node-package-exports-entrypoint",
			qualifiers:   map[string]string{"field": "exports"},
			field:        "exports",
		})
	case nodePackageRootExportUnsupported, nodePackageRootExportMalformed:
		addPartialCoverageOnce(graph, content.NodeID, nodePackageManifestAnalysisArea, export.reason)
	}

	for _, feature := range features {
		emitNodePackageManifestFeature(graph, content, feature)
	}
}

func parseNodePackageRootExport(raw json.RawMessage) nodePackageRootExportResult {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nodePackageRootExportResult{disposition: nodePackageRootExportAbsent}
	}
	// Node treats a null exports field as if no exports map selected the package
	// root, so the bounded package-root adapter may still consider main. Retain
	// no entrypoint Feature for null because it declares no target itself.
	if bytes.Equal(trimmed, []byte("null")) {
		return nodePackageRootExportResult{disposition: nodePackageRootExportAbsent}
	}
	if trimmed[0] == '"' {
		return decodeNodePackageRootExportString(trimmed, "package exports declaration")
	}
	if trimmed[0] != '{' {
		return nodePackageRootExportResult{
			disposition: nodePackageRootExportUnsupported,
			reason:      fmt.Sprintf("package exports declaration uses an unsupported %s shape; only a direct string or a direct string at the root \".\" export is retained", nodePackageJSONShape(trimmed)),
		}
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return nodePackageRootExportResult{disposition: nodePackageRootExportMalformed, reason: "package exports object could not be decoded; the declaration was not retained"}
	}
	root, rootPresent := object["."]
	hasSubpathKey := false
	hasConditionKey := false
	for key := range object {
		if len(key) > 0 && key[0] == '.' {
			hasSubpathKey = true
		} else {
			hasConditionKey = true
		}
	}
	if hasSubpathKey && hasConditionKey {
		return nodePackageRootExportResult{
			disposition: nodePackageRootExportMalformed,
			reason:      "package exports object mixes subpath and condition keys; no root entry declaration was retained",
		}
	}
	if !rootPresent {
		if hasConditionKey {
			return nodePackageRootExportResult{
				disposition: nodePackageRootExportUnsupported,
				reason:      "package exports declaration uses a conditional root object; conditional export selection is not modeled",
			}
		}
		return nodePackageRootExportResult{disposition: nodePackageRootExportNotExported}
	}
	root = bytes.TrimSpace(root)
	if len(root) == 0 || root[0] != '"' {
		shape := "empty"
		if len(root) > 0 {
			shape = nodePackageJSONShape(root)
		}
		return nodePackageRootExportResult{
			disposition: nodePackageRootExportUnsupported,
			reason:      fmt.Sprintf("package root \".\" export uses an unsupported %s target; only a direct string target is retained", shape),
		}
	}
	return decodeNodePackageRootExportString(root, "package root \".\" export")
}

func decodeNodePackageRootExportString(raw []byte, description string) nodePackageRootExportResult {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		// The complete package document has already passed JSON preflight. Keep
		// this fail-closed branch local in case the decoder contract changes.
		return nodePackageRootExportResult{disposition: nodePackageRootExportMalformed, reason: description + " string could not be decoded; the declaration was not retained"}
	}
	if value == "" {
		return nodePackageRootExportResult{disposition: nodePackageRootExportUnsupported, reason: description + " is empty; the declaration was not retained"}
	}
	return nodePackageRootExportResult{disposition: nodePackageRootExportResolved, value: value}
}

func nodePackageJSONShape(raw []byte) string {
	switch raw[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case 'n':
		return "null"
	case 't', 'f':
		return "boolean"
	default:
		return "number"
	}
}

func emitNodePackageManifestFeature(graph *behavior.Graph, content artifact.Content, feature nodePackageManifestFeature) {
	if feature.value == "" {
		return
	}
	if len(feature.value) > maxNodePackageManifestFeatureBytes {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			nodePackageManifestAnalysisArea,
			fmt.Sprintf("package %s declaration exceeds the %d-byte feature limit; the declaration was not retained", feature.field, maxNodePackageManifestFeatureBytes),
		)
		return
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Method:   "package.json",
		Kind:     feature.evidenceKind,
		Value:    feature.value,
	})
	if evidenceID == "" {
		return
	}
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         feature.key,
		Value:       feature.value,
		Qualifiers:  feature.qualifiers,
		EvidenceIDs: []string{evidenceID},
		Support:     behavior.SupportDirect,
		Execution:   unknownExecutionContext(),
	})
}
