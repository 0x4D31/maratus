package report

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/extract"
	"github.com/0x4D31/maratus/internal/rules"
)

const (
	maxReportExecutionContextIDs   = 64
	maxReportMatchTraceClauses     = 32
	maxReportMatchTraceIDs         = 64
	maxReportMatchTracePathBytes   = 512
	maxJavaScriptLexicalValueBytes = 4 << 10
)

// validateReportReferences enforces the graph integrity promised by the
// versioned report schema. Every ID index is built before references are
// checked so valid forward references remain accepted and reference checking
// remains linear; bounded semantic projection checks and current-catalog replay
// follow.
func validateReportReferences(report Report) error {
	nodes, err := indexReportIDs("artifact_nodes", len(report.ArtifactNodes), func(index int) string { return report.ArtifactNodes[index].ID })
	if err != nil {
		return err
	}
	nodeParents := make(map[string]string, len(report.ArtifactNodes))
	artifactNodesByID := make(map[string]artifact.Node, len(report.ArtifactNodes))
	for _, node := range report.ArtifactNodes {
		nodeParents[node.ID] = node.ParentID
		artifactNodesByID[node.ID] = node
	}
	scopes, err := indexReportIDs("scopes", len(report.Scopes), func(index int) string { return report.Scopes[index].ID })
	if err != nil {
		return err
	}
	scopeNodes := make(map[string]string, len(report.Scopes))
	scopeArchitectures := make(map[string]string, len(report.Scopes))
	scopeFunctions := make(map[string]string, len(report.Scopes))
	scopesByID := make(map[string]behavior.Scope, len(report.Scopes))
	for _, scope := range report.Scopes {
		scopeNodes[scope.ID] = scope.NodeID
		scopeArchitectures[scope.ID] = scope.Architecture
		scopeFunctions[scope.ID] = scope.Function
		scopesByID[scope.ID] = scope
	}
	roots, err := indexReportIDs("execution_roots", len(report.ExecutionRoots), func(index int) string { return report.ExecutionRoots[index].ID })
	if err != nil {
		return err
	}
	rootStartNodes := make(map[string]string, len(report.ExecutionRoots))
	rootsByID := make(map[string]behavior.ExecutionRoot, len(report.ExecutionRoots))
	for _, root := range report.ExecutionRoots {
		rootsByID[root.ID] = root
	}
	targets, err := indexReportIDs("invoked_targets", len(report.InvokedTargets), func(index int) string { return report.InvokedTargets[index].ID })
	if err != nil {
		return err
	}
	features, err := indexReportIDs("features", len(report.Features), func(index int) string { return report.Features[index].ID })
	if err != nil {
		return err
	}
	featuresByID := make(map[string]behavior.Feature, len(report.Features))
	for _, feature := range report.Features {
		featuresByID[feature.ID] = feature
	}
	operations, err := indexReportIDs("operations", len(report.Operations), func(index int) string { return report.Operations[index].ID })
	if err != nil {
		return err
	}
	operationNodes := make(map[string]string, len(report.Operations))
	operationsByID := make(map[string]behavior.ModeledOperation, len(report.Operations))
	for _, operation := range report.Operations {
		operationNodes[operation.ID] = operation.SubjectNodeID
		operationsByID[operation.ID] = operation
	}
	operationRelations, err := indexReportIDs("operation_relations", len(report.OperationRelations), func(index int) string { return report.OperationRelations[index].ID })
	if err != nil {
		return err
	}
	operationRelationsByID := make(map[string]behavior.OperationRelation, len(report.OperationRelations))
	for _, relation := range report.OperationRelations {
		operationRelationsByID[relation.ID] = relation
	}
	if _, err = indexReportIDs("network_implementations", len(report.NetworkImplementations), func(index int) string { return report.NetworkImplementations[index].ID }); err != nil {
		return err
	}
	evidence, err := indexReportIDs("evidence", len(report.Evidence), func(index int) string { return report.Evidence[index].ID })
	if err != nil {
		return err
	}
	evidenceByID := make(map[string]behavior.Evidence, len(report.Evidence))
	for _, item := range report.Evidence {
		evidenceByID[item.ID] = item
	}
	if _, err = indexReportIDs("capability_matches", len(report.Capabilities), func(index int) string { return report.Capabilities[index].ID }); err != nil {
		return err
	}

	for index, node := range report.ArtifactNodes {
		path := fmt.Sprintf("artifact_nodes[%d]", index)
		if err := validateOptionalReportReference(fmt.Sprintf("artifact_nodes[%d].parent_id", index), node.ParentID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateFactArchitectureList(path+".architectures", node.Architectures, false); err != nil {
			return err
		}
	}
	if err := validateArtifactParentForest(report.ArtifactNodes, nodeParents); err != nil {
		return err
	}
	ancestry := indexArtifactAncestry(report.ArtifactNodes, nodeParents)
	for index, relationship := range report.Relationships {
		path := fmt.Sprintf("relationships[%d]", index)
		if err := validateRequiredReportReference(fmt.Sprintf("relationships[%d].from", index), relationship.From, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateRequiredReportReference(fmt.Sprintf("relationships[%d].to", index), relationship.To, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateReportReferenceList(fmt.Sprintf("relationships[%d].evidence_ids", index), relationship.EvidenceIDs, "evidence", evidence, false); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", relationship.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range relationship.EvidenceIDs {
			evidenceNodeID := evidenceByID[evidenceID].NodeID
			if evidenceNodeID != "" && !containmentRelatedNodes(relationship.From, evidenceNodeID, ancestry) && !containmentRelatedNodes(relationship.To, evidenceNodeID, ancestry) {
				return fmt.Errorf("%s is not structurally related to evidence %q node_id %q", path, evidenceID, evidenceNodeID)
			}
		}
		if relationship.Kind == "xcode-base-configuration" {
			if !xcodeBaseConfigurationRelationshipHasProofs(relationship, evidenceByID) {
				return fmt.Errorf("%s requires exact project-reference and base-configuration absence evidence", path)
			}
			configurationNode := artifactNodesByID[relationship.To]
			for _, evidenceID := range relationship.EvidenceIDs {
				item := evidenceByID[evidenceID]
				if item.Kind == "xcode-base-configuration-reference" &&
					!strings.HasSuffix(item.Value, " -> "+configurationNode.LogicalPath) {
					return fmt.Errorf("%s reference evidence %q does not name target logical path %q", path, evidenceID, configurationNode.LogicalPath)
				}
			}
		}
	}
	for index, scope := range report.Scopes {
		path := fmt.Sprintf("scopes[%d]", index)
		if err := validateOptionalReportReference(fmt.Sprintf("scopes[%d].node_id", index), scope.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(fmt.Sprintf("scopes[%d].parent_id", index), scope.ParentID, "scope", scopes); err != nil {
			return err
		}
		if err := validateFactArchitecture(path+".architecture", scope.Architecture); err != nil {
			return err
		}
		if scope.Kind == "function" && scope.Function == "" {
			return fmt.Errorf("%s.function must not be empty for a function scope", path)
		}
		if scope.Kind != "function" && scope.Function != "" {
			return fmt.Errorf("%s.function requires kind %q", path, "function")
		}
	}
	for index, item := range report.Evidence {
		path := fmt.Sprintf("evidence[%d]", index)
		if item.Line < 0 {
			return fmt.Errorf("%s.line must not be negative", path)
		}
		if item.ByteOffsetKnown() && item.Offset < 0 {
			return fmt.Errorf("%s.byte_offset must not be negative", path)
		}
		if err := validateOptionalReportReference(fmt.Sprintf("evidence[%d].node_id", index), item.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(fmt.Sprintf("evidence[%d].scope_id", index), item.ScopeID, "scope", scopes); err != nil {
			return err
		}
		if err := validateScopeOwnership(fmt.Sprintf("evidence[%d]", index), item.NodeID, item.ScopeID, scopeNodes); err != nil {
			return err
		}
		if item.Function != "" {
			if item.ScopeID == "" {
				return fmt.Errorf("%s.function requires an exact scope_id", path)
			}
			if scopesByID[item.ScopeID].Kind != "function" {
				return fmt.Errorf("%s.scope_id %q must name a function scope when function is present", path, item.ScopeID)
			}
		}
		if err := validateFactArchitecture(path+".architecture", item.Arch); err != nil {
			return err
		}
		if architecture := scopeArchitectures[item.ScopeID]; architecture != "" && item.Arch != architecture {
			return fmt.Errorf("%s.architecture %q differs from scope architecture %q", path, item.Arch, architecture)
		}
		if function := scopeFunctions[item.ScopeID]; function != "" && item.Function != function {
			return fmt.Errorf("%s.function %q differs from scope function %q", path, item.Function, function)
		}
	}

	for index, root := range report.ExecutionRoots {
		path := fmt.Sprintf("execution_roots[%d]", index)
		if err := validateRequiredReportReference(path+".declaration_node_id", root.DeclarationNodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".start_node_id", root.StartNodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".start_scope_id", root.StartScopeID, "scope", scopes); err != nil {
			return err
		}
		if root.StartNodeID == "" && root.StartScopeID == "" {
			return fmt.Errorf("%s requires start_node_id or start_scope_id", path)
		}
		if root.StartNodeID != "" && root.StartScopeID != "" {
			if scopeNodeID := scopeNodes[root.StartScopeID]; scopeNodeID != "" && scopeNodeID != root.StartNodeID {
				return fmt.Errorf("%s.start_scope_id references a scope owned by artifact node %q, not start_node_id %q", path, scopeNodeID, root.StartNodeID)
			}
		}
		if err := validateReportReferenceList(path+".evidence_ids", root.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", root.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		startNodeID := root.StartNodeID
		if startNodeID == "" {
			startNodeID = scopeNodes[root.StartScopeID]
		}
		for _, evidenceID := range root.EvidenceIDs {
			evidenceNodeID := evidenceByID[evidenceID].NodeID
			if evidenceNodeID != "" && !sameContainerOrContainmentRelated(root.DeclarationNodeID, evidenceNodeID, ancestry) && !sameContainerOrContainmentRelated(startNodeID, evidenceNodeID, ancestry) {
				return fmt.Errorf("%s is not structurally related to evidence %q node_id %q", path, evidenceID, evidenceNodeID)
			}
		}
		rootStartNodes[root.ID] = root.StartNodeID
		if rootStartNodes[root.ID] == "" {
			rootStartNodes[root.ID] = scopeNodes[root.StartScopeID]
		}
	}

	targetByID := make(map[string]behavior.InvokedTarget, len(report.InvokedTargets))
	for _, target := range report.InvokedTargets {
		targetByID[target.ID] = target
	}
	for index, target := range report.InvokedTargets {
		path := fmt.Sprintf("invoked_targets[%d]", index)
		if err := validateRequiredReportReference(path+".node_id", target.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".scope_id", target.ScopeID, "scope", scopes); err != nil {
			return err
		}
		if target.ScopeID != "" {
			if scopeNodeID := scopeNodes[target.ScopeID]; scopeNodeID != "" && scopeNodeID != target.NodeID {
				return fmt.Errorf("%s.scope_id references a scope owned by artifact node %q, not node_id %q", path, scopeNodeID, target.NodeID)
			}
		}
		if err := validateEntityReference(path+".source", target.Source, nodes, roots, targets); err != nil {
			return err
		}
		if target.Source.Kind == behavior.EntityKindInvokedTarget && target.Source.ID == target.ID {
			return fmt.Errorf("%s.source must not reference the target itself", path)
		}
		if err := validateExecutionContext(path+".execution", target.Execution, roots, targets); err != nil {
			return err
		}
		if slices.Contains(target.Execution.InvokedTargetIDs, target.ID) {
			return fmt.Errorf("%s.execution.invoked_target_ids must not contain the target's own ID %q", path, target.ID)
		}
		if err := validateTargetSourceExecution(path, target, targetByID, rootsByID, scopeNodes, report.Relationships); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", target.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", target.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		sourceNodeID := entityReferenceNodeID(target.Source, rootStartNodes, targetByID)
		for _, evidenceID := range target.EvidenceIDs {
			evidenceNodeID := evidenceByID[evidenceID].NodeID
			if evidenceNodeID != "" && !containmentRelatedNodes(target.NodeID, evidenceNodeID, ancestry) && !containmentRelatedNodes(sourceNodeID, evidenceNodeID, ancestry) {
				return fmt.Errorf("%s is not structurally related to evidence %q node_id %q", path, evidenceID, evidenceNodeID)
			}
		}
	}
	if err := validateInvokedTargetSourceAcyclic(report.InvokedTargets); err != nil {
		return err
	}

	selectionNodes := make(map[string]struct{}, len(report.AnalysisSelection))
	executionRootNodes := make(map[string]struct{}, len(report.ExecutionRoots))
	for _, root := range report.ExecutionRoots {
		if root.StartNodeID != "" {
			executionRootNodes[root.StartNodeID] = struct{}{}
		} else if nodeID := scopeNodes[root.StartScopeID]; nodeID != "" {
			executionRootNodes[nodeID] = struct{}{}
		}
	}
	invokedTargetNodes := make(map[string]struct{}, len(report.InvokedTargets))
	for _, target := range report.InvokedTargets {
		invokedTargetNodes[target.NodeID] = struct{}{}
	}
	for index, selection := range report.AnalysisSelection {
		path := fmt.Sprintf("analysis_selection[%d]", index)
		if err := validateRequiredReportReference(path+".node_id", selection.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if _, exists := selectionNodes[selection.NodeID]; exists {
			return fmt.Errorf("%s.node_id duplicates analysis selection for %q", path, selection.NodeID)
		}
		selectionNodes[selection.NodeID] = struct{}{}
		if err := validateSelectionReasons(path+".reasons", selection.Reasons); err != nil {
			return err
		}
		if slices.Contains(selection.Reasons, behavior.SelectionReasonExecutionRoot) {
			if _, ok := executionRootNodes[selection.NodeID]; !ok {
				return fmt.Errorf("%s.reasons includes execution-root but node %q does not declare or start an execution root", path, selection.NodeID)
			}
		}
		if slices.Contains(selection.Reasons, behavior.SelectionReasonInvokedTarget) {
			if _, ok := invokedTargetNodes[selection.NodeID]; !ok {
				return fmt.Errorf("%s.reasons includes invoked-target but node %q is not an invoked target", path, selection.NodeID)
			}
		}
	}

	for index, feature := range report.Features {
		path := fmt.Sprintf("features[%d]", index)
		if err := validateOptionalReportReference(path+".node_id", feature.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".scope_id", feature.ScopeID, "scope", scopes); err != nil {
			return err
		}
		if err := validateScopeOwnership(path, feature.NodeID, feature.ScopeID, scopeNodes); err != nil {
			return err
		}
		if feature.SourceFunction != "" {
			if feature.ScopeID == "" {
				return fmt.Errorf("%s.source_function requires an exact scope_id", path)
			}
			if scopesByID[feature.ScopeID].Kind != "function" {
				return fmt.Errorf("%s.scope_id %q must name a function scope when source_function is present", path, feature.ScopeID)
			}
		}
		if _, hiddenArchitecture := feature.Qualifiers["arch"]; hiddenArchitecture {
			return fmt.Errorf("%s.qualifiers must not contain typed context key %q", path, "arch")
		}
		if err := validateFactArchitecture(path+".architecture", feature.Architecture); err != nil {
			return err
		}
		if architecture := scopeArchitectures[feature.ScopeID]; architecture != "" && feature.Architecture != architecture {
			return fmt.Errorf("%s.architecture %q differs from scope architecture %q", path, feature.Architecture, architecture)
		}
		if function := scopeFunctions[feature.ScopeID]; function != "" && feature.SourceFunction != function {
			return fmt.Errorf("%s.source_function %q differs from scope function %q", path, feature.SourceFunction, function)
		}
		if err := validateExecutionContext(path+".execution", feature.Execution, roots, targets); err != nil {
			return err
		}
		if err := validateRecordExecutionOwnership(path, feature.NodeID, feature.Execution, rootStartNodes, targetByID); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", feature.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", feature.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range feature.EvidenceIDs {
			if !factEvidenceNodeCompatible(feature.NodeID, evidenceID, evidenceByID, nodeParents, report.ExecutionRoots, report.InvokedTargets, scopeNodes, report.Relationships) &&
				!packagingFeatureEvidenceNodeCompatible(feature, evidenceID, evidenceByID, artifactNodesByID, ancestry) {
				return fmt.Errorf("%s.node_id %q is not structurally related to evidence %q node_id %q", path, feature.NodeID, evidenceID, evidenceByID[evidenceID].NodeID)
			}
			if item := evidenceByID[evidenceID]; item.Function != "" && item.ScopeID != feature.ScopeID {
				return fmt.Errorf("%s.scope_id %q differs from function evidence %q scope_id %q", path, feature.ScopeID, evidenceID, item.ScopeID)
			}
			if architecture := evidenceByID[evidenceID].Arch; architecture != "" && feature.Architecture != architecture {
				return fmt.Errorf("%s.architecture %q differs from evidence %q architecture %q", path, feature.Architecture, evidenceID, architecture)
			}
			if function := evidenceByID[evidenceID].Function; function != "" && feature.SourceFunction != function {
				return fmt.Errorf("%s.source_function %q differs from evidence %q function %q", path, feature.SourceFunction, evidenceID, function)
			}
		}
		if !hasExactSameNodeFactEvidence(feature.NodeID, feature.ScopeID, feature.SourceFunction, feature.Architecture, feature.EvidenceIDs, evidenceByID) &&
			!packagingFeatureEvidenceSetCompatible(feature, feature.EvidenceIDs, evidenceByID, artifactNodesByID, ancestry) {
			return fmt.Errorf("%s.evidence_ids requires same-node exact-context semantic evidence", path)
		}
		if err := validateJavaScriptLexicalFeature(
			path,
			feature,
			evidenceByID,
			scopesByID,
		); err != nil {
			return err
		}
	}
	for index, operation := range report.Operations {
		path := fmt.Sprintf("operations[%d]", index)
		if err := validateRequiredReportReference(path+".subject_node_id", operation.SubjectNodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".scope_id", operation.ScopeID, "scope", scopes); err != nil {
			return err
		}
		if err := validateScopeOwnership(path, operation.SubjectNodeID, operation.ScopeID, scopeNodes); err != nil {
			return err
		}
		if operation.SourceFunction != "" {
			if operation.ScopeID == "" {
				return fmt.Errorf("%s.source_function requires an exact scope_id", path)
			}
			if scopesByID[operation.ScopeID].Kind != "function" {
				return fmt.Errorf("%s.scope_id %q must name a function scope when source_function is present", path, operation.ScopeID)
			}
		}
		if err := validateFactArchitecture(path+".architecture", operation.Architecture); err != nil {
			return err
		}
		if architecture := scopeArchitectures[operation.ScopeID]; architecture != "" && operation.Architecture != architecture {
			return fmt.Errorf("%s.architecture %q differs from scope architecture %q", path, operation.Architecture, architecture)
		}
		if function := scopeFunctions[operation.ScopeID]; function != "" && operation.SourceFunction != function {
			return fmt.Errorf("%s.source_function %q differs from scope function %q", path, operation.SourceFunction, function)
		}
		if err := validateExecutionContext(path+".execution", operation.Execution, roots, targets); err != nil {
			return err
		}
		if err := validateRecordExecutionOwnership(path, operation.SubjectNodeID, operation.Execution, rootStartNodes, targetByID); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", operation.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", operation.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range operation.EvidenceIDs {
			if !factEvidenceNodeCompatible(operation.SubjectNodeID, evidenceID, evidenceByID, nodeParents, report.ExecutionRoots, report.InvokedTargets, scopeNodes, report.Relationships) {
				return fmt.Errorf("%s.subject_node_id %q is not structurally related to evidence %q node_id %q", path, operation.SubjectNodeID, evidenceID, evidenceByID[evidenceID].NodeID)
			}
			if item := evidenceByID[evidenceID]; item.Function != "" && item.ScopeID != operation.ScopeID {
				return fmt.Errorf("%s.scope_id %q differs from function evidence %q scope_id %q", path, operation.ScopeID, evidenceID, item.ScopeID)
			}
			if architecture := evidenceByID[evidenceID].Arch; architecture != "" && operation.Architecture != architecture {
				return fmt.Errorf("%s.architecture %q differs from evidence %q architecture %q", path, operation.Architecture, evidenceID, architecture)
			}
			if function := evidenceByID[evidenceID].Function; function != "" && operation.SourceFunction != function {
				return fmt.Errorf("%s.source_function %q differs from evidence %q function %q", path, operation.SourceFunction, evidenceID, function)
			}
		}
		if !hasExactSameNodeFactEvidence(operation.SubjectNodeID, operation.ScopeID, operation.SourceFunction, operation.Architecture, operation.EvidenceIDs, evidenceByID) {
			return fmt.Errorf("%s.evidence_ids requires same-node exact-context semantic evidence", path)
		}
		for bindingIndex, binding := range operation.ResourceBindings {
			if err := validateReportReferenceList(fmt.Sprintf("%s.resource_bindings[%d].evidence_ids", path, bindingIndex), binding.EvidenceIDs, "evidence", evidence, false); err != nil {
				return err
			}
			if err := validateEvidenceNodeIDs(fmt.Sprintf("%s.resource_bindings[%d].evidence_ids", path, bindingIndex), binding.EvidenceIDs, evidenceByID); err != nil {
				return err
			}
			for _, evidenceID := range binding.EvidenceIDs {
				if !factEvidenceNodeCompatible(operation.SubjectNodeID, evidenceID, evidenceByID, nodeParents, report.ExecutionRoots, report.InvokedTargets, scopeNodes, report.Relationships) {
					return fmt.Errorf("%s.subject_node_id %q is not structurally related to resource binding evidence %q node_id %q", path, operation.SubjectNodeID, evidenceID, evidenceByID[evidenceID].NodeID)
				}
				if item := evidenceByID[evidenceID]; item.Function != "" && item.ScopeID != operation.ScopeID {
					return fmt.Errorf("%s.scope_id %q differs from resource binding function evidence %q scope_id %q", path, operation.ScopeID, evidenceID, item.ScopeID)
				}
				if architecture := evidenceByID[evidenceID].Arch; architecture != "" && operation.Architecture != architecture {
					return fmt.Errorf("%s.architecture %q differs from resource binding evidence %q architecture %q", path, operation.Architecture, evidenceID, architecture)
				}
				if function := evidenceByID[evidenceID].Function; function != "" && operation.SourceFunction != function {
					return fmt.Errorf("%s.source_function %q differs from resource binding evidence %q function %q", path, operation.SourceFunction, evidenceID, function)
				}
			}
			if len(binding.EvidenceIDs) > 0 && !hasExactSameNodeFactEvidence(operation.SubjectNodeID, operation.ScopeID, operation.SourceFunction, operation.Architecture, binding.EvidenceIDs, evidenceByID) {
				return fmt.Errorf("%s.resource_bindings[%d].evidence_ids requires same-node exact-context semantic evidence (operation_id=%q kind=%q role=%q subject_node_id=%q scope_id=%q source_function=%q architecture=%q)", path, bindingIndex, operation.ID, operation.Kind, binding.Role, operation.SubjectNodeID, operation.ScopeID, operation.SourceFunction, operation.Architecture)
			}
		}
	}
	for index, relation := range report.OperationRelations {
		path := fmt.Sprintf("operation_relations[%d]", index)
		if err := validateFactArchitecture(path+".architecture", relation.Architecture); err != nil {
			return err
		}
		if err := validateExecutionContext(path+".execution", relation.Execution, roots, targets); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", relation.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", relation.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range relation.EvidenceIDs {
			if architecture := evidenceByID[evidenceID].Arch; architecture != "" && relation.Architecture != architecture {
				return fmt.Errorf("%s.architecture %q differs from evidence %q architecture %q", path, relation.Architecture, evidenceID, architecture)
			}
		}
		if nodeID := relationOwnershipNodeID(relation, operationNodes, scopeNodes, rootStartNodes, targetByID); nodeID != "" {
			if err := validateRecordExecutionOwnership(path, nodeID, relation.Execution, rootStartNodes, targetByID); err != nil {
				return err
			}
		}
	}
	relationGraph := &behavior.Graph{
		Scopes:         report.Scopes,
		Evidence:       report.Evidence,
		Features:       report.Features,
		ExecutionRoots: report.ExecutionRoots,
		InvokedTargets: report.InvokedTargets,
		Operations:     report.Operations,
		Relations:      report.OperationRelations,
	}
	if err := relationGraph.ValidateRelations(); err != nil {
		return err
	}
	if err := relationGraph.ValidateRelationEvidenceLineage(); err != nil {
		return err
	}
	for index, item := range report.ArtifactProperties {
		if err := validateOptionalReportReference(fmt.Sprintf("artifact_properties[%d].node_id", index), item.NodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateReportReferenceList(fmt.Sprintf("artifact_properties[%d].evidence_ids", index), item.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(fmt.Sprintf("artifact_properties[%d].evidence_ids", index), item.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range item.EvidenceIDs {
			evidenceNodeID := evidenceByID[evidenceID].NodeID
			if evidenceNodeID != "" && (item.NodeID == "" || !containmentRelatedNodes(item.NodeID, evidenceNodeID, ancestry)) {
				return fmt.Errorf("artifact_properties[%d].node_id %q is not containment-related to evidence %q node_id %q", index, item.NodeID, evidenceID, evidenceNodeID)
			}
		}
	}
	for index, observation := range report.NetworkImplementations {
		path := fmt.Sprintf("network_implementations[%d]", index)
		if err := validateRequiredReportReference(path+".subject_node_id", observation.SubjectNodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateOptionalReportReference(path+".scope_id", observation.ScopeID, "scope", scopes); err != nil {
			return err
		}
		if err := validateScopeOwnership(path, observation.SubjectNodeID, observation.ScopeID, scopeNodes); err != nil {
			return err
		}
		if err := validateFactArchitecture(path+".architecture", observation.Architecture); err != nil {
			return err
		}
		if architecture := scopeArchitectures[observation.ScopeID]; architecture != "" && observation.Architecture != architecture {
			return fmt.Errorf("%s.architecture %q differs from scope architecture %q", path, observation.Architecture, architecture)
		}
		if err := validateExecutionContext(path+".execution", observation.Execution, roots, targets); err != nil {
			return err
		}
		if err := validateRecordExecutionOwnership(path, observation.SubjectNodeID, observation.Execution, rootStartNodes, targetByID); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".operation_ids", observation.OperationIDs, "operation", operations, false); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", observation.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", observation.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		for _, evidenceID := range observation.EvidenceIDs {
			if !factEvidenceNodeCompatible(observation.SubjectNodeID, evidenceID, evidenceByID, nodeParents, report.ExecutionRoots, report.InvokedTargets, scopeNodes, report.Relationships) {
				return fmt.Errorf("%s.subject_node_id %q is not structurally related to evidence %q node_id %q", path, observation.SubjectNodeID, evidenceID, evidenceByID[evidenceID].NodeID)
			}
			if item := evidenceByID[evidenceID]; item.Function != "" && item.ScopeID != observation.ScopeID {
				return fmt.Errorf("%s.scope_id %q differs from function evidence %q scope_id %q", path, observation.ScopeID, evidenceID, item.ScopeID)
			}
			if architecture := evidenceByID[evidenceID].Arch; architecture != "" && observation.Architecture != architecture {
				return fmt.Errorf("%s.architecture %q differs from evidence %q architecture %q", path, observation.Architecture, evidenceID, architecture)
			}
			if function := evidenceByID[evidenceID].Function; function != "" && function != scopeFunctions[observation.ScopeID] {
				return fmt.Errorf("%s scope function %q differs from evidence %q function %q", path, scopeFunctions[observation.ScopeID], evidenceID, function)
			}
		}
		if !hasExactSameNodeFactEvidence(observation.SubjectNodeID, observation.ScopeID, scopeFunctions[observation.ScopeID], observation.Architecture, observation.EvidenceIDs, evidenceByID) {
			return fmt.Errorf("%s.evidence_ids requires same-node exact-context semantic evidence", path)
		}
		if !behavior.ValidNetworkImplementationKind(observation.Kind) {
			return fmt.Errorf("%s.kind has invalid value %q", path, observation.Kind)
		}
		if strings.TrimSpace(observation.APIOrTool) == "" {
			return fmt.Errorf("%s.api_or_tool must not be empty", path)
		}
		if !behavior.ValidNetworkImplementationOperationPolicy(observation.Kind, len(observation.OperationIDs) > 0) {
			return fmt.Errorf("%s.kind %q is incompatible with operation_ids presence", path, observation.Kind)
		}
		if !behavior.ValidNetworkImplementationTLSContext(observation.TLSProvider, observation.TLSProviderBasis) {
			return fmt.Errorf("%s TLS provider %q and basis %q must either both be set or both be empty and valid", path, observation.TLSProvider, observation.TLSProviderBasis)
		}
		if !validSupport(observation.Support) {
			return fmt.Errorf("%s.support has invalid value %q", path, observation.Support)
		}
		for propertyIndex, property := range observation.SecurityProperties {
			if !behavior.ValidNetworkSecurityProperty(property) {
				return fmt.Errorf("%s.security_properties[%d] has invalid value %q", path, propertyIndex, property)
			}
		}
		if err := validateNetworkImplementationOperations(path, observation, operationsByID); err != nil {
			return err
		}
	}
	for index, coverage := range report.Coverage {
		if err := validateOptionalReportReference(fmt.Sprintf("coverage[%d].node_id", index), coverage.NodeID, "artifact node", nodes); err != nil {
			return err
		}
	}
	for index, capability := range report.Capabilities {
		path := fmt.Sprintf("capability_matches[%d]", index)
		if err := rules.ValidateCapabilityMatchProjectionBounds(capability); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := validateRequiredReportReference(path+".subject_node_id", capability.SubjectNodeID, "artifact node", nodes); err != nil {
			return err
		}
		if err := validateExecutionContext(path+".execution", capability.Execution, roots, targets); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".operation_ids", capability.OperationIDs, "operation", operations, true); err != nil {
			return err
		}
		if err := validateReportReferenceList(path+".evidence_ids", capability.EvidenceIDs, "evidence", evidence, true); err != nil {
			return err
		}
		if err := validateEvidenceNodeIDs(path+".evidence_ids", capability.EvidenceIDs, evidenceByID); err != nil {
			return err
		}
		if err := validateCapabilityMatchTrace(path+".match_trace", capability, operations, features, roots, operationRelations); err != nil {
			return err
		}
		if err := validateCapabilityMatchEvidence(path, capability, operationsByID, featuresByID, rootsByID, operationRelationsByID); err != nil {
			return err
		}
	}
	if err := validateReportSemantics(report); err != nil {
		return err
	}
	return validateCurrentCatalogCapabilities(report)
}

func validateJavaScriptLexicalFeature(
	path string,
	feature behavior.Feature,
	evidenceByID map[string]behavior.Evidence,
	scopesByID map[string]behavior.Scope,
) error {
	const (
		moduleKey = "javascript.module_specifier"
		method    = "javascript-lexical"
	)
	isClosedKey := feature.Key == moduleKey
	isLexical := isClosedKey
	for _, evidenceID := range feature.EvidenceIDs {
		evidence := evidenceByID[evidenceID]
		if evidence.Method == method ||
			javaScriptLexicalEvidenceKindKnown(evidence.Kind) {
			isLexical = true
			break
		}
	}
	if !isLexical {
		return nil
	}
	switch feature.Key {
	case moduleKey, "network.url", "script.sensitive_resource":
	default:
		return fmt.Errorf("%s.key %q is incompatible with JavaScript lexical origin", path, feature.Key)
	}
	if feature.NodeID == "" {
		return fmt.Errorf("%s.node_id must not be empty for JavaScript lexical Feature", path)
	}
	if feature.ScopeID == "" && feature.SourceFunction != "" {
		return fmt.Errorf("%s.source_function requires an exact scope for JavaScript lexical Feature", path)
	}
	if feature.Support != behavior.SupportDirect {
		return fmt.Errorf("%s.support must be DIRECT for JavaScript lexical Feature", path)
	}
	if feature.Execution.Connectivity != behavior.ConnectivityUnknown ||
		len(feature.Execution.ExecutionRootIDs) != 0 ||
		len(feature.Execution.InvokedTargetIDs) != 0 {
		return fmt.Errorf("%s.execution must remain UNKNOWN for JavaScript lexical Feature", path)
	}
	if len(feature.EvidenceIDs) != 1 {
		return fmt.Errorf("%s.evidence_ids must contain exactly one JavaScript lexical evidence reference", path)
	}
	evidence := evidenceByID[feature.EvidenceIDs[0]]
	if evidence.NodeID != feature.NodeID {
		return fmt.Errorf("%s.node_id %q differs from JavaScript lexical evidence node_id %q", path, feature.NodeID, evidence.NodeID)
	}
	if evidence.ScopeID != feature.ScopeID {
		return fmt.Errorf("%s.scope_id %q differs from JavaScript lexical evidence scope_id %q", path, feature.ScopeID, evidence.ScopeID)
	}
	if evidence.Function != feature.SourceFunction {
		return fmt.Errorf("%s.source_function %q differs from JavaScript lexical evidence function %q", path, feature.SourceFunction, evidence.Function)
	}
	if evidence.Arch != feature.Architecture {
		return fmt.Errorf("%s.architecture %q differs from JavaScript lexical evidence architecture %q", path, feature.Architecture, evidence.Arch)
	}
	if feature.ScopeID != "" {
		scope := scopesByID[feature.ScopeID]
		if feature.SourceFunction != "" && scope.Kind != "function" {
			return fmt.Errorf("%s.scope_id %q must name a function scope when source_function is present", path, feature.ScopeID)
		}
		if scope.Kind == "function" && scope.Function == "" {
			return fmt.Errorf("%s.scope_id %q names a function scope without a function identity", path, feature.ScopeID)
		}
		if scope.Function != feature.SourceFunction {
			return fmt.Errorf("%s.source_function %q differs from scope function %q", path, feature.SourceFunction, scope.Function)
		}
	}
	if evidence.Method != method {
		return fmt.Errorf("%s evidence extraction_method must be %q", path, method)
	}
	if evidence.Kind != javaScriptLexicalEvidenceKind(feature.Key) {
		return fmt.Errorf("%s evidence kind %q is incompatible with Feature key %q", path, evidence.Kind, feature.Key)
	}
	if !validJavaScriptLexicalLiteralValue(feature.Value) {
		return fmt.Errorf("%s.value is incompatible with a bounded ordinary JavaScript literal", path)
	}
	if !validJavaScriptLexicalLiteralValue(evidence.Value) {
		return fmt.Errorf("%s evidence matched_value is incompatible with a bounded ordinary JavaScript literal", path)
	}
	if evidence.Value != feature.Value {
		return fmt.Errorf("%s.value %q differs from JavaScript lexical evidence matched_value %q", path, feature.Value, evidence.Value)
	}
	if evidence.Line <= 0 ||
		!evidence.ByteOffsetKnown() ||
		evidence.Offset < 0 {
		return fmt.Errorf("%s evidence requires exact line and byte_offset", path)
	}
	switch feature.Key {
	case moduleKey:
		switch feature.Qualifiers["form"] {
		case "esm-import", "esm-re-export", "dynamic-import", "commonjs-require", "bundled-commonjs-wrapper":
		default:
			return fmt.Errorf("%s.qualifiers.form has invalid JavaScript module form %q", path, feature.Qualifiers["form"])
		}
		if !exactQualifierKeys(feature.Qualifiers, "form") {
			return fmt.Errorf("%s.qualifiers contains unsupported JavaScript module fields", path)
		}
	case "network.url":
		if !validJavaScriptLexicalURL(feature.Value) {
			return fmt.Errorf("%s.value is not an exact supported JavaScript URL literal", path)
		}
		if !exactQualifierKeys(feature.Qualifiers) {
			return fmt.Errorf("%s.qualifiers contains unsupported JavaScript lexical fields", path)
		}
	case "script.sensitive_resource":
		category, valid := extract.JavaScriptSensitiveLiteralCategory(
			feature.Value,
		)
		if !valid ||
			feature.Qualifiers["category"] != category ||
			!exactQualifierKeys(feature.Qualifiers, "category") {
			return fmt.Errorf("%s requires an exact sensitive path and matching supported category for JavaScript lexical Feature", path)
		}
	}
	return nil
}

func validJavaScriptLexicalLiteralValue(value string) bool {
	return value != "" &&
		len(value) <= maxJavaScriptLexicalValueBytes &&
		utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\\\r\n\x00")
}

func javaScriptLexicalEvidenceKind(key string) string {
	switch key {
	case "javascript.module_specifier":
		return "javascript-module-specifier"
	case "network.url":
		return "javascript-url-literal"
	default:
		return "javascript-sensitive-resource-literal"
	}
}

func javaScriptLexicalEvidenceKindKnown(kind string) bool {
	switch kind {
	case "javascript-module-specifier",
		"javascript-url-literal",
		"javascript-sensitive-resource-literal":
		return true
	default:
		return false
	}
}

func validJavaScriptLexicalURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss", "ftp":
		return true
	default:
		return false
	}
}

func exactQualifierKeys(values map[string]string, keys ...string) bool {
	if len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}

// validateCurrentCatalogCapabilities replays only the closed, bounded rule
// engine over the already validated retained facts. It does not reopen or
// re-analyze the artifact. Non-current catalog identities remain subject to
// structural validation because their rule expressions are not available.
func validateCurrentCatalogCapabilities(report Report) error {
	if report.RulesetVersion != RulesetVersion || report.RuleCatalogDigest != rules.CatalogDigest() {
		return nil
	}
	graph := behavior.Graph{
		Scopes:             report.Scopes,
		Evidence:           report.Evidence,
		Features:           report.Features,
		ExecutionRoots:     report.ExecutionRoots,
		InvokedTargets:     report.InvokedTargets,
		AnalysisSelections: report.AnalysisSelection,
		Operations:         report.Operations,
		Network:            report.NetworkImplementations,
		ArtifactProperties: report.ArtifactProperties,
		Coverage:           append([]behavior.Coverage(nil), report.Coverage...),
		Relations:          report.OperationRelations,
	}
	expected := rules.Evaluate(&graph)
	if !rules.EqualCapabilityMatchSets(report.Capabilities, expected) {
		return fmt.Errorf("capability_matches do not equal the deterministic projection of the recorded current rule catalog")
	}
	if !reflect.DeepEqual(ruleEvaluationCoverage(report.Coverage), ruleEvaluationCoverage(graph.Coverage)) {
		return fmt.Errorf("rule-evaluation coverage does not equal the deterministic projection of the recorded current rule catalog")
	}
	return nil
}

func ruleEvaluationCoverage(values []behavior.Coverage) []behavior.Coverage {
	var out []behavior.Coverage
	for _, coverage := range values {
		if coverage.AnalysisArea == "rule-evaluation" {
			out = append(out, coverage)
		}
	}
	slices.SortFunc(out, func(left, right behavior.Coverage) int {
		for _, pair := range [][2]string{
			{left.NodeID, right.NodeID},
			{left.Status, right.Status},
			{left.Detail, right.Detail},
		} {
			if compared := strings.Compare(pair[0], pair[1]); compared != 0 {
				return compared
			}
		}
		return 0
	})
	return out
}

func validateNetworkImplementationOperations(path string, observation behavior.NetworkImplementationObservation, operations map[string]behavior.ModeledOperation) error {
	for _, operationID := range observation.OperationIDs {
		operation := operations[operationID]
		if !isNetworkOperation(operation.Kind) {
			return fmt.Errorf("%s linked operation %q has non-network kind %q", path, operationID, operation.Kind)
		}
		if observation.SubjectNodeID != operation.SubjectNodeID {
			return fmt.Errorf("%s subject %q differs from linked operation %q subject %q", path, observation.SubjectNodeID, operationID, operation.SubjectNodeID)
		}
		if observation.ScopeID != operation.ScopeID {
			return fmt.Errorf("%s scope %q differs from linked operation %q scope %q", path, observation.ScopeID, operationID, operation.ScopeID)
		}
		if observation.Architecture != operation.Architecture {
			return fmt.Errorf("%s architecture %q differs from linked operation %q architecture %q", path, observation.Architecture, operationID, operation.Architecture)
		}
		observationExecution, observationErr := behavior.NewExecutionKey(observation.Execution)
		operationExecution, operationErr := behavior.NewExecutionKey(operation.Execution)
		if observationErr != nil || operationErr != nil || observationExecution != operationExecution {
			return fmt.Errorf("%s execution context differs from linked operation %q", path, operationID)
		}
		if reportSupportStrength(observation.Support) > reportSupportStrength(operation.Support) {
			return fmt.Errorf("%s support %q is stronger than linked operation %q support %q", path, observation.Support, operationID, operation.Support)
		}
	}
	return nil
}

func validateCapabilityMatchTrace(path string, capability behavior.CapabilityMatch, operations, features, roots, relations map[string]struct{}) error {
	if len(capability.MatchTrace) == 0 {
		return fmt.Errorf("%s must not be empty", path)
	}
	if len(capability.MatchTrace) > maxReportMatchTraceClauses {
		return fmt.Errorf("%s exceeds %d-item limit", path, maxReportMatchTraceClauses)
	}
	operationTraceIDs := make(map[string]struct{}, len(capability.OperationIDs))
	previousPath := ""
	previousKind := behavior.MatchTraceClauseKind("")
	for index, clause := range capability.MatchTrace {
		clausePath := fmt.Sprintf("%s[%d]", path, index)
		if clause.Path == "" || len(clause.Path) > maxReportMatchTracePathBytes {
			return fmt.Errorf("%s.path must be nonempty and no more than %d bytes", clausePath, maxReportMatchTracePathBytes)
		}
		if !behavior.ValidMatchTraceClauseKind(clause.Kind) {
			return fmt.Errorf("%s.kind has invalid value %q", clausePath, clause.Kind)
		}
		if !behavior.ValidMatchTraceClausePath(clause.Kind, clause.Path) {
			return fmt.Errorf("%s.path %q is not generated by the closed rule expression vocabulary for %q", clausePath, clause.Path, clause.Kind)
		}
		if index > 0 && (clause.Path < previousPath || clause.Path == previousPath && clause.Kind <= previousKind) {
			return fmt.Errorf("%s is not in canonical path and kind order", clausePath)
		}
		previousPath, previousKind = clause.Path, clause.Kind

		lists := 0
		if len(clause.OperationIDs) > 0 {
			lists++
		}
		if len(clause.FeatureIDs) > 0 {
			lists++
		}
		if len(clause.ExecutionRootIDs) > 0 {
			lists++
		}
		if len(clause.RelationIDs) > 0 {
			lists++
		}
		if lists != 1 {
			return fmt.Errorf("%s must populate exactly one typed fact ID list", clausePath)
		}

		var values []string
		var target string
		var ids map[string]struct{}
		switch clause.Kind {
		case behavior.MatchTraceOperation:
			values, target, ids = clause.OperationIDs, "operation", operations
		case behavior.MatchTraceFeature:
			values, target, ids = clause.FeatureIDs, "feature", features
		case behavior.MatchTraceExecutionRoot:
			values, target, ids = clause.ExecutionRootIDs, "execution root", roots
		case behavior.MatchTraceOperationRelation:
			values, target, ids = clause.RelationIDs, "operation relation", relations
		}
		if len(values) > maxReportMatchTraceIDs {
			return fmt.Errorf("%s exceeds %d referenced facts", clausePath, maxReportMatchTraceIDs)
		}
		if !slices.IsSorted(values) {
			return fmt.Errorf("%s.%s_ids is not in canonical order", clausePath, target)
		}
		if err := validateReportReferenceList(clausePath+"."+traceReferenceField(clause.Kind), values, target, ids, true); err != nil {
			return err
		}
		if clause.Kind == behavior.MatchTraceOperation {
			for _, id := range values {
				operationTraceIDs[id] = struct{}{}
			}
		}
	}
	if !sameExecutionIDSet(capability.OperationIDs, operationTraceIDs) {
		return fmt.Errorf("%s operation facts must equal capability operation_ids", path)
	}
	return nil
}

func validateCapabilityMatchEvidence(
	path string,
	capability behavior.CapabilityMatch,
	operations map[string]behavior.ModeledOperation,
	features map[string]behavior.Feature,
	roots map[string]behavior.ExecutionRoot,
	relations map[string]behavior.OperationRelation,
) error {
	tracedEvidence := make(map[string]struct{})
	add := func(values []string) {
		for _, value := range values {
			tracedEvidence[value] = struct{}{}
		}
	}
	tracedOperations := make(map[string]struct{})
	tracedFeatures := make(map[string]struct{})
	tracedRoots := make(map[string]struct{})
	tracedRelations := make(map[string]struct{})
	for _, clause := range capability.MatchTrace {
		for _, operationID := range clause.OperationIDs {
			tracedOperations[operationID] = struct{}{}
		}
		for _, featureID := range clause.FeatureIDs {
			tracedFeatures[featureID] = struct{}{}
		}
		for _, rootID := range clause.ExecutionRootIDs {
			tracedRoots[rootID] = struct{}{}
		}
		for _, relationID := range clause.RelationIDs {
			tracedRelations[relationID] = struct{}{}
		}
	}
	for operationID := range tracedOperations {
		add(operations[operationID].EvidenceIDs)
	}
	for featureID := range tracedFeatures {
		add(features[featureID].EvidenceIDs)
	}
	for rootID := range tracedRoots {
		add(roots[rootID].EvidenceIDs)
	}
	for relationID := range tracedRelations {
		add(relations[relationID].EvidenceIDs)
	}
	for index, evidenceID := range capability.EvidenceIDs {
		if _, ok := tracedEvidence[evidenceID]; !ok {
			return fmt.Errorf("%s.evidence_ids[%d] %q is not evidence of a fact named by match_trace", path, index, evidenceID)
		}
	}
	return nil
}

func traceReferenceField(kind behavior.MatchTraceClauseKind) string {
	switch kind {
	case behavior.MatchTraceOperation:
		return "operation_ids"
	case behavior.MatchTraceFeature:
		return "feature_ids"
	case behavior.MatchTraceExecutionRoot:
		return "execution_root_ids"
	case behavior.MatchTraceOperationRelation:
		return "operation_relation_ids"
	default:
		return "ids"
	}
}

func relationOwnershipNodeID(
	relation behavior.OperationRelation,
	operationNodes, scopeNodes, rootStartNodes map[string]string,
	targets map[string]behavior.InvokedTarget,
) string {
	endpoint := relation.From
	if endpoint.Kind == behavior.RelationEndpointResource {
		endpoint = relation.To
	}
	switch endpoint.Kind {
	case behavior.RelationEndpointOperation:
		return operationNodes[endpoint.ID]
	case behavior.RelationEndpointScope:
		return scopeNodes[endpoint.ID]
	case behavior.RelationEndpointExecutionRoot:
		return rootStartNodes[endpoint.ID]
	case behavior.RelationEndpointInvokedTarget:
		return targets[endpoint.ID].NodeID
	}
	return ""
}

func factEvidenceNodeCompatible(
	subjectNodeID, evidenceID string,
	evidenceByID map[string]behavior.Evidence,
	nodeParents map[string]string,
	roots []behavior.ExecutionRoot,
	targets []behavior.InvokedTarget,
	scopeNodes map[string]string,
	relationships []artifact.Edge,
) bool {
	evidenceNodeID := evidenceByID[evidenceID].NodeID
	if evidenceNodeID == "" {
		return false
	}
	if subjectNodeID == "" {
		return false
	}
	if subjectNodeID == evidenceNodeID {
		return true
	}
	for _, target := range targets {
		if target.NodeID == subjectNodeID && slices.Contains(target.EvidenceIDs, evidenceID) {
			return true
		}
	}
	for _, root := range roots {
		startNodeID := root.StartNodeID
		if startNodeID == "" {
			startNodeID = scopeNodes[root.StartScopeID]
		}
		if startNodeID == subjectNodeID && slices.Contains(root.EvidenceIDs, evidenceID) {
			return true
		}
	}
	return xcodeBaseConfigurationEvidenceNodeCompatible(subjectNodeID, evidenceID, evidenceByID, relationships)
}

// xcodeBaseConfigurationEvidenceNodeCompatible admits one deliberately
// cross-file proof shape. A project-scoped Xcode build-setting resolution may
// depend on proving that an exact, referenced base configuration does not
// override the setting. The extractor must serialize that relationship
// explicitly and bind it to the same absence Evidence; sibling containment or
// matching text alone is insufficient.
func xcodeBaseConfigurationEvidenceNodeCompatible(
	projectNodeID, evidenceID string,
	evidenceByID map[string]behavior.Evidence,
	relationships []artifact.Edge,
) bool {
	evidence, ok := evidenceByID[evidenceID]
	if !ok || projectNodeID == "" || evidence.NodeID == "" ||
		evidence.Method != "xcode-xcconfig" || evidence.Kind != "xcode-build-setting-absence" {
		return false
	}
	const absenceSuffix = " is not assigned and no unsupported '#' marker is present"
	if !strings.HasSuffix(evidence.Value, absenceSuffix) || strings.TrimSuffix(evidence.Value, absenceSuffix) == "" {
		return false
	}
	for _, relationship := range relationships {
		if relationship.From == projectNodeID && relationship.To == evidence.NodeID &&
			relationship.Kind == "xcode-base-configuration" &&
			slices.Contains(relationship.EvidenceIDs, evidenceID) &&
			xcodeBaseConfigurationRelationshipHasProofs(relationship, evidenceByID) {
			return true
		}
	}
	return false
}

func xcodeBaseConfigurationRelationshipHasProofs(
	relationship artifact.Edge,
	evidenceByID map[string]behavior.Evidence,
) bool {
	if relationship.Kind != "xcode-base-configuration" ||
		relationship.From == "" || relationship.To == "" || len(relationship.EvidenceIDs) < 2 {
		return false
	}
	var hasReference, hasAbsence bool
	for _, evidenceID := range relationship.EvidenceIDs {
		item, ok := evidenceByID[evidenceID]
		if !ok {
			return false
		}
		switch {
		case item.NodeID == relationship.From &&
			item.Method == "xcode-project" &&
			item.Kind == "xcode-base-configuration-reference" &&
			strings.Contains(item.Value, " baseConfigurationReference ") &&
			strings.Contains(item.Value, " -> "):
			hasReference = true
		case item.NodeID == relationship.To &&
			item.Method == "xcode-xcconfig" &&
			item.Kind == "xcode-build-setting-absence":
			const absenceSuffix = " is not assigned and no unsupported '#' marker is present"
			if !strings.HasSuffix(item.Value, absenceSuffix) || strings.TrimSuffix(item.Value, absenceSuffix) == "" {
				return false
			}
			hasAbsence = true
		default:
			return false
		}
	}
	return hasReference && hasAbsence
}

// packagingFeatureEvidenceNodeCompatible is the one semantic Feature adapter
// that deliberately projects exact child metadata onto an owning artifact.
// The public artifact node must carry the same recognized technology, and the
// proof must be facade-recognizer evidence owned by a strict descendant. This
// keeps general Feature/Operation evidence same-node while preserving exact
// bundle-level packaging provenance.
func packagingFeatureEvidenceNodeCompatible(
	feature behavior.Feature,
	evidenceID string,
	evidenceByID map[string]behavior.Evidence,
	nodesByID map[string]artifact.Node,
	ancestry artifactAncestry,
) bool {
	if feature.Key != "artifact.packaging_technology" || feature.Value == "" {
		return false
	}
	node, ok := nodesByID[feature.NodeID]
	if !ok || node.PackagingTechnology != feature.Value {
		return false
	}
	evidence := evidenceByID[evidenceID]
	return evidence.Method == "facade-recognizer" &&
		evidence.NodeID != feature.NodeID &&
		ancestry.isAncestor(feature.NodeID, evidence.NodeID)
}

func packagingFeatureEvidenceSetCompatible(
	feature behavior.Feature,
	evidenceIDs []string,
	evidenceByID map[string]behavior.Evidence,
	nodesByID map[string]artifact.Node,
	ancestry artifactAncestry,
) bool {
	if len(evidenceIDs) == 0 {
		return false
	}
	for _, evidenceID := range evidenceIDs {
		if !packagingFeatureEvidenceNodeCompatible(feature, evidenceID, evidenceByID, nodesByID, ancestry) {
			return false
		}
	}
	return true
}

func hasExactSameNodeFactEvidence(
	nodeID, scopeID, function, architecture string,
	evidenceIDs []string,
	evidenceByID map[string]behavior.Evidence,
) bool {
	for _, evidenceID := range evidenceIDs {
		evidence := evidenceByID[evidenceID]
		if evidence.NodeID != nodeID {
			continue
		}
		if function != "" {
			if evidence.ScopeID == scopeID && evidence.Function == function && evidence.Arch == architecture {
				return true
			}
			continue
		}
		// Non-function scopes on one artifact may deliberately widen/narrow
		// structural context (for example an Xcode run-script child scope backed
		// by its project declaration). Named-function facts remain exact above.
		if evidence.Function != "" {
			continue
		}
		if evidence.Arch == architecture {
			return true
		}
	}
	return false
}

func validateArtifactParentForest(nodes []artifact.Node, parents map[string]string) error {
	complete := make(map[string]bool, len(nodes))
	for _, start := range nodes {
		if complete[start.ID] {
			continue
		}
		chain := make([]string, 0, 8)
		position := make(map[string]int)
		current := start.ID
		for current != "" && !complete[current] {
			if index, seen := position[current]; seen {
				cycle := append(append([]string(nil), chain[index:]...), current)
				return fmt.Errorf("artifact node parent graph contains a cycle: %s", strings.Join(cycle, " -> "))
			}
			position[current] = len(chain)
			chain = append(chain, current)
			current = parents[current]
		}
		for _, id := range chain {
			complete[id] = true
		}
	}
	return nil
}

func validateEvidenceNodeIDs(path string, values []string, evidence map[string]behavior.Evidence) error {
	for index, id := range values {
		if evidence[id].NodeID == "" {
			return fmt.Errorf("%s[%d] references evidence %q without a node_id", path, index, id)
		}
	}
	return nil
}

func entityReferenceNodeID(reference behavior.EntityRef, rootStartNodes map[string]string, targets map[string]behavior.InvokedTarget) string {
	switch reference.Kind {
	case behavior.EntityKindArtifactNode:
		return reference.ID
	case behavior.EntityKindExecutionRoot:
		return rootStartNodes[reference.ID]
	case behavior.EntityKindInvokedTarget:
		return targets[reference.ID].NodeID
	default:
		return ""
	}
}

func containmentRelatedNodes(left, right string, ancestry artifactAncestry) bool {
	if left == "" || right == "" {
		return false
	}
	return left == right || ancestry.isAncestor(left, right) || ancestry.isAncestor(right, left)
}

func sameContainerOrContainmentRelated(left, right string, ancestry artifactAncestry) bool {
	if containmentRelatedNodes(left, right, ancestry) {
		return true
	}
	return left != "" && right != "" && ancestry.parents[left] != "" && ancestry.parents[left] == ancestry.parents[right]
}

func indexReportIDs(collection string, count int, idAt func(int) string) (map[string]struct{}, error) {
	ids := make(map[string]struct{}, count)
	for index := 0; index < count; index++ {
		id := idAt(index)
		if id == "" {
			return nil, fmt.Errorf("%s[%d].id must not be empty", collection, index)
		}
		if _, exists := ids[id]; exists {
			return nil, fmt.Errorf("%s[%d].id duplicates %q", collection, index, id)
		}
		ids[id] = struct{}{}
	}
	return ids, nil
}

func validateRequiredReportReference(path, value, target string, ids map[string]struct{}) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", path)
	}
	if _, ok := ids[value]; !ok {
		return fmt.Errorf("%s references missing %s %q", path, target, value)
	}
	return nil
}

func validateOptionalReportReference(path, value, target string, ids map[string]struct{}) error {
	if value == "" {
		return nil
	}
	return validateRequiredReportReference(path, value, target, ids)
}

func validateReportReferenceList(path string, values []string, target string, ids map[string]struct{}, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("%s must not be empty", path)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateRequiredReportReference(fmt.Sprintf("%s[%d]", path, index), value, target, ids); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d] duplicates %q", path, index, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateExecutionContext(path string, context behavior.ExecutionContext, roots, targets map[string]struct{}) error {
	if context.Connectivity == "" {
		return fmt.Errorf("%s.connectivity must not be empty", path)
	}
	if len(context.ExecutionRootIDs) > maxReportExecutionContextIDs {
		return fmt.Errorf("%s.execution_root_ids exceeds %d-item limit", path, maxReportExecutionContextIDs)
	}
	if len(context.InvokedTargetIDs) > maxReportExecutionContextIDs {
		return fmt.Errorf("%s.invoked_target_ids exceeds %d-item limit", path, maxReportExecutionContextIDs)
	}
	if _, err := behavior.NormalizeExecutionContext(context); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := validateReportReferenceList(path+".execution_root_ids", context.ExecutionRootIDs, "execution root", roots, false); err != nil {
		return err
	}
	return validateReportReferenceList(path+".invoked_target_ids", context.InvokedTargetIDs, "invoked target", targets, false)
}

func validateEntityReference(path string, ref behavior.EntityRef, nodes, roots, targets map[string]struct{}) error {
	switch ref.Kind {
	case behavior.EntityKindArtifactNode:
		return validateRequiredReportReference(path+".id", ref.ID, "artifact node", nodes)
	case behavior.EntityKindExecutionRoot:
		return validateRequiredReportReference(path+".id", ref.ID, "execution root", roots)
	case behavior.EntityKindInvokedTarget:
		return validateRequiredReportReference(path+".id", ref.ID, "invoked target", targets)
	default:
		return fmt.Errorf("%s.kind has invalid value %q", path, ref.Kind)
	}
}

func validateTargetSourceExecution(
	path string,
	target behavior.InvokedTarget,
	targets map[string]behavior.InvokedTarget,
	roots map[string]behavior.ExecutionRoot,
	scopeNodes map[string]string,
	relationships []artifact.Edge,
) error {
	switch target.Source.Kind {
	case behavior.EntityKindArtifactNode:
		// Artifact-sourced UNKNOWN targets are a useful structural/analyst lane
		// (for example a browser-only extension entrypoint). They carry no root
		// ownership. CONNECTED is privileged and must be reproducible from the
		// closed structural adapters used by production extraction.
		if target.Execution.Connectivity != behavior.ConnectivityConnected {
			return nil
		}
		switch target.Kind {
		case "program-entry", "bundle-script", "loader-invokes":
		default:
			return fmt.Errorf("%s.kind %q is unsupported for an artifact-node source", path, target.Kind)
		}
		if !hasArtifactRelationship(relationships, target.Source.ID, target.NodeID, target.Kind) {
			return fmt.Errorf("%s.source artifact node %q lacks exact %q relationship to target node %q", path, target.Source.ID, target.Kind, target.NodeID)
		}
		if len(target.Execution.InvokedTargetIDs) != 0 {
			return fmt.Errorf("%s.execution must not invent an invoked-target chain for artifact source %q", path, target.Source.ID)
		}
		for _, rootID := range target.Execution.ExecutionRootIDs {
			root := roots[rootID]
			startNodeID := root.StartNodeID
			if startNodeID == "" {
				startNodeID = scopeNodes[root.StartScopeID]
			}
			switch target.Kind {
			case "program-entry", "bundle-script":
				if !hasArtifactRelationship(relationships, target.Source.ID, startNodeID, "bundle-executable") {
					return fmt.Errorf("%s.execution root %q is not started by a bundle executable owned by artifact source %q", path, rootID, target.Source.ID)
				}
			case "loader-invokes":
				if startNodeID != target.Source.ID {
					return fmt.Errorf("%s.execution root %q starts node %q, not loader source node %q", path, rootID, startNodeID, target.Source.ID)
				}
			}
		}
	case behavior.EntityKindExecutionRoot:
		if target.Execution.Connectivity != behavior.ConnectivityConnected || !sameExecutionIDs(target.Execution.ExecutionRootIDs, []string{target.Source.ID}) || len(target.Execution.InvokedTargetIDs) != 0 {
			return fmt.Errorf("%s.execution must retain source execution root %q", path, target.Source.ID)
		}
	case behavior.EntityKindInvokedTarget:
		source := targets[target.Source.ID]
		if source.Execution.Connectivity == behavior.ConnectivityConnected {
			if target.Execution.Connectivity != behavior.ConnectivityConnected {
				return fmt.Errorf("%s.execution must retain connected source target %q", path, target.Source.ID)
			}
			if !sameExecutionIDs(target.Execution.ExecutionRootIDs, source.Execution.ExecutionRootIDs) {
				return fmt.Errorf("%s.execution must retain exactly the source target %q execution roots", path, target.Source.ID)
			}
			expected, err := behavior.NormalizeExecutionContext(behavior.ExecutionContext{
				Connectivity:     behavior.ConnectivityConnected,
				ExecutionRootIDs: source.Execution.ExecutionRootIDs,
				InvokedTargetIDs: append(append([]string(nil), source.Execution.InvokedTargetIDs...), target.Source.ID),
			})
			if err != nil {
				return fmt.Errorf("%s.execution cannot normalize source target %q ownership: %w", path, target.Source.ID, err)
			}
			expectedTargets := expected.InvokedTargetIDs
			if !sameExecutionIDs(target.Execution.InvokedTargetIDs, expectedTargets) {
				return fmt.Errorf("%s.execution must retain source invoked target %q and its ownership chain", path, target.Source.ID)
			}
		} else if target.Execution.Connectivity != source.Execution.Connectivity {
			return fmt.Errorf("%s.execution connectivity must retain source target %q connectivity %q", path, target.Source.ID, source.Execution.Connectivity)
		}
	}
	return nil
}

func hasArtifactRelationship(relationships []artifact.Edge, from, to, kind string) bool {
	for _, relationship := range relationships {
		if relationship.From == from && relationship.To == to && relationship.Kind == kind {
			return true
		}
	}
	return false
}

func validateRecordExecutionOwnership(path, nodeID string, context behavior.ExecutionContext, rootStartNodes map[string]string, targets map[string]behavior.InvokedTarget) error {
	if context.Connectivity != behavior.ConnectivityConnected {
		return nil
	}
	if len(context.InvokedTargetIDs) == 0 {
		for _, rootID := range context.ExecutionRootIDs {
			if rootStartNodes[rootID] != nodeID {
				return fmt.Errorf("%s.execution root %q starts artifact node %q, not record node %q", path, rootID, rootStartNodes[rootID], nodeID)
			}
		}
		return nil
	}
	if nodeID == "" {
		return fmt.Errorf("%s.execution has invoked targets but the record has no artifact node", path)
	}
	direct := make([]behavior.InvokedTarget, 0, len(context.InvokedTargetIDs))
	for _, targetID := range context.InvokedTargetIDs {
		if target := targets[targetID]; target.NodeID == nodeID {
			direct = append(direct, target)
		}
	}
	if len(direct) == 0 {
		return fmt.Errorf("%s.execution has no invoked target that owns artifact node %q", path, nodeID)
	}
	allowedTargets := map[string]struct{}{}
	supportedRoots := map[string]struct{}{}
	for _, target := range direct {
		current := target
		for {
			allowedTargets[current.ID] = struct{}{}
			for _, rootID := range current.Execution.ExecutionRootIDs {
				supportedRoots[rootID] = struct{}{}
			}
			if current.Source.Kind != behavior.EntityKindInvokedTarget {
				break
			}
			current = targets[current.Source.ID]
		}
	}
	for _, targetID := range context.InvokedTargetIDs {
		if _, ok := allowedTargets[targetID]; !ok {
			return fmt.Errorf("%s.execution target %q is not in an ownership chain for artifact node %q", path, targetID, nodeID)
		}
	}
	for _, rootID := range context.ExecutionRootIDs {
		if _, ok := supportedRoots[rootID]; !ok {
			return fmt.Errorf("%s.execution root %q does not own any retained target for artifact node %q", path, rootID, nodeID)
		}
	}
	return nil
}

func validateInvokedTargetSourceAcyclic(targets []behavior.InvokedTarget) error {
	byID := make(map[string]behavior.InvokedTarget, len(targets))
	for _, target := range targets {
		byID[target.ID] = target
	}
	state := make(map[string]uint8, len(targets))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("invoked target source graph contains a cycle at %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		target := byID[id]
		if target.Source.Kind == behavior.EntityKindInvokedTarget {
			if err := visit(target.Source.ID); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, target := range targets {
		if err := visit(target.ID); err != nil {
			return err
		}
	}
	return nil
}

func sameExecutionIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}
	return true
}

func validateSelectionReasons(path string, reasons []behavior.SelectionReason) error {
	if len(reasons) == 0 {
		return fmt.Errorf("%s must not be empty", path)
	}
	seen := make(map[behavior.SelectionReason]struct{}, len(reasons))
	for index, reason := range reasons {
		switch reason {
		case behavior.SelectionReasonExecutionRoot,
			behavior.SelectionReasonInvokedTarget,
			behavior.SelectionReasonDeclaredEntry,
			behavior.SelectionReasonRunnableCandidate,
			behavior.SelectionReasonIncludeUnreferenced,
			behavior.SelectionReasonDefaultRelevant,
			behavior.SelectionReasonRawFeatures:
		default:
			return fmt.Errorf("%s[%d] has invalid value %q", path, index, reason)
		}
		if _, exists := seen[reason]; exists {
			return fmt.Errorf("%s[%d] duplicates %q", path, index, reason)
		}
		seen[reason] = struct{}{}
	}
	return nil
}

func validateScopeOwnership(path, nodeID, scopeID string, scopeNodes map[string]string) error {
	if nodeID == "" || scopeID == "" {
		return nil
	}
	if scopeNodeID := scopeNodes[scopeID]; scopeNodeID != "" && scopeNodeID != nodeID {
		return fmt.Errorf("%s.scope_id references a scope owned by artifact node %q, not record node %q", path, scopeNodeID, nodeID)
	}
	return nil
}

// validateReportSemantics rejects unknown values in closed vocabularies.
// Kinds, resource categories, and analysis-area names remain extensible.
func validateReportSemantics(report Report) error {
	if err := validateReportAnalysis(report.Analysis); err != nil {
		return err
	}
	for index, node := range report.ArtifactNodes {
		if node.LogicalPath == "" {
			return fmt.Errorf("artifact_nodes[%d].logical_path must not be empty", index)
		}
		if node.Kind == "" {
			return fmt.Errorf("artifact_nodes[%d].kind must not be empty", index)
		}
		if !validAnalysisStatus(node.AnalyzeStatus) {
			return fmt.Errorf("artifact_nodes[%d].analysis_status has invalid value %q", index, node.AnalyzeStatus)
		}
		if node.DeclaredEntryCount != nil && *node.DeclaredEntryCount < 0 {
			return fmt.Errorf("artifact_nodes[%d].declared_entry_count must not be negative", index)
		}
		if node.ModeledEntryCount != nil && *node.ModeledEntryCount < 0 {
			return fmt.Errorf("artifact_nodes[%d].modeled_entry_count must not be negative", index)
		}
		if node.DeclaredEntryCount != nil && node.ModeledEntryCount != nil && *node.ModeledEntryCount > *node.DeclaredEntryCount {
			return fmt.Errorf("artifact_nodes[%d].modeled_entry_count must not exceed declared_entry_count", index)
		}
	}
	for index, relationship := range report.Relationships {
		if relationship.Kind == "" {
			return fmt.Errorf("relationships[%d].kind must not be empty", index)
		}
		if relationship.Ordinal != nil && *relationship.Ordinal < 0 {
			return fmt.Errorf("relationships[%d].ordinal must not be negative", index)
		}
	}
	for index, scope := range report.Scopes {
		if scope.Kind == "" {
			return fmt.Errorf("scopes[%d].kind must not be empty", index)
		}
	}
	for index, item := range report.Evidence {
		if item.Method == "" {
			return fmt.Errorf("evidence[%d].extraction_method must not be empty", index)
		}
		if item.Kind == "" {
			return fmt.Errorf("evidence[%d].kind must not be empty", index)
		}
	}
	for index, root := range report.ExecutionRoots {
		if root.Kind == "" {
			return fmt.Errorf("execution_roots[%d].kind must not be empty", index)
		}
	}
	for index, target := range report.InvokedTargets {
		if target.Kind == "" {
			return fmt.Errorf("invoked_targets[%d].kind must not be empty", index)
		}
		if target.Ordinal != nil && *target.Ordinal < 0 {
			return fmt.Errorf("invoked_targets[%d].ordinal must not be negative", index)
		}
	}
	for index, feature := range report.Features {
		if feature.Key == "" {
			return fmt.Errorf("features[%d].key must not be empty", index)
		}
		if feature.Value == "" {
			return fmt.Errorf("features[%d].value must not be empty", index)
		}
		if !validSupport(feature.Support) {
			return fmt.Errorf("features[%d].support has invalid value %q", index, feature.Support)
		}
	}
	for index, operation := range report.Operations {
		if !behavior.ValidOperationKind(operation.Kind) {
			return fmt.Errorf("operations[%d].kind has invalid value %q", index, operation.Kind)
		}
		normalized, err := behavior.NormalizeResourceBindings(operation.Kind, operation.ResourceBindings)
		if err != nil {
			return fmt.Errorf("operations[%d]: %w", index, err)
		}
		if !reflect.DeepEqual(operation.ResourceBindings, normalized) {
			return fmt.Errorf("operations[%d].resource_bindings are not normalized", index)
		}
		if !validSupport(operation.Support) {
			return fmt.Errorf("operations[%d].support has invalid value %q", index, operation.Support)
		}
	}
	for index, relation := range report.OperationRelations {
		normalized, err := behavior.NormalizeOperationRelation(relation)
		if err != nil {
			return fmt.Errorf("operation_relations[%d]: %w", index, err)
		}
		if !reflect.DeepEqual(relation, normalized) {
			return fmt.Errorf("operation_relations[%d] is not normalized", index)
		}
	}
	for index, property := range report.ArtifactProperties {
		if property.Kind == "" {
			return fmt.Errorf("artifact_properties[%d].kind must not be empty", index)
		}
		if property.Value == "" {
			return fmt.Errorf("artifact_properties[%d].value must not be empty", index)
		}
		if !validSupport(property.Support) {
			return fmt.Errorf("artifact_properties[%d].support has invalid value %q", index, property.Support)
		}
	}
	for index, coverage := range report.Coverage {
		if coverage.AnalysisArea == "" {
			return fmt.Errorf("coverage[%d].analysis_area must not be empty", index)
		}
		if !validAnalysisStatus(coverage.Status) {
			return fmt.Errorf("coverage[%d].status has invalid value %q", index, coverage.Status)
		}
	}
	operationsByID := make(map[string]behavior.ModeledOperation, len(report.Operations))
	for _, operation := range report.Operations {
		operationsByID[operation.ID] = operation
	}
	featuresByID := make(map[string]behavior.Feature, len(report.Features))
	for _, feature := range report.Features {
		featuresByID[feature.ID] = feature
	}
	relationsByID := make(map[string]behavior.OperationRelation, len(report.OperationRelations))
	for _, relation := range report.OperationRelations {
		relationsByID[relation.ID] = relation
	}
	targetsByID := make(map[string]behavior.InvokedTarget, len(report.InvokedTargets))
	for _, target := range report.InvokedTargets {
		targetsByID[target.ID] = target
	}
	for index, capability := range report.Capabilities {
		if capability.RuleID == "" {
			return fmt.Errorf("capability_matches[%d].rule_id must not be empty", index)
		}
		if capability.Title == "" {
			return fmt.Errorf("capability_matches[%d].title must not be empty", index)
		}
		if capability.Namespace == "" {
			return fmt.Errorf("capability_matches[%d].namespace must not be empty", index)
		}
		resourceKeys := make(map[behavior.ResourceKey]struct{}, len(capability.AffectedResources))
		for resourceIndex, resource := range capability.AffectedResources {
			normalized, err := behavior.NormalizeResource(resource)
			if err != nil {
				return fmt.Errorf("capability_matches[%d].affected_resources[%d]: %w", index, resourceIndex, err)
			}
			if !reflect.DeepEqual(resource, normalized) {
				return fmt.Errorf("capability_matches[%d].affected_resources[%d] is not normalized", index, resourceIndex)
			}
			key := resource.Key()
			if _, exists := resourceKeys[key]; exists {
				return fmt.Errorf("capability_matches[%d].affected_resources[%d] duplicates a projected resource", index, resourceIndex)
			}
			resourceKeys[key] = struct{}{}
		}
		if !validSupport(capability.Support) {
			return fmt.Errorf("capability_matches[%d].support has invalid value %q", index, capability.Support)
		}
		if capability.Support == behavior.SupportHeuristic {
			return fmt.Errorf("capability_matches[%d].support must not be HEURISTIC", index)
		}
		if err := validateCapabilityMatchResources(index, capability, operationsByID); err != nil {
			return err
		}
		if err := validateCapabilityMatchArchitectures(index, capability, operationsByID); err != nil {
			return err
		}
		if err := validateCapabilityMatchSupport(index, capability, operationsByID, featuresByID, relationsByID, targetsByID); err != nil {
			return err
		}
	}
	return nil
}

func validateCapabilityMatchResources(index int, capability behavior.CapabilityMatch, operations map[string]behavior.ModeledOperation) error {
	var bindings []behavior.Resource
	for _, operationID := range capability.OperationIDs {
		for _, binding := range operations[operationID].ResourceBindings {
			bindings = append(bindings, binding.Resource)
		}
	}
	for resourceIndex, resource := range capability.AffectedResources {
		exactIdentity := resource.IdentityKey()
		correlationKey, correlationKnown := resource.CorrelationKey()
		exactlyBound := false
		classifications := make(map[behavior.ResourceClassification]struct{})
		for _, candidate := range bindings {
			if candidate.IdentityKey() == exactIdentity {
				exactlyBound = true
			}
			samePhysicalResource := candidate.IdentityKey() == exactIdentity
			if correlationKnown {
				candidateKey, candidateKnown := candidate.CorrelationKey()
				samePhysicalResource = candidateKnown && candidateKey == correlationKey
			}
			if !samePhysicalResource {
				continue
			}
			for _, classification := range candidate.Classifications {
				classifications[classification] = struct{}{}
			}
		}
		if !exactlyBound {
			return fmt.Errorf("capability_matches[%d].affected_resources[%d] is not physically bound to a supporting operation", index, resourceIndex)
		}
		for _, classification := range resource.Classifications {
			if _, ok := classifications[classification]; !ok {
				return fmt.Errorf("capability_matches[%d].affected_resources[%d] classification %q is not projected from a supporting operation binding", index, resourceIndex, classification)
			}
		}
	}
	return nil
}

func validateCapabilityMatchArchitectures(index int, capability behavior.CapabilityMatch, operations map[string]behavior.ModeledOperation) error {
	path := fmt.Sprintf("capability_matches[%d].architecture_scopes", index)
	if err := validateFactArchitectureList(path, capability.ArchitectureScopes, true); err != nil {
		return err
	}
	expectedSet := make(map[string]struct{})
	for _, operationID := range capability.OperationIDs {
		if architecture := operations[operationID].Architecture; architecture != "" {
			expectedSet[architecture] = struct{}{}
		}
	}
	expected := make([]string, 0, len(expectedSet))
	for architecture := range expectedSet {
		expected = append(expected, architecture)
	}
	slices.Sort(expected)
	if !slices.Equal(capability.ArchitectureScopes, expected) {
		return fmt.Errorf("%s must exactly equal the canonical supporting-operation architectures %q", path, expected)
	}
	return nil
}

func validateCapabilityMatchSupport(
	index int,
	capability behavior.CapabilityMatch,
	operations map[string]behavior.ModeledOperation,
	features map[string]behavior.Feature,
	relations map[string]behavior.OperationRelation,
	targets map[string]behavior.InvokedTarget,
) error {
	var commonRoots map[string]struct{}
	var commonTargets map[string]struct{}
	allUnconnected := true
	allConnected := true
	for operationIndex, operationID := range capability.OperationIDs {
		operation := operations[operationID]
		if operation.SubjectNodeID != capability.SubjectNodeID {
			return fmt.Errorf("capability_matches[%d].subject_node_id %q differs from supporting operation %q subject %q", index, capability.SubjectNodeID, operationID, operation.SubjectNodeID)
		}
		if reportSupportStrength(capability.Support) > reportSupportStrength(operation.Support) {
			return fmt.Errorf("capability_matches[%d].support %q is stronger than supporting operation %q support %q", index, capability.Support, operationID, operation.Support)
		}
		allUnconnected = allUnconnected && operation.Execution.Connectivity == behavior.ConnectivityUnconnected
		allConnected = allConnected && operation.Execution.Connectivity == behavior.ConnectivityConnected
		if operationIndex == 0 {
			commonRoots = executionIDSet(operation.Execution.ExecutionRootIDs)
			commonTargets = executionIDSet(operation.Execution.InvokedTargetIDs)
		} else {
			commonRoots = intersectExecutionIDs(commonRoots, operation.Execution.ExecutionRootIDs)
			commonTargets = intersectExecutionIDs(commonTargets, operation.Execution.InvokedTargetIDs)
		}
	}
	for _, clause := range capability.MatchTrace {
		for _, featureID := range clause.FeatureIDs {
			if feature := features[featureID]; reportSupportStrength(capability.Support) > reportSupportStrength(feature.Support) {
				return fmt.Errorf("capability_matches[%d].support %q is stronger than traced feature %q support %q", index, capability.Support, featureID, feature.Support)
			}
		}
		for _, relationID := range clause.RelationIDs {
			if relation := relations[relationID]; reportSupportStrength(capability.Support) > reportSupportStrength(relation.Support) {
				return fmt.Errorf("capability_matches[%d].support %q is stronger than traced operation relation %q support %q", index, capability.Support, relationID, relation.Support)
			}
		}
	}
	expectedConnectivity := behavior.ConnectivityUnknown
	if allUnconnected {
		expectedConnectivity = behavior.ConnectivityUnconnected
	} else if allConnected && len(commonRoots) > 0 {
		expectedConnectivity = behavior.ConnectivityConnected
	}
	if capability.Execution.Connectivity != expectedConnectivity {
		return fmt.Errorf("capability_matches[%d].execution connectivity %q does not match supporting-operation connectivity %q", index, capability.Execution.Connectivity, expectedConnectivity)
	}
	if expectedConnectivity != behavior.ConnectivityConnected {
		return nil
	}
	tracedRoots := make(map[string]struct{})
	for _, clause := range capability.MatchTrace {
		for _, rootID := range clause.ExecutionRootIDs {
			tracedRoots[rootID] = struct{}{}
		}
	}
	expectedRoots := commonRoots
	if len(tracedRoots) > 0 {
		for rootID := range tracedRoots {
			if _, ok := commonRoots[rootID]; !ok {
				return fmt.Errorf("capability_matches[%d].match_trace execution root %q is not in the supporting-operation root intersection", index, rootID)
			}
		}
		expectedRoots = tracedRoots
	}
	if !sameExecutionIDSet(capability.Execution.ExecutionRootIDs, expectedRoots) {
		return fmt.Errorf("capability_matches[%d].execution roots must equal the retained supporting-operation root projection", index)
	}
	compatibleTargets := make(map[string]struct{}, len(commonTargets))
	for targetID := range commonTargets {
		if hasExecutionIDIntersection(capability.Execution.ExecutionRootIDs, targets[targetID].Execution.ExecutionRootIDs) {
			compatibleTargets[targetID] = struct{}{}
		}
	}
	if !sameExecutionIDSet(capability.Execution.InvokedTargetIDs, compatibleTargets) {
		return fmt.Errorf("capability_matches[%d].execution targets must equal the root-compatible supporting-operation target intersection", index)
	}
	return nil
}

func hasExecutionIDIntersection(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func sameExecutionIDSet(values []string, expected map[string]struct{}) bool {
	if len(values) != len(expected) {
		return false
	}
	for _, value := range values {
		if _, ok := expected[value]; !ok {
			return false
		}
	}
	return true
}

func executionIDSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func intersectExecutionIDs(current map[string]struct{}, values []string) map[string]struct{} {
	next := make(map[string]struct{})
	for _, value := range values {
		if _, ok := current[value]; ok {
			next[value] = struct{}{}
		}
	}
	return next
}

func reportSupportStrength(value behavior.Support) int {
	switch value {
	case behavior.SupportDirect:
		return 3
	case behavior.SupportCorroborated:
		return 2
	case behavior.SupportHeuristic:
		return 1
	default:
		return 0
	}
}

// validFactArchitecture accepts only the canonical labels emitted by the
// Mach-O inventory and extractor producers. Analysis selection has a separate
// vocabulary: "all" is never a concrete fact architecture.
func validFactArchitecture(value string) bool {
	if value == "" {
		return true
	}
	base, subtype, hasSubtype := strings.Cut(value, "/")
	if hasSubtype && strings.Contains(subtype, "/") {
		return false
	}

	allowSubtype := false
	switch base {
	case "i386", "x86_64", "arm", "arm64", "ppc", "ppc64":
		allowSubtype = true
	case "x86_64h", "arm64e", "CpuArm", "CpuPpc", "CpuPpc64":
		return !hasSubtype
	default:
		parsed, err := strconv.ParseUint(base, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != base {
			return false
		}
		allowSubtype = true
	}
	if !hasSubtype {
		return true
	}
	if !allowSubtype || !strings.HasPrefix(subtype, "0x") || len(subtype) <= 2 {
		return false
	}
	parsed, err := strconv.ParseUint(subtype[2:], 16, 24)
	if err != nil || parsed == 0 || "0x"+strconv.FormatUint(parsed, 16) != subtype {
		return false
	}
	// These subtypes have dedicated canonical labels or are omitted by the
	// current producers.
	if base == "arm64" && parsed == 2 ||
		base == "x86_64" && (parsed == 3 || parsed == 8) ||
		base == "i386" && parsed == 3 {
		return false
	}
	return true
}

func validateFactArchitecture(path, value string) error {
	if !validFactArchitecture(value) {
		return fmt.Errorf("%s has noncanonical fact architecture %q", path, value)
	}
	return nil
}

func validateFactArchitectureList(path string, values []string, requireSorted bool) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value == "" {
			return fmt.Errorf("%s[%d] must not be empty", path, index)
		}
		if err := validateFactArchitecture(fmt.Sprintf("%s[%d]", path, index), value); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d] duplicates %q", path, index, value)
		}
		seen[value] = struct{}{}
	}
	if requireSorted && !slices.IsSorted(values) {
		return fmt.Errorf("%s is not in canonical order", path)
	}
	return nil
}

func validateReportAnalysis(analysis AnalysisMetadata) error {
	if architecture := analysis.Architecture; architecture != "all" && architecture != "arm64" && architecture != "x86_64" && architecture != "i386" {
		return fmt.Errorf("analysis.architecture has invalid value %q", architecture)
	}
	positiveLimits := []struct {
		name  string
		value int64
	}{
		{name: "max_file_bytes", value: analysis.MaxFileBytes},
		{name: "max_archive_bytes", value: analysis.MaxArchiveBytes},
		{name: "max_expanded_bytes", value: analysis.MaxExpandedBytes},
		{name: "max_total_bytes", value: analysis.MaxTotalBytes},
		{name: "max_archive_depth", value: int64(analysis.MaxArchiveDepth)},
		{name: "max_directory_depth", value: int64(analysis.MaxDirectoryDepth)},
		{name: "max_compression_ratio", value: analysis.MaxCompressionRatio},
		{name: "max_artifact_nodes", value: int64(analysis.MaxArtifactNodes)},
		{name: "max_artifact_path_bytes", value: analysis.MaxArtifactPathBytes},
		{name: "max_evidence", value: int64(analysis.MaxEvidence)},
		{name: "max_diagnostics", value: int64(analysis.MaxDiagnostics)},
		{name: "max_diagnostic_bytes", value: analysis.MaxDiagnosticBytes},
	}
	for _, limit := range positiveLimits {
		if limit.value <= 0 {
			return fmt.Errorf("analysis.%s must be positive", limit.name)
		}
	}
	if analysis.MaxArtifactNodes > artifact.DefaultMaxArtifactNodes {
		return fmt.Errorf("analysis.max_artifact_nodes exceeds maximum %d", artifact.DefaultMaxArtifactNodes)
	}
	if analysis.MaxEvidence > artifact.DefaultMaxEvidence {
		return fmt.Errorf("analysis.max_evidence exceeds maximum %d", artifact.DefaultMaxEvidence)
	}
	return nil
}

func validSupport(value behavior.Support) bool {
	return value.Valid()
}

func validAnalysisStatus(value string) bool {
	switch value {
	case "analyzed", "partial", "skipped":
		return true
	default:
		return false
	}
}
