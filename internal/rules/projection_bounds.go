package rules

import (
	"fmt"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/behavior"
)

// ValidateCapabilityMatchProjectionBounds rejects a retained match that could
// not have been emitted by the bounded rule engine. Report loaders call this
// before reference expansion or semantic joins so hostile cardinalities remain
// cheap to reject.
func ValidateCapabilityMatchProjectionBounds(match behavior.CapabilityMatch) error {
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{name: "id", value: match.ID, limit: maxCapabilityMatchIDBytes},
		{name: "rule_id", value: match.RuleID, limit: maxCapabilityMatchIDBytes},
		{name: "title", value: match.Title, limit: maxCapabilityMatchLabelBytes},
		{name: "namespace", value: match.Namespace, limit: maxCapabilityMatchLabelBytes},
		{name: "support", value: string(match.Support), limit: maxCapabilityMatchLabelBytes},
		{name: "subject_node_id", value: match.SubjectNodeID, limit: maxCapabilityMatchIDBytes},
		{name: "execution.connectivity", value: string(match.Execution.Connectivity), limit: maxCapabilityMatchLabelBytes},
	} {
		if err := validateProjectionString(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name      string
		values    []string
		count     int
		byteLimit int
	}{
		{name: "execution.execution_root_ids", values: match.Execution.ExecutionRootIDs, count: maxCapabilityMatchExecutionIDs, byteLimit: maxCapabilityMatchIDBytes},
		{name: "execution.invoked_target_ids", values: match.Execution.InvokedTargetIDs, count: maxCapabilityMatchExecutionIDs, byteLimit: maxCapabilityMatchIDBytes},
		{name: "operation_ids", values: match.OperationIDs, count: maxCapabilityMatchOperations, byteLimit: maxCapabilityMatchIDBytes},
		{name: "evidence_ids", values: match.EvidenceIDs, count: maxCapabilityMatchEvidence, byteLimit: maxCapabilityMatchIDBytes},
		{name: "attack", values: match.Attack, count: maxCapabilityMatchMappings, byteLimit: maxCapabilityMatchLabelBytes},
		{name: "mbc", values: match.MBC, count: maxCapabilityMatchMappings, byteLimit: maxCapabilityMatchLabelBytes},
		{name: "architecture_scopes", values: match.ArchitectureScopes, count: maxCapabilityMatchResources, byteLimit: maxCapabilityMatchLabelBytes},
	} {
		if err := validateProjectionStrings(field.name, field.values, field.count, field.byteLimit); err != nil {
			return err
		}
	}
	if len(match.AffectedResources) > maxCapabilityMatchResources {
		return fmt.Errorf("affected_resources has %d items; limit is %d", len(match.AffectedResources), maxCapabilityMatchResources)
	}
	for index, resource := range match.AffectedResources {
		if err := validateProjectionString(fmt.Sprintf("affected_resources[%d].value", index), resource.Value, maxCapabilityMatchValueBytes); err != nil {
			return err
		}
	}
	if len(match.MatchTrace) > maxCapabilityMatchTraceClauses {
		return fmt.Errorf("match_trace has %d clauses; limit is %d", len(match.MatchTrace), maxCapabilityMatchTraceClauses)
	}
	for index, clause := range match.MatchTrace {
		if err := validateProjectionString(fmt.Sprintf("match_trace[%d].path", index), clause.Path, maxCapabilityMatchTracePath); err != nil {
			return err
		}
		for _, field := range []struct {
			name   string
			values []string
		}{
			{name: "operation_ids", values: clause.OperationIDs},
			{name: "feature_ids", values: clause.FeatureIDs},
			{name: "execution_root_ids", values: clause.ExecutionRootIDs},
			{name: "operation_relation_ids", values: clause.RelationIDs},
		} {
			if err := validateProjectionStrings(
				fmt.Sprintf("match_trace[%d].%s", index, field.name),
				field.values,
				maxCapabilityMatchTraceIDs,
				maxCapabilityMatchIDBytes,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProjectionStrings(name string, values []string, count, byteLimit int) error {
	if len(values) > count {
		return fmt.Errorf("%s has %d items; limit is %d", name, len(values), count)
	}
	for index, value := range values {
		if err := validateProjectionString(fmt.Sprintf("%s[%d]", name, index), value, byteLimit); err != nil {
			return err
		}
	}
	return nil
}

func validateProjectionString(name, value string, limit int) error {
	if len(value) > limit {
		return fmt.Errorf("%s has %d bytes; limit is %d", name, len(value), limit)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	return nil
}
