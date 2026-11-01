package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

const (
	maxReportJSONDepth            = 256
	maxReportJSONStringBytes      = 16 << 20
	maxReportJSONStructuralTokens = 4_000_000
	maxReportJSONArrayElements    = 8 * artifact.DefaultMaxArtifactNodes
	maxReportJSONObjectMembers    = 4_096
	maxReportTotalArrayElements   = 1_000_000
	maxReportRelationships        = 8 * artifact.DefaultMaxArtifactNodes
	maxReportBehaviorItems        = behavior.DefaultItemLimit + behavior.PostLimitCoverageAllowance
)

var reportBehaviorArrayFields = map[string]bool{
	"scopes":                  true,
	"analysis_selection":      true,
	"execution_roots":         true,
	"invoked_targets":         true,
	"features":                true,
	"operations":              true,
	"operation_relations":     true,
	"artifact_properties":     true,
	"network_implementations": true,
	"coverage":                true,
}

var boundedReportArrayLimits = map[string]int{
	"artifact_nodes":          artifact.DefaultMaxArtifactNodes,
	"relationships":           maxReportRelationships,
	"scopes":                  maxReportBehaviorItems,
	"analysis_selection":      maxReportBehaviorItems,
	"execution_roots":         maxReportBehaviorItems,
	"invoked_targets":         maxReportBehaviorItems,
	"capability_matches":      rules.DefaultCapabilityMatchLimit,
	"features":                maxReportBehaviorItems,
	"operations":              maxReportBehaviorItems,
	"operation_relations":     maxReportBehaviorItems,
	"artifact_properties":     maxReportBehaviorItems,
	"network_implementations": maxReportBehaviorItems,
	"coverage":                maxReportBehaviorItems,
	"evidence":                artifact.DefaultMaxEvidence,
	"diagnostics":             artifact.DefaultMaxDiagnostics,
}

var boundedReportArrayFieldNames = []string{
	"artifact_nodes",
	"relationships",
	"scopes",
	"analysis_selection",
	"execution_roots",
	"invoked_targets",
	"capability_matches",
	"features",
	"operations",
	"operation_relations",
	"artifact_properties",
	"network_implementations",
	"coverage",
	"evidence",
	"diagnostics",
}

type reportJSONFrame struct {
	kind          byte
	field         string
	elements      int
	expectElement bool
	members       int
}

type reportJSONLimitState struct {
	fieldElements   map[string]int
	behaviorItems   int
	totalElements   int
	structuralToken int
}

func validateReportJSONStructure(data []byte) error {
	frames := make([]reportJSONFrame, 0, 16)
	arrayFields := map[int]string{}
	state := reportJSONLimitState{fieldElements: map[string]int{}}

	for index := 0; index < len(data); index++ {
		current := data[index]
		if isJSONWhitespace(current) {
			continue
		}

		if len(frames) > 0 {
			frame := &frames[len(frames)-1]
			if frame.kind == '[' && frame.expectElement && current != ']' {
				if err := state.addArrayElement(frame); err != nil {
					return err
				}
			}
		}

		switch current {
		case '"':
			end, err := reportJSONStringEnd(data, index)
			if err != nil {
				return err
			}
			if err := state.addStructuralToken(); err != nil {
				return err
			}
			if len(frames) > 0 && frames[len(frames)-1].kind == '{' {
				after := skipJSONWhitespace(data, end+1)
				if after < len(data) && data[after] == ':' {
					frame := &frames[len(frames)-1]
					frame.members++
					if frame.members > maxReportJSONObjectMembers {
						return fmt.Errorf("report JSON object exceeds %d-member limit", maxReportJSONObjectMembers)
					}
					if len(frames) == 1 {
						var field string
						if err := json.Unmarshal(data[index:end+1], &field); err != nil {
							return fmt.Errorf("invalid report JSON object key: %w", err)
						}
						value := skipJSONWhitespace(data, after+1)
						if canonical, ok := canonicalBoundedReportArrayField(field); ok && value < len(data) && data[value] == '[' {
							arrayFields[value] = canonical
						}
					}
				}
			}
			index = end
		case '{', '[':
			if err := state.addStructuralToken(); err != nil {
				return err
			}
			if len(frames) >= maxReportJSONDepth {
				return fmt.Errorf("report JSON exceeds nesting depth %d", maxReportJSONDepth)
			}
			frame := reportJSONFrame{kind: current}
			if current == '[' {
				frame.field = arrayFields[index]
				frame.expectElement = true
			}
			frames = append(frames, frame)
		case '}', ']':
			if err := state.addStructuralToken(); err != nil {
				return err
			}
			if len(frames) == 0 || current == '}' && frames[len(frames)-1].kind != '{' || current == ']' && frames[len(frames)-1].kind != '[' {
				return fmt.Errorf("invalid report JSON structure")
			}
			frames = frames[:len(frames)-1]
		case ',':
			if err := state.addStructuralToken(); err != nil {
				return err
			}
			if len(frames) > 0 && frames[len(frames)-1].kind == '[' {
				frames[len(frames)-1].expectElement = true
			}
		case ':':
			if err := state.addStructuralToken(); err != nil {
				return err
			}
		}
	}
	if len(frames) != 0 {
		return fmt.Errorf("invalid report JSON structure")
	}
	return nil
}

func (s *reportJSONLimitState) addStructuralToken() error {
	s.structuralToken++
	if s.structuralToken > maxReportJSONStructuralTokens {
		return fmt.Errorf("report JSON exceeds structural token limit %d", maxReportJSONStructuralTokens)
	}
	return nil
}

func (s *reportJSONLimitState) addArrayElement(frame *reportJSONFrame) error {
	frame.expectElement = false
	frame.elements++
	s.totalElements++
	if frame.elements > reportArrayElementLimit(frame.field) {
		if frame.field == "" {
			return fmt.Errorf("report JSON array exceeds %d-element limit", maxReportJSONArrayElements)
		}
		return fmt.Errorf("report JSON field %q exceeds %d-element limit", frame.field, reportArrayElementLimit(frame.field))
	}
	if s.totalElements > maxReportTotalArrayElements {
		return fmt.Errorf("report JSON exceeds aggregate array-element limit %d", maxReportTotalArrayElements)
	}
	if frame.field == "" {
		return nil
	}
	s.fieldElements[frame.field]++
	if s.fieldElements[frame.field] > reportArrayElementLimit(frame.field) {
		return fmt.Errorf("report JSON field %q exceeds %d-element limit", frame.field, reportArrayElementLimit(frame.field))
	}
	if reportBehaviorArrayFields[frame.field] {
		s.behaviorItems++
		if s.behaviorItems > maxReportBehaviorItems {
			return fmt.Errorf("report JSON exceeds aggregate behavior-item limit %d", maxReportBehaviorItems)
		}
	}
	return nil
}

func isBoundedReportArrayField(field string) bool {
	_, ok := boundedReportArrayLimits[field]
	return ok
}

// encoding/json matches object keys to struct fields using Unicode simple
// case folding. Apply the same policy before typed decoding so alternate key
// casing cannot bypass field-specific and aggregate collection limits.
func canonicalBoundedReportArrayField(field string) (string, bool) {
	if isBoundedReportArrayField(field) {
		return field, true
	}
	for _, canonical := range boundedReportArrayFieldNames {
		if strings.EqualFold(field, canonical) {
			return canonical, true
		}
	}
	return "", false
}

func reportArrayElementLimit(field string) int {
	if limit, ok := boundedReportArrayLimits[field]; ok {
		return limit
	}
	return maxReportJSONArrayElements
}

func reportJSONStringEnd(data []byte, start int) (int, error) {
	for index := start + 1; index < len(data); index++ {
		if index-start-1 > maxReportJSONStringBytes {
			return 0, fmt.Errorf("report JSON string exceeds %d-byte limit", maxReportJSONStringBytes)
		}
		switch data[index] {
		case '\\':
			index++
			if index >= len(data) {
				return 0, fmt.Errorf("invalid report JSON string")
			}
		case '"':
			return index, nil
		}
	}
	return 0, fmt.Errorf("invalid report JSON string")
}

func skipJSONWhitespace(data []byte, index int) int {
	for index < len(data) && isJSONWhitespace(data[index]) {
		index++
	}
	return index
}

func isJSONWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}
