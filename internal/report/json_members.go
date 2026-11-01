package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

type reportJSONValueKind uint8

const (
	reportJSONValueAbsent reportJSONValueKind = iota
	reportJSONValueNull
	reportJSONValueScalar
	reportJSONValueObject
	reportJSONValueArray
)

type reportJSONType struct {
	kind       reflect.Kind
	fields     map[string]reportJSONField
	fieldNames []string
	element    *reportJSONType
}

type reportJSONField struct {
	name     string
	value    *reportJSONType
	required bool
}

type reportJSONMemberState struct {
	memberNameBytes int64
	path            []string
	requiredErr     error
}

type reportJSONMemberValidation struct {
	requiredErr error
}

func (v reportJSONMemberValidation) validateRequired() error {
	if v.requiredErr == nil {
		return nil
	}
	return fmt.Errorf("invalid report JSON member structure: %w", v.requiredErr)
}

var savedReportJSONType = buildReportJSONType(reflect.TypeOf(Report{}), map[reflect.Type]*reportJSONType{})

// validateReportJSONMembers closes two ambiguities left by encoding/json:
// duplicate member names use last-value-wins semantics, and differently cased
// names can resolve to the same typed struct field. Exact duplicate names are
// rejected in every object, including analyst-controlled maps. Noncanonical
// case-folded aliases are rejected in typed objects even when they occur alone,
// while case-sensitive map keys retain their meaning.
//
// validateReportJSONStructure runs first and supplies strict input, depth,
// token, string, per-object member, and collection bounds. The aggregate bytes
// retained for decoded member names are independently capped at the already
// enforced report input limit.
func validateReportJSONMembers(data []byte) (reportJSONMemberValidation, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	state := reportJSONMemberState{path: []string{"report"}}
	if _, err := state.validateValue(decoder, savedReportJSONType); err != nil {
		return reportJSONMemberValidation{}, fmt.Errorf("invalid report JSON member structure: %w", err)
	}
	return reportJSONMemberValidation{requiredErr: state.requiredErr}, nil
}

func (s *reportJSONMemberState) validateValue(decoder *json.Decoder, expected *reportJSONType) (reportJSONValueKind, error) {
	token, err := decoder.Token()
	if err != nil {
		return reportJSONValueAbsent, err
	}
	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if token == nil {
			return reportJSONValueNull, nil
		}
		return reportJSONValueScalar, nil
	}

	switch delim {
	case '{':
		if err := s.validateObject(decoder, expected); err != nil {
			return reportJSONValueAbsent, err
		}
		return reportJSONValueObject, nil
	case '[':
		if err := s.validateArray(decoder, expected); err != nil {
			return reportJSONValueAbsent, err
		}
		return reportJSONValueArray, nil
	default:
		return reportJSONValueAbsent, fmt.Errorf("unexpected delimiter %q at %s", delim, s.pathString())
	}
}

func (s *reportJSONMemberState) validateObject(decoder *json.Decoder, expected *reportJSONType) error {
	var exactNames map[string]struct{}
	var typedNames map[string]string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("object member at %s is not a string", s.pathString())
		}
		s.memberNameBytes += int64(len(name))
		if s.memberNameBytes > maxReportInputBytes {
			return fmt.Errorf("decoded object member names exceed %d-byte aggregate limit", maxReportInputBytes)
		}
		if _, exists := exactNames[name]; exists {
			return fmt.Errorf("object %s duplicates member %q", s.pathString(), boundedReportMemberName(name))
		}
		if exactNames == nil {
			exactNames = make(map[string]struct{})
		}
		exactNames[name] = struct{}{}

		field, typed := expected.lookupField(name)
		if typed {
			if previous, exists := typedNames[field.name]; exists {
				return fmt.Errorf("object %s maps members %q and %q to typed field %q", s.pathString(), boundedReportMemberName(previous), boundedReportMemberName(name), field.name)
			}
			if name != field.name {
				return fmt.Errorf("object %s uses noncanonical member %q for typed field %q", s.pathString(), boundedReportMemberName(name), field.name)
			}
			if typedNames == nil {
				typedNames = make(map[string]string)
			}
			typedNames[field.name] = name
		}

		childType := field.value
		if !typed && expected != nil && expected.kind == reflect.Map {
			childType = expected.element
		}
		s.path = append(s.path, boundedReportMemberName(name))
		kind, err := s.validateValue(decoder, childType)
		s.path = s.path[:len(s.path)-1]
		if err != nil {
			return err
		}
		if typed && field.required && kind == reportJSONValueNull {
			s.recordRequiredError(fmt.Errorf("object %s member %q must not be null", s.pathString(), field.name))
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("object %s has invalid closing delimiter", s.pathString())
	}
	if expected != nil && expected.kind == reflect.Struct {
		for _, name := range expected.fieldNames {
			field := expected.fields[name]
			if !field.required {
				continue
			}
			if _, present := typedNames[name]; !present {
				s.recordRequiredError(fmt.Errorf("object %s is missing required member %q", s.pathString(), name))
			}
		}
	}
	return nil
}

func (s *reportJSONMemberState) validateArray(decoder *json.Decoder, expected *reportJSONType) error {
	element := expected.elementType()
	s.path = append(s.path, "[]")
	defer func() { s.path = s.path[:len(s.path)-1] }()
	for decoder.More() {
		if _, err := s.validateValue(decoder, element); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("array %s has invalid closing delimiter", s.pathString())
	}
	return nil
}

func (s *reportJSONMemberState) recordRequiredError(err error) {
	if s.requiredErr == nil {
		s.requiredErr = err
	}
}

func (s *reportJSONMemberState) pathString() string {
	return strings.Join(s.path, ".")
}

func boundedReportMemberName(name string) string {
	const maxBytes = 128
	if len(name) <= maxBytes {
		return name
	}
	return name[:maxBytes] + "..."
}

func (t *reportJSONType) lookupField(name string) (reportJSONField, bool) {
	if t == nil || t.kind != reflect.Struct {
		return reportJSONField{}, false
	}
	if field, ok := t.fields[name]; ok {
		return field, true
	}
	for _, canonical := range t.fieldNames {
		if strings.EqualFold(name, canonical) {
			return t.fields[canonical], true
		}
	}
	return reportJSONField{}, false
}

func (t *reportJSONType) elementType() *reportJSONType {
	if t == nil || t.kind != reflect.Array && t.kind != reflect.Slice {
		return nil
	}
	return t.element
}

func buildReportJSONType(value reflect.Type, cache map[reflect.Type]*reportJSONType) *reportJSONType {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if existing := cache[value]; existing != nil {
		return existing
	}
	typeInfo := &reportJSONType{kind: value.Kind()}
	cache[value] = typeInfo

	switch value.Kind() {
	case reflect.Array, reflect.Slice:
		typeInfo.element = buildReportJSONType(value.Elem(), cache)
	case reflect.Map:
		typeInfo.element = buildReportJSONType(value.Elem(), cache)
	case reflect.Struct:
		typeInfo.fields = map[string]reportJSONField{}
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tagParts := strings.Split(field.Tag.Get("json"), ",")
			name := tagParts[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			required := true
			for _, option := range tagParts[1:] {
				if option == "omitempty" {
					required = false
					break
				}
			}
			typeInfo.fields[name] = reportJSONField{name: name, value: buildReportJSONType(field.Type, cache), required: required}
		}
		// Evidence has a custom decoder that exposes byte_offset through an
		// internal pointer field. Model it here so a case-fold alias cannot
		// evade duplicate detection at that one custom-decoding boundary.
		if value == reflect.TypeOf(behavior.Evidence{}) {
			typeInfo.fields["byte_offset"] = reportJSONField{name: "byte_offset", value: buildReportJSONType(reflect.TypeOf(int64(0)), cache)}
		}
		for name := range typeInfo.fields {
			typeInfo.fieldNames = append(typeInfo.fieldNames, name)
		}
		sort.Strings(typeInfo.fieldNames)
	}
	return typeInfo
}

func validateRequiredSavedReport(report Report) error {
	if report.Tool != "maratus" {
		return fmt.Errorf("tool must equal %q", "maratus")
	}
	if report.ToolVersion == "" {
		return fmt.Errorf("tool_version must not be empty")
	}
	if report.RulesetVersion == "" {
		return fmt.Errorf("ruleset_version must not be empty")
	}
	if !rules.ValidCatalogDigest(report.RuleCatalogDigest) {
		return fmt.Errorf("rule_catalog_digest must be a sha256 catalog digest")
	}
	if report.Artifact == "" {
		return fmt.Errorf("artifact must not be empty")
	}
	if len(report.ArtifactNodes) == 0 {
		return fmt.Errorf("artifact_nodes must not be empty")
	}
	return nil
}
