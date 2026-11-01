package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

type Metadata struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Namespace   string   `json:"namespace"`
	Description string   `json:"description,omitempty"`
	Attack      []string `json:"attack,omitempty"`
	MBC         []string `json:"mbc,omitempty"`
}

type CatalogEntry struct {
	Metadata
	Kind           RuleKind         `json:"kind"`
	MinimumSupport behavior.Support `json:"minimum_support"`
	LibraryRuleIDs []string         `json:"library_rule_ids"`
}

type RuleKind string

const (
	CapabilityRule RuleKind = "capability"
	LibraryRule    RuleKind = "library"
)

var ruleKinds = [...]RuleKind{CapabilityRule, LibraryRule}

// RuleKinds returns the closed rule-kind vocabulary.
func RuleKinds() []RuleKind {
	return append([]RuleKind(nil), ruleKinds[:]...)
}

// Spec is the compiler-checked source declaration for one built-in rule.
// catalog_gen.go is generated from top-level Spec declarations, so adding a
// rule never requires editing a separate metadata or registration table.
type Spec struct {
	Metadata       Metadata
	Kind           RuleKind
	Match          Pattern
	MinimumSupport behavior.Support
}

type compiledSpec struct {
	spec  Spec
	match Pattern
}

func (rule compiledSpec) evaluateIndexed(view *analysisView, budget *ruleWorkBudget) []behavior.CapabilityMatch {
	spec := rule.spec
	if rule.match != nil {
		spec.Match = rule.match
	} else if expanded, err := expandLibraryRuleReferences(spec.Match, librarySpecs(Specs())); err == nil {
		// Direct compiledSpec construction is retained for focused package tests.
		// The generated production catalog precompiles this expression once.
		spec.Match = expanded
	}
	return evaluatePatternSpec(view, budget, spec)
}

type SpecDiagnostic struct {
	Code       string `json:"code"`
	RuleID     string `json:"rule_id,omitempty"`
	Field      string `json:"field,omitempty"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

var stableRuleID = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func ValidateSpecs(specs []Spec) []SpecDiagnostic {
	seen := make(map[string]bool, len(specs))
	var diagnostics []SpecDiagnostic
	for _, spec := range specs {
		id := strings.TrimSpace(spec.Metadata.ID)
		add := func(code, field, message, suggestion string) {
			diagnostics = append(diagnostics, SpecDiagnostic{Code: code, RuleID: id, Field: field, Message: message, Suggestion: suggestion})
		}
		if id == "" || !stableRuleID.MatchString(id) {
			add("RULE_ID_INVALID", "metadata.id", fmt.Sprintf("rule ID %q is not a stable dotted identifier", id), "use lowercase letters and digits separated by dots or hyphens")
		} else if seen[id] {
			add("RULE_ID_DUPLICATE", "metadata.id", fmt.Sprintf("rule ID %q is declared more than once", id), "choose one unique stable ID")
		}
		seen[id] = true
		if strings.TrimSpace(spec.Metadata.Title) == "" {
			add("RULE_TITLE_REQUIRED", "metadata.title", "rule title is empty", "add a concise analyst-facing title")
		}
		if strings.TrimSpace(spec.Metadata.Namespace) == "" {
			add("RULE_NAMESPACE_REQUIRED", "metadata.namespace", "rule namespace is empty", "add a stable dotted namespace")
		}
		if strings.TrimSpace(spec.Metadata.Description) == "" {
			add("RULE_DESCRIPTION_REQUIRED", "metadata.description", "rule description is empty", "describe exactly what the static match establishes")
		}
		switch spec.Kind {
		case CapabilityRule, LibraryRule:
		default:
			add("RULE_KIND_INVALID", "kind", fmt.Sprintf("rule kind %q is not in the closed vocabulary", spec.Kind), "use CapabilityRule or LibraryRule")
		}
		if spec.Match == nil {
			add("RULE_MATCH_REQUIRED", "match", "rule has no typed matching expression", "attach a typed match expression")
		}
		if spec.Match != nil {
			if !spec.MinimumSupport.Valid() {
				add("RULE_MINIMUM_SUPPORT_INVALID", "minimum_support", fmt.Sprintf("minimum support %q is not in the closed vocabulary", spec.MinimumSupport), "use DIRECT or CORROBORATED")
			} else if spec.MinimumSupport == behavior.SupportHeuristic {
				add("RULE_MINIMUM_SUPPORT_HEURISTIC", "minimum_support", "typed capability rules cannot promote heuristic operations into execution-backed matches", "use DIRECT or CORROBORATED; retain weaker observations as scoped features")
			}
			if spec.Kind == LibraryRule && spec.MinimumSupport != behavior.SupportCorroborated {
				add("RULE_LIBRARY_SUPPORT_POLICY", "minimum_support", "library rules currently require CORROBORATED minimum support", "use CORROBORATED; a consuming capability may require DIRECT support")
			}
			if spec.Kind == LibraryRule && (len(spec.Metadata.Attack) != 0 || len(spec.Metadata.MBC) != 0) {
				add("RULE_LIBRARY_MAPPING_INVALID", "metadata", "library rules cannot carry analyst-facing ATT&CK or MBC mappings", "attach mappings only to the operation-backed CapabilityRule that emits the public match")
			}
		}
	}
	all := specIndex(specs)
	libraries := librarySpecs(specs)
	for _, spec := range specs {
		if spec.Match == nil {
			continue
		}
		diagnostics = append(diagnostics, validateLibraryReferences(spec, all)...)
		expanded, err := expandLibraryRuleReferences(spec.Match, libraries)
		if err != nil {
			continue
		}
		for _, diagnostic := range validatePattern(expanded) {
			diagnostics = append(diagnostics, SpecDiagnostic{Code: diagnostic.Code, RuleID: strings.TrimSpace(spec.Metadata.ID), Field: diagnostic.Field, Message: diagnostic.Message, Suggestion: diagnostic.Suggestion})
		}
		if spec.Kind == CapabilityRule && !everyPatternMatchHasOperation(expanded) {
			diagnostics = append(diagnostics, SpecDiagnostic{Code: "RULE_CAPABILITY_OPERATION_REQUIRED", RuleID: strings.TrimSpace(spec.Metadata.ID), Field: "match", Message: "every capability match path must contain a ModeledOperation", Suggestion: "use Feature only inside an operation-backed Each expression or a LibraryRule"})
		}
	}
	sort.SliceStable(diagnostics, func(i, j int) bool {
		if diagnostics[i].RuleID != diagnostics[j].RuleID {
			return diagnostics[i].RuleID < diagnostics[j].RuleID
		}
		if diagnostics[i].Code != diagnostics[j].Code {
			return diagnostics[i].Code < diagnostics[j].Code
		}
		return diagnostics[i].Field < diagnostics[j].Field
	})
	return diagnostics
}

func Specs() []Spec {
	return append([]Spec(nil), generatedSpecs...)
}

func SpecByID(id string) (Spec, bool) {
	for _, spec := range generatedSpecs {
		if spec.Metadata.ID == id {
			return spec, true
		}
	}
	return Spec{}, false
}
