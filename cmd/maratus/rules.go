package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0x4D31/maratus/internal/report"
	ruleengine "github.com/0x4D31/maratus/internal/rules"
)

const ruleCheckSchemaVersion = "maratus.rule-check.v0.2-preview.1"

type ruleCheckResult struct {
	SchemaVersion string                      `json:"schema_version"`
	Valid         bool                        `json:"valid"`
	RuleID        string                      `json:"rule_id,omitempty"`
	Checked       int                         `json:"checked"`
	Diagnostics   []ruleengine.SpecDiagnostic `json:"diagnostics"`
}

func runRules(args []string) error {
	if len(args) == 0 {
		rulesUsage(os.Stderr)
		return usageErrorf("rules requires a subcommand")
	}
	switch args[0] {
	case "help", "--help", "-h":
		if len(args) != 1 {
			return usageErrorf("rules help does not accept arguments")
		}
		rulesUsage(os.Stdout)
		return nil
	case "list":
		return runRulesList(args[1:])
	case "check":
		return runRulesCheck(args[1:])
	case "vocab":
		return runRulesVocab(args[1:])
	default:
		return usageErrorf("unknown rules subcommand %q; run \"maratus rules --help\" for usage", args[0])
	}
}

func runRulesVocab(args []string) error {
	fs := newFlagSet("rules vocab")
	formatValue := fs.String("format", "text", "output format: text or json")
	if wantsHelp(fs, args) {
		rulesVocabUsage(os.Stdout)
		return nil
	}
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return newUsageError(err)
	}
	if len(positionals) != 0 {
		return usageErrorf("rules vocab does not accept positional arguments")
	}
	format, err := parseOutputFormat(*formatValue, "text", "json")
	if err != nil {
		return newUsageError(err)
	}
	vocabulary := ruleengine.RuleVocabulary()
	if format == "json" {
		return report.WriteJSON(os.Stdout, vocabulary)
	}
	return writeRulesVocabularyText(os.Stdout, vocabulary)
}

func writeRulesVocabularyText(out io.Writer, vocabulary ruleengine.Vocabulary) error {
	var text strings.Builder
	fmt.Fprintf(&text, "rule vocabulary: %s\n", vocabulary.SchemaVersion)
	fmt.Fprintf(&text, "rule kinds: %s\n", joinVocabulary(vocabulary.RuleKinds))
	fmt.Fprintf(&text, "pattern nodes: %s\n", joinVocabulary(vocabulary.PatternNodes))
	fmt.Fprintf(&text, "operation constraints: %s\n", joinVocabulary(vocabulary.OperationConstraints))
	fmt.Fprintf(&text, "each constraints: %s\n", joinVocabulary(vocabulary.EachConstraints))
	fmt.Fprintf(&text, "relation constraints: %s\n", joinVocabulary(vocabulary.RelationConstraints))
	fmt.Fprintf(&text, "typed capability minimum support: %s\n", joinVocabulary(vocabulary.TypedCapabilityMinimumSupport))
	fmt.Fprintf(&text, "support: %s\n", joinVocabulary(vocabulary.Support))
	fmt.Fprintf(&text, "connectivity: %s\n", joinVocabulary(vocabulary.Connectivity))
	fmt.Fprintf(&text, "resource kinds: %s\n", joinVocabulary(vocabulary.ResourceKinds))
	fmt.Fprintf(&text, "resource roles: %s\n", joinVocabulary(vocabulary.ResourceRoles))
	fmt.Fprintf(&text, "relation endpoint kinds: %s\n", joinVocabulary(vocabulary.RelationEndpointKinds))
	text.WriteString("\noperation kinds:\n")
	for _, operation := range vocabulary.OperationKinds {
		fmt.Fprintf(&text, "  %s\n", operation.Kind)
		for _, policy := range operation.ResourceRoles {
			requirement := "optional"
			if policy.Required {
				requirement = "required"
			}
			fmt.Fprintf(&text, "    %s (%s): %s\n", policy.Role, requirement, joinVocabulary(policy.Kinds))
		}
	}
	text.WriteString("\nresource classifications:\n")
	for _, classification := range vocabulary.ResourceClassifications {
		fmt.Fprintf(&text, "  %s: %s\n", classification.Classification, joinVocabulary(classification.PhysicalKinds))
	}
	text.WriteString("\nrelation kinds:\n")
	for _, relation := range vocabulary.RelationKinds {
		fmt.Fprintf(&text, "  %s\n", relation.Kind)
		for _, endpoints := range relation.Endpoints {
			fmt.Fprintf(&text, "    %s -> %s\n", endpoints.From, endpoints.To)
		}
	}
	_, err := io.WriteString(out, text.String())
	return err
}

func joinVocabulary[T ~string](values []T) string {
	stringsValue := make([]string, len(values))
	for index, value := range values {
		stringsValue[index] = string(value)
	}
	return strings.Join(stringsValue, ", ")
}

func runRulesCheck(args []string) error {
	fs := newFlagSet("rules check")
	formatValue := fs.String("format", "text", "output format: text or json")
	if wantsHelp(fs, args) {
		rulesCheckUsage(os.Stdout)
		return nil
	}
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return newUsageError(err)
	}
	if len(positionals) > 1 {
		return usageErrorf("rules check accepts at most one rule ID")
	}
	format, err := parseOutputFormat(*formatValue, "text", "json")
	if err != nil {
		return newUsageError(err)
	}
	specs := ruleengine.Specs()
	result := ruleCheckResult{SchemaVersion: ruleCheckSchemaVersion, Valid: true, Diagnostics: []ruleengine.SpecDiagnostic{}}
	if len(positionals) == 1 {
		result.RuleID = strings.TrimSpace(positionals[0])
		spec, ok := ruleengine.SpecByID(result.RuleID)
		if !ok {
			result.Valid = false
			result.Diagnostics = append(result.Diagnostics, ruleengine.SpecDiagnostic{Code: "RULE_NOT_FOUND", RuleID: result.RuleID, Message: fmt.Sprintf("rule %q is not present in the generated catalog", result.RuleID), Suggestion: "run maratus rules list to inspect stable rule IDs"})
			specs = nil
		} else {
			specs = []ruleengine.Spec{spec}
		}
	}
	result.Checked = len(specs)
	result.Diagnostics = append(result.Diagnostics, ruleengine.ValidateSpecs(specs)...)
	result.Valid = result.Valid && len(result.Diagnostics) == 0
	if format == "json" {
		if err := report.WriteJSON(os.Stdout, result); err != nil {
			return err
		}
	} else if result.Valid {
		_, err = fmt.Fprintf(os.Stdout, "valid: %d rule specs checked\n", result.Checked)
		if err != nil {
			return err
		}
	} else {
		for _, diagnostic := range result.Diagnostics {
			if _, err = fmt.Fprintf(os.Stdout, "%s %s: %s\n", diagnostic.Code, diagnostic.RuleID, diagnostic.Message); err != nil {
				return err
			}
		}
	}
	if !result.Valid {
		return fmt.Errorf("rule spec validation failed")
	}
	return nil
}

func runRulesList(args []string) error {
	fs := newFlagSet("rules list")
	formatValue := fs.String("format", "text", "output format: text or json")
	presentation := addPresentationFlags(fs)
	if wantsHelp(fs, args) {
		rulesListUsage(os.Stdout)
		return nil
	}
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return newUsageError(err)
	}
	if len(positionals) != 0 {
		return usageErrorf("rules list does not accept positional arguments")
	}
	format, err := parseOutputFormat(*formatValue, "text", "json")
	if err != nil {
		return newUsageError(err)
	}
	textOptions, err := presentation.resolve(format)
	if err != nil {
		return newUsageError(err)
	}
	info := report.ListRules()
	if format == "json" {
		return report.WriteJSON(os.Stdout, info)
	}
	return report.WriteRulesText(os.Stdout, info, textOptions)
}
