package rules

import (
	"fmt"
	"sort"
	"strings"
)

const (
	maxLibraryDependencyDepth = 64
	maxExpandedPatternNodes   = 4096
)

type libraryReferenceError struct {
	code string
	id   string
	path []string
}

func (err libraryReferenceError) Error() string {
	switch err.code {
	case "RULE_LIBRARY_REFERENCE_ID_INVALID":
		return fmt.Sprintf("library rule reference %q is not a stable rule ID", err.id)
	case "RULE_LIBRARY_REFERENCE_NOT_FOUND":
		return fmt.Sprintf("library rule reference %q does not exist", err.id)
	case "RULE_LIBRARY_REFERENCE_KIND":
		return fmt.Sprintf("rule reference %q does not target a LibraryRule", err.id)
	case "RULE_LIBRARY_REFERENCE_CYCLE":
		return "library rule dependency cycle: " + strings.Join(err.path, " -> ")
	case "RULE_LIBRARY_DEPENDENCY_LIMIT":
		return "library rule dependency expansion exceeds the bounded depth or pattern-node limit"
	default:
		return fmt.Sprintf("invalid library rule reference %q", err.id)
	}
}

func librarySpecs(specs []Spec) map[string]Spec {
	out := make(map[string]Spec)
	for _, spec := range specs {
		if spec.Kind == LibraryRule && stableRuleID.MatchString(spec.Metadata.ID) {
			out[spec.Metadata.ID] = spec
		}
	}
	return out
}

func directLibraryRuleIDs(pattern Pattern) []string {
	seen := map[string]bool{}
	var visit func(Pattern)
	visit = func(pattern Pattern) {
		switch pattern := pattern.(type) {
		case libraryRulePattern:
			if pattern.id != "" {
				seen[pattern.id] = true
			}
		case anyPattern:
			for _, child := range pattern.patterns {
				visit(child)
			}
		case eachPattern:
			visit(pattern.left)
			visit(pattern.right)
		case relatePattern:
			visit(pattern.left)
			visit(pattern.right)
		case resourceFlowPattern:
			for _, raw := range pattern.steps {
				if step, ok := raw.(resourceFlowStepPattern); ok {
					visit(step.operation)
				}
			}
		}
	}
	visit(pattern)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func specIndex(specs []Spec) map[string]Spec {
	out := make(map[string]Spec)
	for _, spec := range specs {
		if stableRuleID.MatchString(spec.Metadata.ID) {
			if _, exists := out[spec.Metadata.ID]; !exists {
				out[spec.Metadata.ID] = spec
			}
		}
	}
	return out
}

func expandLibraryRuleReferences(pattern Pattern, libraries map[string]Spec) (Pattern, error) {
	remaining := maxExpandedPatternNodes
	return expandLibraryRuleReferencesBounded(pattern, libraries, nil, &remaining)
}

func expandLibraryRuleReferencesBounded(pattern Pattern, libraries map[string]Spec, stack []string, remaining *int) (Pattern, error) {
	if remaining == nil || *remaining <= 0 || len(stack) > maxLibraryDependencyDepth {
		return nil, libraryReferenceError{code: "RULE_LIBRARY_DEPENDENCY_LIMIT"}
	}
	(*remaining)--
	switch pattern := pattern.(type) {
	case libraryRulePattern:
		if !stableRuleID.MatchString(pattern.id) {
			return nil, libraryReferenceError{code: "RULE_LIBRARY_REFERENCE_ID_INVALID", id: pattern.id}
		}
		target, ok := libraries[pattern.id]
		if !ok {
			return nil, libraryReferenceError{code: "RULE_LIBRARY_REFERENCE_NOT_FOUND", id: pattern.id}
		}
		for index, id := range stack {
			if id == pattern.id {
				cycle := append(append([]string(nil), stack[index:]...), pattern.id)
				return nil, libraryReferenceError{code: "RULE_LIBRARY_REFERENCE_CYCLE", id: pattern.id, path: cycle}
			}
		}
		if len(stack) >= maxLibraryDependencyDepth {
			return nil, libraryReferenceError{code: "RULE_LIBRARY_DEPENDENCY_LIMIT"}
		}
		return expandLibraryRuleReferencesBounded(target.Match, libraries, append(stack, pattern.id), remaining)
	case anyPattern:
		children := make([]Pattern, 0, len(pattern.patterns))
		for _, child := range pattern.patterns {
			expanded, err := expandLibraryRuleReferencesBounded(child, libraries, stack, remaining)
			if err != nil {
				return nil, err
			}
			children = append(children, expanded)
		}
		return anyPattern{patterns: children}, nil
	case eachPattern:
		left, err := expandLibraryRuleReferencesBounded(pattern.left, libraries, stack, remaining)
		if err != nil {
			return nil, err
		}
		right, err := expandLibraryRuleReferencesBounded(pattern.right, libraries, stack, remaining)
		if err != nil {
			return nil, err
		}
		return eachPattern{left: left, right: right, constraints: append([]EachConstraint(nil), pattern.constraints...)}, nil
	case relatePattern:
		left, err := expandLibraryRuleReferencesBounded(pattern.left, libraries, stack, remaining)
		if err != nil {
			return nil, err
		}
		right, err := expandLibraryRuleReferencesBounded(pattern.right, libraries, stack, remaining)
		if err != nil {
			return nil, err
		}
		return relatePattern{left: left, right: right, constraints: append([]RelationConstraint(nil), pattern.constraints...)}, nil
	case resourceFlowPattern:
		steps := make([]ResourceFlowStep, 0, len(pattern.steps))
		for _, raw := range pattern.steps {
			step, ok := raw.(resourceFlowStepPattern)
			if !ok {
				steps = append(steps, raw)
				continue
			}
			expanded, err := expandLibraryRuleReferencesBounded(step.operation, libraries, stack, remaining)
			if err != nil {
				return nil, err
			}
			steps = append(steps, resourceFlowStepPattern{operation: expanded, role: step.role})
		}
		return resourceFlowPattern{steps: steps}, nil
	default:
		return pattern, nil
	}
}

func validateLibraryReferences(spec Spec, all map[string]Spec) []SpecDiagnostic {
	var diagnostics []SpecDiagnostic
	remaining := maxExpandedPatternNodes
	limited := false
	var visit func(Pattern, []string)
	visit = func(pattern Pattern, stack []string) {
		if limited {
			return
		}
		if remaining <= 0 || len(stack) > maxLibraryDependencyDepth {
			diagnostics = append(diagnostics, SpecDiagnostic{Code: "RULE_LIBRARY_DEPENDENCY_LIMIT", RuleID: spec.Metadata.ID, Field: "match.library_rule", Message: "library rule dependency expansion exceeds the bounded depth or pattern-node limit", Suggestion: "flatten or split the reusable expression DAG"})
			limited = true
			return
		}
		remaining--
		switch pattern := pattern.(type) {
		case libraryRulePattern:
			referenceError := func(code, message, suggestion string) {
				diagnostics = append(diagnostics, SpecDiagnostic{Code: code, RuleID: spec.Metadata.ID, Field: "match.library_rule.id", Message: message, Suggestion: suggestion})
			}
			if !stableRuleID.MatchString(pattern.id) {
				referenceError("RULE_LIBRARY_REFERENCE_ID_INVALID", fmt.Sprintf("library rule reference %q is not a stable rule ID", pattern.id), "use the exact stable ID of a generated LibraryRule")
				return
			}
			target, exists := all[pattern.id]
			if !exists {
				referenceError("RULE_LIBRARY_REFERENCE_NOT_FOUND", fmt.Sprintf("library rule reference %q does not exist", pattern.id), "declare one generated LibraryRule with this ID or correct the reference")
				return
			}
			if target.Kind != LibraryRule {
				referenceError("RULE_LIBRARY_REFERENCE_KIND", fmt.Sprintf("rule reference %q targets a CapabilityRule", pattern.id), "references may target only LibraryRule declarations")
				return
			}
			for index, id := range stack {
				if id == pattern.id {
					cycle := append(append([]string(nil), stack[index:]...), pattern.id)
					referenceError("RULE_LIBRARY_REFERENCE_CYCLE", "library rule dependency cycle: "+strings.Join(cycle, " -> "), "remove one reference so the library dependency graph is acyclic")
					return
				}
			}
			if len(stack) >= maxLibraryDependencyDepth {
				referenceError("RULE_LIBRARY_DEPENDENCY_LIMIT", "library rule dependency depth exceeds the bounded limit", "flatten or split the reusable expression DAG")
				limited = true
				return
			}
			visit(target.Match, append(stack, pattern.id))
		case anyPattern:
			for _, child := range pattern.patterns {
				visit(child, stack)
			}
		case eachPattern:
			visit(pattern.left, stack)
			visit(pattern.right, stack)
		case relatePattern:
			visit(pattern.left, stack)
			visit(pattern.right, stack)
		case resourceFlowPattern:
			for _, raw := range pattern.steps {
				if step, ok := raw.(resourceFlowStepPattern); ok {
					visit(step.operation, stack)
				}
			}
		}
	}
	visit(spec.Match, nil)
	return diagnostics
}
