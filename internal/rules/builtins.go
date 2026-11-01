package rules

import (
	"fmt"
	"sort"
)

//go:generate go run ./cmd/rulegen -dir . -output catalog_gen.go

// compiledBuiltins validates and expands the generated typed catalog into the
// only rule representation accepted by production evaluation.
func compiledBuiltins() []compiledSpec {
	specs := Specs()
	if diagnostics := ValidateSpecs(specs); len(diagnostics) != 0 {
		panic(fmt.Sprintf("invalid generated rule catalog: %s: %s", diagnostics[0].Code, diagnostics[0].Message))
	}
	libraries := librarySpecs(specs)
	rules := make([]compiledSpec, 0, len(specs))
	for _, spec := range specs {
		expanded, err := expandLibraryRuleReferences(spec.Match, libraries)
		if err != nil {
			panic(fmt.Sprintf("invalid generated rule catalog: %v", err))
		}
		rules = append(rules, compiledSpec{spec: spec, match: expanded})
	}
	return rules
}

func CatalogEntries() []CatalogEntry {
	specs := Specs()
	if diagnostics := ValidateSpecs(specs); len(diagnostics) != 0 {
		panic(fmt.Sprintf("invalid generated rule catalog: %s: %s", diagnostics[0].Code, diagnostics[0].Message))
	}
	entries := make([]CatalogEntry, 0, len(specs))
	for _, spec := range specs {
		dependencies := directLibraryRuleIDs(spec.Match)
		metadata := spec.Metadata
		metadata.Attack = append([]string(nil), metadata.Attack...)
		metadata.MBC = append([]string(nil), metadata.MBC...)
		entries = append(entries, CatalogEntry{
			Metadata: metadata, Kind: spec.Kind, MinimumSupport: spec.MinimumSupport,
			LibraryRuleIDs: dependencies,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}
