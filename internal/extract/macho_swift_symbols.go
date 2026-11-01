package extract

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

type machoSwiftSymbol struct {
	module   string
	mangling string
	origin   string
}

// machoSwiftSymbolInfo recognizes only documented Swift mangling prefixes and
// the exact leading module production. It deliberately does not implement a
// partial demangler: the raw linker symbol remains the function identity.
func machoSwiftSymbolInfo(name string) (machoSwiftSymbol, bool) {
	if len(name) == 0 || len(name) > maxMachOSymbolDemangleInputBytes {
		return machoSwiftSymbol{}, false
	}
	body, mangling, ok := swiftMangledBody(name)
	if !ok {
		return machoSwiftSymbol{}, false
	}
	for _, r := range body {
		if r != '_' && r != '$' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return machoSwiftSymbol{}, false
		}
	}
	module, ok := swiftLeadingModule(body)
	if !ok {
		return machoSwiftSymbol{}, false
	}
	return machoSwiftSymbol{module: module, mangling: mangling, origin: swiftSymbolOrigin(module)}, true
}

func swiftMangledBody(name string) (body, mangling string, ok bool) {
	switch {
	case strings.HasPrefix(name, "$s"):
		return name[2:], "stable", true
	case strings.HasPrefix(name, "$S"):
		return name[2:], "swift-4.2", true
	case strings.HasPrefix(name, "$e"):
		return name[2:], "embedded", true
	case strings.HasPrefix(name, "_T0"):
		return name[3:], "swift-4.0", true
	default:
		return "", "", false
	}
}

func isSwiftMangledPrefix(name string) bool {
	return strings.HasPrefix(name, "$s") || strings.HasPrefix(name, "$S") || strings.HasPrefix(name, "$e") || strings.HasPrefix(name, "_T0")
}

func swiftLeadingModule(body string) (string, bool) {
	switch {
	case strings.HasPrefix(body, "SC") && len(body) > 2:
		return "ClangImporter", true
	case strings.HasPrefix(body, "So") && len(body) > 2:
		return "ObjectiveC", true
	case strings.HasPrefix(body, "s") && len(body) > 1:
		return "Swift", true
	}
	end := 0
	for end < len(body) && body[end] >= '0' && body[end] <= '9' && end < 6 {
		end++
	}
	if end == 0 || end == len(body) || body[0] == '0' {
		// Word-substituted and punycode identifiers need a complete demangler;
		// do not guess their module boundary here.
		return "", false
	}
	length, err := strconv.Atoi(body[:end])
	if err != nil || length <= 0 || length > 1<<maxMachOSymbolDemangleOutputPower || end+length >= len(body) {
		return "", false
	}
	module := body[end : end+length]
	for index, r := range module {
		if r != '_' && r != '$' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return "", false
		}
		if index == 0 && r >= '0' && r <= '9' {
			return "", false
		}
	}
	return module, true
}

func swiftSymbolOrigin(module string) string {
	switch module {
	case "Swift":
		return "swift-standard-library"
	case "ClangImporter", "ObjectiveC":
		return "swift-runtime-compiler"
	default:
		return "swift-other"
	}
}

type machoSwiftFunctionSummary struct {
	stable, swift42, embedded, swift40 int
	runtime, standard, other           int
	inputLimited                       int
}

func summarizeSwiftFunctions(functions []machoFunction) machoSwiftFunctionSummary {
	var summary machoSwiftFunctionSummary
	for _, function := range functions {
		switch function.Metadata {
		case "swift-runtime-compiler":
			summary.runtime++
		case "swift-standard-library":
			summary.standard++
		case "swift-other":
			summary.other++
		}
		if function.Language == "swift" {
			switch function.Mangling {
			case "stable":
				summary.stable++
			case "swift-4.2":
				summary.swift42++
			case "embedded":
				summary.embedded++
			case "swift-4.0":
				summary.swift40++
			}
			if function.SwiftSymbolInputLimited {
				summary.inputLimited++
			}
		}
	}
	return summary
}

func addMachOSwiftSymbolCoverage(graph *behavior.Graph, content artifact.Content, arch string, functions []machoFunction) {
	summary := summarizeSwiftFunctions(functions)
	if total := summary.runtime + summary.standard + summary.other; total > 0 {
		value := fmt.Sprintf("functions=%d stable=%d swift_4_2=%d embedded=%d swift_4_0=%d runtime_compiler=%d standard_library=%d other=%d", total, summary.stable, summary.swift42, summary.embedded, summary.swift40, summary.runtime, summary.standard, summary.other)
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-symbols",
			Kind: "swift-function-symbols", Value: value, Arch: arch,
		})
		if evidenceID == "" || graph.AddFeature(behavior.Feature{
			NodeID: content.NodeID, Architecture: arch, Key: "swift.symbols", Value: value,
			EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect,
			Qualifiers: map[string]string{"identity": "exact-leading-module", "demangling": "not-performed"},
		}) == "" {
			graph.MarkWorkOmitted()
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID: content.NodeID, AnalysisArea: "macho-swift-symbols/" + arch, Status: "analyzed",
			Detail: fmt.Sprintf("bounded Swift symbol enrichment recovered %d exact mangling/module identities (%d runtime/compiler, %d standard-library, %d other); symbols remain raw and non-runtime module identity does not establish application ownership", total, summary.runtime, summary.standard, summary.other),
		})
	}
	if summary.inputLimited > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "macho-swift-symbol-input/"+arch, fmt.Sprintf("%d Swift-prefixed function symbols exceeded the %d-byte input cap and remained raw generic symbol identities", summary.inputLimited, maxMachOSymbolDemangleInputBytes))
	}
}
