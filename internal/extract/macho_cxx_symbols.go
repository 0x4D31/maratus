package extract

import (
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/ianlancetaylor/demangle"
)

type machoCXXSymbol struct {
	display          string
	displayTruncated bool
	module           string
	origin           string
}

// machoCXXSymbolInfo accepts only a complete Itanium ABI symbol decoded by the
// pinned in-process parser. Rust legacy names are rejected before the shared
// demangler can interpret their Itanium-shaped envelope as C++.
func machoCXXSymbolInfo(name string) (machoCXXSymbol, bool) {
	if len(name) == 0 || len(name) > maxMachOSymbolDemangleInputBytes || !strings.HasPrefix(name, "_Z") {
		return machoCXXSymbol{}, false
	}
	if strings.HasPrefix(name, "_ZN") && legacyRustSymbolHashTail(name) {
		return machoCXXSymbol{}, false
	}
	display, err := demangle.ToString(name, demangle.NoParams, demangle.MaxLength(maxMachOSymbolDemangleOutputPower), demangle.NoRust)
	if err != nil || display == "" || display == name {
		return machoCXXSymbol{}, false
	}
	module := cxxSymbolModule(display)
	return machoCXXSymbol{
		display:          display,
		displayTruncated: len(display) >= 1<<maxMachOSymbolDemangleOutputPower,
		module:           module,
		origin:           cxxSymbolOrigin(module),
	}, true
}

func cxxSymbolModule(display string) string {
	value := strings.TrimLeft(display, "<(&* ")
	end := strings.Index(value, "::")
	if end <= 0 {
		return ""
	}
	module := value[:end]
	for _, r := range module {
		if r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return ""
		}
	}
	return module
}

func cxxSymbolOrigin(module string) string {
	switch module {
	case "__cxxabiv1":
		return "cxx-runtime-compiler"
	case "std", "__gnu_cxx":
		return "cxx-standard-library"
	default:
		return "cxx-other"
	}
}

type machoCXXFunctionSummary struct {
	runtime, standard, other       int
	displayTruncated, inputLimited int
}

func summarizeCXXFunctions(functions []machoFunction) machoCXXFunctionSummary {
	var summary machoCXXFunctionSummary
	for _, function := range functions {
		switch function.Metadata {
		case "cxx-runtime-compiler":
			summary.runtime++
		case "cxx-standard-library":
			summary.standard++
		case "cxx-other":
			summary.other++
		}
		if function.Language == "c++" && function.DisplayTruncated {
			summary.displayTruncated++
		}
		if function.CXXSymbolInputLimited {
			summary.inputLimited++
		}
	}
	return summary
}

func addMachOCXXSymbolCoverage(graph *behavior.Graph, content artifact.Content, arch string, functions []machoFunction) {
	summary := summarizeCXXFunctions(functions)
	if total := summary.runtime + summary.standard + summary.other; total > 0 {
		value := fmt.Sprintf("functions=%d runtime_compiler=%d standard_library=%d other=%d", total, summary.runtime, summary.standard, summary.other)
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-symbols",
			Kind: "cxx-function-symbols", Value: value, Arch: arch,
		})
		if evidenceID != "" {
			if graph.AddFeature(behavior.Feature{
				NodeID: content.NodeID, Architecture: arch, Key: "cxx.symbols", Value: value,
				EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect,
				Qualifiers: map[string]string{"mangling": "itanium"},
			}) == "" {
				graph.MarkWorkOmitted()
			}
		} else {
			graph.MarkWorkOmitted()
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID: content.NodeID, AnalysisArea: "macho-cxx-symbols/" + arch, Status: "analyzed",
			Detail: fmt.Sprintf("bounded C++ symbol enrichment recovered %d exact demangled function identities (%d runtime/compiler, %d standard-library, %d other); non-runtime identity does not establish application ownership", total, summary.runtime, summary.standard, summary.other),
		})
		if summary.displayTruncated > 0 {
			addPartialCoverageOnce(graph, content.NodeID, "macho-cxx-symbol-display/"+arch, fmt.Sprintf("%d C++ function display names reached the %d-byte demangling output cap; exact raw linker symbols were retained", summary.displayTruncated, 1<<maxMachOSymbolDemangleOutputPower))
		}
	}
	if summary.inputLimited > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "macho-cxx-symbol-input/"+arch, fmt.Sprintf("%d unambiguous Itanium C++ function symbols exceeded the %d-byte demangling input cap and remained raw generic symbol identities", summary.inputLimited, maxMachOSymbolDemangleInputBytes))
	}
}
