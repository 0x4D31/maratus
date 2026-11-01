package extract

import (
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/ianlancetaylor/demangle"
)

const (
	maxMachOSymbolDemangleInputBytes = 16 << 10
	// demangle.MaxLength expresses the limit as a power of two. Keeping the
	// analyst-facing name to 1 KiB prevents pathological generic signatures
	// from dominating reports while the exact linker symbol remains retained.
	maxMachOSymbolDemangleOutputPower = 10
)

type machoRustSymbol struct {
	display          string
	displayTruncated bool
	module           string
	origin           string
	mangling         string
}

// machoRustSymbolInfo recognizes only rustc's unambiguous v0 prefix or a
// legacy name accepted by the mature demangler's strict Rust-hash checks. In
// particular, an ordinary Itanium C++ _ZN name is not classified as Rust.
func machoRustSymbolInfo(name string) (machoRustSymbol, bool) {
	if len(name) == 0 || len(name) > maxMachOSymbolDemangleInputBytes {
		return machoRustSymbol{}, false
	}
	mangling := ""
	switch {
	case strings.HasPrefix(name, "_R"):
		mangling = "v0"
	case strings.HasPrefix(name, "_ZN"):
		mangling = "legacy"
	default:
		return machoRustSymbol{}, false
	}
	display, err := demangle.ToString(name, demangle.NoTemplateParams, demangle.MaxLength(maxMachOSymbolDemangleOutputPower))
	if err != nil || display == "" || display == name {
		return machoRustSymbol{}, false
	}
	// ToString deliberately falls back to the C++ grammar for non-Rust _ZN
	// symbols. A successful demangle is therefore sufficient only for v0. For
	// legacy names, require rustc's exact hash-tail shape independently.
	if mangling == "legacy" && !legacyRustSymbolHashTail(name) {
		return machoRustSymbol{}, false
	}
	module := rustSymbolModule(display)
	return machoRustSymbol{
		display:          display,
		displayTruncated: len(display) >= 1<<maxMachOSymbolDemangleOutputPower,
		module:           module,
		origin:           rustSymbolOrigin(display, module),
		mangling:         mangling,
	}, true
}

func legacyRustSymbolHashTail(name string) bool {
	// A platform/tool suffix may follow the terminal E. The demangler accepts
	// only a dot-prefixed suffix; mirror that boundary before checking the
	// rustc-generated 17h<16 lowercase hex digits>E tail.
	if index := strings.LastIndex(name, "E."); index > 0 {
		name = name[:index+1]
	}
	if len(name) < 21 || name[len(name)-1] != 'E' || name[len(name)-20:len(name)-17] != "17h" {
		return false
	}
	var seen [16]bool
	distinct := 0
	for _, value := range name[len(name)-17 : len(name)-1] {
		var index int
		if value < '0' || value > '9' {
			if value < 'a' || value > 'f' {
				return false
			}
			index = int(value-'a') + 10
		} else {
			index = int(value - '0')
		}
		if !seen[index] {
			seen[index] = true
			distinct++
		}
	}
	// This is the same conservative legacy-Rust discriminator used by the
	// demangler to avoid mistaking an Itanium C++ component named h<hex> for a
	// rustc hash.
	return distinct >= 5
}

func rustSymbolModule(display string) string {
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

func rustSymbolOrigin(display, module string) string {
	switch module {
	case "core", "alloc", "compiler_builtins", "panic_abort", "panic_unwind", "unwind", "rustc_std_workspace_alloc", "rustc_std_workspace_core":
		return "rust-runtime-compiler"
	case "std", "test":
		return "rust-standard-library"
	}
	// Trait-method demanglings can start with the implementing type rather than
	// the crate. These checks classify only explicit standard/runtime paths.
	if strings.HasPrefix(display, "<core::") || strings.Contains(display, " as core::") ||
		strings.HasPrefix(display, "<alloc::") || strings.Contains(display, " as alloc::") {
		return "rust-runtime-compiler"
	}
	if strings.HasPrefix(display, "<std::") || strings.Contains(display, " as std::") {
		return "rust-standard-library"
	}
	return "rust-other"
}

func applyMachOFunctionQualifiers(qualifiers map[string]string, function machoFunction, prefix string) {
	if qualifiers == nil {
		return
	}
	if function.Metadata != "" {
		qualifiers[prefix+"origin"] = function.Metadata
	}
	if function.Language != "" {
		qualifiers[prefix+"language"] = function.Language
	}
	if function.Module != "" {
		qualifiers[prefix+"module"] = function.Module
	}
	if function.DisplayName != "" && function.DisplayName != function.Name {
		qualifiers[prefix+"display"] = function.DisplayName
	}
	if function.Mangling != "" {
		qualifiers[prefix+"mangling"] = function.Mangling
	}
	if function.DisplayTruncated {
		qualifiers[prefix+"display_truncated"] = "true"
	}
}

func machoFunctionQualifiers(function machoFunction, qualifiers map[string]string) map[string]string {
	if qualifiers == nil {
		qualifiers = map[string]string{}
	}
	applyMachOFunctionQualifiers(qualifiers, function, "function_")
	return qualifiers
}

type machoRustFunctionSummary struct {
	runtime, standard, other       int
	v0, legacy                     int
	displayTruncated, inputLimited int
}

func summarizeRustFunctions(functions []machoFunction) machoRustFunctionSummary {
	var summary machoRustFunctionSummary
	for _, function := range functions {
		switch function.Metadata {
		case "rust-runtime-compiler":
			summary.runtime++
		case "rust-standard-library":
			summary.standard++
		case "rust-other":
			summary.other++
		}
		switch function.Mangling {
		case "v0":
			if !function.RustSymbolInputLimited {
				summary.v0++
			}
		case "legacy":
			summary.legacy++
		}
		if function.DisplayTruncated {
			summary.displayTruncated++
		}
		if function.RustSymbolInputLimited {
			summary.inputLimited++
		}
	}
	return summary
}

func addMachORustSymbolCoverage(graph *behavior.Graph, content artifact.Content, arch string, functions []machoFunction) {
	summary := summarizeRustFunctions(functions)
	if total := summary.runtime + summary.standard + summary.other; total > 0 {
		value := fmt.Sprintf("functions=%d v0=%d legacy=%d runtime_compiler=%d standard_library=%d other=%d", total, summary.v0, summary.legacy, summary.runtime, summary.standard, summary.other)
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID: content.NodeID, Logical: content.LogicalPath, Method: "macho-symbols",
			Kind: "rust-function-symbols", Value: value, Arch: arch,
		})
		if evidenceID != "" {
			if graph.AddFeature(behavior.Feature{
				NodeID: content.NodeID, Architecture: arch, Key: "rust.symbols", Value: value,
				EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect,
				Qualifiers: map[string]string{"mangling": "rustc-v0-or-legacy"},
			}) == "" {
				graph.MarkWorkOmitted()
			}
		} else {
			graph.MarkWorkOmitted()
		}
		graph.AddCoverage(behavior.Coverage{
			NodeID: content.NodeID, AnalysisArea: "macho-rust-symbols/" + arch, Status: "analyzed",
			Detail: fmt.Sprintf("bounded Rust symbol enrichment recovered %d exact demangled function identities (%d v0, %d legacy; %d runtime/compiler, %d standard-library, %d other); non-runtime identity does not establish application ownership", total, summary.v0, summary.legacy, summary.runtime, summary.standard, summary.other),
		})
		if summary.displayTruncated > 0 {
			addPartialCoverageOnce(graph, content.NodeID, "macho-rust-symbol-display/"+arch, fmt.Sprintf("%d Rust function display names reached the %d-byte demangling output cap; exact raw linker symbols were retained", summary.displayTruncated, 1<<maxMachOSymbolDemangleOutputPower))
		}
	}
	if summary.inputLimited > 0 {
		addPartialCoverageOnce(graph, content.NodeID, "macho-rust-symbol-input/"+arch, fmt.Sprintf("%d Rust v0-prefixed function symbols exceeded the %d-byte demangling input cap and remained raw generic symbol identities", summary.inputLimited, maxMachOSymbolDemangleInputBytes))
	}
}
