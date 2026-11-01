package extract

import (
	"strings"
	"testing"
)

func TestMachORustSymbolInfoLegacyAndV0(t *testing.T) {
	tests := []struct {
		name     string
		symbol   string
		contains string
		module   string
		origin   string
		mangling string
	}{
		{
			name:     "legacy standard library",
			symbol:   "_ZN3std3sys3pal4unix7process13process_inner71_$LT$impl$u20$std..sys..pal..unix..process..process_common..Command$GT$7do_exec17h0ca29777b02c6652E",
			contains: "std::sys::pal::unix::process::process_inner", module: "std",
			origin: "rust-standard-library", mangling: "legacy",
		},
		{
			name:     "v0 non-runtime crate",
			symbol:   "_RNvCskwGfYPst2Cb_3foo16example_function",
			contains: "foo::example_function", module: "foo",
			origin: "rust-other", mangling: "v0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := machoRustSymbolInfo(test.symbol)
			if !ok {
				t.Fatalf("machoRustSymbolInfo(%q) was not recognized", test.symbol)
			}
			if !strings.Contains(got.display, test.contains) || got.module != test.module || got.origin != test.origin || got.mangling != test.mangling {
				t.Fatalf("machoRustSymbolInfo(%q) = %#v", test.symbol, got)
			}
		})
	}
}

func TestMachORustSymbolInfoRejectsLookalikesMalformedAndBudget(t *testing.T) {
	for _, symbol := range []string{
		"_ZN3foo3barEv",                   // ordinary Itanium C++
		"_ZN3foo3bar17h0000000000000000E", // Rust-shaped low-diversity C++ component
		"_RNvC3foo",                       // malformed v0 path
		"_R" + strings.Repeat("A", maxMachOSymbolDemangleInputBytes),
	} {
		if got, ok := machoRustSymbolInfo(symbol); ok {
			t.Fatalf("machoRustSymbolInfo(%q) unexpectedly accepted %#v", symbol, got)
		}
	}
}

func TestMachORustFunctionQualifiersPreserveRawSymbol(t *testing.T) {
	function := machoFunction{
		Name: "_RNvC4demo3run", DisplayName: "demo::run", Language: "rust", Module: "demo",
		Mangling: "v0", Metadata: "rust-other", DisplayTruncated: true,
	}
	qualifiers := machoFunctionQualifiers(function, map[string]string{"api": "open"})
	want := map[string]string{
		"api": "open", "function_origin": "rust-other", "function_language": "rust",
		"function_module": "demo", "function_display": "demo::run", "function_mangling": "v0",
		"function_display_truncated": "true",
	}
	for key, value := range want {
		if qualifiers[key] != value {
			t.Fatalf("qualifiers[%q] = %q, want %q: %#v", key, qualifiers[key], value, qualifiers)
		}
	}
}

func TestSummarizeRustFunctions(t *testing.T) {
	summary := summarizeRustFunctions([]machoFunction{
		{Metadata: "rust-runtime-compiler", Mangling: "legacy"}, {Metadata: "rust-standard-library", Mangling: "v0"},
		{Metadata: "rust-other", Mangling: "legacy", DisplayTruncated: true}, {Metadata: "macho-symbol", Mangling: "v0", RustSymbolInputLimited: true},
	})
	if summary.runtime != 1 || summary.standard != 1 || summary.other != 1 || summary.v0 != 1 || summary.legacy != 2 || summary.displayTruncated != 1 || summary.inputLimited != 1 {
		t.Fatalf("summarizeRustFunctions = %#v", summary)
	}
}

func TestGenericRustStdlibProcessWrapperDemangled(t *testing.T) {
	function := machoFunction{
		Name:        "_ZN3std_fake17h1234567890abcdefE",
		DisplayName: "std::sys::pal::unix::process::process_inner::<impl std::sys::pal::unix::process::process_common::Command>::do_exec",
		Metadata:    "rust-standard-library",
	}
	if !genericRustStdlibProcessWrapper(function, "execvp") {
		t.Fatal("demangled exact Rust stdlib process wrapper was not recognized")
	}
	function.Metadata = "rust-other"
	if genericRustStdlibProcessWrapper(function, "execvp") {
		t.Fatal("non-stdlib lookalike was recognized")
	}
}
