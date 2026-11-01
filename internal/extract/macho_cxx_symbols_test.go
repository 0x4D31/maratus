package extract

import (
	"bytes"
	"debug/macho"
	"strings"
	"testing"
)

func TestMachOCXXSymbolInfo(t *testing.T) {
	tests := []struct {
		name, symbol, contains, module, origin string
	}{
		{"libcxx", "_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi", "std::__1::vector", "std", "cxx-standard-library"},
		{"cxx abi", "_ZN10__cxxabiv117__class_type_infoD1Ev", "__cxxabiv1::__class_type_info", "__cxxabiv1", "cxx-runtime-compiler"},
		{"other", "_ZN10appkitdemo3runEv", "appkitdemo::run", "appkitdemo", "cxx-other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := machoCXXSymbolInfo(test.symbol)
			if !ok || !strings.Contains(got.display, test.contains) || got.module != test.module || got.origin != test.origin {
				t.Fatalf("machoCXXSymbolInfo(%q) = %#v, %t", test.symbol, got, ok)
			}
		})
	}
}

func TestMachOCXXSymbolInfoRejectsRustMalformedAndBudget(t *testing.T) {
	for _, symbol := range []string{
		"_ZN3std3sys3pal4unix7process13process_inner71_$LT$impl$u20$std..sys..pal..unix..process..process_common..Command$GT$7do_exec17h0ca29777b02c6652E",
		"_ZN3foo", "plain_c_symbol", "_Z" + strings.Repeat("A", maxMachOSymbolDemangleInputBytes),
	} {
		if got, ok := machoCXXSymbolInfo(symbol); ok {
			t.Fatalf("machoCXXSymbolInfo(%q) unexpectedly accepted %#v", symbol, got)
		}
	}
}

func TestSummarizeCXXFunctions(t *testing.T) {
	summary := summarizeCXXFunctions([]machoFunction{
		{Language: "c++", Metadata: "cxx-runtime-compiler"},
		{Language: "c++", Metadata: "cxx-standard-library", DisplayTruncated: true},
		{Language: "c++", Metadata: "cxx-other"},
		{Language: "c++", Metadata: "macho-symbol", CXXSymbolInputLimited: true},
	})
	if summary.runtime != 1 || summary.standard != 1 || summary.other != 1 || summary.displayTruncated != 1 || summary.inputLimited != 1 {
		t.Fatalf("summarizeCXXFunctions = %#v", summary)
	}
}

func TestMachOCXXFunctionRangesRetainCanonicalRawIdentity(t *testing.T) {
	text := testMachOSection("__text", 0x1000, bytes.Repeat([]byte{0x90}, 0x30))
	text.Seg = "__TEXT"
	file := &macho.File{Symtab: &macho.Symtab{Syms: []macho.Symbol{
		{Name: "__ZN4demo3runEv", Type: 0x0e, Sect: 1, Value: 0x1000},
		{Name: "_plain_c", Type: 0x0e, Sect: 1, Value: 0x1010},
	}}}
	functions, _, _ := functionRangesBounded(file, text, 1, nil)
	if len(functions) != 2 {
		t.Fatalf("function ranges = %#v", functions)
	}
	if functions[0].Name != "_ZN4demo3runEv" || functions[0].DisplayName != "demo::run" || functions[0].Language != "c++" || functions[0].Metadata != "cxx-other" {
		t.Fatalf("C++ function identity = %#v", functions[0])
	}
	if functions[1].Name != "plain_c" || functions[1].DisplayName != "" || functions[1].Language != "" || functions[1].Metadata != "macho-symbol" {
		t.Fatalf("benign C function was reclassified: %#v", functions[1])
	}
}
