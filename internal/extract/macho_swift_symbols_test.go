package extract

import (
	"bytes"
	"debug/macho"
	"strings"
	"testing"
)

func TestMachOSwiftSymbolInfo(t *testing.T) {
	tests := []struct {
		name, symbol, module, mangling, origin string
	}{
		{"stable app module", "$s3GUI8StartJobC4mainyyF", "GUI", "stable", "swift-other"},
		{"stable standard library", "$ss25_unimplementedInitializerys5NeverOyF", "Swift", "stable", "swift-standard-library"},
		{"stable Objective-C context", "$sSo8NSStringC", "ObjectiveC", "stable", "swift-runtime-compiler"},
		{"stable Clang importer", "$sSC3FooV", "ClangImporter", "stable", "swift-runtime-compiler"},
		{"Swift 4.2", "$S4Demo3runyyF", "Demo", "swift-4.2", "swift-other"},
		{"embedded Swift", "$e4Demo3runyyF", "Demo", "embedded", "swift-other"},
		{"Swift 4.0", "_T04Demo3runyyF", "Demo", "swift-4.0", "swift-other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := machoSwiftSymbolInfo(test.symbol)
			if !ok || got.module != test.module || got.mangling != test.mangling || got.origin != test.origin {
				t.Fatalf("machoSwiftSymbolInfo(%q) = %#v, %t", test.symbol, got, ok)
			}
		})
	}
}

func TestMachOSwiftSymbolInfoRejectsLookalikesMalformedAndBudget(t *testing.T) {
	for _, symbol := range []string{
		"$s", "$s3GUI", "$s03GUI3runyyF", "$s999999GUI3runyyF", "$s3GU!3runyyF",
		"$s3GUI\x013runyyF", "$s3GUI3runyyF!", "$s" + strings.Repeat("A", maxMachOSymbolDemangleInputBytes),
		"_$s3GUI3runyyF", "_ZN3GUI3runEv", "plain_c_symbol",
	} {
		if got, ok := machoSwiftSymbolInfo(symbol); ok {
			t.Fatalf("machoSwiftSymbolInfo(%q) unexpectedly accepted %#v", symbol, got)
		}
	}
}

func TestMachOSwiftFunctionRangesRetainCanonicalRawIdentity(t *testing.T) {
	text := testMachOSection("__text", 0x1000, bytes.Repeat([]byte{0x90}, 0x30))
	text.Seg = "__TEXT"
	file := &macho.File{Symtab: &macho.Symtab{Syms: []macho.Symbol{
		{Name: "_$s4Demo3runyyF", Type: 0x0e, Sect: 1, Value: 0x1000},
		{Name: "_plain_c", Type: 0x0e, Sect: 1, Value: 0x1010},
	}}}
	functions, _, _ := functionRangesBounded(file, text, 1, nil)
	if len(functions) != 2 {
		t.Fatalf("function ranges = %#v", functions)
	}
	if functions[0].Name != "$s4Demo3runyyF" || functions[0].DisplayName != "" || functions[0].Language != "swift" || functions[0].Module != "Demo" || functions[0].Metadata != "swift-other" {
		t.Fatalf("Swift function identity = %#v", functions[0])
	}
	if functions[1].Name != "plain_c" || functions[1].Language != "" || functions[1].Metadata != "macho-symbol" {
		t.Fatalf("benign C function was reclassified: %#v", functions[1])
	}
}

func TestSummarizeSwiftFunctions(t *testing.T) {
	summary := summarizeSwiftFunctions([]machoFunction{
		{Language: "swift", Mangling: "stable", Metadata: "swift-runtime-compiler"},
		{Language: "swift", Mangling: "swift-4.2", Metadata: "swift-standard-library"},
		{Language: "swift", Mangling: "embedded", Metadata: "swift-other"},
		{Language: "swift", Mangling: "swift-4.0", SwiftSymbolInputLimited: true},
	})
	if summary.stable != 1 || summary.swift42 != 1 || summary.embedded != 1 || summary.swift40 != 1 || summary.runtime != 1 || summary.standard != 1 || summary.other != 1 || summary.inputLimited != 1 {
		t.Fatalf("summarizeSwiftFunctions = %#v", summary)
	}
}
