package extract

import (
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

func TestGoPCLNFunctionsFromDataRecoversExactNamesAndRuntimeClass(t *testing.T) {
	data := syntheticGo120PCLN(t, 0x1000)
	functions, runtimeCount, standardCount, detail, ok := goPCLNFunctionsFromData(data, 0x1000, 0x1100)
	if !ok || detail != "" {
		t.Fatalf("parse = ok %v detail %q", ok, detail)
	}
	if len(functions) != 2 || runtimeCount != 1 || standardCount != 0 {
		t.Fatalf("functions = %#v runtime=%d standard=%d", functions, runtimeCount, standardCount)
	}
	if functions[0].Name != "main.main" || functions[0].Start != 0x1000 || functions[0].End != 0x1020 || functions[0].Metadata != "go-other" {
		t.Fatalf("first function = %#v", functions[0])
	}
	if functions[1].Name != "runtime.main" || functions[1].Metadata != "go-runtime-compiler" {
		t.Fatalf("second function = %#v", functions[1])
	}
}

func TestGoPCLNFunctionRangesEnrichesGenericBoundaries(t *testing.T) {
	pcln := syntheticGo120PCLN(t, 0x1000)
	image := make([]byte, 0x200+len(pcln))
	copy(image[0x200:], pcln)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: 0x1000, Size: 0x100, Offset: 0x100}}
	pclnSection := &macho.Section{SectionHeader: macho.SectionHeader{Seg: "__DATA_CONST", Name: "__gopclntab", Addr: 0x2000, Size: uint64(len(pcln)), Offset: 0x200}}
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{text, pclnSection}}

	functions, _, truncated, status := functionRangesBoundedDetailed(file, text, 1, image)
	if truncated || !status.present || !status.used || status.functions != 2 {
		t.Fatalf("status = %#v truncated=%v", status, truncated)
	}
	if len(functions) != 2 || functions[0].Name != "main.main" || functions[1].Name != "runtime.main" {
		t.Fatalf("enriched functions = %#v", functions)
	}
	if functions[1].End != 0x1040 {
		t.Fatalf("exact pclntab end was expanded into padding: %#v", functions[1])
	}
}

func TestGoPCLNFunctionsRejectsMalformedAndBudgetCases(t *testing.T) {
	if _, _, _, detail, ok := goPCLNFunctionsFromData(syntheticGo120PCLN(t, 0x1000), 0x1000, 0x1100, binary.BigEndian); ok || !strings.Contains(detail, "byte order") {
		t.Fatalf("byte-order mismatch = ok %v detail %q", ok, detail)
	}
	tests := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{name: "function count", mutate: func(data []byte) { binary.LittleEndian.PutUint64(data[8:16], maxGoPCLNFunctions+1) }, want: "function count"},
		{name: "text base", mutate: func(data []byte) { binary.LittleEndian.PutUint64(data[24:32], 0x5000) }, want: "text base"},
		{name: "offset order", mutate: func(data []byte) { binary.LittleEndian.PutUint64(data[40:48], 64) }, want: "offsets"},
		{name: "function extent", mutate: func(data []byte) { binary.LittleEndian.PutUint32(data[128+16:128+20], 0x200) }, want: "out-of-range"},
		{name: "name terminator", mutate: func(data []byte) {
			for index := 72; index < 128; index++ {
				if data[index] == 0 {
					data[index] = 'x'
				}
			}
		}, want: "name"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := syntheticGo120PCLN(t, 0x1000)
			test.mutate(data)
			_, _, _, detail, ok := goPCLNFunctionsFromData(data, 0x1000, 0x1100)
			if ok || !strings.Contains(detail, test.want) {
				t.Fatalf("parse = ok %v detail %q, want %q", ok, detail, test.want)
			}
		})
	}
}

func TestGoCompilerOrRuntimeFunctionUsesExactPrefixes(t *testing.T) {
	for _, name := range []string{"runtime.main", "internal/abi.Kind.String", "internal/chacha8rand.(*State).Refill"} {
		if !goCompilerOrRuntimeFunction(name) {
			t.Fatalf("runtime/compiler function %q was not classified", name)
		}
	}
	for _, name := range []string{"sync.(*Mutex).Lock", "syscall.Exec", "net/http.(*Client).Do", "crypto.(*Hash).String", "slices.Sort"} {
		if !goStandardLibraryFunction(name) {
			t.Fatalf("standard-library function %q was not classified", name)
		}
	}
	for _, name := range []string{"main.main", "example.com/runtime.main", "example.com/sync.Work", "example.com/internal/collect.Run"} {
		if goCompilerOrRuntimeFunction(name) {
			t.Fatalf("application function %q was classified as runtime", name)
		}
	}
}

func syntheticGo120PCLN(t *testing.T, textStart uint64) []byte {
	t.Helper()
	const (
		nameOffset = 72
		auxOffset  = 96
		funcOffset = 128
	)
	data := make([]byte, 180)
	binary.LittleEndian.PutUint32(data[0:4], 0xfffffff1)
	data[6], data[7] = 1, 8
	words := []uint64{2, 0, textStart, nameOffset, auxOffset, auxOffset, auxOffset, funcOffset}
	for index, value := range words {
		binary.LittleEndian.PutUint64(data[8+index*8:16+index*8], value)
	}
	copy(data[nameOffset:], []byte("main.main\x00runtime.main\x00"))

	// Two functab entries followed by the terminal PC offset.
	binary.LittleEndian.PutUint32(data[funcOffset:funcOffset+4], 0)
	binary.LittleEndian.PutUint32(data[funcOffset+4:funcOffset+8], 20)
	binary.LittleEndian.PutUint32(data[funcOffset+8:funcOffset+12], 0x20)
	binary.LittleEndian.PutUint32(data[funcOffset+12:funcOffset+16], 36)
	binary.LittleEndian.PutUint32(data[funcOffset+16:funcOffset+20], 0x40)

	// Minimal _func records: entry offset, name offset, args, deferreturn.
	binary.LittleEndian.PutUint32(data[funcOffset+20:funcOffset+24], 0)
	binary.LittleEndian.PutUint32(data[funcOffset+24:funcOffset+28], 0)
	binary.LittleEndian.PutUint32(data[funcOffset+36:funcOffset+40], 0x20)
	binary.LittleEndian.PutUint32(data[funcOffset+40:funcOffset+44], uint32(len("main.main")+1))
	return data
}
