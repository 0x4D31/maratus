package artifact

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMachOCPUDisplayNames(t *testing.T) {
	tests := []struct {
		name string
		cpu  macho.Cpu
		sub  uint32
		want string
	}{
		{name: "x86 all", cpu: macho.CpuAmd64, sub: 3, want: "x86_64"},
		{name: "i386 all", cpu: macho.Cpu386, sub: 3, want: "i386"},
		{name: "x86_64h", cpu: macho.CpuAmd64, sub: 8, want: "x86_64h"},
		{name: "arm64 all", cpu: macho.CpuArm64, sub: 0, want: "arm64"},
		{name: "arm64e", cpu: macho.CpuArm64, sub: 0x80000002, want: "arm64e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := machoCPU(tt.cpu, tt.sub); got != tt.want {
				t.Fatalf("machoCPU() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectFatMachO64Magic(t *testing.T) {
	tests := [][]byte{
		{0xca, 0xfe, 0xba, 0xbf},
		{0xbf, 0xba, 0xfe, 0xca},
	}
	for _, data := range tests {
		kind, media := Detect("fat64", data, true)
		if kind != "macho-fat" || media != "application/x-mach-binary" {
			t.Fatalf("Detect(% x) = %s %s, want macho-fat application/x-mach-binary", data, kind, media)
		}
	}
}

func TestMachOPreflightAllowsAllFatFormats(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
		is64  bool
	}{
		{name: "fat32-big-endian", order: binary.BigEndian},
		{name: "fat32-little-endian", order: binary.LittleEndian},
		{name: "fat64-big-endian", order: binary.BigEndian, is64: true},
		{name: "fat64-little-endian", order: binary.LittleEndian, is64: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner := testThinMachO()
			data := append(testFatMachO(test.order, test.is64, inner), []byte("outer-overlay")...)
			isFat, slices, err := PreflightMachOSlices(data)
			if !isFat || err != nil {
				t.Fatalf("PreflightMachOSlices() = %v, %#v, %v; want fat success", isFat, slices, err)
			}
			if len(slices) != 1 || slices[0].CPU != macho.CpuArm64 || slices[0].SubCPU != 0 {
				t.Fatalf("fat slice descriptors = %#v; want one arm64 image", slices)
			}
			image, ok := slices[0].Bytes(data)
			if !ok || !bytes.Equal(image, inner) {
				t.Fatalf("fat slice bytes include an outer overlay or differ from inner image: ok=%v len=%d", ok, len(image))
			}
			if got := architectures(data); len(got) != 1 || got[0] != "arm64" {
				t.Fatalf("architectures() = %#v; want [arm64]", got)
			}
		})
	}
}

func TestMachOPreflightRejectsMalformedFatLayout(t *testing.T) {
	t.Run("slice overlaps table", func(t *testing.T) {
		data := testFatMachO(binary.BigEndian, false, testThinMachO())
		binary.BigEndian.PutUint32(data[16:20], 8)
		assertFatPreflightError(t, data, "overlaps the fat header")
	})

	t.Run("misaligned slice", func(t *testing.T) {
		data := testFatMachO(binary.LittleEndian, true, testThinMachO())
		binary.LittleEndian.PutUint32(data[32:36], 4)
		assertFatPreflightError(t, data, "is not aligned")
	})

	t.Run("alignment shift overflow", func(t *testing.T) {
		data := testFatMachO(binary.BigEndian, true, testThinMachO())
		binary.BigEndian.PutUint32(data[32:36], 64)
		assertFatPreflightError(t, data, "alignment exponent")
	})

	t.Run("fat64 range overflow", func(t *testing.T) {
		data := testFatMachO(binary.LittleEndian, true, testThinMachO())
		binary.LittleEndian.PutUint64(data[16:24], ^uint64(0)-1)
		binary.LittleEndian.PutUint64(data[24:32], 4)
		assertFatPreflightError(t, data, "outside file data")
	})

	t.Run("fat64 reserved field", func(t *testing.T) {
		data := testFatMachO(binary.BigEndian, true, testThinMachO())
		binary.BigEndian.PutUint32(data[36:40], 1)
		assertFatPreflightError(t, data, "non-zero reserved field")
	})

	t.Run("overlapping slices", func(t *testing.T) {
		first := testThinMachO()
		second := testThinMachO()
		binary.LittleEndian.PutUint32(second[4:8], uint32(macho.CpuAmd64))
		binary.LittleEndian.PutUint32(second[8:12], 3)
		data := testFatMachO(binary.BigEndian, false, first, second)
		firstOffset := binary.BigEndian.Uint32(data[16:20])
		binary.BigEndian.PutUint32(data[36:40], firstOffset)
		assertFatPreflightError(t, data, "overlaps architecture 0")
	})

	t.Run("duplicate architecture", func(t *testing.T) {
		data := testFatMachO(binary.BigEndian, false, testThinMachO(), testThinMachO())
		assertFatPreflightError(t, data, "duplicates CPU/subtype")
	})

	t.Run("inconsistent file type", func(t *testing.T) {
		first := testThinMachO()
		second := testThinMachO()
		binary.LittleEndian.PutUint32(second[4:8], uint32(macho.CpuAmd64))
		binary.LittleEndian.PutUint32(second[8:12], 3)
		binary.LittleEndian.PutUint32(second[12:16], uint32(macho.TypeDylib))
		data := testFatMachO(binary.LittleEndian, true, first, second)
		assertFatPreflightError(t, data, "file type")
	})
}

func TestMachOPreflightAllowsAlignedAdjacentFatSlices(t *testing.T) {
	first := testThinMachO()
	second := testThinMachO()
	binary.LittleEndian.PutUint32(second[4:8], uint32(macho.CpuAmd64))
	binary.LittleEndian.PutUint32(second[8:12], 3)
	data := testFatMachO(binary.LittleEndian, true, first, second)
	binary.LittleEndian.PutUint32(data[32:36], 3)
	binary.LittleEndian.PutUint32(data[64:68], 3)

	if isFat, err := PreflightMachO(data); !isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want adjacent fat-slice success", isFat, err)
	}
	if got := architectures(data); len(got) != 2 || got[0] != "arm64" || got[1] != "x86_64" {
		t.Fatalf("architectures() = %#v; want [arm64 x86_64]", got)
	}
}

func TestParseFatMachOArchitecturesRejectsInvalidFormatDescriptor(t *testing.T) {
	data := make([]byte, 8)
	for _, format := range []fatMachOFormat{
		{},
		{order: binary.BigEndian},
		{order: binary.BigEndian, archBytes: fatMachOArch64HeaderSize},
		{order: binary.BigEndian, archBytes: fatMachOArchHeaderSize, is64: true},
	} {
		if _, err := parseFatMachOArchitectures(data, format); err == nil || !strings.Contains(err.Error(), "format descriptor") {
			t.Fatalf("parseFatMachOArchitectures(%#v) error = %v; want safe format rejection", format, err)
		}
	}
}

func TestMachOPreflightRejectsFatArchitectureFloodBeforeParsing(t *testing.T) {
	for _, test := range []struct {
		name  string
		order binary.ByteOrder
		magic uint32
	}{
		{name: "fat32-big-endian", order: binary.BigEndian, magic: macho.MagicFat},
		{name: "fat32-little-endian", order: binary.LittleEndian, magic: macho.MagicFat},
		{name: "fat64-big-endian", order: binary.BigEndian, magic: fatMachOMagic64},
		{name: "fat64-little-endian", order: binary.LittleEndian, magic: fatMachOMagic64},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, 8)
			test.order.PutUint32(data[0:4], test.magic)
			test.order.PutUint32(data[4:8], maxMachOFatArchitectures+1)
			assertFatPreflightError(t, data, "architecture count")
		})
	}
}

func TestMachOPreflightRejectsThinAllocationCounts(t *testing.T) {
	tests := []struct {
		name    string
		command []byte
		mutate  func([]byte)
		want    string
	}{
		{
			name:    "symbols",
			command: testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize),
			mutate: func(command []byte) {
				binary.LittleEndian.PutUint32(command[12:16], maxMachOSymbols+1)
			},
			want: "symbol count",
		},
		{
			name:    "indirect symbols",
			command: testMachOLoadCommand(macho.LoadCmdDysymtab, dysymtabCommandSize),
			mutate: func(command []byte) {
				binary.LittleEndian.PutUint32(command[60:64], maxMachOIndirectSymbols+1)
			},
			want: "indirect symbol count",
		},
		{
			name:    "relocations",
			command: testMachOSegment64Command(1),
			mutate: func(command []byte) {
				binary.LittleEndian.PutUint32(command[segment64CommandSize+60:segment64CommandSize+64], maxMachORelocations+1)
			},
			want: "relocation count",
		},
		{
			name:    "sections",
			command: testMachOSegment64Command(maxMachOSections + 1),
			mutate:  func([]byte) {},
			want:    "section count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mutate(tt.command)
			_, err := PreflightMachO(testThinMachO(tt.command))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PreflightMachO() error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestMachOPreflightValidatesEncryptionCommands(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, test := range []struct {
			name           string
			cmd            uint32
			size           int
			offset, length uint32
			want           string
		}{
			{"32 exact", lcEncryptionInfo, 20, 0, 52, ""},
			{"32 truncated", lcEncryptionInfo, 16, 0, 0, "truncated"},
			{"64 exact", lcEncryptionInfo64, 24, 0, 56, ""},
			{"64 missing padding", lcEncryptionInfo64, 20, 0, 0, "truncated"},
			{"range beyond file", lcEncryptionInfo64, 24, 1, 56, "outside file data"},
			{"range overflow", lcEncryptionInfo64, 24, ^uint32(0), 2, "outside file data"},
		} {
			t.Run(order.String()+"/"+test.name, func(t *testing.T) {
				data := make([]byte, 32+test.size)
				for index, value := range []uint32{macho.Magic64, uint32(macho.CpuArm64), 0, uint32(macho.TypeExec), 1, uint32(test.size), 0, 0, test.cmd, uint32(test.size), test.offset, test.length} {
					order.PutUint32(data[index*4:index*4+4], value)
				}
				_, err := PreflightMachO(data)
				if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
					t.Fatalf("PreflightMachO() error = %v; want %q", err, test.want)
				}
			})
		}
	}
}

func TestMachOPreflightAllowsMinimalThinFile(t *testing.T) {
	data := testThinMachO()
	isFat, err := PreflightMachO(data)
	if isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want thin success", isFat, err)
	}
	if got := architectures(data); len(got) != 1 || got[0] != "arm64" {
		t.Fatalf("architectures() = %#v; want [arm64]", got)
	}
}

func TestElectronLoaderRequiresCanonicalFrameworkDylibPath(t *testing.T) {
	command := testMachOLoadCommand(macho.LoadCmd(lcLoadDylib), 96)
	binary.LittleEndian.PutUint32(command[8:12], 24)
	copy(command[24:], []byte("@rpath/NotElectron Framework.framework/Electron Framework\x00"))
	loader := testThinMachO(testMachOLoadCommand(macho.LoadCmdSegment64, segment64CommandSize), command)
	if machoLoadsElectronFrameworkBytes(loader) {
		t.Fatal("noncanonical dylib path was accepted as Electron Framework linkage")
	}
}

func TestMachOPreflightRejectsFatHeaderSliceCPUDisagreement(t *testing.T) {
	inner := testThinMachO()
	const sliceOffset = 28
	data := make([]byte, sliceOffset, sliceOffset+len(inner))
	binary.BigEndian.PutUint32(data[0:4], macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:8], 1)
	binary.BigEndian.PutUint32(data[8:12], uint32(macho.CpuAmd64))
	binary.BigEndian.PutUint32(data[12:16], 3)
	binary.BigEndian.PutUint32(data[16:20], sliceOffset)
	binary.BigEndian.PutUint32(data[20:24], uint32(len(inner)))
	data = append(data, inner...)

	isFat, err := PreflightMachO(data)
	if !isFat || err == nil || !strings.Contains(err.Error(), "disagrees with inner slice") {
		t.Fatalf("PreflightMachO() = %v, %v; want fat CPU mismatch rejection", isFat, err)
	}
	if got := architectures(data); got != nil {
		t.Fatalf("architectures() labeled rejected fat input: %#v", got)
	}
}

func TestMachOPreflightAllowsMatchingFatHeaderAndSliceCPU(t *testing.T) {
	inner := testThinMachO()
	const sliceOffset = 28
	data := make([]byte, sliceOffset, sliceOffset+len(inner))
	binary.BigEndian.PutUint32(data[0:4], macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:8], 1)
	binary.BigEndian.PutUint32(data[8:12], uint32(macho.CpuArm64))
	binary.BigEndian.PutUint32(data[12:16], 0)
	binary.BigEndian.PutUint32(data[16:20], sliceOffset)
	binary.BigEndian.PutUint32(data[20:24], uint32(len(inner)))
	data = append(data, inner...)

	if isFat, err := PreflightMachO(data); !isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want matching fat success", isFat, err)
	}
	if got := architectures(data); len(got) != 1 || got[0] != "arm64" {
		t.Fatalf("architectures() = %#v; want [arm64]", got)
	}
}

func TestMachOPreflightRejectsOverflowedUndefinedSymbolRange(t *testing.T) {
	symtab := testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize)
	dysymtab := testMachOLoadCommand(macho.LoadCmdDysymtab, dysymtabCommandSize)
	symoff := thinMachOHeader64Size + len(symtab) + len(dysymtab)
	stroff := symoff + 16
	binary.LittleEndian.PutUint32(symtab[8:12], uint32(symoff))
	binary.LittleEndian.PutUint32(symtab[12:16], 1)
	binary.LittleEndian.PutUint32(symtab[16:20], uint32(stroff))
	binary.LittleEndian.PutUint32(symtab[20:24], 1)
	binary.LittleEndian.PutUint32(dysymtab[24:28], 1)
	binary.LittleEndian.PutUint32(dysymtab[28:32], ^uint32(0))
	data := append(testThinMachO(symtab, dysymtab), make([]byte, 17)...)

	_, err := PreflightMachO(data)
	if err == nil || !strings.Contains(err.Error(), "undefined symbol range") {
		t.Fatalf("PreflightMachO() error = %v; want overflow-safe undefined range rejection", err)
	}
}

func TestMachOPreflightValidatesDataInCodeExtent(t *testing.T) {
	command := testMachOLoadCommand(macho.LoadCmd(lcDataInCode), linkeditDataCommandSize)
	binary.LittleEndian.PutUint32(command[8:12], ^uint32(0))
	binary.LittleEndian.PutUint32(command[12:16], dataInCodeEntrySize)
	if _, err := PreflightMachO(testThinMachO(command)); err == nil || !strings.Contains(err.Error(), "data-in-code records") {
		t.Fatalf("PreflightMachO() error = %v; want data-in-code extent rejection", err)
	}

	command = testMachOLoadCommand(macho.LoadCmd(lcDataInCode), linkeditDataCommandSize)
	tableOffset := thinMachOHeader64Size + len(command)
	binary.LittleEndian.PutUint32(command[8:12], uint32(tableOffset))
	binary.LittleEndian.PutUint32(command[12:16], dataInCodeEntrySize)
	data := append(testThinMachO(command), make([]byte, dataInCodeEntrySize)...)
	binary.LittleEndian.PutUint32(data[tableOffset:tableOffset+4], ^uint32(0))
	binary.LittleEndian.PutUint16(data[tableOffset+4:tableOffset+6], 2)
	if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "data-in-code entry") {
		t.Fatalf("PreflightMachO() error = %v; want data-in-code entry rejection", err)
	}
}

func TestMachOPreflightAggregatesRepeatedCommands(t *testing.T) {
	first := testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize)
	second := testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize)
	const symbolsPerCommand = maxMachOSymbols/2 + 1
	symbolOffset := thinMachOHeader64Size + len(first) + len(second)
	stringOffset := symbolOffset + symbolsPerCommand*16
	for _, command := range [][]byte{first, second} {
		binary.LittleEndian.PutUint32(command[8:12], uint32(symbolOffset))
		binary.LittleEndian.PutUint32(command[12:16], symbolsPerCommand)
		binary.LittleEndian.PutUint32(command[16:20], uint32(stringOffset))
		binary.LittleEndian.PutUint32(command[20:24], 1)
	}
	data := testThinMachO(first, second)
	data = append(data, make([]byte, symbolsPerCommand*16+1)...)

	_, err := PreflightMachO(data)
	if err == nil || !strings.Contains(err.Error(), "aggregate symbol count") {
		t.Fatalf("PreflightMachO() error = %v; want aggregate symbol rejection", err)
	}
}

func TestMachOPreflightRejectsLoadCommandFlood(t *testing.T) {
	data := testThinMachO()
	binary.LittleEndian.PutUint32(data[16:20], maxMachOLoadCommands+1)

	_, err := PreflightMachO(data)
	if err == nil || !strings.Contains(err.Error(), "load command count") {
		t.Fatalf("PreflightMachO() error = %v; want load-command rejection", err)
	}
}

func TestMachOPreflightRejectsDuplicateLongSymbolNameAmplification(t *testing.T) {
	const (
		nsyms   = 1000
		strsize = 64 << 10
		symsize = 16
	)
	command := testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize)
	symoff := thinMachOHeader64Size + len(command)
	stroff := symoff + nsyms*symsize
	binary.LittleEndian.PutUint32(command[8:12], uint32(symoff))
	binary.LittleEndian.PutUint32(command[12:16], nsyms)
	binary.LittleEndian.PutUint32(command[16:20], uint32(stroff))
	binary.LittleEndian.PutUint32(command[20:24], strsize)
	data := testThinMachO(command)
	data = append(data, make([]byte, nsyms*symsize+strsize)...)
	for i := stroff; i < len(data); i++ {
		data[i] = 'A'
	}

	_, err := PreflightMachO(data)
	if err == nil || !strings.Contains(err.Error(), "decoded symbol name bytes") {
		t.Fatalf("PreflightMachO() error = %v; want decoded-name amplification rejection", err)
	}
}

func TestMachOPreflightValidatesSymbolTableExtentsAndStringIndexes(t *testing.T) {
	command := testMachOLoadCommand(macho.LoadCmdSymtab, symtabCommandSize)
	symoff := thinMachOHeader64Size + len(command)
	stroff := symoff + 16
	binary.LittleEndian.PutUint32(command[8:12], uint32(symoff))
	binary.LittleEndian.PutUint32(command[12:16], 1)
	binary.LittleEndian.PutUint32(command[16:20], uint32(stroff))
	binary.LittleEndian.PutUint32(command[20:24], 2)
	data := testThinMachO(command)
	data = append(data, make([]byte, 18)...)
	data[stroff] = 'x'
	data[stroff+1] = 0

	if _, err := PreflightMachO(data); err != nil {
		t.Fatalf("valid symbol table rejected: %v", err)
	}
	binary.LittleEndian.PutUint32(data[symoff:symoff+4], 2)
	if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "string index") {
		t.Fatalf("out-of-range string index error = %v", err)
	}
	binary.LittleEndian.PutUint32(data[symoff:symoff+4], 0)
	binary.LittleEndian.PutUint32(data[thinMachOHeader64Size+8:thinMachOHeader64Size+12], uint32(len(data)))
	if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "symbol records") {
		t.Fatalf("out-of-range symbol extent error = %v", err)
	}
}

func TestMachOPreflightRejectsOverlappingSectionAmplification(t *testing.T) {
	const (
		sectionCount = maxMachOSectionDataBytes/(1<<20) + 1
		sectionSize  = 1 << 20
	)
	command := testMachOSegment64Command(sectionCount)
	payloadOffset := thinMachOHeader64Size + len(command)
	setTestMachOSegment64Mapping(command, 0, sectionSize, uint64(payloadOffset), sectionSize)
	for i := 0; i < sectionCount; i++ {
		section := segment64CommandSize + i*section64HeaderSize
		binary.LittleEndian.PutUint64(command[section+40:section+48], sectionSize)
		binary.LittleEndian.PutUint32(command[section+48:section+52], uint32(payloadOffset))
	}
	data := testThinMachO(command)
	data = append(data, make([]byte, sectionSize)...)

	_, err := PreflightMachO(data)
	if err == nil || !strings.Contains(err.Error(), "aggregate section data bytes") {
		t.Fatalf("PreflightMachO() error = %v; want overlapping-section rejection", err)
	}
}

func TestMachOPreflightRejectsSectionAndRelocationExtentsOutsideFile(t *testing.T) {
	command := testMachOSegment64Command(1)
	section := segment64CommandSize
	binary.LittleEndian.PutUint64(command[section+40:section+48], 16)
	binary.LittleEndian.PutUint32(command[section+48:section+52], ^uint32(0))
	if _, err := PreflightMachO(testThinMachO(command)); err == nil || !strings.Contains(err.Error(), "data points outside") {
		t.Fatalf("out-of-range section extent error = %v", err)
	}

	binary.LittleEndian.PutUint64(command[section+40:section+48], 0)
	binary.LittleEndian.PutUint32(command[section+56:section+60], ^uint32(0))
	binary.LittleEndian.PutUint32(command[section+60:section+64], 1)
	if _, err := PreflightMachO(testThinMachO(command)); err == nil || !strings.Contains(err.Error(), "relocation records") {
		t.Fatalf("out-of-range relocation extent error = %v", err)
	}
}

func TestMachOPreflightRejectsAmbiguousFileBackedSectionVMRanges(t *testing.T) {
	for _, test := range []struct {
		name       string
		secondAddr uint64
	}{
		{name: "duplicate", secondAddr: 0x1000},
		{name: "partial overlap", secondAddr: 0x1008},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := testMachOSegment64Command(2)
			payloadOffset := thinMachOHeader64Size + len(command)
			setTestMachOSegment64Mapping(command, 0x1000, 32, uint64(payloadOffset), 32)
			setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), 0)
			setTestMachOSection64(command, 1, test.secondAddr, 16, uint32(payloadOffset)+uint32(test.secondAddr-0x1000), 0)
			data := append(testThinMachO(command), make([]byte, 32)...)

			if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "file-backed section virtual ranges overlap") {
				t.Fatalf("PreflightMachO() error = %v; want ambiguous section VM-range rejection", err)
			}
		})
	}
}

func TestMachOPreflightAllowsOverlappingNonFileBackedSectionVMRange(t *testing.T) {
	command := testMachOSegment64Command(2)
	payloadOffset := thinMachOHeader64Size + len(command)
	setTestMachOSegment64Mapping(command, 0x1000, 16, uint64(payloadOffset), 16)
	setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), 0)
	setTestMachOSection64(command, 1, 0x1000, 0x1000, ^uint32(0), 0x1) // S_ZEROFILL.
	data := append(testThinMachO(command), make([]byte, 16)...)

	if isFat, err := PreflightMachO(data); isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want zero-fill overlap success", isFat, err)
	}
}

func TestMachOPreflightAllowsObjectSectionAfterZeroFillGap(t *testing.T) {
	command := testMachOSegment64Command(3)
	payloadOffset := thinMachOHeader64Size + len(command)
	setTestMachOSegment64Mapping(command, 0, 24, uint64(payloadOffset), 16)
	setTestMachOSection64(command, 0, 0, 8, uint32(payloadOffset), 0)
	setTestMachOSection64(command, 1, 8, 8, 0, 0x1) // S_ZEROFILL.
	setTestMachOSection64(command, 2, 16, 8, uint32(payloadOffset+8), 0)
	data := append(testThinMachO(command), make([]byte, 16)...)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeObj))

	if isFat, err := PreflightMachO(data); isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want valid object zero-fill gap success", isFat, err)
	}
}

func TestMachOPreflightAllowsOnlyExactFileOnlyDWARFSegments(t *testing.T) {
	fixture := func(segmentName string, sectionFlags, initProt uint32) []byte {
		command := testMachOSegment64Command(1)
		copy(command[8:24], segmentName)
		section := segment64CommandSize
		copy(command[section+16:section+32], segmentName)
		payloadOffset := thinMachOHeader64Size + len(command)
		setTestMachOSegment64Mapping(command, 0x1000, 0, uint64(payloadOffset), 16)
		binary.LittleEndian.PutUint32(command[60:64], initProt)
		setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), sectionFlags)
		return append(testThinMachO(command), make([]byte, 16)...)
	}

	if isFat, err := PreflightMachO(fixture("__DWARF", 0x02000000, 0)); isFat || err != nil {
		t.Fatalf("file-only DWARF = %v, %v; want valid debug data", isFat, err)
	}
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "non-debug section", data: fixture("__DWARF", 0, 0), want: "lacks S_ATTR_DEBUG"},
		{name: "other segment", data: fixture("__DATA", 0x02000000, 0), want: "exceeds VM size"},
		{name: "mapped protection", data: fixture("__DWARF", 0x02000000, 1), want: "exceeds VM size"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PreflightMachO(test.data); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PreflightMachO() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestMachOPreflightRejectsOverlappingObjectSectionFileRanges(t *testing.T) {
	command := testMachOSegment64Command(2)
	payloadOffset := thinMachOHeader64Size + len(command)
	setTestMachOSegment64Mapping(command, 0, 32, uint64(payloadOffset), 32)
	setTestMachOSection64(command, 0, 0, 16, uint32(payloadOffset), 0)
	setTestMachOSection64(command, 1, 16, 16, uint32(payloadOffset+8), 0)
	data := append(testThinMachO(command), make([]byte, 32)...)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeObj))

	if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "file-backed section file ranges overlap") {
		t.Fatalf("PreflightMachO() error = %v; want object section file-range overlap rejection", err)
	}
}

func TestMachOPreflightRequiresSectionOwningSegmentName(t *testing.T) {
	command := testMachOSegment64Command(1)
	payloadOffset := thinMachOHeader64Size + len(command)
	copy(command[8:24], []byte("__DATA"))
	section := segment64CommandSize
	copy(command[section+16:section+32], []byte("__TEXT"))
	setTestMachOSegment64Mapping(command, 0x1000, 16, uint64(payloadOffset), 16)
	setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), 0)
	data := append(testThinMachO(command), make([]byte, 16)...)

	if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "segment name does not match its owning segment") {
		t.Fatalf("PreflightMachO() error = %v; want owning-segment name rejection", err)
	}
}

func TestMachOPreflightComparesOwningSegmentNamesAsCStrings(t *testing.T) {
	command := testMachOSegment64Command(1)
	payloadOffset := thinMachOHeader64Size + len(command)
	for index := 8; index < 24; index++ {
		command[index] = 'A'
	}
	copy(command[8:24], []byte("__TEXT\x00"))
	section := segment64CommandSize
	for index := section + 16; index < section+32; index++ {
		command[index] = 'B'
	}
	copy(command[section+16:section+32], []byte("__TEXT\x00"))
	setTestMachOSegment64Mapping(command, 0x1000, 16, uint64(payloadOffset), 16)
	setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), 0)
	data := append(testThinMachO(command), make([]byte, 16)...)

	if isFat, err := PreflightMachO(data); isFat || err != nil {
		t.Fatalf("PreflightMachO() = %v, %v; want equal C-string segment names accepted", isFat, err)
	}
}

func TestMachOPreflightRejectsOverflowingFileBackedVMRanges(t *testing.T) {
	t.Run("segment", func(t *testing.T) {
		command := testMachOSegment64Command(0)
		setTestMachOSegment64Mapping(command, ^uint64(0)-7, 16, 0, 16)
		if _, err := PreflightMachO(testThinMachO(command)); err == nil || !strings.Contains(err.Error(), "file-backed segment VM range overflows") {
			t.Fatalf("PreflightMachO() error = %v; want overflowing segment VM-range rejection", err)
		}
	})

	t.Run("section", func(t *testing.T) {
		command := testMachOSegment64Command(1)
		payloadOffset := thinMachOHeader64Size + len(command)
		setTestMachOSection64(command, 0, ^uint64(0)-7, 16, uint32(payloadOffset), 0)
		data := append(testThinMachO(command), make([]byte, 16)...)
		if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), "file-backed section virtual range overflows") {
			t.Fatalf("PreflightMachO() error = %v; want overflowing section VM-range rejection", err)
		}
	})
}

func TestMachOPreflightRequiresExactOwningSegmentMapping(t *testing.T) {
	for _, test := range []struct {
		name             string
		segmentVMSize    uint64
		segmentFileSize  uint64
		sectionVMAddr    uint64
		sectionFileDelta uint32
		want             string
	}{
		{name: "outside segment file range", segmentVMSize: 16, segmentFileSize: 16, sectionVMAddr: 0x1000, sectionFileDelta: 16, want: "outside its owning segment file range"},
		{name: "outside segment VM range", segmentVMSize: 16, segmentFileSize: 16, sectionVMAddr: 0x1010, sectionFileDelta: 0, want: "outside its owning segment VM range"},
		{name: "mismatched file and VM deltas", segmentVMSize: 32, segmentFileSize: 32, sectionVMAddr: 0x1004, sectionFileDelta: 8, want: "do not match its owning segment mapping"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := testMachOSegment64Command(1)
			payloadOffset := thinMachOHeader64Size + len(command)
			setTestMachOSegment64Mapping(command, 0x1000, test.segmentVMSize, uint64(payloadOffset), test.segmentFileSize)
			setTestMachOSection64(command, 0, test.sectionVMAddr, 8, uint32(payloadOffset)+test.sectionFileDelta, 0)
			data := append(testThinMachO(command), make([]byte, 32)...)

			if _, err := PreflightMachO(data); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PreflightMachO() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestMachOPreflightKeepsMappedRangesSliceLocal(t *testing.T) {
	mappedThin := func(cpu macho.Cpu, subCPU uint32) []byte {
		command := testMachOSegment64Command(1)
		payloadOffset := thinMachOHeader64Size + len(command)
		setTestMachOSegment64Mapping(command, 0x1000, 16, uint64(payloadOffset), 16)
		setTestMachOSection64(command, 0, 0x1000, 16, uint32(payloadOffset), 0)
		data := append(testThinMachO(command), make([]byte, 16)...)
		binary.LittleEndian.PutUint32(data[4:8], uint32(cpu))
		binary.LittleEndian.PutUint32(data[8:12], subCPU)
		return data
	}
	data := testFatMachO(
		binary.BigEndian,
		false,
		mappedThin(macho.CpuArm64, 0),
		mappedThin(macho.CpuAmd64, 3),
	)

	if isFat, slices, err := PreflightMachOSlices(data); !isFat || err != nil || len(slices) != 2 {
		t.Fatalf("PreflightMachOSlices() = %v, %#v, %v; want two independently mapped fat slices", isFat, slices, err)
	}
}

func TestMachOPreflightRejectsAmbiguousSegmentMappings(t *testing.T) {
	for _, test := range []struct {
		name       string
		firstVM    uint64
		firstFile  uint64
		secondVM   uint64
		secondFile uint64
		want       string
	}{
		{name: "duplicate file range", firstVM: 0x1000, firstFile: 0, secondVM: 0x2000, secondFile: 0, want: "segment file-offset ranges overlap"},
		{name: "partial file overlap", firstVM: 0x1000, firstFile: 0, secondVM: 0x2000, secondFile: 8, want: "segment file-offset ranges overlap"},
		{name: "duplicate VM range", firstVM: 0x1000, firstFile: 0, secondVM: 0x1000, secondFile: 16, want: "file-backed segment VM ranges overlap"},
		{name: "partial VM overlap", firstVM: 0x1000, firstFile: 0, secondVM: 0x1008, secondFile: 16, want: "file-backed segment VM ranges overlap"},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := testMachOSegment64Command(0)
			second := testMachOSegment64Command(0)
			setTestMachOSegment64Mapping(first, test.firstVM, 16, test.firstFile, 16)
			setTestMachOSegment64Mapping(second, test.secondVM, 16, test.secondFile, 16)

			if _, err := PreflightMachO(testThinMachO(first, second)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PreflightMachO() error = %v; want %q", err, test.want)
			}
		})
	}
}

func testThinMachO(commands ...[]byte) []byte {
	commandBytes := 0
	for _, command := range commands {
		commandBytes += len(command)
	}
	data := make([]byte, thinMachOHeader64Size, thinMachOHeader64Size+commandBytes)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(commands)))
	binary.LittleEndian.PutUint32(data[20:24], uint32(commandBytes))
	for _, command := range commands {
		data = append(data, command...)
	}
	return data
}

func testMachOLoadCommand(cmd macho.LoadCmd, size int) []byte {
	command := make([]byte, size)
	binary.LittleEndian.PutUint32(command[0:4], uint32(cmd))
	binary.LittleEndian.PutUint32(command[4:8], uint32(size))
	return command
}

func testMachOSegment64Command(nsect uint32) []byte {
	size := segment64CommandSize + int(nsect)*section64HeaderSize
	command := testMachOLoadCommand(macho.LoadCmdSegment64, size)
	binary.LittleEndian.PutUint32(command[64:68], nsect)
	return command
}

func setTestMachOSegment64Mapping(command []byte, vmAddr, vmSize, fileOffset, fileSize uint64) {
	binary.LittleEndian.PutUint64(command[24:32], vmAddr)
	binary.LittleEndian.PutUint64(command[32:40], vmSize)
	binary.LittleEndian.PutUint64(command[40:48], fileOffset)
	binary.LittleEndian.PutUint64(command[48:56], fileSize)
}

func setTestMachOSection64(command []byte, index int, vmAddr, size uint64, fileOffset, flags uint32) {
	section := segment64CommandSize + index*section64HeaderSize
	binary.LittleEndian.PutUint64(command[section+32:section+40], vmAddr)
	binary.LittleEndian.PutUint64(command[section+40:section+48], size)
	binary.LittleEndian.PutUint32(command[section+48:section+52], fileOffset)
	binary.LittleEndian.PutUint32(command[section+64:section+68], flags)
}

func testFatMachO(order binary.ByteOrder, is64 bool, slices ...[]byte) []byte {
	entrySize := fatMachOArchHeaderSize
	magic := uint32(macho.MagicFat)
	if is64 {
		entrySize = fatMachOArch64HeaderSize
		magic = fatMachOMagic64
	}
	tableEnd := 8 + entrySize*len(slices)
	totalSize := tableEnd
	for _, slice := range slices {
		totalSize += len(slice)
	}
	data := make([]byte, totalSize)
	order.PutUint32(data[0:4], magic)
	order.PutUint32(data[4:8], uint32(len(slices)))
	sliceOffset := tableEnd
	for index, slice := range slices {
		cpu, subCPU, _, ok := thinMachOIdentity(slice)
		if !ok {
			panic("testFatMachO requires structurally recognizable thin slices")
		}
		entry := 8 + index*entrySize
		order.PutUint32(data[entry:entry+4], cpu)
		order.PutUint32(data[entry+4:entry+8], subCPU)
		if is64 {
			order.PutUint64(data[entry+8:entry+16], uint64(sliceOffset))
			order.PutUint64(data[entry+16:entry+24], uint64(len(slice)))
		} else {
			order.PutUint32(data[entry+8:entry+12], uint32(sliceOffset))
			order.PutUint32(data[entry+12:entry+16], uint32(len(slice)))
		}
		copy(data[sliceOffset:], slice)
		sliceOffset += len(slice)
	}
	return data
}

func assertFatPreflightError(t *testing.T, data []byte, want string) {
	t.Helper()
	isFat, err := PreflightMachO(data)
	if !isFat || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("PreflightMachO() = %v, %v; want fat rejection containing %q", isFat, err, want)
	}
	if got := architectures(data); got != nil {
		t.Fatalf("architectures() labeled rejected fat input: %#v", got)
	}
}
