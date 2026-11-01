package extract

import (
	"bytes"
	"debug/gosym"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxGoPCLNBytes         = 32 << 20
	maxGoPCLNFunctions     = 100000
	maxGoPCLNNameBytes     = 8 << 20
	maxGoFunctionNameBytes = 4096
)

type goPCLNStatus struct {
	present       bool
	used          bool
	truncated     bool
	detail        string
	sectionOffset uint32
	sectionSize   uint64
	functions     int
	runtime       int
	standard      int
}

// goPCLNFunctionRangesBounded recovers modern Go function boundaries and names
// from the dedicated Mach-O pclntab section. The result only enriches the
// ordinary native function model. It does not itself interpret Go ABI values,
// infer call arguments, or create a second execution engine; a separate closed
// recognizer may use its exact function identity at decoded direct callsites.
func goPCLNFunctionRangesBounded(file *macho.File, text *macho.Section, image []byte) ([]machoFunction, goPCLNStatus) {
	var candidates []*macho.Section
	for _, section := range file.Sections {
		if section != nil && goPCLNMachOSegment(section.Seg) && section.Name == "__gopclntab" && machoSectionHasFileData(section) {
			candidates = append(candidates, section)
		}
	}
	if len(candidates) == 0 {
		return nil, goPCLNStatus{}
	}
	status := goPCLNStatus{present: true}
	if len(candidates) != 1 {
		status.detail = "multiple supported __gopclntab sections make Go function provenance ambiguous"
		return nil, status
	}
	section := candidates[0]
	status.sectionOffset = section.Offset
	status.sectionSize = section.Size
	data, truncated, err := machoSectionPrefix(image, section, maxGoPCLNBytes)
	if err != nil {
		status.detail = "Go pclntab section could not be read within its validated file extent"
		return nil, status
	}
	if truncated {
		status.truncated = true
		status.detail = fmt.Sprintf("Go pclntab exceeds the %d-byte parser budget", maxGoPCLNBytes)
		return nil, status
	}
	functions, runtimeCount, standardCount, detail, ok := goPCLNFunctionsFromData(data, text.Addr, text.Addr+text.Size, file.ByteOrder)
	if !ok {
		status.detail = detail
		return nil, status
	}
	status.used = true
	status.functions = len(functions)
	status.runtime = runtimeCount
	status.standard = standardCount
	return functions, status
}

func goPCLNMachOSegment(name string) bool {
	// Current Go linkers place read-only runtime metadata in __DATA_CONST;
	// older layouts used __TEXT. Other same-named sections are not trusted as
	// compiler metadata.
	return name == "__DATA_CONST" || name == "__TEXT"
}

func goPCLNFunctionsFromData(data []byte, textStart, textEnd uint64, expectedOrder ...binary.ByteOrder) (functions []machoFunction, runtimeCount, standardCount int, detail string, ok bool) {
	defer func() {
		if recover() != nil {
			functions = nil
			runtimeCount = 0
			standardCount = 0
			detail = "Go pclntab parser rejected malformed bounded metadata"
			ok = false
		}
	}()
	order, pointerSize, count, metadataText, headerDetail, headerOK := goPCLNHeader(data)
	if !headerOK {
		return nil, 0, 0, headerDetail, false
	}
	if len(expectedOrder) > 0 && expectedOrder[0] != nil && !sameGoPCLNByteOrder(order, expectedOrder[0]) {
		return nil, 0, 0, "Go pclntab byte order does not match the Mach-O slice", false
	}
	if count == 0 || count > maxGoPCLNFunctions {
		return nil, 0, 0, fmt.Sprintf("Go pclntab function count %d is outside the 1..%d bound", count, maxGoPCLNFunctions), false
	}
	if metadataText < textStart || metadataText >= textEnd {
		return nil, 0, 0, "Go pclntab text base is outside the analyzed executable section", false
	}
	funcDataOffset := goPCLNWord(data, 7, pointerSize, order)
	fieldSize := uint64(4)
	functabBytes := (count*2 + 1) * fieldSize
	if funcDataOffset > uint64(len(data)) || functabBytes > uint64(len(data))-funcDataOffset {
		return nil, 0, 0, "Go pclntab function table exceeds the bounded section", false
	}
	exactNames, namesDetail, namesOK := goPCLNFunctionNames(data, order, count, funcDataOffset)
	if !namesOK {
		return nil, 0, 0, namesDetail, false
	}

	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, metadataText))
	if err != nil || table == nil {
		return nil, 0, 0, "Go pclntab could not be decoded as a modern Go symbol table", false
	}
	if uint64(len(table.Funcs)) != count {
		return nil, 0, 0, "Go pclntab decoded function count does not match its header", false
	}
	functions = make([]machoFunction, 0, len(table.Funcs))
	var previousEnd uint64
	for index := range table.Funcs {
		function := &table.Funcs[index]
		if function.Sym == nil || function.Name != exactNames[index] || !validGoFunctionName(function.Name) {
			return nil, 0, 0, "Go pclntab contains a malformed or overlong function name", false
		}
		if function.Entry < metadataText || function.End <= function.Entry || function.End > textEnd || (index > 0 && function.Entry < previousEnd) {
			return nil, 0, 0, "Go pclntab contains an overlapping or out-of-range function boundary", false
		}
		previousEnd = function.End
		if function.Entry < textStart {
			continue
		}
		name := function.Name
		classification := "go-other"
		switch {
		case goCompilerOrRuntimeFunction(name):
			classification = "go-runtime-compiler"
			runtimeCount++
		case goStandardLibraryFunction(name):
			classification = "go-standard-library"
			standardCount++
		}
		functions = append(functions, machoFunction{Name: name, Start: function.Entry, End: function.End, Metadata: classification})
	}
	if len(functions) == 0 {
		return nil, 0, 0, "Go pclntab contains no functions inside the analyzed executable section", false
	}
	return functions, runtimeCount, standardCount, "", true
}

func sameGoPCLNByteOrder(left, right binary.ByteOrder) bool {
	var probe [4]byte
	copy(probe[:], []byte{1, 2, 3, 4})
	return left.Uint32(probe[:]) == right.Uint32(probe[:])
}

func goPCLNFunctionNames(data []byte, order binary.ByteOrder, count, funcDataOffset uint64) ([]string, string, bool) {
	nameStart := goPCLNWord(data, 3, 8, order)
	nameEnd := goPCLNWord(data, 4, 8, order)
	if nameStart >= nameEnd || nameEnd > uint64(len(data)) {
		return nil, "Go pclntab function-name table is empty or out of range", false
	}
	names := make([]string, 0, count)
	nameBytes := 0
	for index := uint64(0); index < count; index++ {
		entry := funcDataOffset + (2*index+1)*4
		if entry > uint64(len(data))-4 {
			return nil, "Go pclntab function record offset is truncated", false
		}
		functionOffset := uint64(order.Uint32(data[entry : entry+4]))
		record := funcDataOffset + functionOffset
		if record > uint64(len(data))-8 {
			return nil, "Go pclntab function record is truncated", false
		}
		nameOffset := uint64(order.Uint32(data[record+4 : record+8]))
		if nameOffset >= nameEnd-nameStart {
			return nil, "Go pclntab function name points outside its exact table", false
		}
		candidate := data[nameStart+nameOffset : nameEnd]
		if len(candidate) > maxGoFunctionNameBytes+1 {
			candidate = candidate[:maxGoFunctionNameBytes+1]
		}
		terminator := bytes.IndexByte(candidate, 0)
		if terminator < 0 {
			return nil, "Go pclntab function name is not terminated inside its exact table", false
		}
		name := string(candidate[:terminator])
		if !validGoFunctionName(name) {
			return nil, "Go pclntab contains a malformed or overlong function name", false
		}
		nameBytes += len(name)
		if nameBytes > maxGoPCLNNameBytes {
			return nil, fmt.Sprintf("Go pclntab function names exceed the %d-byte cumulative budget", maxGoPCLNNameBytes), false
		}
		names = append(names, name)
	}
	return names, "", true
}

func goPCLNHeader(data []byte) (binary.ByteOrder, uint64, uint64, uint64, string, bool) {
	if len(data) < 72 || data[4] != 0 || data[5] != 0 || (data[6] != 1 && data[6] != 2 && data[6] != 4) || data[7] != 8 {
		return nil, 0, 0, 0, "Go pclntab header is truncated or unsupported", false
	}
	var order binary.ByteOrder
	magicLE := binary.LittleEndian.Uint32(data[:4])
	magicBE := binary.BigEndian.Uint32(data[:4])
	switch {
	case magicLE == 0xfffffff0 || magicLE == 0xfffffff1:
		order = binary.LittleEndian
	case magicBE == 0xfffffff0 || magicBE == 0xfffffff1:
		order = binary.BigEndian
	default:
		return nil, 0, 0, 0, "Go pclntab is not a supported Go 1.18+ table", false
	}
	const pointerSize = uint64(8)
	count := goPCLNWord(data, 0, pointerSize, order)
	text := goPCLNWord(data, 2, pointerSize, order)
	previous := uint64(0)
	for word := uint64(3); word <= 7; word++ {
		offset := goPCLNWord(data, word, pointerSize, order)
		if offset < previous || offset > uint64(len(data)) {
			return nil, 0, 0, 0, "Go pclntab header offsets are noncanonical or out of range", false
		}
		previous = offset
	}
	return order, pointerSize, count, text, "", true
}

func goPCLNWord(data []byte, word, pointerSize uint64, order binary.ByteOrder) uint64 {
	offset := 8 + word*pointerSize
	return order.Uint64(data[offset : offset+pointerSize])
}

func validGoFunctionName(name string) bool {
	if name == "" || len(name) > maxGoFunctionNameBytes || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func goCompilerOrRuntimeFunction(name string) bool {
	for _, prefix := range []string{
		"runtime.", "runtime/", "internal/",
		"type:", "go:",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func goStandardLibraryFunction(name string) bool {
	for _, prefix := range []string{
		"archive/", "bufio.", "bytes.", "cmp.", "compress/", "container/", "context.", "crypto.", "crypto/", "database/", "debug/", "embed.", "encoding.", "encoding/",
		"errors.", "flag.", "fmt.", "hash/", "html/", "image/", "io.", "io/", "log.", "log/", "math.", "math/",
		"mime.", "mime/", "net.", "net/", "os.", "os/", "path.", "path/", "reflect.", "regexp.", "regexp/",
		"sort.", "strconv.", "strings.", "sync.", "sync/", "syscall.", "testing.", "text/", "time.", "unicode.",
		"unicode/", "go/", "index/", "maps.", "slices.", "structs.", "unique.", "weak.", "vendor/golang.org/x/",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
