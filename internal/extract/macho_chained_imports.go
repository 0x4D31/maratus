package extract

import (
	"debug/macho"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	lcDyldChainedFixups            = 0x80000034
	maxMachOChainedFixupBytes      = 16 << 20
	maxMachOChainedImports         = 200000
	maxMachOChainedImportNameLen   = 4096
	maxMachOChainedImportNameBytes = 8 << 20
)

type machoChainedImport struct {
	name       string
	nameOffset int64
	addend     int64
}

// machoChainedImports recovers only the immutable import-name table from
// LC_DYLD_CHAINED_FIXUPS. It deliberately does not apply pointer fixups or
// infer a call target. The names enrich the same import Feature lane used by
// the ordinary undefined symbol table, while their source qualifier and exact
// string offset preserve provenance.
func machoChainedImports(file *macho.File, image []byte, byteOffsetBase int64) (imports []machoChainedImport, present bool, detail string) {
	if file == nil || file.ByteOrder == nil {
		return nil, false, ""
	}
	command, present, commandDetail := findMachOChainedFixupCommand(file)
	if !present || commandDetail != "" {
		return nil, present, commandDetail
	}
	if command.dataSize < 28 {
		return nil, true, "LC_DYLD_CHAINED_FIXUPS payload is truncated before its header"
	}
	if command.dataSize > maxMachOChainedFixupBytes {
		return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS payload size %d exceeds parser limit %d", command.dataSize, maxMachOChainedFixupBytes)
	}
	start := uint64(command.dataOff)
	size := uint64(command.dataSize)
	if start > uint64(len(image)) || size > uint64(len(image))-start {
		return nil, true, "LC_DYLD_CHAINED_FIXUPS payload exceeds retained Mach-O bytes"
	}
	payload := image[start : start+size]
	order := file.ByteOrder
	version := order.Uint32(payload[0:4])
	importsOffset := uint64(order.Uint32(payload[8:12]))
	symbolsOffset := uint64(order.Uint32(payload[12:16]))
	count := uint64(order.Uint32(payload[16:20]))
	format := order.Uint32(payload[20:24])
	symbolsFormat := order.Uint32(payload[24:28])
	if version != 0 {
		return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS version %d is unsupported", version)
	}
	if count > maxMachOChainedImports {
		return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import count %d exceeds parser limit %d", count, maxMachOChainedImports)
	}
	if count == 0 {
		return nil, true, ""
	}
	if symbolsFormat != 0 {
		return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS symbol format %d is unsupported; compressed import names were not decoded", symbolsFormat)
	}
	entrySize := uint64(0)
	switch format {
	case 1:
		entrySize = 4
	case 2:
		entrySize = 8
	case 3:
		entrySize = 16
	default:
		return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import format %d is unsupported", format)
	}
	if importsOffset > uint64(len(payload)) || count > (uint64(len(payload))-importsOffset)/entrySize {
		return nil, true, "LC_DYLD_CHAINED_FIXUPS import table is truncated"
	}
	if symbolsOffset >= uint64(len(payload)) {
		return nil, true, "LC_DYLD_CHAINED_FIXUPS symbol table is outside its payload"
	}
	symbols := payload[symbolsOffset:]
	imports = make([]machoChainedImport, 0, count)
	nameBytes := 0
	for index := uint64(0); index < count; index++ {
		entry := payload[importsOffset+index*entrySize : importsOffset+(index+1)*entrySize]
		nameOffset := uint64(0)
		addend := int64(0)
		switch format {
		case 1, 2:
			word := order.Uint32(entry[0:4])
			nameOffset = uint64(word>>9) & 0x7fffff
			if format == 2 {
				addend = int64(int32(order.Uint32(entry[4:8])))
			}
		case 3:
			word := order.Uint64(entry[0:8])
			nameOffset = word >> 32
			addend = int64(order.Uint64(entry[8:16]))
		}
		if nameOffset >= uint64(len(symbols)) {
			return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import %d has an out-of-range symbol offset", index)
		}
		available := symbols[nameOffset:]
		limit := min(len(available), maxMachOChainedImportNameLen+1)
		terminator := -1
		for cursor, value := range available[:limit] {
			if value == 0 {
				terminator = cursor
				break
			}
		}
		if terminator <= 0 {
			return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import %d has an empty, unterminated, or overlong symbol name", index)
		}
		// Repeated offsets still allocate a name for each import record.
		if terminator > maxMachOChainedImportNameBytes-nameBytes {
			return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import names exceed the %d-byte cumulative budget", maxMachOChainedImportNameBytes)
		}
		nameBytes += terminator
		name := string(available[:terminator])
		if !validMachOChainedImportName(name) {
			return nil, true, fmt.Sprintf("LC_DYLD_CHAINED_FIXUPS import %d has an invalid symbol name", index)
		}
		relative := int64(command.dataOff) + int64(symbolsOffset) + int64(nameOffset)
		if relative < 0 || (byteOffsetBase > 0 && relative > int64(^uint64(0)>>1)-byteOffsetBase) {
			return nil, true, "LC_DYLD_CHAINED_FIXUPS symbol offset is unrepresentable"
		}
		absolute := byteOffsetBase + relative
		imports = append(imports, machoChainedImport{name: name, nameOffset: absolute, addend: addend})
	}
	return imports, true, ""
}

func findMachOChainedFixupCommand(file *macho.File) (linkeditCommand, bool, string) {
	var command linkeditCommand
	found := false
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 4 || file.ByteOrder.Uint32(raw[:4]) != lcDyldChainedFixups {
			continue
		}
		if found {
			return linkeditCommand{}, true, "multiple LC_DYLD_CHAINED_FIXUPS commands are ambiguous"
		}
		if len(raw) < 16 {
			return linkeditCommand{}, true, "LC_DYLD_CHAINED_FIXUPS command is truncated"
		}
		command = linkeditCommand{dataOff: file.ByteOrder.Uint32(raw[8:12]), dataSize: file.ByteOrder.Uint32(raw[12:16])}
		found = true
	}
	return command, found, ""
}

func validMachOChainedImportName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return false
	}
	return true
}
