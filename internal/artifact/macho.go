package artifact

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/machox"
)

const (
	maxMachOFatArchitectures = 32
	maxMachOLoadCommands     = 4096
	maxMachOLoadCommandBytes = 16 << 20
	maxMachOSections         = 16384
	maxMachOSymbols          = 400000
	maxMachOIndirectSymbols  = 400000
	maxMachORelocations      = 400000
	maxMachODataInCode       = 400000
	maxMachOSectionDataBytes = 128 << 20
	maxMachOStringTableBytes = 32 << 20
	maxMachOSymbolNameBytes  = 64 << 10
	maxMachODecodedNameBytes = 16 << 20
	thinMachOHeader32Size    = 28
	thinMachOHeader64Size    = 32
	fatMachOArchHeaderSize   = 20
	fatMachOArch64HeaderSize = 32
	fatMachOMagic64          = 0xcafebabf
	loadCommandHeaderSize    = 8
	segment32CommandSize     = 56
	segment64CommandSize     = 72
	section32HeaderSize      = 68
	section64HeaderSize      = 80
	symtabCommandSize        = 24
	dysymtabCommandSize      = 80
	linkeditDataCommandSize  = 16
	encryptionCommandSize    = 20
	dataInCodeEntrySize      = 8
	lcDataInCode             = 0x29
	lcEncryptionInfo         = 0x21
	lcEncryptionInfo64       = 0x2c
	lcIDDylib                = 0x0d
	lcLoadDylib              = 0x0c
	lcLoadWeakDylib          = 0x80000018
	lcReexportDylib          = 0x8000001f
	lcLazyLoadDylib          = 0x20
	lcLoadUpwardDylib        = 0x80000023
)

func validElectronFrameworkMachOBytes(data []byte) bool {
	return validElectronFrameworkMachO(bytes.NewReader(data), int64(len(data)))
}

// validElectronFrameworkMachO validates only the bounded structural facts
// needed to corroborate the canonical Electron carrier. It deliberately uses
// ReaderAt so a large framework does not need to be retained merely to inspect
// its headers, and it applies the same aggregate command budgets as the normal
// Mach-O preflight before allocating a load-command block.
func validElectronFrameworkMachO(reader io.ReaderAt, size int64) bool {
	if reader == nil || size < 4 {
		return false
	}
	var magicBytes [4]byte
	if _, err := reader.ReadAt(magicBytes[:], 0); err != nil {
		return false
	}
	magicBE := binary.BigEndian.Uint32(magicBytes[:])
	magicLE := binary.LittleEndian.Uint32(magicBytes[:])
	budget := &machoPreflightBudget{}
	if magicBE == macho.MagicFat || magicBE == fatMachOMagic64 || magicLE == macho.MagicFat || magicLE == fatMachOMagic64 {
		return validElectronMachOFat(reader, size, magicBE, magicLE, budget, macho.TypeDylib, electronFrameworkIDCommand)
	}
	_, _, ok := validElectronMachOThin(reader, 0, size, budget, macho.TypeDylib, electronFrameworkIDCommand)
	return ok
}

func machoLoadsElectronFrameworkBytes(data []byte) bool {
	return machoLoadsElectronFramework(bytes.NewReader(data), int64(len(data)))
}

func machoLoadsElectronFramework(reader io.ReaderAt, size int64) bool {
	if reader == nil || size < 4 {
		return false
	}
	var magicBytes [4]byte
	if _, err := reader.ReadAt(magicBytes[:], 0); err != nil {
		return false
	}
	magicBE := binary.BigEndian.Uint32(magicBytes[:])
	magicLE := binary.LittleEndian.Uint32(magicBytes[:])
	budget := &machoPreflightBudget{}
	if magicBE == macho.MagicFat || magicBE == fatMachOMagic64 || magicLE == macho.MagicFat || magicLE == fatMachOMagic64 {
		return validElectronMachOFat(reader, size, magicBE, magicLE, budget, macho.TypeExec, electronFrameworkLoadCommand)
	}
	_, _, ok := validElectronMachOThin(reader, 0, size, budget, macho.TypeExec, electronFrameworkLoadCommand)
	return ok
}

type electronMachOCommandPredicate func(binary.ByteOrder, uint32, []byte) bool

func validElectronMachOFat(reader io.ReaderAt, size int64, magicBE, magicLE uint32, budget *machoPreflightBudget, requiredType macho.Type, requiredCommand electronMachOCommandPredicate) bool {
	var order binary.ByteOrder = binary.BigEndian
	magic := magicBE
	if magicBE != macho.MagicFat && magicBE != fatMachOMagic64 {
		order = binary.LittleEndian
		magic = magicLE
	}
	entrySize := int64(fatMachOArchHeaderSize)
	if magic == fatMachOMagic64 {
		entrySize = 32
	}
	var header [8]byte
	if _, err := reader.ReadAt(header[:], 0); err != nil {
		return false
	}
	narch := uint64(order.Uint32(header[4:8]))
	if narch == 0 || narch > maxMachOFatArchitectures || uint64(entrySize) > uint64(size-8)/narch {
		return false
	}
	tableSize := int64(narch) * entrySize
	table := make([]byte, tableSize)
	if _, err := reader.ReadAt(table, 8); err != nil {
		return false
	}
	for index := uint64(0); index < narch; index++ {
		entry := table[int64(index)*entrySize : int64(index+1)*entrySize]
		outerCPU := order.Uint32(entry[0:4])
		outerSubCPU := order.Uint32(entry[4:8])
		var offset, sliceSize uint64
		if entrySize == fatMachOArchHeaderSize {
			offset = uint64(order.Uint32(entry[8:12]))
			sliceSize = uint64(order.Uint32(entry[12:16]))
		} else {
			offset = order.Uint64(entry[8:16])
			sliceSize = order.Uint64(entry[16:24])
		}
		if sliceSize == 0 || offset > uint64(size) || sliceSize > uint64(size)-offset || offset > uint64(^uint64(0)>>1) || sliceSize > uint64(^uint64(0)>>1) {
			return false
		}
		innerCPU, innerSubCPU, ok := validElectronMachOThin(reader, int64(offset), int64(sliceSize), budget, requiredType, requiredCommand)
		if !ok || outerCPU != innerCPU || outerSubCPU != innerSubCPU {
			return false
		}
	}
	return true
}

func validElectronMachOThin(reader io.ReaderAt, base, size int64, budget *machoPreflightBudget, requiredType macho.Type, requiredCommand electronMachOCommandPredicate) (uint32, uint32, bool) {
	if base < 0 || size < thinMachOHeader32Size {
		return 0, 0, false
	}
	var header [thinMachOHeader64Size]byte
	if _, err := reader.ReadAt(header[:thinMachOHeader32Size], base); err != nil {
		return 0, 0, false
	}
	order, magic, ok := thinMachOByteOrder(header[:])
	if !ok {
		return 0, 0, false
	}
	headerSize := int64(thinMachOHeader32Size)
	if magic == macho.Magic64 {
		headerSize = thinMachOHeader64Size
		if _, err := reader.ReadAt(header[thinMachOHeader32Size:thinMachOHeader64Size], base+thinMachOHeader32Size); err != nil {
			return 0, 0, false
		}
	}
	if size < headerSize || macho.Type(order.Uint32(header[12:16])) != requiredType {
		return 0, 0, false
	}
	cpu := order.Uint32(header[4:8])
	subCPU := order.Uint32(header[8:12])
	switch macho.Cpu(cpu) {
	case macho.Cpu386, macho.CpuAmd64, macho.CpuArm, macho.CpuArm64:
	default:
		return 0, 0, false
	}
	ncmd := uint64(order.Uint32(header[16:20]))
	cmdsz := uint64(order.Uint32(header[20:24]))
	if ncmd == 0 || cmdsz == 0 || cmdsz > uint64(size-headerSize) {
		return 0, 0, false
	}
	if err := addMachOPreflightCount(&budget.commands, ncmd, maxMachOLoadCommands, "load command count"); err != nil {
		return 0, 0, false
	}
	if err := addMachOPreflightCount(&budget.commandBytes, cmdsz, maxMachOLoadCommandBytes, "load command bytes"); err != nil {
		return 0, 0, false
	}
	commands := make([]byte, int(cmdsz))
	if _, err := reader.ReadAt(commands, base+headerSize); err != nil {
		return 0, 0, false
	}
	remaining := commands
	hasSegment := false
	hasRequiredCommand := false
	for index := uint64(0); index < ncmd; index++ {
		if len(remaining) < loadCommandHeaderSize {
			return 0, 0, false
		}
		cmd := order.Uint32(remaining[0:4])
		commandSize := uint64(order.Uint32(remaining[4:8]))
		if commandSize < loadCommandHeaderSize || commandSize%4 != 0 || commandSize > uint64(len(remaining)) {
			return 0, 0, false
		}
		command := remaining[:int(commandSize)]
		switch macho.LoadCmd(cmd) {
		case macho.LoadCmdSegment, macho.LoadCmdSegment64:
			hasSegment = true
		}
		if requiredCommand != nil && requiredCommand(order, cmd, command) {
			hasRequiredCommand = true
		}
		remaining = remaining[int(commandSize):]
	}
	if len(remaining) != 0 || !hasSegment || !hasRequiredCommand {
		return 0, 0, false
	}
	return cpu, subCPU, true
}

func electronFrameworkIDCommand(order binary.ByteOrder, cmd uint32, command []byte) bool {
	return cmd == lcIDDylib && electronFrameworkDylibName(order, command)
}

func electronFrameworkLoadCommand(order binary.ByteOrder, cmd uint32, command []byte) bool {
	switch cmd {
	case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpwardDylib:
		return electronFrameworkDylibName(order, command)
	default:
		return false
	}
}

func electronFrameworkDylibName(order binary.ByteOrder, command []byte) bool {
	if len(command) < 24 {
		return false
	}
	nameOffset := uint64(order.Uint32(command[8:12]))
	if nameOffset < 24 || nameOffset >= uint64(len(command)) {
		return false
	}
	nameBytes := command[nameOffset:]
	nul := bytes.IndexByte(nameBytes, 0)
	if nul < 0 {
		return false
	}
	name := strings.ToLower(string(nameBytes[:nul]))
	for _, suffix := range []string{
		"electron framework.framework/electron framework",
		"electron framework.framework/versions/a/electron framework",
	} {
		if name == suffix || strings.HasSuffix(name, "/"+suffix) {
			return true
		}
	}
	return false
}

type machoPreflightBudget struct {
	commands         uint64
	commandBytes     uint64
	sections         uint64
	symbols          uint64
	indirectSymbols  uint64
	relocations      uint64
	sectionDataBytes uint64
	stringTableBytes uint64
	decodedNameBytes uint64
}

type machoPreflightRange struct {
	start       uint64
	end         uint64
	loadCommand uint64
	section     int64
}

type machoPreflightMappings struct {
	segmentFileRanges         []machoPreflightRange
	fileBackedSegmentVMRanges []machoPreflightRange
	sectionFileRanges         []machoPreflightRange
	sectionVMRanges           []machoPreflightRange
}

// PreflightMachO validates attacker-controlled collection counts before the
// standard library parser allocates them. The returned boolean reports whether
// data is a fat container.
func PreflightMachO(data []byte) (bool, error) {
	isFat, _, err := PreflightMachOSlices(data)
	return isFat, err
}

// MachOSliceDescriptor identifies a thin Mach-O image whose extent and header
// identity were validated by PreflightMachOSlices. Fat-container extents do not
// include bytes in an outer overlay appended after the indexed thin image.
type MachOSliceDescriptor struct {
	Offset uint64
	Size   uint64
	CPU    macho.Cpu
	SubCPU uint32
}

// Bytes returns the descriptor's bounded thin image. It remains bounds-safe if
// a caller retains a descriptor but supplies different backing data.
func (descriptor MachOSliceDescriptor) Bytes(data []byte) ([]byte, bool) {
	if !machORangeWithinData(len(data), descriptor.Offset, descriptor.Size) {
		return nil, false
	}
	return data[int(descriptor.Offset):int(descriptor.Offset+descriptor.Size)], true
}

// PreflightMachOSlices applies the aggregate Mach-O allocation budgets and
// returns descriptors only after every indexed thin image validates. Thin input
// is represented by one descriptor spanning the input.
func PreflightMachOSlices(data []byte) (bool, []MachOSliceDescriptor, error) {
	if len(data) < 4 {
		return false, nil, fmt.Errorf("header is shorter than 4 bytes")
	}
	budget := &machoPreflightBudget{}
	fatFormat, isFat := detectFatMachOFormat(data)
	if isFat {
		architectures, err := preflightFatMachO(data, fatFormat, budget)
		if err != nil {
			return true, nil, err
		}
		descriptors := make([]MachOSliceDescriptor, 0, len(architectures))
		for _, architecture := range architectures {
			descriptors = append(descriptors, MachOSliceDescriptor{
				Offset: architecture.offset,
				Size:   architecture.size,
				CPU:    macho.Cpu(architecture.cpu),
				SubCPU: architecture.subCPU,
			})
		}
		return true, descriptors, nil
	}
	if err := preflightThinMachO(data, budget); err != nil {
		return false, nil, err
	}
	cpu, subCPU, _, ok := thinMachOIdentity(data)
	if !ok {
		return false, nil, fmt.Errorf("thin Mach-O header identity is unreadable after preflight")
	}
	return false, []MachOSliceDescriptor{{
		Offset: 0,
		Size:   uint64(len(data)),
		CPU:    macho.Cpu(cpu),
		SubCPU: subCPU,
	}}, nil
}

type fatMachOFormat struct {
	order     binary.ByteOrder
	archBytes uint64
	is64      bool
}

type fatMachOArchitecture struct {
	cpu    uint32
	subCPU uint32
	offset uint64
	size   uint64
	align  uint32
}

func detectFatMachOFormat(data []byte) (fatMachOFormat, bool) {
	if len(data) < 4 {
		return fatMachOFormat{}, false
	}
	magicBE := binary.BigEndian.Uint32(data[:4])
	magicLE := binary.LittleEndian.Uint32(data[:4])
	switch {
	case magicBE == macho.MagicFat:
		return fatMachOFormat{order: binary.BigEndian, archBytes: fatMachOArchHeaderSize}, true
	case magicLE == macho.MagicFat:
		return fatMachOFormat{order: binary.LittleEndian, archBytes: fatMachOArchHeaderSize}, true
	case magicBE == fatMachOMagic64:
		return fatMachOFormat{order: binary.BigEndian, archBytes: fatMachOArch64HeaderSize, is64: true}, true
	case magicLE == fatMachOMagic64:
		return fatMachOFormat{order: binary.LittleEndian, archBytes: fatMachOArch64HeaderSize, is64: true}, true
	default:
		return fatMachOFormat{}, false
	}
}

func preflightFatMachO(data []byte, format fatMachOFormat, budget *machoPreflightBudget) ([]fatMachOArchitecture, error) {
	architectures, err := parseFatMachOArchitectures(data, format)
	if err != nil {
		return nil, err
	}
	var firstType macho.Type
	for i, architecture := range architectures {
		slice := data[int(architecture.offset):int(architecture.offset+architecture.size)]
		if err := preflightThinMachO(slice, budget); err != nil {
			return nil, fmt.Errorf("fat architecture %d: %w", i, err)
		}
		innerCPU, innerSubCPU, innerType, ok := thinMachOIdentity(slice)
		if !ok {
			return nil, fmt.Errorf("fat architecture %d has an unreadable inner Mach-O header", i)
		}
		if architecture.cpu != innerCPU || architecture.subCPU != innerSubCPU {
			return nil, fmt.Errorf("fat architecture %d CPU/subtype %#x/%#x disagrees with inner slice %#x/%#x", i, architecture.cpu, architecture.subCPU, innerCPU, innerSubCPU)
		}
		if i == 0 {
			firstType = innerType
		} else if innerType != firstType {
			return nil, fmt.Errorf("fat architecture %d file type %#x disagrees with first slice %#x", i, innerType, firstType)
		}
	}
	return architectures, nil
}

func parseFatMachOArchitectures(data []byte, format fatMachOFormat) ([]fatMachOArchitecture, error) {
	expectedArchBytes := uint64(fatMachOArchHeaderSize)
	if format.is64 {
		expectedArchBytes = fatMachOArch64HeaderSize
	}
	if format.order == nil || format.archBytes != expectedArchBytes {
		return nil, fmt.Errorf("invalid fat Mach-O format descriptor")
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("fat header is shorter than 8 bytes")
	}
	narch := uint64(format.order.Uint32(data[4:8]))
	if narch == 0 {
		return nil, fmt.Errorf("fat header contains no architectures")
	}
	if narch > maxMachOFatArchitectures {
		return nil, fmt.Errorf("fat architecture count %d exceeds limit %d", narch, maxMachOFatArchitectures)
	}
	if format.archBytes == 0 || narch > uint64(len(data)-8)/format.archBytes {
		return nil, fmt.Errorf("fat architecture table is truncated")
	}
	tableEnd := uint64(8) + narch*format.archBytes
	architectures := make([]fatMachOArchitecture, 0, int(narch))
	seenArchitectures := make(map[uint64]struct{}, int(narch))
	for i := uint64(0); i < narch; i++ {
		entry := uint64(8) + i*format.archBytes
		entryData := data[int(entry):int(entry+format.archBytes)]
		architecture := fatMachOArchitecture{
			cpu:    format.order.Uint32(entryData[0:4]),
			subCPU: format.order.Uint32(entryData[4:8]),
		}
		if format.is64 {
			architecture.offset = format.order.Uint64(entryData[8:16])
			architecture.size = format.order.Uint64(entryData[16:24])
			architecture.align = format.order.Uint32(entryData[24:28])
			if reserved := format.order.Uint32(entryData[28:32]); reserved != 0 {
				return nil, fmt.Errorf("fat architecture %d has non-zero reserved field %#x", i, reserved)
			}
		} else {
			architecture.offset = uint64(format.order.Uint32(entryData[8:12]))
			architecture.size = uint64(format.order.Uint32(entryData[12:16]))
			architecture.align = format.order.Uint32(entryData[16:20])
		}
		identity := uint64(architecture.cpu)<<32 | uint64(architecture.subCPU)
		if _, exists := seenArchitectures[identity]; exists {
			return nil, fmt.Errorf("fat architecture %d duplicates CPU/subtype %#x/%#x", i, architecture.cpu, architecture.subCPU)
		}
		seenArchitectures[identity] = struct{}{}
		if architecture.align >= 64 {
			return nil, fmt.Errorf("fat architecture %d alignment exponent %d is invalid", i, architecture.align)
		}
		alignment := uint64(1) << architecture.align
		if architecture.offset&(alignment-1) != 0 {
			return nil, fmt.Errorf("fat architecture %d offset %d is not aligned to %d bytes", i, architecture.offset, alignment)
		}
		if architecture.offset < tableEnd {
			return nil, fmt.Errorf("fat architecture %d overlaps the fat header or architecture table", i)
		}
		offset, size := architecture.offset, architecture.size
		if size == 0 || offset > uint64(len(data)) || size > uint64(len(data))-offset {
			return nil, fmt.Errorf("fat architecture %d points outside file data", i)
		}
		end := offset + size
		for previousIndex, previous := range architectures {
			previousEnd := previous.offset + previous.size
			if offset < previousEnd && previous.offset < end {
				return nil, fmt.Errorf("fat architecture %d overlaps architecture %d", i, previousIndex)
			}
		}
		architectures = append(architectures, architecture)
	}
	return architectures, nil
}

func thinMachOIdentity(data []byte) (uint32, uint32, macho.Type, bool) {
	if len(data) < 16 {
		return 0, 0, 0, false
	}
	order, _, ok := thinMachOByteOrder(data)
	if !ok {
		return 0, 0, 0, false
	}
	return order.Uint32(data[4:8]), order.Uint32(data[8:12]), macho.Type(order.Uint32(data[12:16])), true
}

func thinMachOByteOrder(data []byte) (binary.ByteOrder, uint32, bool) {
	if len(data) < 4 {
		return nil, 0, false
	}
	beMagic := binary.BigEndian.Uint32(data[:4])
	leMagic := binary.LittleEndian.Uint32(data[:4])
	switch {
	case beMagic&^1 == macho.Magic32&^1:
		return binary.BigEndian, beMagic, true
	case leMagic&^1 == macho.Magic32&^1:
		return binary.LittleEndian, leMagic, true
	default:
		return nil, 0, false
	}
}

func preflightThinMachO(data []byte, budget *machoPreflightBudget) error {
	if len(data) < 4 {
		return fmt.Errorf("thin header is shorter than 4 bytes")
	}
	order, magic, ok := thinMachOByteOrder(data)
	if !ok {
		return fmt.Errorf("invalid thin Mach-O magic")
	}
	headerSize := thinMachOHeader32Size
	is64 := magic == macho.Magic64
	if is64 {
		headerSize = thinMachOHeader64Size
	}
	if len(data) < headerSize {
		return fmt.Errorf("thin header is truncated")
	}
	ncmd := uint64(order.Uint32(data[16:20]))
	cmdsz := uint64(order.Uint32(data[20:24]))
	if err := addMachOPreflightCount(&budget.commands, ncmd, maxMachOLoadCommands, "load command count"); err != nil {
		return err
	}
	if err := addMachOPreflightCount(&budget.commandBytes, cmdsz, maxMachOLoadCommandBytes, "load command bytes"); err != nil {
		return err
	}
	if cmdsz > uint64(len(data)-headerSize) {
		return fmt.Errorf("load command block is truncated")
	}
	commands := data[headerSize : headerSize+int(cmdsz)]
	fileType := macho.Type(order.Uint32(data[12:16]))
	var symbolCount uint64
	symbolTableSeen := false
	mappings := &machoPreflightMappings{}
	for i := uint64(0); i < ncmd; i++ {
		if len(commands) < loadCommandHeaderSize {
			return fmt.Errorf("load command %d header is truncated", i)
		}
		cmd := macho.LoadCmd(order.Uint32(commands[0:4]))
		size := uint64(order.Uint32(commands[4:8]))
		if size < loadCommandHeaderSize || size > uint64(len(commands)) {
			return fmt.Errorf("load command %d has invalid size %d", i, size)
		}
		command := commands[:int(size)]
		switch cmd {
		case macho.LoadCmdSegment:
			if err := preflightMachOSegment(data, command, order, false, fileType, i, budget, mappings); err != nil {
				return fmt.Errorf("load command %d: %w", i, err)
			}
		case macho.LoadCmdSegment64:
			if err := preflightMachOSegment(data, command, order, true, fileType, i, budget, mappings); err != nil {
				return fmt.Errorf("load command %d: %w", i, err)
			}
		case macho.LoadCmdSymtab:
			if len(command) < symtabCommandSize {
				return fmt.Errorf("symbol table command is truncated")
			}
			symbolCount = uint64(order.Uint32(command[12:16]))
			symbolTableSeen = true
			if err := addMachOPreflightCount(&budget.symbols, symbolCount, maxMachOSymbols, "symbol count"); err != nil {
				return err
			}
			if err := addMachOPreflightCount(&budget.stringTableBytes, uint64(order.Uint32(command[20:24])), maxMachOStringTableBytes, "string table bytes"); err != nil {
				return err
			}
			if err := preflightMachOSymbolTable(data, command, order, is64, budget); err != nil {
				return fmt.Errorf("load command %d: %w", i, err)
			}
		case macho.LoadCmdDysymtab:
			if len(command) < dysymtabCommandSize {
				return fmt.Errorf("dynamic symbol table command is truncated")
			}
			if err := preflightMachODynamicSymbolTable(data, command, order, is64, symbolCount, budget); err != nil {
				return fmt.Errorf("load command %d: %w", i, err)
			}
			if !symbolTableSeen {
				return fmt.Errorf("load command %d: dynamic symbol table precedes ordinary symbol table", i)
			}
		case macho.LoadCmd(lcDataInCode):
			if len(command) < linkeditDataCommandSize {
				return fmt.Errorf("data-in-code command is truncated")
			}
			offset := uint64(order.Uint32(command[8:12]))
			size := uint64(order.Uint32(command[12:16]))
			if size%dataInCodeEntrySize != 0 {
				return fmt.Errorf("load command %d: data-in-code table size is not a multiple of %d", i, dataInCodeEntrySize)
			}
			if size/dataInCodeEntrySize > maxMachODataInCode || !machORangeWithinData(len(data), offset, size) {
				return fmt.Errorf("load command %d: data-in-code records point outside file data or exceed limit %d", i, maxMachODataInCode)
			}
			table := data[int(offset):int(offset+size)]
			for recordOffset := 0; recordOffset < len(table); recordOffset += dataInCodeEntrySize {
				entryOffset := uint64(order.Uint32(table[recordOffset : recordOffset+4]))
				entryLength := uint64(order.Uint16(table[recordOffset+4 : recordOffset+6]))
				if !machORangeWithinData(len(data), entryOffset, entryLength) {
					return fmt.Errorf("load command %d: data-in-code entry %d points outside file data", i, recordOffset/dataInCodeEntrySize)
				}
			}
		case macho.LoadCmd(lcEncryptionInfo), macho.LoadCmd(lcEncryptionInfo64):
			minimumSize := encryptionCommandSize
			if cmd == macho.LoadCmd(lcEncryptionInfo64) {
				minimumSize += 4 // encryption_info_command_64 includes a padding word.
			}
			if len(command) < minimumSize {
				return fmt.Errorf("encryption-info command is truncated")
			}
			offset := uint64(order.Uint32(command[8:12]))
			size := uint64(order.Uint32(command[12:16]))
			if !machORangeWithinData(len(data), offset, size) {
				return fmt.Errorf("load command %d: encrypted range points outside file data", i)
			}
		}
		commands = commands[int(size):]
	}
	if err := validateMachONonOverlappingRanges(mappings.segmentFileRanges, "segment file-offset ranges"); err != nil {
		return err
	}
	if err := validateMachONonOverlappingRanges(mappings.fileBackedSegmentVMRanges, "file-backed segment VM ranges"); err != nil {
		return err
	}
	if err := validateMachONonOverlappingRanges(mappings.sectionVMRanges, "file-backed section virtual ranges"); err != nil {
		return err
	}
	if err := validateMachONonOverlappingRanges(mappings.sectionFileRanges, "file-backed section file ranges"); err != nil {
		return err
	}
	return nil
}

func preflightMachODynamicSymbolTable(data, command []byte, order binary.ByteOrder, is64 bool, symbolCount uint64, budget *machoPreflightBudget) error {
	symbolRanges := []struct {
		name        string
		indexOffset int
		countOffset int
	}{
		{"local symbol range", 8, 12},
		{"external-defined symbol range", 16, 20},
		{"undefined symbol range", 24, 28},
	}
	for _, item := range symbolRanges {
		start := uint64(order.Uint32(command[item.indexOffset : item.indexOffset+4]))
		count := uint64(order.Uint32(command[item.countOffset : item.countOffset+4]))
		if start > symbolCount || count > symbolCount-start {
			return fmt.Errorf("%s [%d,%d) exceeds ordinary symbol count %d", item.name, start, start+count, symbolCount)
		}
	}

	moduleRecordSize := uint64(52)
	if is64 {
		moduleRecordSize = 56
	}
	fileTables := []struct {
		name        string
		offsetField int
		countField  int
		recordSize  uint64
	}{
		{"table-of-contents records", 32, 36, 8},
		{"module records", 40, 44, moduleRecordSize},
		{"external-reference records", 48, 52, 4},
		{"indirect symbol records", 56, 60, 4},
		{"external relocation records", 64, 68, 8},
		{"local relocation records", 72, 76, 8},
	}
	for _, item := range fileTables {
		offset := uint64(order.Uint32(command[item.offsetField : item.offsetField+4]))
		count := uint64(order.Uint32(command[item.countField : item.countField+4]))
		switch item.name {
		case "indirect symbol records":
			if err := addMachOPreflightCount(&budget.indirectSymbols, count, maxMachOIndirectSymbols, "indirect symbol count"); err != nil {
				return err
			}
		case "external relocation records", "local relocation records":
			if err := addMachOPreflightCount(&budget.relocations, count, maxMachORelocations, "relocation count"); err != nil {
				return err
			}
		}
		if count > ^uint64(0)/item.recordSize || !machORangeWithinData(len(data), offset, count*item.recordSize) {
			return fmt.Errorf("%s point outside file data", item.name)
		}
	}
	return nil
}

func preflightMachOSymbolTable(data, command []byte, order binary.ByteOrder, is64 bool, budget *machoPreflightBudget) error {
	symbolOffset := uint64(order.Uint32(command[8:12]))
	symbolCount := uint64(order.Uint32(command[12:16]))
	stringOffset := uint64(order.Uint32(command[16:20]))
	stringSize := uint64(order.Uint32(command[20:24]))
	symbolSize := uint64(12)
	if is64 {
		symbolSize = 16
	}
	if symbolCount > ^uint64(0)/symbolSize || !machORangeWithinData(len(data), symbolOffset, symbolCount*symbolSize) {
		return fmt.Errorf("symbol records point outside file data")
	}
	if !machORangeWithinData(len(data), stringOffset, stringSize) {
		return fmt.Errorf("symbol string table points outside file data")
	}
	if stringSize == 0 {
		if symbolCount > 0 {
			return fmt.Errorf("non-empty symbol table has an empty string table")
		}
		return nil
	}
	stringTable := data[int(stringOffset):int(stringOffset+stringSize)]
	for i := uint64(0); i < symbolCount; i++ {
		recordOffset := symbolOffset + i*symbolSize
		stringIndex := uint64(order.Uint32(data[int(recordOffset) : int(recordOffset)+4]))
		if stringIndex >= stringSize {
			return fmt.Errorf("symbol %d string index %d is outside string table", i, stringIndex)
		}
		nameData := stringTable[int(stringIndex):]
		nameLength := bytes.IndexByte(nameData, 0)
		if nameLength < 0 {
			nameLength = len(nameData)
		}
		if nameLength > maxMachOSymbolNameBytes {
			return fmt.Errorf("symbol %d name length %d exceeds limit %d", i, nameLength, maxMachOSymbolNameBytes)
		}
		if err := addMachOPreflightCount(&budget.decodedNameBytes, uint64(nameLength), maxMachODecodedNameBytes, "decoded symbol name bytes"); err != nil {
			return err
		}
	}
	return nil
}

func machORangeWithinData(dataLength int, offset, size uint64) bool {
	return offset <= uint64(dataLength) && size <= uint64(dataLength)-offset
}

func preflightMachOSegment(data, command []byte, order binary.ByteOrder, is64 bool, fileType macho.Type, commandIndex uint64, budget *machoPreflightBudget, mappings *machoPreflightMappings) error {
	baseSize := segment32CommandSize
	sectionSize := section32HeaderSize
	nsectOffset := 48
	segmentVMAddrOffset := 24
	segmentVMSizeOffset := 28
	segmentFileOffsetOffset := 32
	segmentFileSizeOffset := 36
	sectionVMAddrOffset := 32
	sectionDataSizeOffset := 36
	sectionDataOffsetOffset := 40
	sectionRelocOffset := 48
	nrelocOffset := 52
	sectionFlagsOffset := 56
	segmentMaxProtOffset := 40
	segmentInitProtOffset := 44
	if is64 {
		baseSize = segment64CommandSize
		sectionSize = section64HeaderSize
		nsectOffset = 64
		segmentVMSizeOffset = 32
		segmentFileOffsetOffset = 40
		segmentFileSizeOffset = 48
		sectionDataSizeOffset = 40
		sectionDataOffsetOffset = 48
		sectionRelocOffset = 56
		nrelocOffset = 60
		sectionFlagsOffset = 64
		segmentMaxProtOffset = 56
		segmentInitProtOffset = 60
	}
	if len(command) < baseSize {
		return fmt.Errorf("segment command is truncated")
	}
	segmentVMAddr := uint64(order.Uint32(command[segmentVMAddrOffset : segmentVMAddrOffset+4]))
	segmentVMSize := uint64(order.Uint32(command[segmentVMSizeOffset : segmentVMSizeOffset+4]))
	segmentFileOffset := uint64(order.Uint32(command[segmentFileOffsetOffset : segmentFileOffsetOffset+4]))
	segmentFileSize := uint64(order.Uint32(command[segmentFileSizeOffset : segmentFileSizeOffset+4]))
	if is64 {
		segmentVMAddr = order.Uint64(command[segmentVMAddrOffset : segmentVMAddrOffset+8])
		segmentVMSize = order.Uint64(command[segmentVMSizeOffset : segmentVMSizeOffset+8])
		segmentFileOffset = order.Uint64(command[segmentFileOffsetOffset : segmentFileOffsetOffset+8])
		segmentFileSize = order.Uint64(command[segmentFileSizeOffset : segmentFileSizeOffset+8])
	}
	segmentMaxProt := order.Uint32(command[segmentMaxProtOffset : segmentMaxProtOffset+4])
	segmentInitProt := order.Uint32(command[segmentInitProtOffset : segmentInitProtOffset+4])
	fileOnlyDebug := fileType != macho.TypeObj && segmentVMSize == 0 && segmentFileSize > 0 && segmentMaxProt == 0 && segmentInitProt == 0 && machoFixedNameIs(command[8:24], "__DWARF")
	if segmentFileSize > 0 {
		if segmentFileSize > segmentVMSize && !fileOnlyDebug {
			return fmt.Errorf("segment file size %d exceeds VM size %d", segmentFileSize, segmentVMSize)
		}
		if !machORangeWithinData(len(data), segmentFileOffset, segmentFileSize) {
			return fmt.Errorf("segment file range points outside file data")
		}
		if err := appendMachOPreflightRange(&mappings.segmentFileRanges, segmentFileOffset, segmentFileSize, commandIndex, -1, "segment file-offset range"); err != nil {
			return err
		}
		if !fileOnlyDebug {
			// A mapped segment with file data reserves its whole VM range,
			// including any zero-fill tail after those bytes. Linker-produced
			// __DWARF segments with no VM protections are file-only debug data.
			if err := appendMachOPreflightRange(&mappings.fileBackedSegmentVMRanges, segmentVMAddr, segmentVMSize, commandIndex, -1, "file-backed segment VM range"); err != nil {
				return err
			}
		}
	}
	nsect := uint64(order.Uint32(command[nsectOffset : nsectOffset+4]))
	if nsect > uint64((len(command)-baseSize)/sectionSize) {
		return fmt.Errorf("segment section table is truncated")
	}
	if err := addMachOPreflightCount(&budget.sections, nsect, maxMachOSections, "section count"); err != nil {
		return err
	}
	for i := uint64(0); i < nsect; i++ {
		offset := baseSize + int(i)*sectionSize
		if fileType != macho.TypeObj && !machoFixedNameEqual(command[8:24], command[offset+16:offset+32]) {
			return fmt.Errorf("section %d segment name does not match its owning segment", i)
		}
		sectionVMAddr := uint64(order.Uint32(command[offset+sectionVMAddrOffset : offset+sectionVMAddrOffset+4]))
		sectionDataSize := uint64(order.Uint32(command[offset+sectionDataSizeOffset : offset+sectionDataSizeOffset+4]))
		if is64 {
			sectionVMAddr = order.Uint64(command[offset+sectionVMAddrOffset : offset+sectionVMAddrOffset+8])
			sectionDataSize = order.Uint64(command[offset+sectionDataSizeOffset : offset+sectionDataSizeOffset+8])
		}
		sectionDataOffset := uint64(order.Uint32(command[offset+sectionDataOffsetOffset : offset+sectionDataOffsetOffset+4]))
		sectionType := order.Uint32(command[offset+sectionFlagsOffset:offset+sectionFlagsOffset+4]) & 0xff
		sectionFlags := order.Uint32(command[offset+sectionFlagsOffset : offset+sectionFlagsOffset+4])
		if fileOnlyDebug && sectionFlags&0x02000000 == 0 { // S_ATTR_DEBUG
			return fmt.Errorf("section %d in file-only __DWARF segment lacks S_ATTR_DEBUG", i)
		}
		if machoSectionHasFileData(sectionType) && sectionDataSize > 0 {
			if !machORangeWithinData(len(data), sectionDataOffset, sectionDataSize) {
				return fmt.Errorf("section %d data points outside file data", i)
			}
			if err := addMachOPreflightCount(&budget.sectionDataBytes, sectionDataSize, maxMachOSectionDataBytes, "section data bytes"); err != nil {
				return err
			}
			if err := appendMachOPreflightRange(&mappings.sectionFileRanges, sectionDataOffset, sectionDataSize, commandIndex, int64(i), "file-backed section file range"); err != nil {
				return fmt.Errorf("section %d: %w", i, err)
			}
			if !fileOnlyDebug {
				if err := appendMachOPreflightRange(&mappings.sectionVMRanges, sectionVMAddr, sectionDataSize, commandIndex, int64(i), "file-backed section virtual range"); err != nil {
					return fmt.Errorf("section %d: %w", i, err)
				}
			}
			segmentFileEnd := segmentFileOffset + segmentFileSize
			sectionFileEnd := sectionDataOffset + sectionDataSize
			if segmentFileSize == 0 || sectionDataOffset < segmentFileOffset || sectionFileEnd > segmentFileEnd {
				return fmt.Errorf("section %d data range is outside its owning segment file range", i)
			}
			if !fileOnlyDebug {
				segmentVMEnd := segmentVMAddr + segmentVMSize
				sectionVMEnd := sectionVMAddr + sectionDataSize
				if sectionVMAddr < segmentVMAddr || sectionVMEnd > segmentVMEnd {
					return fmt.Errorf("section %d virtual range is outside its owning segment VM range", i)
				}
				// Relocatable objects may interleave zero-fill VM space between later
				// file-backed sections, so their section offsets need not share one
				// affine segment mapping. Loaded images do not have that exception.
				if fileType != macho.TypeObj && sectionDataOffset-segmentFileOffset != sectionVMAddr-segmentVMAddr {
					return fmt.Errorf("section %d file and VM offsets do not match its owning segment mapping", i)
				}
			}
		}
		relocationOffset := uint64(order.Uint32(command[offset+sectionRelocOffset : offset+sectionRelocOffset+4]))
		nreloc := uint64(order.Uint32(command[offset+nrelocOffset : offset+nrelocOffset+4]))
		if err := addMachOPreflightCount(&budget.relocations, nreloc, maxMachORelocations, "relocation count"); err != nil {
			return err
		}
		if nreloc > ^uint64(0)/8 || !machORangeWithinData(len(data), relocationOffset, nreloc*8) {
			return fmt.Errorf("section %d relocation records point outside file data", i)
		}
	}
	return nil
}

func machoFixedNameEqual(first, second []byte) bool {
	if len(first) < 16 || len(second) < 16 {
		return false
	}
	first = first[:16]
	second = second[:16]
	if end := bytes.IndexByte(first, 0); end >= 0 {
		first = first[:end]
	}
	if end := bytes.IndexByte(second, 0); end >= 0 {
		second = second[:end]
	}
	return bytes.Equal(first, second)
}

func machoFixedNameIs(value []byte, want string) bool {
	var expected [16]byte
	copy(expected[:], want)
	return machoFixedNameEqual(value, expected[:])
}

func appendMachOPreflightRange(ranges *[]machoPreflightRange, start, size, commandIndex uint64, section int64, name string) error {
	if size == 0 {
		return nil
	}
	if start > ^uint64(0)-size {
		return fmt.Errorf("%s overflows", name)
	}
	*ranges = append(*ranges, machoPreflightRange{
		start:       start,
		end:         start + size,
		loadCommand: commandIndex,
		section:     section,
	})
	return nil
}

func validateMachONonOverlappingRanges(ranges []machoPreflightRange, name string) error {
	if len(ranges) < 2 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		if ranges[i].end != ranges[j].end {
			return ranges[i].end < ranges[j].end
		}
		if ranges[i].loadCommand != ranges[j].loadCommand {
			return ranges[i].loadCommand < ranges[j].loadCommand
		}
		return ranges[i].section < ranges[j].section
	})
	for i := 1; i < len(ranges); i++ {
		if ranges[i].start < ranges[i-1].end {
			return fmt.Errorf("%s overlap between %s and %s", name, machoPreflightRangeOwner(ranges[i-1]), machoPreflightRangeOwner(ranges[i]))
		}
	}
	return nil
}

func machoPreflightRangeOwner(item machoPreflightRange) string {
	if item.section >= 0 {
		return fmt.Sprintf("load command %d section %d", item.loadCommand, item.section)
	}
	return fmt.Sprintf("load command %d", item.loadCommand)
}

func machoSectionHasFileData(sectionType uint32) bool {
	switch sectionType {
	case 0x1, 0xc, 0x12: // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL.
		return false
	default:
		return true
	}
}

func addMachOPreflightCount(total *uint64, value, limit uint64, name string) error {
	if value > limit || *total > limit-value {
		return fmt.Errorf("aggregate %s exceeds limit %d", name, limit)
	}
	*total += value
	return nil
}

func architectures(data []byte) []string {
	if len(data) < 4 {
		return nil
	}
	isFat, slices, err := PreflightMachOSlices(data)
	if err != nil {
		return nil
	}
	if isFat {
		arches := make([]string, 0, len(slices))
		for _, slice := range slices {
			arches = append(arches, machoCPU(slice.CPU, slice.SubCPU))
		}
		return uniqueStrings(arches)
	}
	if file, err := machox.NewFile(bytes.NewReader(data)); err == nil {
		return []string{machoCPU(file.Cpu, file.SubCpu)}
	}
	return nil
}

func machoCPU(cpu macho.Cpu, sub uint32) string {
	base := ""
	switch cpu {
	case macho.Cpu386:
		base = "i386"
	case macho.CpuAmd64:
		base = "x86_64"
	case macho.CpuArm:
		base = "arm"
	case macho.CpuArm64:
		base = "arm64"
	case macho.CpuPpc:
		base = "ppc"
	case macho.CpuPpc64:
		base = "ppc64"
	default:
		base = cpu.String()
	}
	sub = cleanCPUSubtype(sub)
	if cpu == macho.CpuArm64 && sub == 2 {
		return "arm64e"
	}
	if cpu == macho.CpuAmd64 && sub == 8 {
		return "x86_64h"
	}
	if sub == 0 || ((cpu == macho.Cpu386 || cpu == macho.CpuAmd64) && sub == 3) {
		return base
	}
	return fmt.Sprintf("%s/%#x", base, sub)
}

func cleanCPUSubtype(sub uint32) uint32 {
	return sub & 0x00ffffff
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
