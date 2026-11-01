package extract

import (
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	machOObjCArray64RecordSize = 24
	maxMachOObjCArrayEntries   = 16
	maxMachOObjCArrayBytes     = 16 << 10
)

type machoObjCStringArrayElement struct {
	String     machoCallStringArgument
	SlotVA     uint64
	SlotOffset int
}

type machoObjCStringArray struct {
	ReferenceVA    uint64
	ReferenceOff   int
	ObjectVA       uint64
	ObjectOffset   int
	DataVA         uint64
	DataOffset     int
	Elements       []machoObjCStringArrayElement
	EvidenceIDs    []string
	Representation string
}

func objcCFStringArrayAtTargetLocationIndexed(file *macho.File, reader *machoCFStringReader, target uint64, loadsMemory bool) (machoObjCStringArray, bool) {
	if file == nil || file.ByteOrder == nil || reader == nil || reader.index == nil {
		return machoObjCStringArray{}, false
	}
	sections := reader.index
	if loadsMemory {
		pointer, ok := readPointerAtVAIndexed(file, sections, target)
		if !ok {
			return machoObjCStringArray{}, false
		}
		target = pointer
	}
	var result machoObjCStringArray
	matches := 0
	for _, candidate := range normalizedMachOPointersIndexed(sections, target) {
		objectSection := sections.namedContaining(candidate, machOObjCArray64RecordSize, "__objc_arrayobj")
		if objectSection == nil || (candidate-objectSection.Addr)%machOObjCArray64RecordSize != 0 {
			continue
		}
		record, err := readMachOSectionAt(objectSection, candidate-objectSection.Addr, machOObjCArray64RecordSize)
		if err != nil || len(record) != machOObjCArray64RecordSize {
			continue
		}
		count := file.ByteOrder.Uint64(record[8:16])
		dataPointer := file.ByteOrder.Uint64(record[16:24])
		if count == 0 || count > maxMachOObjCArrayEntries || count > ^uint64(0)/8 {
			continue
		}
		array, ok := readMachOObjCStringArrayData(file, reader, dataPointer, int(count))
		if !ok {
			continue
		}
		objectOffset, ok := machoSectionFileOffsetForVA(sections, candidate)
		if !ok {
			continue
		}
		array.ObjectVA = candidate
		array.ObjectOffset = objectOffset
		array.Representation = "static-nsconstantarray"
		matches++
		result = array
		if matches > 1 {
			return machoObjCStringArray{}, false
		}
	}
	return result, matches == 1
}

func readMachOObjCStringArrayData(file *macho.File, reader *machoCFStringReader, pointer uint64, count int) (machoObjCStringArray, bool) {
	if count <= 0 || count > maxMachOObjCArrayEntries {
		return machoObjCStringArray{}, false
	}
	sections := reader.index
	var result machoObjCStringArray
	matches := 0
	for _, candidate := range normalizedMachOPointersIndexed(sections, pointer) {
		byteCount := uint64(count) * 8
		dataSection := sections.namedContaining(candidate, byteCount, "__objc_arraydata")
		if dataSection == nil || candidate%8 != 0 {
			continue
		}
		elements := make([]machoObjCStringArrayElement, 0, count)
		totalBytes := 0
		valid := true
		for index := 0; index < count; index++ {
			slotVA := candidate + uint64(index)*8
			valuePointer, ok := readPointerAtVAIndexed(file, sections, slotVA)
			if !ok {
				valid = false
				break
			}
			argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, valuePointer, false)
			if !ok {
				valid = false
				break
			}
			totalBytes += len(argument.Value)
			if totalBytes > maxMachOObjCArrayBytes {
				valid = false
				break
			}
			slotOffset, ok := machoSectionFileOffsetForVA(sections, slotVA)
			if !ok {
				valid = false
				break
			}
			elements = append(elements, machoObjCStringArrayElement{String: argument, SlotVA: slotVA, SlotOffset: slotOffset})
		}
		if !valid {
			continue
		}
		dataOffset, ok := machoSectionFileOffsetForVA(sections, candidate)
		if !ok {
			continue
		}
		matches++
		result = machoObjCStringArray{DataVA: candidate, DataOffset: dataOffset, Elements: elements}
		if matches > 1 {
			return machoObjCStringArray{}, false
		}
	}
	return result, matches == 1
}

func (context *machoCallContext) setObjCStringArray(index int, array machoObjCStringArray) {
	if context == nil || index < 0 || index >= len(context.ObjCStringArrays) || len(array.Elements) == 0 {
		return
	}
	context.ObjCStringArrays[index] = array
}

func (context machoCallContext) objcStringArray(index int) machoObjCStringArray {
	if index < 0 || index >= len(context.ObjCStringArrays) {
		return machoObjCStringArray{}
	}
	return context.ObjCStringArrays[index]
}

func (context *machoCallContext) materializeObjCStringArrayEvidence(lookup *machoCallLookup, function machoFunction, scopeID string, positions ...int) {
	if context == nil || lookup == nil {
		return
	}
	for _, position := range positions {
		if position < 0 || position >= len(context.ObjCStringArrays) {
			continue
		}
		array := &context.ObjCStringArrays[position]
		if len(array.Elements) == 0 || array.ReferenceVA == 0 {
			continue
		}
		referenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, array.ReferenceOff, behavior.Evidence{
			NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
			VA: array.ReferenceVA, Function: function.Name, Arch: lookup.arch,
			Method: "macho-objc-array-dataflow", Kind: "objc-array-argument-reference",
			Value: fmt.Sprintf("arg%d -> static NSArray[%d]", position, len(array.Elements)),
		}))
		if referenceID == "" {
			lookup.graph.MarkWorkOmitted()
			array.EvidenceIDs = nil
			continue
		}
		array.EvidenceIDs = appendMachOObjCArrayEvidence(nil, referenceID)
		if array.ObjectVA != 0 && array.DataVA != 0 {
			objectID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, array.ObjectOffset, behavior.Evidence{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
				VA: array.ObjectVA, Function: function.Name, Arch: lookup.arch,
				Method: "macho-objc-array-object", Kind: "objc-array-object",
				Value: fmt.Sprintf("static NSArray[%d]", len(array.Elements)),
			}))
			if objectID == "" {
				lookup.graph.MarkWorkOmitted()
				array.EvidenceIDs = nil
				continue
			}
			array.EvidenceIDs = appendMachOObjCArrayEvidence(array.EvidenceIDs, objectID)
		}
		for index := range array.Elements {
			element := &array.Elements[index]
			slotID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, element.SlotOffset, behavior.Evidence{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
				VA: element.SlotVA, Function: function.Name, Arch: lookup.arch,
				Method: "macho-objc-array-element", Kind: "objc-array-element-pointer",
				Value: fmt.Sprintf("element[%d] -> %s", index, evidenceSnippet(element.String.Value)),
			}))
			literalID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, element.String.LiteralOffset, behavior.Evidence{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
				VA: element.String.LiteralVA, Function: function.Name, Arch: lookup.arch,
				Method: "macho-objc-array-element", Kind: "objc-array-element-cfstring",
				Value: evidenceSnippet(element.String.Value),
			}))
			backingID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, element.String.BackingOffset, behavior.Evidence{
				NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
				VA: element.String.BackingVA, Function: function.Name, Arch: lookup.arch,
				Method: "macho-objc-array-element", Kind: "objc-array-element-backing",
				Value: evidenceSnippet(element.String.Value),
			}))
			if slotID == "" || literalID == "" || backingID == "" {
				lookup.graph.MarkWorkOmitted()
				array.EvidenceIDs = nil
				break
			}
			element.String.EvidenceIDs = []string{slotID, literalID, backingID}
			array.EvidenceIDs = appendMachOObjCArrayEvidence(array.EvidenceIDs, element.String.EvidenceIDs...)
		}
	}
}

type machoObjCReceiverValue struct {
	Identity          string
	Class             string
	OriginEvidenceIDs []string
	ReferenceVA       uint64
	ReferenceOff      int
	Instruction       int
	StringArray       machoObjCStringArray
}

type machoObjCClassValue struct {
	Name         string
	Instruction  int
	ReferenceVA  uint64
	ReferenceOff int
	SlotVA       uint64
}

func objcClassNameFromImportedSymbol(symbol string) (string, bool) {
	const prefix = "_OBJC_CLASS_$_"
	class := strings.TrimPrefix(symbol, prefix)
	if class == symbol || !isMachOObjCClassIdentifier(class) {
		return "", false
	}
	return class, true
}

func copyMachOObjCClassState[Register machoRegisterIndex](classes map[Register]machoObjCClassValue, dst, src Register, instruction int) {
	if value, ok := classes[src]; ok {
		value.Instruction = instruction
		classes[dst] = value
	} else {
		delete(classes, dst)
	}
}

func clearMachOObjCClassState[Register machoRegisterIndex](classes map[Register]machoObjCClassValue) {
	for register := range classes {
		delete(classes, register)
	}
}

func preserveX86ObjCClassCalleeSaved(classes map[uint8]machoObjCClassValue) {
	for register := range classes {
		if register != 3 && register != 5 && (register < 12 || register > 15) {
			delete(classes, register)
		}
	}
}

func preserveArm64ObjCClassCalleeSaved(classes map[uint32]machoObjCClassValue) {
	for register := range classes {
		if register < 19 || register > 28 {
			delete(classes, register)
		}
	}
}

// swiftImportedObjCAllocatingInit recognizes the stable Swift mangling form
// for an imported Objective-C class's zero-argument allocating initializer.
// This is deliberately not a general Swift demangler: the length-prefixed
// class component and complete suffix must both match exactly.
func swiftImportedObjCAllocatingInit(symbol string) (string, bool) {
	if len(symbol) == 0 || len(symbol) > maxMachOSymbolDemangleInputBytes {
		return "", false
	}
	body, _, ok := swiftMangledBody(symbol)
	if !ok || !strings.HasPrefix(body, "So") {
		return "", false
	}
	body = body[2:]
	lengthEnd := 0
	for lengthEnd < len(body) && body[lengthEnd] >= '0' && body[lengthEnd] <= '9' {
		lengthEnd++
	}
	if lengthEnd == 0 || lengthEnd > 6 || body[0] == '0' {
		return "", false
	}
	length, err := strconv.Atoi(body[:lengthEnd])
	if err != nil || length <= 0 || length > 256 || lengthEnd+length > len(body) {
		return "", false
	}
	class := body[lengthEnd : lengthEnd+length]
	if body[lengthEnd+length:] != "CABycfC" || !isMachOObjCClassIdentifier(class) {
		return "", false
	}
	return class, true
}

func isMachOObjCClassIdentifier(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index, character := range []byte(value) {
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

type machoStackAddressValue struct {
	Offset      int64
	Instruction int
}

type machoObjCStackSlot struct {
	String machoCallStringArgument
}

func copyMachOStackAddressState[Register machoRegisterIndex](values map[Register]machoStackAddressValue, dst, src Register, instruction int) {
	if value, ok := values[src]; ok {
		value.Instruction = instruction
		values[dst] = value
	} else {
		delete(values, dst)
	}
}

func clearMachOStackAddressState[Register machoRegisterIndex](values map[Register]machoStackAddressValue) {
	for register := range values {
		delete(values, register)
	}
}

func clearMachOObjCStackSlots(values map[int64]machoObjCStackSlot) {
	for offset := range values {
		delete(values, offset)
	}
}

func objcStringArrayFromStack(address machoStackAddressValue, count uint64, slots map[int64]machoObjCStackSlot, referenceVA uint64, referenceOff int) (machoObjCStringArray, bool) {
	if count == 0 || count > maxMachOObjCArrayEntries {
		return machoObjCStringArray{}, false
	}
	array := machoObjCStringArray{
		ReferenceVA: referenceVA, ReferenceOff: referenceOff, Representation: "stack-cfstring-pointer-array",
		Elements: make([]machoObjCStringArrayElement, 0, int(count)),
	}
	totalBytes := 0
	for index := uint64(0); index < count; index++ {
		if index > uint64(^uint64(0)>>1)/8 {
			return machoObjCStringArray{}, false
		}
		offset := address.Offset + int64(index*8)
		slot, ok := slots[offset]
		if !ok || slot.String.Value == "" || slot.String.ReferenceVA == 0 {
			return machoObjCStringArray{}, false
		}
		totalBytes += len(slot.String.Value)
		if totalBytes > maxMachOObjCArrayBytes {
			return machoObjCStringArray{}, false
		}
		array.Elements = append(array.Elements, machoObjCStringArrayElement{
			String: slot.String, SlotVA: slot.String.ReferenceVA, SlotOffset: slot.String.ReferenceOff,
		})
	}
	return array, true
}

func arm64SPRelativeAddress(insn uint32) (register uint32, offset int64, ok bool) {
	if insn&0xff0003e0 != 0x910003e0 {
		return 0, 0, false
	}
	register = insn & 0x1f
	if register == 31 {
		return 0, 0, false
	}
	shift := (insn >> 22) & 0x3
	if shift > 1 {
		return 0, 0, false
	}
	value := uint64((insn >> 10) & 0xfff)
	if shift == 1 {
		value <<= 12
	}
	if value > uint64(^uint64(0)>>1) {
		return 0, 0, false
	}
	return register, int64(value), true
}

func arm64SPRelativePairStore(insn uint32) (first, second uint32, offset int64, ok bool) {
	if insn&0xffc003e0 != 0xa90003e0 {
		return 0, 0, 0, false
	}
	imm := int64(signExtend64(uint64((insn>>15)&0x7f), 7)) * 8
	first = insn & 0x1f
	second = (insn >> 10) & 0x1f
	if first == 31 || second == 31 {
		return 0, 0, 0, false
	}
	return first, second, imm, true
}

func arm64SPRelativeStore(insn uint32) (register uint32, offset int64, ok bool) {
	if insn&0xffc003e0 != 0xf90003e0 {
		return 0, 0, false
	}
	register = insn & 0x1f
	if register == 31 {
		return 0, 0, false
	}
	return register, int64((insn>>10)&0xfff) * 8, true
}

func x86FrameRelativeLEA(data []byte) (register uint8, offset int64, size int, ok bool) {
	if len(data) < 4 || data[0] < 0x48 || data[0] > 0x4f || data[1] != 0x8d {
		return 0, 0, 0, false
	}
	rex := data[0]
	modrm := data[2]
	mod := modrm >> 6
	base := (modrm & 7) | (rex&1)*8
	if base != 5 || mod != 1 && mod != 2 {
		return 0, 0, 0, false
	}
	register = ((modrm >> 3) & 7) | ((rex>>2)&1)*8
	if mod == 1 {
		if len(data) != 4 {
			return 0, 0, 0, false
		}
		return register, int64(int8(data[3])), 4, true
	}
	if len(data) != 7 {
		return 0, 0, 0, false
	}
	return register, int64(int32(binary.LittleEndian.Uint32(data[3:7]))), 7, true
}

func x86RegisterStackStore(data []byte, addresses map[uint8]machoStackAddressValue) (source uint8, offset int64, size int, ok bool) {
	if len(data) < 3 || data[0] < 0x48 || data[0] > 0x4f || data[1] != 0x89 {
		return 0, 0, 0, false
	}
	rex := data[0]
	modrm := data[2]
	mod := modrm >> 6
	base := (modrm & 7) | (rex&1)*8
	baseAddress, exists := addresses[base]
	if !exists || mod == 3 || modrm&7 == 4 {
		return 0, 0, 0, false
	}
	source = ((modrm >> 3) & 7) | ((rex>>2)&1)*8
	displacement := int64(0)
	switch mod {
	case 0:
		if len(data) != 3 || modrm&7 == 5 {
			return 0, 0, 0, false
		}
		size = 3
	case 1:
		if len(data) != 4 {
			return 0, 0, 0, false
		}
		displacement = int64(int8(data[3]))
		size = 4
	case 2:
		if len(data) != 7 {
			return 0, 0, 0, false
		}
		displacement = int64(int32(binary.LittleEndian.Uint32(data[3:7])))
		size = 7
	default:
		return 0, 0, 0, false
	}
	return source, baseAddress.Offset + displacement, size, true
}

type x86ImportedPointerValue struct {
	Symbol      string
	SlotVA      uint64
	Instruction int
}

func copyX86ImportedPointerState(values map[uint8]x86ImportedPointerValue, dst, src uint8, instruction int) {
	if value, ok := values[src]; ok {
		value.Instruction = instruction
		values[dst] = value
	} else {
		delete(values, dst)
	}
}

func clearX86ImportedPointerState(values map[uint8]x86ImportedPointerValue) {
	for register := range values {
		delete(values, register)
	}
}

func preserveX86ImportedCalleeSaved(values map[uint8]x86ImportedPointerValue) {
	for register := range values {
		if register != 3 && register != 5 && (register < 12 || register > 15) {
			delete(values, register)
		}
	}
}

func x86RegisterIndirectCall(data []byte) (register uint8, size int, ok bool) {
	index := 0
	rex := byte(0)
	if len(data) > 0 && data[0] >= 0x40 && data[0] <= 0x4f {
		rex = data[0]
		index = 1
	}
	if len(data) != index+2 || data[index] != 0xff {
		return 0, 0, false
	}
	modrm := data[index+1]
	if modrm>>6 != 3 || (modrm>>3)&7 != 2 {
		return 0, 0, false
	}
	register = modrm & 7
	if rex&1 != 0 {
		register += 8
	}
	return register, len(data), true
}

func newMachOObjCReceiverValue(lookup *machoCallLookup, function machoFunction, callVA uint64, callOffset, instructionOffset int, producer string, class machoObjCClassValue) (machoObjCReceiverValue, bool) {
	if lookup == nil || function.Name == "" || callVA == 0 || producer != "objc_alloc_init" && producer != "objc_allocWithZone" {
		return machoObjCReceiverValue{}, false
	}
	identity := function.Name + "@" + strconv.FormatUint(callVA, 16)
	evidenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, callOffset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Logical: lookup.content.LogicalPath,
		VA: callVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-objc-dataflow", Kind: "objc-object-origin",
		Value: function.Name + " -> " + producer + objcClassEvidenceSuffix(class.Name),
	}))
	if evidenceID == "" {
		return machoObjCReceiverValue{}, false
	}
	originEvidence := []string{evidenceID}
	if class.Name != "" && class.ReferenceVA != 0 {
		classEvidenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, class.ReferenceOff, behavior.Evidence{
			NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Logical: lookup.content.LogicalPath,
			VA: class.ReferenceVA, Function: function.Name, Arch: lookup.arch,
			Method: "macho-objc-class-dataflow", Kind: "objc-class-reference",
			Value: fmt.Sprintf("%s -> slot 0x%x -> %s", function.Name, class.SlotVA, class.Name),
		}))
		if classEvidenceID == "" {
			return machoObjCReceiverValue{}, false
		}
		originEvidence = appendMachOCorrelatedEvidence(originEvidence, classEvidenceID)
	}
	return machoObjCReceiverValue{
		Identity: identity, Class: class.Name, OriginEvidenceIDs: originEvidence,
		ReferenceVA: callVA, ReferenceOff: callOffset, Instruction: instructionOffset,
	}, true
}

func objcClassEvidenceSuffix(class string) string {
	if class == "" {
		return ""
	}
	return " -> " + class
}

func newMachOSwiftObjCConstructorReceiver(lookup *machoCallLookup, function, constructor machoFunction, callVA uint64, callOffset, instructionOffset int) (machoObjCReceiverValue, bool) {
	class, ok := swiftImportedObjCAllocatingInit(constructor.Name)
	if lookup == nil || function.Name == "" || callVA == 0 || !ok {
		return machoObjCReceiverValue{}, false
	}
	identity := function.Name + "@swift-objc-" + strconv.FormatUint(callVA, 16)
	evidenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, callOffset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Logical: lookup.content.LogicalPath,
		VA: callVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-swift-objc-dataflow", Kind: "objc-object-origin",
		Value: function.Name + " -> " + constructor.Name + " -> " + class,
	}))
	if evidenceID == "" {
		return machoObjCReceiverValue{}, false
	}
	return machoObjCReceiverValue{
		Identity: identity, Class: class, OriginEvidenceIDs: []string{evidenceID},
		ReferenceVA: callVA, ReferenceOff: callOffset, Instruction: instructionOffset,
	}, true
}

func newMachOObjCMessageReturnValue(lookup *machoCallLookup, function machoFunction, callVA uint64, callOffset, instructionOffset int, selector string, context machoCallContext) (machoObjCReceiverValue, bool) {
	if lookup == nil || function.Name == "" {
		return machoObjCReceiverValue{}, false
	}
	if selector == "init" && context.ObjCReceiver.Identity != "" {
		returned := context.ObjCReceiver
		returned.ReferenceVA = callVA
		returned.ReferenceOff = callOffset
		returned.Instruction = instructionOffset
		return returned, true
	}
	if selector != "arrayWithObjects:count:" {
		return machoObjCReceiverValue{}, false
	}
	array := context.objcStringArray(2)
	if len(array.Elements) == 0 || len(array.EvidenceIDs) == 0 {
		return machoObjCReceiverValue{}, false
	}
	identity := function.Name + "@array-" + strconv.FormatUint(callVA, 16)
	evidenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, callOffset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Logical: lookup.content.LogicalPath,
		VA: callVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-objc-dataflow", Kind: "objc-object-origin",
		Value: function.Name + " -> " + selector,
	}))
	if evidenceID == "" {
		return machoObjCReceiverValue{}, false
	}
	return machoObjCReceiverValue{
		Identity: identity, OriginEvidenceIDs: appendMachOCorrelatedEvidence([]string{evidenceID}, array.EvidenceIDs...),
		ReferenceVA: callVA, ReferenceOff: callOffset, Instruction: instructionOffset, StringArray: array,
	}, true
}

func initializedMachOObjCReceiver(lookup *machoCallLookup, function machoFunction, callVA uint64, callOffset, instructionOffset int, context machoCallContext) (machoObjCReceiverValue, bool) {
	if lookup == nil || function.Name == "" || context.ObjCReceiver.Identity == "" {
		return machoObjCReceiverValue{}, false
	}
	evidenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, callOffset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Logical: lookup.content.LogicalPath,
		VA: callVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-objc-dataflow", Kind: "objc-initializer-call",
		Value: function.Name + " -> init -> " + context.ObjCReceiver.Identity,
	}))
	if evidenceID == "" {
		return machoObjCReceiverValue{}, false
	}
	returned := context.ObjCReceiver
	returned.OriginEvidenceIDs = appendMachOCorrelatedEvidence(returned.OriginEvidenceIDs, evidenceID)
	returned.ReferenceVA = callVA
	returned.ReferenceOff = callOffset
	returned.Instruction = instructionOffset
	return returned, true
}

func objcOwnershipPassthrough(symbol string) bool {
	switch strings.TrimPrefix(symbol, "_") {
	case "objc_retain", "objc_retainAutoreleasedReturnValue", "objc_retainBlock", "objc_autoreleaseReturnValue":
		return true
	default:
		return false
	}
}

func objcOwnershipOnlyCall(symbol string) bool {
	plain := strings.TrimPrefix(symbol, "_")
	if objcOwnershipPassthrough(symbol) {
		return true
	}
	switch plain {
	case "objc_release", "objc_autorelease", "objc_autoreleasePoolPush", "objc_autoreleasePoolPop", "objc_storeStrong", "objc_destroyWeak", "objc_initWeak", "objc_copyWeak", "objc_moveWeak":
		return true
	default:
		return false
	}
}

func copyMachOObjCReceiverState[Register machoRegisterIndex](receivers map[Register]machoObjCReceiverValue, dst, src Register, instruction int, referenceVA uint64, referenceOff int) {
	if value, ok := receivers[src]; ok {
		value.Instruction = instruction
		value.ReferenceVA = referenceVA
		value.ReferenceOff = referenceOff
		receivers[dst] = value
	} else {
		delete(receivers, dst)
	}
}

func clearMachOObjCReceiverState[Register machoRegisterIndex](receivers map[Register]machoObjCReceiverValue) {
	for register := range receivers {
		delete(receivers, register)
	}
}

func preserveX86ObjCCalleeSaved(receivers map[uint8]machoObjCReceiverValue) {
	for register := range receivers {
		if register != 3 && register != 5 && (register < 12 || register > 15) {
			delete(receivers, register)
		}
	}
}

func preserveArm64ObjCCalleeSaved(receivers map[uint32]machoObjCReceiverValue) {
	for register := range receivers {
		if register < 19 || register > 28 {
			delete(receivers, register)
		}
	}
}

func (context *machoCallContext) setObjCReceiver(receiver machoObjCReceiverValue) {
	if context == nil || receiver.Identity == "" {
		return
	}
	context.ObjCReceiver = receiver
}

func (context *machoCallContext) materializeObjCReceiverEvidence(lookup *machoCallLookup, function machoFunction, scopeID string) []string {
	if context == nil || lookup == nil || context.ObjCReceiver.Identity == "" {
		return nil
	}
	evidence := appendMachOCorrelatedEvidence(nil, context.ObjCReceiver.OriginEvidenceIDs...)
	if context.ObjCReceiver.ReferenceVA == 0 {
		return evidence
	}
	referenceID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, context.ObjCReceiver.ReferenceOff, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
		VA: context.ObjCReceiver.ReferenceVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-objc-dataflow", Kind: "objc-receiver-reference",
		Value: "receiver -> " + context.ObjCReceiver.Identity,
	}))
	return appendMachOCorrelatedEvidence(evidence, referenceID)
}

type machoNSTaskReceiverState struct {
	PathConfigured   bool
	Path             machoCallStringArgument
	PathEvidence     []string
	Arguments        machoObjCStringArray
	ArgumentEvidence []string
}

func addOperationFromExactNSTaskReceiverIndexed(lookup *machoCallLookup, function machoFunction, selector, callEvidence string, context machoCallContext, receiverEvidence []string) bool {
	if lookup == nil || function.Name == "" || context.ObjCReceiver.Identity == "" {
		return false
	}
	state := lookup.nstaskReceivers[context.ObjCReceiver.Identity]
	if state == nil {
		state = &machoNSTaskReceiverState{}
		lookup.nstaskReceivers[context.ObjCReceiver.Identity] = state
	}
	switch selector {
	case "setLaunchPath:":
		state.PathConfigured = true
		state.Path = context.stringArgument(2)
		state.PathEvidence = appendMachOCorrelatedEvidence(nil, receiverEvidence...)
		state.PathEvidence = appendMachOCorrelatedEvidence(state.PathEvidence, callEvidence)
		state.PathEvidence = appendMachOCorrelatedEvidence(state.PathEvidence, state.Path.EvidenceIDs...)
		return false
	case "setArguments:":
		state.Arguments = context.objcStringArray(2)
		state.ArgumentEvidence = appendMachOCorrelatedEvidence(nil, receiverEvidence...)
		state.ArgumentEvidence = appendMachOCorrelatedEvidence(state.ArgumentEvidence, callEvidence)
		state.ArgumentEvidence = appendMachOCorrelatedEvidence(state.ArgumentEvidence, state.Arguments.EvidenceIDs...)
		return false
	case "launch":
		if !state.PathConfigured {
			return false
		}
	default:
		delete(lookup.nstaskReceivers, context.ObjCReceiver.Identity)
		return false
	}
	path := normalizeProcessLaunchPath(state.Path.Value)
	if !looksProcessLaunchPath(path) || len(state.Path.EvidenceIDs) == 0 {
		path = ""
	}
	resource := behavior.NewResource(behavior.ResourceFile, path)
	evidence := appendMachOCorrelatedEvidence(nil, state.PathEvidence...)
	evidence = appendMachOCorrelatedEvidence(evidence, state.ArgumentEvidence...)
	evidence = appendMachOCorrelatedEvidence(evidence, receiverEvidence...)
	evidence = appendMachOCorrelatedEvidence(evidence, callEvidence)
	receiverClass := context.ObjCReceiver.Class
	if receiverClass == "" {
		receiverClass = "unresolved"
	}
	qualifiers := map[string]string{
		"api": "NSTask", "receiver_identity": "exact-linear-object", "receiver_class": receiverClass,
		"semantic_basis": "exact-receiver-lifecycle", "resource_binding": "unresolved",
	}
	if path != "" {
		qualifiers["resource_binding"] = "exact-call-argument"
	}
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(function), Kind: behavior.OperationProcessExecute,
		ResourceBindings: requiredResourceBindings(behavior.OperationProcessExecute, resource), Qualifiers: qualifiers,
		EvidenceIDs: evidence, Support: behavior.SupportHeuristic,
		Execution: executionContextForMachOFunction(lookup.content, function), Architecture: lookup.arch, SourceFunction: function.Name,
	}
	if path != "" {
		operation.ResourceBindings = []behavior.ResourceBinding{behavior.Bind(
			behavior.ResourceRoleExecutable, resource, state.Path.EvidenceIDs...,
		)}
	}
	if receiverClass == "NSTask" && path != "" {
		operation.Support = behavior.SupportCorroborated
	}
	bindMachOObjCStringArrayArguments(&operation, state.Arguments)
	lookup.addOperation(operation)
	return true
}

func invalidateNSTaskReceiverArguments[Register machoRegisterIndex](lookup *machoCallLookup, receivers map[Register]machoObjCReceiverValue, argumentRegisters ...Register) {
	if lookup == nil {
		return
	}
	for _, register := range argumentRegisters {
		identity := receivers[register].Identity
		if identity != "" {
			delete(lookup.nstaskReceivers, identity)
		}
	}
}

func bindMachOObjCStringArrayArguments(operation *behavior.ModeledOperation, array machoObjCStringArray) {
	if operation == nil || len(array.Elements) == 0 || len(array.EvidenceIDs) == 0 {
		return
	}
	values := make([]string, 0, len(array.Elements))
	evidence := make([]string, 0, len(array.EvidenceIDs))
	for _, element := range array.Elements {
		if element.String.Value == "" || len(element.String.EvidenceIDs) == 0 {
			return
		}
		values = append(values, element.String.Value)
		evidence = appendMachOObjCArrayEvidence(evidence, element.String.EvidenceIDs...)
	}
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maxMachOObjCArrayBytes {
		return
	}
	operation.EvidenceIDs = appendMachOCorrelatedEvidence(operation.EvidenceIDs, array.EvidenceIDs...)
	operation.ResourceBindings = append(operation.ResourceBindings, behavior.Bind(
		behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, string(encoded)), evidence...,
	))
	operation.Qualifiers["argument_binding"] = "exact-static-nsarray"
	if array.Representation == "stack-cfstring-pointer-array" {
		operation.Qualifiers["argument_binding"] = "exact-stack-cfstring-array"
	}
	operation.Qualifiers["argument_count"] = strconv.Itoa(len(values))
}

func appendMachOObjCArrayEvidence(existing []string, additions ...string) []string {
	for _, addition := range additions {
		if len(existing) >= behavior.MaxResourceBindingEvidenceIDs {
			break
		}
		if addition == "" {
			continue
		}
		duplicate := false
		for _, current := range existing {
			if current == addition {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, addition)
		}
	}
	return existing
}

func objcReceiverQualifier(context machoCallContext) string {
	if context.ObjCReceiver.Identity != "" {
		return "exact-linear-object"
	}
	return "unresolved"
}
