package extract

import (
	"debug/macho"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxMachOStaticArgvEntries = 16
	maxMachOStaticArgvBytes   = 16 << 10
)

type machoStaticArgument struct {
	Value         string
	SlotVA        uint64
	SlotOffset    int
	LiteralVA     uint64
	LiteralOffset int
}

func nativeProcessArgvIndex(symbol string) (int, bool) {
	switch strings.TrimPrefix(symbol, "_") {
	case "execv", "execve", "execvp":
		return 1, true
	case "execvP":
		// Darwin execvP(file, search_path, argv) puts the array after the
		// search-path string, unlike the other supported execv variants.
		return 2, true
	default:
		return 0, false
	}
}

func readMachOStaticArgvIndexed(file *macho.File, index *machoSectionIndex, pointer uint64) ([]machoStaticArgument, bool) {
	var result []machoStaticArgument
	matches := 0
	for _, candidate := range normalizedMachOPointersIndexed(index, pointer) {
		section := index.containing(candidate, 8)
		if section == nil || candidate%8 != 0 || !machoSectionHasFileData(section) || section.Flags&0x80000400 != 0 || section.Name == "__text" || strings.Contains(section.Name, "stub") {
			continue
		}
		arguments, ok := readMachOStaticArgvAt(file, index, candidate)
		if !ok {
			continue
		}
		matches++
		result = arguments
		if matches > 1 {
			return nil, false
		}
	}
	return result, matches == 1
}

func readMachOStaticArgvAt(file *macho.File, index *machoSectionIndex, arrayVA uint64) ([]machoStaticArgument, bool) {
	arraySection := index.containing(arrayVA, 8)
	if arraySection == nil {
		return nil, false
	}
	arguments := make([]machoStaticArgument, 0, maxMachOStaticArgvEntries)
	totalBytes := 0
	for position := 0; position <= maxMachOStaticArgvEntries; position++ {
		if uint64(position) > (^uint64(0)-arrayVA)/8 {
			return nil, false
		}
		slotVA := arrayVA + uint64(position)*8
		if index.containing(slotVA, 8) != arraySection {
			return nil, false
		}
		pointer, ok := readPointerAtVAIndexed(file, index, slotVA)
		if !ok {
			return nil, false
		}
		if pointer == 0 {
			return arguments, len(arguments) > 0
		}
		if position == maxMachOStaticArgvEntries {
			return nil, false
		}
		value, literalVA, literalOffset, ok := readCStringAtPointerLocationIndexed(file, index, pointer, 4096)
		if !ok || value == "" {
			return nil, false
		}
		totalBytes += len(value)
		if totalBytes > maxMachOStaticArgvBytes {
			return nil, false
		}
		slotOffset, ok := machoSectionFileOffsetForVA(index, slotVA)
		if !ok {
			return nil, false
		}
		arguments = append(arguments, machoStaticArgument{
			Value: value, SlotVA: slotVA, SlotOffset: slotOffset, LiteralVA: literalVA, LiteralOffset: literalOffset,
		})
	}
	return nil, false
}

func bindMachOStaticArgv(lookup *machoCallLookup, operation *behavior.ModeledOperation, arguments []machoStaticArgument) {
	if operation == nil || len(arguments) == 0 {
		return
	}
	values := make([]string, 0, len(arguments))
	evidenceIDs := make([]string, 0, 2*len(arguments))
	for index, argument := range arguments {
		slotID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.SlotOffset, behavior.Evidence{
			NodeID: lookup.content.NodeID, Logical: lookup.content.LogicalPath, VA: argument.SlotVA, Arch: lookup.arch,
			ScopeID: operation.ScopeID, Function: operation.SourceFunction,
			Method: "macho-argv-pointer", Kind: "argv-pointer", Value: fmt.Sprintf("argv[%d] -> %s", index, evidenceSnippet(argument.Value)),
		}))
		literalID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.LiteralOffset, behavior.Evidence{
			NodeID: lookup.content.NodeID, Logical: lookup.content.LogicalPath, VA: argument.LiteralVA, Arch: lookup.arch,
			ScopeID: operation.ScopeID, Function: operation.SourceFunction,
			Method: "macho-argv-literal", Kind: "argv-literal", Value: evidenceSnippet(argument.Value),
		}))
		if slotID == "" || literalID == "" {
			lookup.graph.MarkWorkOmitted()
			return
		}
		values = append(values, argument.Value)
		evidenceIDs = append(evidenceIDs, slotID, literalID)
	}
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maxMachOStaticArgvBytes {
		return
	}
	operation.EvidenceIDs = append(operation.EvidenceIDs, evidenceIDs...)
	operation.ResourceBindings = append(operation.ResourceBindings, behavior.Bind(
		behavior.ResourceRoleArguments,
		behavior.NewResource(behavior.ResourceCommand, string(encoded)),
		evidenceIDs...,
	))
	operation.Qualifiers["argument_binding"] = "exact-static-argv"
}

func applyMachOLocalAgentInvocation(operation *behavior.ModeledOperation, arguments []machoStaticArgument) {
	if operation == nil {
		return
	}
	executable, ok := operation.FirstBinding(behavior.ResourceRoleExecutable)
	if !ok || executable.Resource.Value == "" {
		return
	}
	fields := []string{executable.Resource.Value}
	// A C argv vector repeats the selected program name in argv[0]. Only the
	// remaining exact entries are command arguments.
	for index := 1; index < len(arguments); index++ {
		fields = append(fields, arguments[index].Value)
	}
	applyLocalAgentInvocationSemantics(operation, fields)
}
