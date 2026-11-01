package extract

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const maxMachOGoABIStringBytes = 4096

const machoGoSemanticCoverageDetail = "bounded ABIInternal pointer/length recovery is supported for exact static strings at selected direct Go standard-library calls; interfaces, slices and variadic argv, closures, indirect or dynamic calls, interprocedural values, stack spills, branches, and general control flow remain unsupported"

// machoGoStringArgument is an exact ABIInternal string value recovered at one
// direct Go callsite. Go strings are pointer/length pairs and are deliberately
// kept separate from the NUL-terminated C arguments used by imported calls.
type machoGoStringArgument struct {
	Value               string
	PointerReferenceVA  uint64
	PointerReferenceOff int
	LengthReferenceVA   uint64
	LengthReferenceOff  int
	LiteralVA           uint64
	LiteralOffset       int
	EvidenceIDs         []string
}

type machoGoCallContext struct {
	StringArguments [4]machoGoStringArgument
}

func arm64GoCallContext(fileSections *machoSectionIndex, textOffset uint32, textAddress uint64, callInstruction int, addresses map[uint32]arm64RegisterValue, integers map[uint32]machoRegisterInteger) machoGoCallContext {
	var context machoGoCallContext
	for stringIndex := range context.StringArguments {
		pointerRegister := uint32(stringIndex * 2)
		lengthRegister := pointerRegister + 1
		pointer, pointerOK := addresses[pointerRegister]
		length, lengthOK := integers[lengthRegister]
		if !pointerOK || !lengthOK || pointer.loadsMemory || callInstruction-pointer.instruction > 96 || callInstruction-length.instruction > 96 || length.value == 0 || length.value > maxMachOGoABIStringBytes {
			continue
		}
		value, literalVA, literalOffset, ok := readExactStringAtPointerLocationIndexed(fileSections, pointer.value, length.value)
		if !ok {
			continue
		}
		context.StringArguments[stringIndex] = machoGoStringArgument{
			Value:              value,
			PointerReferenceVA: textAddress + uint64(pointer.instruction), PointerReferenceOff: int(textOffset) + pointer.instruction,
			LengthReferenceVA: textAddress + uint64(length.instruction), LengthReferenceOff: int(textOffset) + length.instruction,
			LiteralVA: literalVA, LiteralOffset: literalOffset,
		}
	}
	return context
}

func x86GoCallContext(fileSections *machoSectionIndex, textOffset uint32, textAddress uint64, callInstruction int, addresses map[uint8]x86AddressValue, integers map[uint8]machoRegisterInteger) machoGoCallContext {
	// ABIInternal uses AX, BX, CX, DI, SI, R8, R9, R10, R11 in this order.
	registers := [...]uint8{0, 3, 1, 7, 6, 8, 9, 10, 11}
	var context machoGoCallContext
	for stringIndex := range context.StringArguments {
		pointer, pointerOK := addresses[registers[stringIndex*2]]
		length, lengthOK := integers[registers[stringIndex*2+1]]
		if !pointerOK || !lengthOK || pointer.value == 0 || length.value == 0 || callInstruction-pointer.instruction > 96 || callInstruction-length.instruction > 96 || length.value > maxMachOGoABIStringBytes {
			continue
		}
		value, literalVA, literalOffset, ok := readExactStringAtPointerLocationIndexed(fileSections, pointer.value, length.value)
		if !ok {
			continue
		}
		context.StringArguments[stringIndex] = machoGoStringArgument{
			Value:              value,
			PointerReferenceVA: textAddress + uint64(pointer.instruction), PointerReferenceOff: int(textOffset) + pointer.instruction,
			LengthReferenceVA: textAddress + uint64(length.instruction), LengthReferenceOff: int(textOffset) + length.instruction,
			LiteralVA: literalVA, LiteralOffset: literalOffset,
		}
	}
	return context
}

type machoGoUnaryCallSpec struct {
	name                string
	kind                behavior.OperationKind
	stringIndex         int
	resourceKind        behavior.ResourceKind
	role                behavior.ResourceRole
	unresolvedArguments string
}

var machoGoUnaryCallSpecs = map[string]machoGoUnaryCallSpec{
	"os.Chmod":        {name: "os.Chmod", kind: behavior.OperationFilePermissionModify, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.Chown":        {name: "os.Chown", kind: behavior.OperationFilePermissionModify, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.Lchown":       {name: "os.Lchown", kind: behavior.OperationFilePermissionModify, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.Lstat":        {name: "os.Lstat", kind: behavior.OperationFileMetadataQuery, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleSource},
	"os.Mkdir":        {name: "os.Mkdir", kind: behavior.OperationDirectoryCreate, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.MkdirAll":     {name: "os.MkdirAll", kind: behavior.OperationDirectoryCreate, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.ReadDir":      {name: "os.ReadDir", kind: behavior.OperationFileEnumerate, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleSource},
	"os.ReadFile":     {name: "os.ReadFile", kind: behavior.OperationFileRead, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleSource},
	"os.Remove":       {name: "os.Remove", kind: behavior.OperationFileDelete, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.RemoveAll":    {name: "os.RemoveAll", kind: behavior.OperationFileDelete, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleTarget},
	"os.Stat":         {name: "os.Stat", kind: behavior.OperationFileMetadataQuery, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleSource},
	"os.WriteFile":    {name: "os.WriteFile", kind: behavior.OperationFileWrite, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleLocalOutput},
	"os.StartProcess": {name: "os.StartProcess", kind: behavior.OperationProcessExecute, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleExecutable, unresolvedArguments: "argv and process attributes"},
	"syscall.Exec":    {name: "syscall.Exec", kind: behavior.OperationProcessExecute, stringIndex: 0, resourceKind: behavior.ResourceFile, role: behavior.ResourceRoleExecutable, unresolvedArguments: "argv and environment"},
}

type machoGoLaunchConfiguration struct {
	caller              machoFunction
	executable          string
	operationID         string
	evidenceIDs         []string
	resourceEvidenceIDs []string
	nextOffset          int
}

func (context *machoGoCallContext) materializeStringArgumentEvidence(lookup *machoCallLookup, function machoFunction, scopeID string, index int) []string {
	if context == nil || lookup == nil || index < 0 || index >= len(context.StringArguments) {
		return nil
	}
	argument := &context.StringArguments[index]
	if argument.Value == "" || argument.PointerReferenceVA == 0 || argument.LengthReferenceVA == 0 || argument.LiteralVA == 0 {
		return nil
	}
	pointerID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.PointerReferenceOff, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
		VA: argument.PointerReferenceVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-go-abi-dataflow", Kind: "go-string-pointer-reference",
		Value: fmt.Sprintf("string%d pointer -> %s", index, evidenceSnippet(argument.Value)),
	}))
	lengthID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.LengthReferenceOff, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
		VA: argument.LengthReferenceVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-go-abi-dataflow", Kind: "go-string-length-reference",
		Value: fmt.Sprintf("string%d length=%d", index, len(argument.Value)),
	}))
	literalID := lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, argument.LiteralOffset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
		VA: argument.LiteralVA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-go-string-literal", Kind: "go-string-literal",
		Value: evidenceSnippet(argument.Value),
	}))
	if pointerID == "" || lengthID == "" || literalID == "" {
		lookup.graph.MarkWorkOmitted()
		argument.EvidenceIDs = nil
		return nil
	}
	argument.EvidenceIDs = []string{pointerID, lengthID, literalID}
	return append([]string(nil), argument.EvidenceIDs...)
}

func goFunctionMetadata(metadata string) bool {
	return metadata == "go-other" || metadata == "go-standard-library" || metadata == "go-runtime-compiler"
}

func addGoLocalCallSemanticsIndexed(lookup *machoCallLookup, caller, callee machoFunction, callVA uint64, context machoGoCallContext, nextOffset int) *machoGoLaunchConfiguration {
	if lookup == nil || !goFunctionMetadata(caller.Metadata) || callee.Metadata != "go-standard-library" || caller.Name == "" || callee.Name == "" {
		return nil
	}
	if callee.Name == "os/exec.Command" || callee.Name == "os/exec.CommandContext" {
		stringIndex := 0
		if callee.Name == "os/exec.CommandContext" {
			// context.Context is a two-register interface value before name.
			stringIndex = 1
		}
		argument := context.StringArguments[stringIndex]
		if argument.Value == "" {
			return nil
		}
		callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
		scopeID := lookup.functionScopeID(caller)
		argumentEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, stringIndex)
		if callEvidence == "" || len(argumentEvidence) == 0 {
			return nil
		}
		evidenceIDs := append([]string{callEvidence}, argumentEvidence...)
		operation := behavior.ModeledOperation{
			SubjectNodeID: lookup.content.NodeID, ScopeID: scopeID,
			Kind:             behavior.OperationProcessLaunchConfigure,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, argument.Value), argumentEvidence...)),
			EvidenceIDs:      evidenceIDs, Support: behavior.SupportCorroborated,
			Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
			Qualifiers: map[string]string{"api": callee.Name, "semantic_basis": "exact-go-pclntab-direct-call-and-abi-string", "argument_coverage": "executable-only", "unresolved_arguments": "variadic argv", "function_origin": caller.Metadata},
		}
		operationID := lookup.addOperation(operation)
		if operationID == "" {
			return nil
		}
		return &machoGoLaunchConfiguration{caller: caller, executable: argument.Value, operationID: operationID, evidenceIDs: evidenceIDs, resourceEvidenceIDs: argumentEvidence, nextOffset: nextOffset}
	}
	if callee.Name == "net.Dial" || callee.Name == "net.DialTimeout" {
		return addGoDialOperationIndexed(lookup, caller, callee, callVA, &context)
	}
	if callee.Name == "net.Interfaces" {
		callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
		if callEvidence == "" {
			return nil
		}
		lookup.addOperation(behavior.ModeledOperation{
			SubjectNodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(caller), Kind: behavior.OperationNetworkConfigurationQuery,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceConfiguration, "local network interfaces"))),
			EvidenceIDs:      []string{callEvidence}, Support: behavior.SupportCorroborated,
			Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
			Qualifiers: map[string]string{"api": callee.Name, "semantic_basis": "exact-go-pclntab-direct-call", "function_origin": caller.Metadata},
		})
		return nil
	}
	if callee.Name == "net/http.Get" || callee.Name == "net/http.Head" {
		return addGoHTTPConnectOperationIndexed(lookup, caller, callee, callVA, &context)
	}
	if callee.Name == "os.Rename" {
		return addGoRenameOperationIndexed(lookup, caller, callee, callVA, &context)
	}
	spec, ok := machoGoUnaryCallSpecs[callee.Name]
	if !ok || spec.name != callee.Name || spec.stringIndex < 0 || spec.stringIndex >= len(context.StringArguments) {
		return nil
	}
	argument := context.StringArguments[spec.stringIndex]
	if argument.Value == "" {
		return nil
	}
	callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
	scopeID := lookup.functionScopeID(caller)
	argumentEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, spec.stringIndex)
	if callEvidence == "" || len(argumentEvidence) == 0 {
		return nil
	}
	resource := behavior.NewResource(spec.resourceKind, argument.Value)
	if spec.resourceKind == behavior.ResourceFile {
		resource = classifiedFileResource(argument.Value)
	}
	qualifiers := map[string]string{"api": callee.Name, "semantic_basis": "exact-go-pclntab-direct-call-and-abi-string", "function_origin": caller.Metadata}
	if spec.unresolvedArguments != "" {
		qualifiers["argument_coverage"] = "executable-only"
		qualifiers["unresolved_arguments"] = spec.unresolvedArguments
	}
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: scopeID, Kind: spec.kind,
		ResourceBindings: behavior.Bindings(behavior.Bind(spec.role, resource, argumentEvidence...)),
		EvidenceIDs:      append([]string{callEvidence}, argumentEvidence...), Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
		Qualifiers: qualifiers,
	}
	if operation.Kind == behavior.OperationProcessExecute {
		applyLocalAgentInvocationSemantics(&operation, []string{argument.Value})
	}
	operationID := lookup.addOperation(operation)
	if operationID != "" && isNetworkOperationKind(operation.Kind) {
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, scopeID, lookup.arch,
			operation.Execution, operation.Support, operationID, callee.Name, callEvidence, false,
		))
	}
	return nil
}

func addGoHTTPConnectOperationIndexed(lookup *machoCallLookup, caller, callee machoFunction, callVA uint64, context *machoGoCallContext) *machoGoLaunchConfiguration {
	if context == nil || context.StringArguments[0].Value == "" {
		return nil
	}
	destination := context.StringArguments[0].Value
	parsed, err := url.Parse(destination)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		// A direct helper call with a relative, non-HTTP, or malformed URL can
		// fail before communication. Retain its exact call and string Features,
		// but do not promote it to a network operation.
		return nil
	}
	callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
	scopeID := lookup.functionScopeID(caller)
	destinationEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, 0)
	if callEvidence == "" || len(destinationEvidence) == 0 {
		return nil
	}
	evidenceIDs := append([]string{callEvidence}, destinationEvidence...)
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: scopeID, Kind: behavior.OperationNetworkConnect,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceURL, destination), destinationEvidence...)),
		EvidenceIDs:      evidenceIDs, Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
		Qualifiers: map[string]string{"api": callee.Name, "semantic_basis": "exact-go-pclntab-direct-call-and-http-url", "function_origin": caller.Metadata},
	}
	operationID := lookup.addOperation(operation)
	if operationID != "" {
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, scopeID, lookup.arch,
			operation.Execution, operation.Support, operationID, callee.Name, callEvidence, false,
		))
	}
	return nil
}

func addGoDialOperationIndexed(lookup *machoCallLookup, caller, callee machoFunction, callVA uint64, context *machoGoCallContext) *machoGoLaunchConfiguration {
	if context == nil || context.StringArguments[0].Value == "" || context.StringArguments[1].Value == "" {
		return nil
	}
	network := context.StringArguments[0].Value
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if _, _, err := net.SplitHostPort(context.StringArguments[1].Value); err != nil {
			return nil
		}
	case "ip", "ip4", "ip6":
	default:
		// In particular, do not classify a Unix-domain socket path as an
		// Internet endpoint. Unsupported and dynamic network kinds remain at
		// the exact direct-call Feature layer.
		return nil
	}
	callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
	scopeID := lookup.functionScopeID(caller)
	networkEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, 0)
	destinationEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, 1)
	if callEvidence == "" || len(networkEvidence) == 0 || len(destinationEvidence) == 0 {
		return nil
	}
	evidenceIDs := append(append([]string{callEvidence}, networkEvidence...), destinationEvidence...)
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: scopeID, Kind: behavior.OperationNetworkConnect,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleRemoteDestination, behavior.NewResource(behavior.ResourceNetworkEndpoint, context.StringArguments[1].Value), destinationEvidence...)),
		EvidenceIDs:      evidenceIDs, Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
		Qualifiers: map[string]string{"api": callee.Name, "network": network, "semantic_basis": "exact-go-pclntab-direct-call-and-abi-strings", "function_origin": caller.Metadata},
	}
	operationID := lookup.addOperation(operation)
	if operationID != "" {
		lookup.graph.AddNetworkImplementation(apiNetworkImplementation(
			behavior.NetworkImplementationAPICall, lookup.content, scopeID, lookup.arch,
			operation.Execution, operation.Support, operationID, callee.Name, callEvidence, false,
		))
	}
	return nil
}

func addGoRenameOperationIndexed(lookup *machoCallLookup, caller, callee machoFunction, callVA uint64, context *machoGoCallContext) *machoGoLaunchConfiguration {
	if context == nil || context.StringArguments[0].Value == "" || context.StringArguments[1].Value == "" {
		return nil
	}
	callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
	scopeID := lookup.functionScopeID(caller)
	fromEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, 0)
	toEvidence := context.materializeStringArgumentEvidence(lookup, caller, scopeID, 1)
	if callEvidence == "" || len(fromEvidence) == 0 || len(toEvidence) == 0 {
		return nil
	}
	from := classifiedFileResource(context.StringArguments[0].Value)
	to := classifiedFileResource(context.StringArguments[1].Value)
	lookup.addOperation(behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: scopeID, Kind: behavior.OperationFileMove,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, from, fromEvidence...),
			behavior.Bind(behavior.ResourceRoleTarget, to, toEvidence...),
		),
		EvidenceIDs: append(append([]string{callEvidence}, fromEvidence...), toEvidence...), Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
		Qualifiers: map[string]string{"api": callee.Name, "semantic_basis": "exact-go-pclntab-direct-call-and-abi-string", "function_origin": caller.Metadata},
	})
	return nil
}

func addMachOGoCallEvidence(lookup *machoCallLookup, caller, callee machoFunction, callVA uint64) string {
	return lookup.graph.AddEvidence(behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(caller), Logical: lookup.content.LogicalPath,
		VA: callVA, Function: caller.Name, Arch: lookup.arch,
		Method: "macho-go-abi-call", Kind: "go-direct-call", Value: caller.Name + " -> " + callee.Name,
	})
}

func addGoImmediateLaunchExecutionIndexed(lookup *machoCallLookup, pending *machoGoLaunchConfiguration, caller, callee machoFunction, callVA uint64) bool {
	if lookup == nil || pending == nil || caller.Name != pending.caller.Name || !goFunctionMetadata(caller.Metadata) || callee.Metadata != "go-standard-library" {
		return false
	}
	method := callee.Name
	if !strings.HasPrefix(method, "os/exec.(*Cmd).") {
		return false
	}
	switch strings.TrimPrefix(method, "os/exec.(*Cmd).") {
	case "CombinedOutput", "Output", "Run", "Start":
	default:
		return false
	}
	callEvidence := addMachOGoCallEvidence(lookup, caller, callee, callVA)
	if callEvidence == "" {
		return false
	}
	evidenceIDs := append(append([]string(nil), pending.evidenceIDs...), callEvidence)
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID, ScopeID: lookup.functionScopeID(caller), Kind: behavior.OperationProcessExecute,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, pending.executable), pending.resourceEvidenceIDs...)),
		EvidenceIDs:      evidenceIDs, Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch, SourceFunction: caller.Name,
		Qualifiers: map[string]string{"api": method, "semantic_basis": "exact-adjacent-go-command-return-receiver", "argument_coverage": "executable-only", "unresolved_arguments": "variadic argv", "function_origin": caller.Metadata},
	}
	applyLocalAgentInvocationSemantics(&operation, []string{pending.executable})
	operationID := lookup.addOperation(operation)
	if operationID == "" {
		return false
	}
	lookup.graph.AddRelation(behavior.OperationRelation{
		Kind:        behavior.RelationPrecedes,
		From:        behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, pending.operationID),
		To:          behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, operationID),
		EvidenceIDs: evidenceIDs, Support: behavior.SupportCorroborated,
		Execution: executionContextForMachOFunction(lookup.content, caller), Architecture: lookup.arch,
	})
	return true
}
