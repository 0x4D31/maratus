package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestGoABISemanticsRecoverExactCommandExecutionAcrossArchitectures(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		t.Run(architecture, func(t *testing.T) {
			graph := extractGoCommandFixture(t, architecture, true, false)
			assertGoCommandOperations(t, graph, true)
		})
	}
}

func TestGoABIImmediateDecodersCoverCompilerLengthForms(t *testing.T) {
	for _, test := range []struct {
		name         string
		instruction  uint32
		wantRegister uint32
		wantValue    uint64
		want         bool
	}{
		{name: "arm64-orr-bitmask", instruction: 0xb2400fe1, wantRegister: 1, wantValue: 15, want: true},
		{name: "arm64-movz", instruction: 0xd2800321, wantRegister: 1, wantValue: 25, want: true},
		{name: "arm64-w-movz", instruction: 0x52800043, wantRegister: 3, wantValue: 2, want: true},
		{name: "arm64-w-movk-is-not-complete", instruction: 0x72800043},
		{name: "arm64-zero-register-destination", instruction: 0xb2400fff},
	} {
		t.Run(test.name, func(t *testing.T) {
			register, value, ok := arm64ImmediateRegister(test.instruction)
			if ok != test.want || ok && (register != test.wantRegister || value != test.wantValue) {
				t.Fatalf("decoded register=%d value=%d ok=%v", register, value, ok)
			}
		})
	}

	for _, test := range []struct {
		name         string
		instruction  []byte
		wantRegister uint8
		wantValue    uint64
		wantSize     int
		want         bool
	}{
		{name: "x86-imm32-r8", instruction: []byte{0x41, 0xb8, 0x19, 0, 0, 0}, wantRegister: 8, wantValue: 25, wantSize: 6, want: true},
		{name: "x86-imm64-rbx", instruction: []byte{0x48, 0xbb, 0x0f, 0, 0, 0, 0, 0, 0, 0}, wantRegister: 3, wantValue: 15, wantSize: 10, want: true},
		{name: "x86-truncated", instruction: []byte{0x48, 0xbb, 0x0f}},
	} {
		t.Run(test.name, func(t *testing.T) {
			register, value, size, ok := x86ImmediateRegister(test.instruction)
			if ok != test.want || ok && (register != test.wantRegister || value != test.wantValue || size != test.wantSize) {
				t.Fatalf("decoded register=%d value=%d size=%d ok=%v", register, value, size, ok)
			}
		})
	}
}

func TestGoABISemanticsDoNotPromoteNonAdjacentCommandUse(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		t.Run(architecture, func(t *testing.T) {
			graph := extractGoCommandFixture(t, architecture, true, true)
			assertGoCommandOperations(t, graph, false)
		})
	}
}

func TestGoABISemanticsRequireCompleteBoundedStringPair(t *testing.T) {
	sectionData := []byte("/tmp/maratus-inert")
	section := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__rodata", Addr: 0x3000, Size: uint64(len(sectionData)), Offset: 0x300},
		ReaderAt:      bytes.NewReader(sectionData),
	}
	index := newMachOSectionIndex(&macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}})

	tests := []struct {
		name      string
		addresses map[uint32]arm64RegisterValue
		integers  map[uint32]machoRegisterInteger
	}{
		{name: "pointer-only", addresses: map[uint32]arm64RegisterValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint32]machoRegisterInteger{}},
		{name: "length-only", addresses: map[uint32]arm64RegisterValue{}, integers: map[uint32]machoRegisterInteger{1: {value: uint64(len(sectionData)), instruction: 4}}},
		{name: "zero-length", addresses: map[uint32]arm64RegisterValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint32]machoRegisterInteger{1: {value: 0, instruction: 4}}},
		{name: "oversized", addresses: map[uint32]arm64RegisterValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint32]machoRegisterInteger{1: {value: maxMachOGoABIStringBytes + 1, instruction: 4}}},
		{name: "stale-pointer", addresses: map[uint32]arm64RegisterValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint32]machoRegisterInteger{1: {value: uint64(len(sectionData)), instruction: 100}}},
		{name: "memory-loaded-pointer", addresses: map[uint32]arm64RegisterValue{0: {value: 0x3000, instruction: 100, loadsMemory: true}}, integers: map[uint32]machoRegisterInteger{1: {value: uint64(len(sectionData)), instruction: 100}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := arm64GoCallContext(index, 0x100, 0x1000, 100, test.addresses, test.integers)
			if got := context.StringArguments[0].Value; got != "" {
				t.Fatalf("recovered incomplete or unsafe string %q", got)
			}
		})
	}
}

func TestX86GoABISemanticsRequireCompleteBoundedStringPair(t *testing.T) {
	sectionData := []byte("/tmp/maratus-inert")
	section := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__rodata", Addr: 0x3000, Size: uint64(len(sectionData)), Offset: 0x300},
		ReaderAt:      bytes.NewReader(sectionData),
	}
	index := newMachOSectionIndex(&macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}})

	tests := []struct {
		name      string
		addresses map[uint8]x86AddressValue
		integers  map[uint8]machoRegisterInteger
	}{
		{name: "pointer-only", addresses: map[uint8]x86AddressValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint8]machoRegisterInteger{}},
		{name: "length-only", addresses: map[uint8]x86AddressValue{}, integers: map[uint8]machoRegisterInteger{3: {value: uint64(len(sectionData)), instruction: 4}}},
		{name: "zero-length", addresses: map[uint8]x86AddressValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint8]machoRegisterInteger{3: {value: 0, instruction: 4}}},
		{name: "oversized", addresses: map[uint8]x86AddressValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint8]machoRegisterInteger{3: {value: maxMachOGoABIStringBytes + 1, instruction: 4}}},
		{name: "stale-pointer", addresses: map[uint8]x86AddressValue{0: {value: 0x3000, instruction: 0}}, integers: map[uint8]machoRegisterInteger{3: {value: uint64(len(sectionData)), instruction: 100}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := x86GoCallContext(index, 0x100, 0x1000, 100, test.addresses, test.integers)
			if got := context.StringArguments[0].Value; got != "" {
				t.Fatalf("recovered incomplete or unsafe string %q", got)
			}
		})
	}
}

func TestGoABICommandContextStringFollowsTwoRegisterInterface(t *testing.T) {
	literal := []byte("/usr/bin/printf")
	section := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__rodata", Addr: 0x3000, Size: uint64(len(literal)), Offset: 0x300},
		ReaderAt:      bytes.NewReader(literal),
	}
	index := newMachOSectionIndex(&macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}})
	arm := arm64GoCallContext(index, 0x100, 0x1000, 12,
		map[uint32]arm64RegisterValue{2: {value: 0x3000, instruction: 4}},
		map[uint32]machoRegisterInteger{3: {value: uint64(len(literal)), instruction: 8}},
	)
	x86 := x86GoCallContext(index, 0x100, 0x1000, 12,
		map[uint8]x86AddressValue{1: {value: 0x3000, instruction: 4}},
		map[uint8]machoRegisterInteger{7: {value: uint64(len(literal)), instruction: 8}},
	)
	if arm.StringArguments[1].Value != string(literal) || x86.StringArguments[1].Value != string(literal) || arm.StringArguments[0].Value != "" || x86.StringArguments[0].Value != "" {
		t.Fatalf("CommandContext registers: arm=%#v x86=%#v", arm.StringArguments, x86.StringArguments)
	}
}

func TestGoABISemanticsRecoverExactFileResourcesAcrossArchitectures(t *testing.T) {
	for _, architecture := range []string{"arm64", "x86_64"} {
		t.Run(architecture, func(t *testing.T) {
			graph := extractGoUnaryFixture(t, architecture)
			want := map[behavior.OperationKind]string{
				behavior.OperationFileRead:  "/tmp/maratus-input",
				behavior.OperationFileWrite: "/tmp/maratus-output",
			}
			if len(graph.Operations) != len(want) {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			for _, operation := range graph.Operations {
				expected, ok := want[operation.Kind]
				if !ok {
					t.Fatalf("unexpected operation %#v", operation)
				}
				binding := operation.ResourceBindings[0]
				if binding.Resource.Value != expected || operation.Support != behavior.SupportCorroborated || operation.Qualifiers["semantic_basis"] != "exact-go-pclntab-direct-call-and-abi-string" {
					t.Fatalf("operation = %#v", operation)
				}
			}
		})
	}
}

func TestGoABISemanticTableProducesOnlyDeclaredTypedOperations(t *testing.T) {
	for name, spec := range machoGoUnaryCallSpecs {
		t.Run(name, func(t *testing.T) {
			var graph behavior.Graph
			lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "arm64")
			context := machoGoCallContext{}
			context.StringArguments[spec.stringIndex] = testGoStringArgument("/tmp/maratus-inert")
			addGoLocalCallSemanticsIndexed(
				lookup,
				machoFunction{Name: "main.test", Start: 0x1000, End: 0x1100, Metadata: "go-other"},
				machoFunction{Name: name, Start: 0x2000, End: 0x2100, Metadata: "go-standard-library"},
				0x1010,
				context,
				20,
			)
			if len(graph.Operations) != 1 {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			operation := graph.Operations[0]
			if operation.Kind != spec.kind || operation.ResourceBindings[0].Role != spec.role || operation.ResourceBindings[0].Resource.Kind != spec.resourceKind || operation.ResourceBindings[0].Resource.Value != "/tmp/maratus-inert" || len(operation.ResourceBindings[0].EvidenceIDs) != 3 || operation.Qualifiers["function_origin"] != "go-other" {
				t.Fatalf("operation = %#v; spec = %#v", operation, spec)
			}
			if operation.Qualifiers["unresolved_arguments"] != spec.unresolvedArguments {
				t.Fatalf("unresolved arguments = %q; spec = %#v", operation.Qualifiers["unresolved_arguments"], spec)
			}
		})
	}
}

func TestGoABIDialRequiresExactInternetNetworkKind(t *testing.T) {
	for _, test := range []struct {
		name        string
		network     string
		destination string
		want        bool
	}{
		{name: "tcp", network: "tcp", destination: "example.test:443", want: true},
		{name: "udp6", network: "udp6", destination: "[2001:db8::1]:53", want: true},
		{name: "unix-domain", network: "unix", destination: "/tmp/maratus.sock"},
		{name: "tcp-missing-port", network: "tcp", destination: "example.test"},
		{name: "missing-network", destination: "example.test:443"},
		{name: "missing-destination", network: "tcp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "arm64")
			context := machoGoCallContext{}
			if test.network != "" {
				context.StringArguments[0] = testGoStringArgument(test.network)
			}
			if test.destination != "" {
				context.StringArguments[1] = testGoStringArgument(test.destination)
			}
			addGoLocalCallSemanticsIndexed(
				lookup,
				machoFunction{Name: "main.test", Start: 0x1000, End: 0x1100, Metadata: "go-other"},
				machoFunction{Name: "net.Dial", Start: 0x2000, End: 0x2100, Metadata: "go-standard-library"},
				0x1010,
				context,
				20,
			)
			if !test.want {
				if len(graph.Operations) != 0 {
					t.Fatalf("unsupported Dial form produced operations: %#v", graph.Operations)
				}
				return
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			binding := graph.Operations[0].ResourceBindings[0]
			if binding.Resource.Kind != behavior.ResourceNetworkEndpoint || binding.Resource.Value != test.destination || len(binding.EvidenceIDs) != 3 || graph.Operations[0].Qualifiers["network"] != test.network {
				t.Fatalf("Dial operation = %#v", graph.Operations[0])
			}
		})
	}
}

func TestGoABINetworkInterfacesEmitsNeutralConfigurationQuery(t *testing.T) {
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "arm64")
	addGoLocalCallSemanticsIndexed(
		lookup,
		machoFunction{Name: "main.test", Start: 0x1000, End: 0x1100, Metadata: "go-other"},
		machoFunction{Name: "net.Interfaces", Start: 0x2000, End: 0x2100, Metadata: "go-standard-library"},
		0x1010,
		machoGoCallContext{},
		20,
	)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConfigurationQuery || graph.Operations[0].RequiredResource().Kind != behavior.ResourceConfiguration || graph.Operations[0].Qualifiers["semantic_basis"] != "exact-go-pclntab-direct-call" {
		t.Fatalf("net.Interfaces operation = %#v", graph.Operations)
	}

	var negative behavior.Graph
	negativeLookup := newMachOCallLookup(&negative, artifact.Content{NodeID: "node-2", LogicalPath: "fixture"}, "arm64")
	addGoLocalCallSemanticsIndexed(
		negativeLookup,
		machoFunction{Name: "main.test", Metadata: "go-other"},
		machoFunction{Name: "example.net.Interfaces", Metadata: "go-other"},
		0x1010,
		machoGoCallContext{},
		20,
	)
	if len(negative.Operations) != 0 {
		t.Fatalf("lookalike Go function produced semantics: %#v", negative.Operations)
	}
}

func TestGoABIHTTPConnectRequiresAbsoluteHTTPURL(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination string
		want        bool
	}{
		{name: "https", destination: "https://example.test/path", want: true},
		{name: "http-ipv6", destination: "http://[2001:db8::1]:8080/path", want: true},
		{name: "relative", destination: "/relative/path"},
		{name: "file-url", destination: "file:///tmp/maratus"},
		{name: "missing-host", destination: "https:///path"},
		{name: "malformed", destination: "://bad"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "x86_64")
			context := machoGoCallContext{}
			context.StringArguments[0] = testGoStringArgument(test.destination)
			addGoLocalCallSemanticsIndexed(
				lookup,
				machoFunction{Name: "main.test", Start: 0x1000, End: 0x1100, Metadata: "go-other"},
				machoFunction{Name: "net/http.Get", Start: 0x2000, End: 0x2100, Metadata: "go-standard-library"},
				0x1010,
				context,
				20,
			)
			if !test.want {
				if len(graph.Operations) != 0 {
					t.Fatalf("unsupported HTTP URL produced operations: %#v", graph.Operations)
				}
				return
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect {
				t.Fatalf("operations = %#v", graph.Operations)
			}
			binding := graph.Operations[0].ResourceBindings[0]
			if binding.Resource.Kind != behavior.ResourceURL || binding.Resource.Value != test.destination || len(binding.EvidenceIDs) != 3 {
				t.Fatalf("HTTP operation = %#v", graph.Operations[0])
			}
		})
	}
}

func TestGoABIRenameRetainsExactSourceAndTarget(t *testing.T) {
	var graph behavior.Graph
	lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "x86_64")
	context := machoGoCallContext{}
	context.StringArguments[0] = testGoStringArgument("/tmp/maratus-from")
	context.StringArguments[1] = testGoStringArgument("/tmp/maratus-to")
	addGoLocalCallSemanticsIndexed(
		lookup,
		machoFunction{Name: "main.test", Start: 0x1000, End: 0x1100, Metadata: "go-other"},
		machoFunction{Name: "os.Rename", Start: 0x2000, End: 0x2100, Metadata: "go-standard-library"},
		0x1010,
		context,
		20,
	)
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileMove {
		t.Fatalf("operations = %#v", graph.Operations)
	}
	from, fromOK := graph.Operations[0].FirstBinding(behavior.ResourceRoleSource)
	to, toOK := graph.Operations[0].FirstBinding(behavior.ResourceRoleTarget)
	if !fromOK || !toOK || from.Resource.Value != "/tmp/maratus-from" || to.Resource.Value != "/tmp/maratus-to" {
		t.Fatalf("move bindings = from %#v to %#v", from, to)
	}
}

func TestGoABISemanticsRejectUntrustedFunctionProvenance(t *testing.T) {
	for _, test := range []struct {
		name   string
		caller machoFunction
		callee machoFunction
	}{
		{name: "non-go-caller", caller: machoFunction{Name: "main", Metadata: "macho-symbol"}, callee: machoFunction{Name: "os.ReadFile", Metadata: "go-standard-library"}},
		{name: "non-stdlib-target", caller: machoFunction{Name: "main.main", Metadata: "go-other"}, callee: machoFunction{Name: "os.ReadFile", Metadata: "go-other"}},
		{name: "name-collision", caller: machoFunction{Name: "main.main", Metadata: "go-other"}, callee: machoFunction{Name: "example.invalid/os.ReadFile", Metadata: "go-standard-library"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			lookup := newMachOCallLookup(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "fixture"}, "arm64")
			context := machoGoCallContext{}
			context.StringArguments[0] = testGoStringArgument("/tmp/maratus-inert")
			addGoLocalCallSemanticsIndexed(lookup, test.caller, test.callee, 0x1010, context, 20)
			if len(graph.Operations) != 0 {
				t.Fatalf("untrusted provenance produced operations: %#v", graph.Operations)
			}
		})
	}
}

func TestGoABISemanticsExposeBudgetOmissionWithoutPartialOperation(t *testing.T) {
	graph := extractGoCommandFixture(t, "arm64", true, false)
	if len(graph.Operations) != 2 {
		t.Fatalf("unlimited fixture operations = %#v", graph.Operations)
	}

	limited := behavior.Graph{EvidenceLimit: 2}
	extractGoCommandFixtureInto(t, "arm64", true, false, &limited)
	limited.FinalizeLimits()
	if len(limited.Operations) != 0 {
		t.Fatalf("partially evidenced operation was retained: %#v", limited.Operations)
	}
	if !slices.ContainsFunc(limited.Coverage, func(item behavior.Coverage) bool {
		return item.AnalysisArea == "behavior-ir" && item.Status == "partial"
	}) {
		t.Fatalf("missing explicit budget coverage: %#v", limited.Coverage)
	}
}

func TestGoCommandExecutionFeedsSharedLocalAgentSemantics(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-agent", LogicalPath: "fixture", Role: "executable"}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	caller := machoFunction{Name: "main.actions", Start: 0x1000, End: 0x1100, Metadata: "go-other"}
	command := machoFunction{Name: "os/exec.Command", Start: 0x5000, End: 0x5080, Metadata: "go-standard-library"}
	output := machoFunction{Name: "os/exec.(*Cmd).Output", Start: 0x5100, End: 0x5180, Metadata: "go-standard-library"}
	context := machoGoCallContext{}
	context.StringArguments[0] = testGoStringArgument("claude")
	pending := addGoLocalCallSemanticsIndexed(lookup, caller, command, 0x1010, context, 20)
	if pending == nil || !addGoImmediateLaunchExecutionIndexed(lookup, pending, caller, output, 0x1020) {
		t.Fatalf("Go command execution was not correlated: pending=%#v operations=%#v", pending, graph.Operations)
	}
	operation := findOperationWithClassification(graph.Operations, behavior.OperationProcessExecute, behavior.ResourceClassAgentRuntime)
	if operation == nil || operation.Support != behavior.SupportCorroborated || operation.Qualifiers["agent_product"] != "Claude Code" {
		t.Fatalf("Go agent execution did not feed shared semantics: %#v", graph.Operations)
	}
	executable, _ := operation.FirstBinding(behavior.ResourceRoleExecutable)
	if executable.Resource.Value != "" || operation.Qualifiers["path_resolution"] != "runtime PATH lookup not authenticated" {
		t.Fatalf("Go PATH selection was overclaimed: resource=%#v qualifiers=%#v", executable.Resource, operation.Qualifiers)
	}
}

func extractGoCommandFixture(t *testing.T, architecture string, complete, interrupt bool) behavior.Graph {
	t.Helper()
	var graph behavior.Graph
	extractGoCommandFixtureInto(t, architecture, complete, interrupt, &graph)
	return graph
}

func extractGoCommandFixtureInto(t *testing.T, architecture string, complete, interrupt bool, graph *behavior.Graph) {
	t.Helper()
	const (
		textVA    = uint64(0x1000)
		literalVA = uint64(0x3000)
		commandVA = uint64(0x5000)
		outputVA  = uint64(0x5100)
	)
	literal := []byte("/usr/bin/printf")
	file := goSemanticMachOFixture(literalVA, literal)
	functions := []machoFunction{
		{Name: "main.actions", Start: textVA, End: textVA + 0x100, Metadata: "go-other"},
		{Name: "os/exec.Command", Start: commandVA, End: commandVA + 0x80, Metadata: "go-standard-library"},
		{Name: "os/exec.(*Cmd).Output", Start: outputVA, End: outputVA + 0x80, Metadata: "go-standard-library"},
	}
	var data []byte
	switch architecture {
	case "arm64":
		data = appendArm64GoString(data, textVA, 0, 1, literalVA, uint64(len(literal)), complete)
		callOffset := len(data)
		data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(callOffset), commandVA))
		if interrupt {
			data = appendArm64Instruction(data, 0xd503201f) // nop: deliberately unmodeled boundary
		}
		callOffset = len(data)
		data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(callOffset), outputVA))
	case "x86_64":
		data = append(data, encodeTestX86RIPRelativeLEAToReg(0, textVA+uint64(len(data)), literalVA)...)
		if complete {
			data = appendX86Immediate(data, 3, uint32(len(literal)))
		}
		data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), commandVA)...)
		if interrupt {
			data = append(data, 0x90) // nop: deliberately invalidates pending receiver correlation
		}
		data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), outputVA)...)
	default:
		t.Fatalf("unsupported fixture architecture %q", architecture)
	}
	text := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: textVA, Size: uint64(len(data)), Offset: 0x100},
		ReaderAt:      bytes.NewReader(data),
	}
	file.Sections = append([]*macho.Section{text}, file.Sections...)
	content := artifact.Content{NodeID: "node-1", LogicalPath: "fixture", Role: "executable"}
	if architecture == "arm64" {
		extractArm64DirectCalls(graph, content, file, text, data, functions, nil, nil, architecture)
	} else {
		extractX86DirectCalls(graph, content, file, text, data, functions, nil, nil, architecture)
	}
}

func extractGoUnaryFixture(t *testing.T, architecture string) behavior.Graph {
	t.Helper()
	const (
		textVA      = uint64(0x1000)
		readVA      = uint64(0x3000)
		readCallVA  = uint64(0x5000)
		writeCallVA = uint64(0x5100)
	)
	readPath := []byte("/tmp/maratus-input")
	writePath := []byte("/tmp/maratus-output")
	file := goSemanticMachOFixture(readVA, append(append([]byte(nil), readPath...), writePath...))
	functions := []machoFunction{
		{Name: "main.actions", Start: textVA, End: textVA + 0x200, Metadata: "go-other"},
		{Name: "os.ReadFile", Start: readCallVA, End: readCallVA + 0x80, Metadata: "go-standard-library"},
		{Name: "os.WriteFile", Start: writeCallVA, End: writeCallVA + 0x80, Metadata: "go-standard-library"},
	}
	writePathVA := readVA + uint64(len(readPath))
	var data []byte
	switch architecture {
	case "arm64":
		data = appendArm64GoString(data, textVA, 0, 1, readVA, uint64(len(readPath)), true)
		data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(len(data)), readCallVA))
		data = appendArm64GoString(data, textVA, 0, 1, writePathVA, uint64(len(writePath)), true)
		data = appendArm64Instruction(data, encodeTestBL(textVA+uint64(len(data)), writeCallVA))
	case "x86_64":
		data = append(data, encodeTestX86RIPRelativeLEAToReg(0, textVA+uint64(len(data)), readVA)...)
		data = appendX86Immediate(data, 3, uint32(len(readPath)))
		data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), readCallVA)...)
		data = append(data, encodeTestX86RIPRelativeLEAToReg(0, textVA+uint64(len(data)), writePathVA)...)
		data = appendX86Immediate(data, 3, uint32(len(writePath)))
		data = append(data, encodeTestX86CALL(textVA+uint64(len(data)), writeCallVA)...)
	default:
		t.Fatalf("unsupported fixture architecture %q", architecture)
	}
	text := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__text", Addr: textVA, Size: uint64(len(data)), Offset: 0x100},
		ReaderAt:      bytes.NewReader(data),
	}
	file.Sections = append([]*macho.Section{text}, file.Sections...)
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "fixture", Role: "executable"}
	if architecture == "arm64" {
		extractArm64DirectCalls(&graph, content, file, text, data, functions, nil, nil, architecture)
	} else {
		extractX86DirectCalls(&graph, content, file, text, data, functions, nil, nil, architecture)
	}
	return graph
}

func assertGoCommandOperations(t *testing.T, graph behavior.Graph, expectExecution bool) {
	t.Helper()
	var configured, executed *behavior.ModeledOperation
	for index := range graph.Operations {
		operation := &graph.Operations[index]
		switch operation.Kind {
		case behavior.OperationProcessLaunchConfigure:
			configured = operation
		case behavior.OperationProcessExecute:
			executed = operation
		}
	}
	if configured == nil {
		t.Fatalf("missing configuration operation: %#v", graph.Operations)
		return
	}
	binding, ok := configured.FirstBinding(behavior.ResourceRoleExecutable)
	if !ok || binding.Resource.Value != "/usr/bin/printf" || len(binding.EvidenceIDs) != 3 || configured.Support != behavior.SupportCorroborated {
		t.Fatalf("configuration = %#v", configured)
	}
	if expectExecution {
		if executed == nil {
			t.Fatalf("missing execution operation: %#v", graph.Operations)
			return
		}
		executedBinding, executedBindingOK := executed.FirstBinding(behavior.ResourceRoleExecutable)
		if !executedBindingOK || len(executedBinding.EvidenceIDs) != 3 || len(graph.Relations) != 1 || graph.Relations[0].Kind != behavior.RelationPrecedes || graph.Relations[0].From.ID != configured.ID || graph.Relations[0].To.ID != executed.ID {
			t.Fatalf("execution or relation = operations %#v relations %#v", graph.Operations, graph.Relations)
		}
		return
	}
	if executed != nil || len(graph.Relations) != 0 {
		t.Fatalf("non-adjacent receiver was promoted: operations %#v relations %#v", graph.Operations, graph.Relations)
	}
}

func goSemanticMachOFixture(literalVA uint64, literal []byte) *macho.File {
	section := &macho.Section{
		SectionHeader: macho.SectionHeader{Seg: "__TEXT", Name: "__rodata", Addr: literalVA, Size: uint64(len(literal)), Offset: 0x300},
		ReaderAt:      bytes.NewReader(literal),
	}
	return &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}, ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}}
}

func appendArm64GoString(data []byte, textVA uint64, pointerRegister, lengthRegister uint32, literalVA, length uint64, includeLength bool) []byte {
	data = appendArm64Instruction(data, encodeTestADRP(pointerRegister, textVA+uint64(len(data)), literalVA))
	data = appendArm64Instruction(data, encodeTestADDImmediate(pointerRegister, pointerRegister, literalVA&0xfff))
	if includeLength {
		data = appendArm64Instruction(data, 0xd2800000|uint32(length&0xffff)<<5|(lengthRegister&0x1f))
	}
	return data
}

func appendArm64Instruction(data []byte, instruction uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], instruction)
	return append(data, raw[:]...)
}

func appendX86Immediate(data []byte, register uint8, value uint32) []byte {
	data = append(data, 0xb8+(register&0x7), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(data[len(data)-4:], value)
	return data
}

func testGoStringArgument(value string) machoGoStringArgument {
	return machoGoStringArgument{
		Value: value, PointerReferenceVA: 0x1010, PointerReferenceOff: 0x110,
		LengthReferenceVA: 0x1014, LengthReferenceOff: 0x114,
		LiteralVA: 0x3000, LiteralOffset: 0x300,
	}
}
