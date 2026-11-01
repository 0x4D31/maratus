package extract

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func TestReadMachOStaticSocketAddressIndexed(t *testing.T) {
	ipv4 := make([]byte, 16)
	ipv4[0], ipv4[1] = 16, darwinAFINET
	binary.BigEndian.PutUint16(ipv4[2:4], 443)
	copy(ipv4[4:8], []byte{203, 0, 113, 8})

	ipv6 := make([]byte, 28)
	ipv6[0], ipv6[1] = 28, darwinAFINET6
	binary.BigEndian.PutUint16(ipv6[2:4], 8443)
	copy(ipv6[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	for _, test := range []struct {
		name, endpoint, family string
		data                   []byte
	}{
		{name: "ipv4", data: ipv4, endpoint: "203.0.113.8:443", family: "ipv4"},
		{name: "ipv6", data: ipv6, endpoint: "[2001:db8::1]:8443", family: "ipv6"},
	} {
		t.Run(test.name, func(t *testing.T) {
			section := testMachOSection("__const", 0x2000, test.data)
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}}
			address, ok := readMachOStaticSocketAddressIndexed(file, newMachOSectionIndex(file), 0x2000, false)
			if !ok || address.Endpoint != test.endpoint || address.Family != test.family || address.VA != 0x2000 {
				t.Fatalf("address = %#v ok=%v", address, ok)
			}
		})
	}
}

func TestReadMachOStaticSocketAddressRejectsMalformedAndNeighboringStructures(t *testing.T) {
	valid := make([]byte, 16)
	valid[0], valid[1] = 16, darwinAFINET
	binary.BigEndian.PutUint16(valid[2:4], 80)
	copy(valid[4:8], []byte{127, 0, 0, 1})

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "truncated", data: valid[:8]},
		{name: "wrong length", data: func() []byte { out := bytes.Clone(valid); out[0] = 15; return out }()},
		{name: "unix socket", data: func() []byte { out := bytes.Clone(valid); out[1] = 1; return out }()},
		{name: "unknown family", data: func() []byte { out := bytes.Clone(valid); out[1] = 99; return out }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			section := testMachOSection("__const", 0x2000, test.data)
			file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{section}}
			if address, ok := readMachOStaticSocketAddressIndexed(file, newMachOSectionIndex(file), 0x2000, false); ok {
				t.Fatalf("malformed structure was accepted: %#v", address)
			}
		})
	}
	if nativeConnectUsesSockaddr("_connectx") || !nativeConnectUsesSockaddr("_connect") {
		t.Fatal("connect and connectx argument contracts were conflated")
	}
}

func TestMachOCalledConnectWithExactSockaddrCreatesBoundNetworkOperation(t *testing.T) {
	var graph behavior.Graph
	content := artifact.Content{NodeID: "node-1", LogicalPath: "client"}
	callEvidence := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "test", Kind: "call", Value: "connect", Arch: "arm64"})
	addressEvidence := graph.AddEvidence(behavior.Evidence{NodeID: content.NodeID, Logical: content.LogicalPath, Method: "test", Kind: "sockaddr", Value: "203.0.113.8:443", Arch: "arm64"})
	context := machoCallContext{SocketAddress: machoStaticSocketAddress{Endpoint: "203.0.113.8:443", Family: "ipv4", Evidence: addressEvidence}}
	addOperationFromCalledImportedSymbolWithContext(&graph, content, "_connect", "arm64", callEvidence, machoFunction{Name: "dial", Reachable: true}, context)

	if len(graph.Operations) != 2 {
		t.Fatalf("operations = %#v, want socket primitive and bound network operation", graph.Operations)
	}
	var network behavior.ModeledOperation
	for _, operation := range graph.Operations {
		if operation.Kind == behavior.OperationNetworkConnect {
			network = operation
		}
	}
	if network.RequiredResource().Value != "203.0.113.8:443" || network.Qualifiers["resource_binding"] != "exact-static-sockaddr" || network.Support != behavior.SupportCorroborated {
		t.Fatalf("network operation = %#v", network)
	}
	if len(graph.Network) != 1 || len(graph.Network[0].OperationIDs) != 1 || graph.Network[0].OperationIDs[0] != network.ID ||
		stringSliceContains(graph.Network[0].UnresolvedProperties, "destination") || stringSliceContains(graph.Network[0].UnresolvedProperties, "port") {
		t.Fatalf("network implementation = %#v", graph.Network)
	}
}

func TestNativeDecodersBindStaticSockaddrAcrossArchitectures(t *testing.T) {
	const endpoint = "203.0.113.8:443"
	sockaddr := make([]byte, 16)
	sockaddr[0], sockaddr[1] = 16, darwinAFINET
	binary.BigEndian.PutUint16(sockaddr[2:4], 443)
	copy(sockaddr[4:8], []byte{203, 0, 113, 8})

	t.Run("x86_64", func(t *testing.T) {
		textVA, sockaddrVA, stubVA := uint64(0x1000), uint64(0x2000), uint64(0x1100)
		data := make([]byte, 12)
		copy(data[0:3], []byte{0x48, 0x8d, 0x35}) // lea rsi,[rip+disp32]
		binary.LittleEndian.PutUint32(data[3:7], uint32(int64(sockaddrVA)-int64(textVA+7)))
		data[7] = 0xe8
		binary.LittleEndian.PutUint32(data[8:12], uint32(int64(stubVA)-int64(textVA+12)))
		text := testMachOSection("__text", textVA, data)
		file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{text, testMachOSection("__const", sockaddrVA, sockaddr)}}
		var graph behavior.Graph
		extractX86DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "client"}, file, text, data,
			[]machoFunction{{Name: "dial", Start: textVA, End: textVA + uint64(len(data))}}, map[uint64]string{stubVA: "_connect"}, nil, "x86_64")
		assertExactSockaddrNetworkOperation(t, graph.Operations, endpoint)
	})

	t.Run("arm64", func(t *testing.T) {
		textVA, sockaddrVA, stubVA := uint64(0x100000000), uint64(0x100010000), uint64(0x100000100)
		data := make([]byte, 12)
		binary.LittleEndian.PutUint32(data[0:4], encodeTestADRP(1, textVA, sockaddrVA))
		binary.LittleEndian.PutUint32(data[4:8], encodeTestADDImmediate(1, 1, sockaddrVA&0xfff))
		binary.LittleEndian.PutUint32(data[8:12], encodeTestBL(textVA+8, stubVA))
		text := testMachOSection("__text", textVA, data)
		file := &macho.File{ByteOrder: binary.LittleEndian, Sections: []*macho.Section{text, testMachOSection("__const", sockaddrVA, sockaddr)}}
		var graph behavior.Graph
		extractArm64DirectCalls(&graph, artifact.Content{NodeID: "node-1", LogicalPath: "client"}, file, text, data,
			[]machoFunction{{Name: "dial", Start: textVA, End: textVA + uint64(len(data))}}, map[uint64]string{stubVA: "_connect"}, nil, "arm64")
		assertExactSockaddrNetworkOperation(t, graph.Operations, endpoint)
	})
}

func assertExactSockaddrNetworkOperation(t *testing.T, operations []behavior.ModeledOperation, endpoint string) {
	t.Helper()
	for _, operation := range operations {
		if operation.Kind == behavior.OperationNetworkConnect && operation.RequiredResource().Value == endpoint {
			return
		}
	}
	t.Fatalf("no exact sockaddr network operation in %#v", operations)
}
