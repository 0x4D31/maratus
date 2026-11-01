package extract

import (
	"debug/macho"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	darwinAFINET  = 2
	darwinAFINET6 = 30
)

type machoStaticSocketAddress struct {
	Endpoint string
	Family   string
	VA       uint64
	Offset   int
	Evidence string
}

func nativeConnectUsesSockaddr(symbol string) bool {
	switch strings.TrimPrefix(symbol, "_") {
	case "connect", "connect$NOCANCEL":
		return true
	default:
		// connectx receives an sa_endpoints_t rather than a sockaddr pointer.
		return false
	}
}

func readMachOStaticSocketAddressIndexed(file *macho.File, index *machoSectionIndex, pointer uint64, indirect bool) (machoStaticSocketAddress, bool) {
	if indirect {
		resolved, ok := readPointerAtVAIndexed(file, index, pointer)
		if !ok {
			return machoStaticSocketAddress{}, false
		}
		pointer = resolved
	}
	for _, candidate := range normalizedMachOPointersIndexed(index, pointer) {
		section := index.containing(candidate, 2)
		if section == nil || !machoSectionHasFileData(section) || section.Flags&0x80000400 != 0 || section.Name == "__text" || strings.Contains(section.Name, "stub") {
			continue
		}
		header, err := readMachOSectionAt(section, candidate-section.Addr, 2)
		if err != nil || len(header) != 2 {
			continue
		}
		length, family := int(header[0]), header[1]
		var size int
		switch family {
		case darwinAFINET:
			size = 16
		case darwinAFINET6:
			size = 28
		default:
			continue
		}
		if length != size || index.containing(candidate, uint64(size)) != section {
			continue
		}
		data, err := readMachOSectionAt(section, candidate-section.Addr, size)
		if err != nil || len(data) != size {
			continue
		}
		port := binary.BigEndian.Uint16(data[2:4])
		var address netip.Addr
		familyName := "ipv4"
		if family == darwinAFINET {
			address = netip.AddrFrom4([4]byte(data[4:8]))
		} else {
			address = netip.AddrFrom16([16]byte(data[8:24]))
			familyName = "ipv6"
			if scope := binary.LittleEndian.Uint32(data[24:28]); scope != 0 {
				address = address.WithZone(strconv.FormatUint(uint64(scope), 10))
			}
		}
		offset, ok := machoSectionFileOffsetForVA(index, candidate)
		if !ok {
			continue
		}
		return machoStaticSocketAddress{
			Endpoint: netip.AddrPortFrom(address, port).String(),
			Family:   familyName,
			VA:       candidate,
			Offset:   offset,
		}, true
	}
	return machoStaticSocketAddress{}, false
}

func (context *machoCallContext) materializeSocketAddressEvidence(lookup *machoCallLookup, function machoFunction, scopeID string) {
	if context == nil || lookup == nil || context.SocketAddress.Endpoint == "" || context.SocketAddress.VA == 0 {
		return
	}
	context.SocketAddress.Evidence = lookup.graph.AddEvidence(machOEvidenceAt(lookup.content, context.SocketAddress.Offset, behavior.Evidence{
		NodeID: lookup.content.NodeID, ScopeID: scopeID, Logical: lookup.content.LogicalPath,
		VA: context.SocketAddress.VA, Function: function.Name, Arch: lookup.arch,
		Method: "macho-static-sockaddr", Kind: "socket-address",
		Value: context.SocketAddress.Family + " " + context.SocketAddress.Endpoint,
	}))
	if context.SocketAddress.Evidence == "" {
		lookup.graph.MarkWorkOmitted()
	}
}

func addMachOStaticSocketNetworkConnect(lookup *machoCallLookup, function machoFunction, symbol, callEvidence string, address machoStaticSocketAddress) bool {
	if lookup == nil || address.Endpoint == "" || address.Evidence == "" || !nativeConnectUsesSockaddr(symbol) {
		return false
	}
	operation := behavior.ModeledOperation{
		SubjectNodeID: lookup.content.NodeID,
		ScopeID:       lookup.functionScopeID(function),
		Kind:          behavior.OperationNetworkConnect,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			behavior.ResourceRoleRemoteDestination,
			behavior.NewResource(behavior.ResourceNetworkEndpoint, address.Endpoint),
			address.Evidence,
		)),
		Qualifiers: map[string]string{
			"address_family":   address.Family,
			"api":              strings.TrimPrefix(symbol, "_"),
			"resource_binding": "exact-static-sockaddr",
			"semantic_basis":   "exact-called-import-and-static-sockaddr",
		},
		EvidenceIDs:    []string{callEvidence, address.Evidence},
		Support:        behavior.SupportCorroborated,
		Execution:      executionContextForMachOFunction(lookup.content, function),
		Architecture:   lookup.arch,
		SourceFunction: function.Name,
	}
	applyMachOFunctionQualifiers(operation.Qualifiers, function, "function_")
	operationID := lookup.addOperation(operation)
	if operationID == "" {
		return false
	}
	implementation := apiNetworkImplementation(
		behavior.NetworkImplementationAPICall, lookup.content, operation.ScopeID, lookup.arch,
		operation.Execution, operation.Support, operationID, strings.TrimPrefix(symbol, "_"), callEvidence, true,
	)
	for _, property := range []string{"socket address family", "port", "sockaddr-to-IP binding"} {
		implementation.UnresolvedProperties = removeUnresolved(implementation.UnresolvedProperties, property)
	}
	implementation.EvidenceIDs = append(implementation.EvidenceIDs, address.Evidence)
	lookup.graph.AddNetworkImplementation(implementation)
	return true
}
