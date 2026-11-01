package report

import (
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

type networkPresentationRecord struct {
	SubjectNodeID      string
	OperationIDs       []string
	Caller             string
	HTTPStack          string
	TLSOwner           string
	TLSLinkage         string
	Family             string
	Direction          string
	Destinations       []string
	Security           []string
	Unresolved         []string
	EvidenceIDs        []string
	ImplementationKind behavior.NetworkImplementationKind
	ObservableKey      string
	Support            behavior.Support
}

func networkPresentationRecords(rep Report) []networkPresentationRecord {
	operations := operationsByID(rep.Operations)
	linkedOperations := make(map[string]bool)
	records := make([]networkPresentationRecord, 0, len(rep.NetworkImplementations)+len(rep.Features))
	for _, observation := range rep.NetworkImplementations {
		record := networkPresentationRecord{
			SubjectNodeID:      observation.SubjectNodeID,
			OperationIDs:       append([]string(nil), observation.OperationIDs...),
			Caller:             observation.APIOrTool,
			HTTPStack:          observation.HTTPImplementation,
			TLSOwner:           observation.TLSProvider,
			TLSLinkage:         string(observation.TLSProviderBasis),
			Family:             observation.TLSProfileFamily,
			Security:           networkSecurityPropertyLabels(observation.SecurityProperties),
			Unresolved:         append([]string(nil), observation.UnresolvedProperties...),
			EvidenceIDs:        append([]string(nil), observation.EvidenceIDs...),
			ImplementationKind: observation.Kind,
			Support:            observation.Support,
		}
		if record.Caller == "" {
			record.Caller = string(observation.Kind)
		}
		record.Destinations = networkDestinationsForOperations(record.OperationIDs, operations)
		for _, operationID := range record.OperationIDs {
			linkedOperations[operationID] = true
		}
		records = append(records, record)
	}
	for _, operation := range rep.Operations {
		if linkedOperations[operation.ID] || !isNetworkOperation(operation.Kind) {
			continue
		}
		records = append(records, networkPresentationRecord{
			SubjectNodeID: operation.SubjectNodeID,
			OperationIDs:  []string{operation.ID},
			Caller:        string(operation.Kind),
			Direction:     networkOperationDirection(operation.Kind),
			Destinations:  networkDestinationsForOperations([]string{operation.ID}, operations),
			EvidenceIDs:   append([]string(nil), operation.EvidenceIDs...),
			Support:       operation.Support,
		})
	}

	scoped := make(map[string]bool)
	for _, feature := range rep.Features {
		if !isNetworkObservableFeature(feature) || feature.ScopeID == "" {
			continue
		}
		scoped[networkObservableIdentity(feature)] = true
	}
	for _, feature := range rep.Features {
		if !isNetworkObservableFeature(feature) || feature.Value == "" {
			continue
		}
		if feature.ScopeID == "" && scoped[networkObservableIdentity(feature)] {
			continue
		}
		records = append(records, networkPresentationRecord{
			SubjectNodeID: feature.NodeID,
			Caller:        "Feature " + feature.Key,
			Destinations:  []string{feature.Value},
			EvidenceIDs:   append([]string(nil), feature.EvidenceIDs...),
			ObservableKey: feature.Key,
			Support:       feature.Support,
		})
	}
	return records
}

func networkDirectionForOperations(ids []string, operations map[string]behavior.ModeledOperation) string {
	direction := ""
	for _, id := range ids {
		operation, ok := operations[id]
		if !ok || !isNetworkOperation(operation.Kind) {
			continue
		}
		candidate := networkOperationDirection(operation.Kind)
		if direction != "" && candidate != direction {
			return "mixed"
		}
		direction = candidate
	}
	return direction
}

func isNetworkOperation(kind behavior.OperationKind) bool {
	switch kind {
	case behavior.OperationNetworkConnect, behavior.OperationNetworkDownload, behavior.OperationNetworkUpload:
		return true
	default:
		return false
	}
}

func networkOperationDirection(kind behavior.OperationKind) string {
	switch kind {
	case behavior.OperationNetworkDownload:
		return "download"
	case behavior.OperationNetworkUpload:
		return "upload"
	case behavior.OperationNetworkConnect:
		return "outbound"
	default:
		return ""
	}
}

func isNetworkObservableFeature(feature behavior.Feature) bool {
	switch feature.Key {
	case "network.url", "network.domain", "network.ip":
		return true
	default:
		return false
	}
}

func networkObservableIdentity(feature behavior.Feature) string {
	return semanticIdentityKey(feature.NodeID, feature.Architecture, feature.Key, feature.Value)
}

func networkSecurityPropertyLabels(properties []behavior.NetworkSecurityProperty) []string {
	labels := make([]string, 0, len(properties))
	for _, property := range properties {
		switch property {
		case behavior.NetworkSecurityTLSCertificateVerificationDisabled:
			labels = append(labels, "TLS certificate verification disabled")
		default:
			labels = append(labels, string(property))
		}
	}
	sort.Strings(labels)
	return labels
}

func uniqueNetworkImplementations(items []behavior.NetworkImplementationObservation) []behavior.NetworkImplementationObservation {
	byKey := make(map[string]int, len(items))
	out := make([]behavior.NetworkImplementationObservation, 0, len(items))
	for _, item := range items {
		security := make([]string, len(item.SecurityProperties))
		for index := range item.SecurityProperties {
			security[index] = string(item.SecurityProperties[index])
		}
		key := semanticIdentityKey(
			string(item.Kind), item.SubjectNodeID, item.ScopeID, item.Architecture,
			item.APIOrTool, item.HTTPImplementation, item.TLSProvider, string(item.TLSProviderBasis),
			item.TLSProfileFamily, string(item.Support), executionContextIdentityKey(item.Execution),
			semanticIdentityKey(security...), semanticIdentityKey(sortedStrings(item.OperationIDs)...),
			semanticIdentityKey(sortedStrings(item.UnresolvedProperties)...),
		)
		if index, exists := byKey[key]; exists {
			out[index].EvidenceIDs = sortedStrings(append(out[index].EvidenceIDs, item.EvidenceIDs...))
			continue
		}
		byKey[key] = len(out)
		item.OperationIDs = sortedStrings(item.OperationIDs)
		item.UnresolvedProperties = sortedStrings(item.UnresolvedProperties)
		item.EvidenceIDs = sortedStrings(item.EvidenceIDs)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i].ID, out[j].ID) < 0
	})
	return out
}
