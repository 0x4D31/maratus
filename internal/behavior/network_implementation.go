package behavior

import "strings"

type NetworkImplementationKind string

const (
	NetworkImplementationToolInvocation   NetworkImplementationKind = "tool-invocation"
	NetworkImplementationRuntimeAPI       NetworkImplementationKind = "runtime-api"
	NetworkImplementationAPICall          NetworkImplementationKind = "api-call"
	NetworkImplementationAPIImport        NetworkImplementationKind = "api-import"
	NetworkImplementationDynamicLinkage   NetworkImplementationKind = "dynamic-linkage"
	NetworkImplementationDelegatedHandler NetworkImplementationKind = "delegated-handler"
)

var networkImplementationKinds = [...]NetworkImplementationKind{
	NetworkImplementationToolInvocation,
	NetworkImplementationRuntimeAPI,
	NetworkImplementationAPICall,
	NetworkImplementationAPIImport,
	NetworkImplementationDynamicLinkage,
	NetworkImplementationDelegatedHandler,
}

func NetworkImplementationKinds() []NetworkImplementationKind {
	return append([]NetworkImplementationKind(nil), networkImplementationKinds[:]...)
}

func ValidNetworkImplementationKind(kind NetworkImplementationKind) bool {
	for _, allowed := range networkImplementationKinds {
		if kind == allowed {
			return true
		}
	}
	return false
}

type TLSProviderBasis string

const (
	TLSProviderBasisDynamicLibrary  TLSProviderBasis = "dynamic-library"
	TLSProviderBasisOperatingSystem TLSProviderBasis = "operating-system"
	TLSProviderBasisDelegated       TLSProviderBasis = "delegated-process"
	TLSProviderBasisRuntimeSelected TLSProviderBasis = "runtime-selected"
	TLSProviderBasisToolRuntime     TLSProviderBasis = "tool-runtime"
)

var tlsProviderBases = [...]TLSProviderBasis{
	TLSProviderBasisDynamicLibrary,
	TLSProviderBasisOperatingSystem,
	TLSProviderBasisDelegated,
	TLSProviderBasisRuntimeSelected,
	TLSProviderBasisToolRuntime,
}

func TLSProviderBases() []TLSProviderBasis {
	return append([]TLSProviderBasis(nil), tlsProviderBases[:]...)
}

func ValidTLSProviderBasis(basis TLSProviderBasis) bool {
	if basis == "" {
		return true
	}
	for _, allowed := range tlsProviderBases {
		if basis == allowed {
			return true
		}
	}
	return false
}

type NetworkSecurityProperty string

const NetworkSecurityTLSCertificateVerificationDisabled NetworkSecurityProperty = "tls-certificate-verification-disabled"

var networkSecurityProperties = [...]NetworkSecurityProperty{
	NetworkSecurityTLSCertificateVerificationDisabled,
}

func NetworkSecurityProperties() []NetworkSecurityProperty {
	return append([]NetworkSecurityProperty(nil), networkSecurityProperties[:]...)
}

func ValidNetworkSecurityProperty(property NetworkSecurityProperty) bool {
	for _, allowed := range networkSecurityProperties {
		if property == allowed {
			return true
		}
	}
	return false
}

// NetworkImplementationObservation describes statically observed software that
// may implement a network operation. It is independent from both the operation
// itself and unlinked URL/domain/IP Features.
type NetworkImplementationObservation struct {
	ID                   string                    `json:"id"`
	Kind                 NetworkImplementationKind `json:"kind"`
	SubjectNodeID        string                    `json:"subject_node_id"`
	ScopeID              string                    `json:"scope_id,omitempty"`
	Architecture         string                    `json:"architecture,omitempty"`
	OperationIDs         []string                  `json:"operation_ids,omitempty"`
	APIOrTool            string                    `json:"api_or_tool,omitempty"`
	HTTPImplementation   string                    `json:"http_implementation,omitempty"`
	TLSProvider          string                    `json:"tls_provider,omitempty"`
	TLSProviderBasis     TLSProviderBasis          `json:"tls_provider_basis,omitempty"`
	TLSProfileFamily     string                    `json:"tls_profile_family,omitempty"`
	SecurityProperties   []NetworkSecurityProperty `json:"security_properties,omitempty"`
	UnresolvedProperties []string                  `json:"unresolved_properties,omitempty"`
	EvidenceIDs          []string                  `json:"evidence_ids"`
	Support              Support                   `json:"support"`
	Execution            ExecutionContext          `json:"execution"`
}

func ValidNetworkImplementationOperationPolicy(kind NetworkImplementationKind, hasOperations bool) bool {
	switch kind {
	case NetworkImplementationToolInvocation, NetworkImplementationRuntimeAPI, NetworkImplementationDelegatedHandler:
		return hasOperations
	case NetworkImplementationAPIImport, NetworkImplementationDynamicLinkage:
		return !hasOperations
	case NetworkImplementationAPICall:
		return true
	default:
		return false
	}
}

func ValidNetworkImplementationTLSContext(provider string, basis TLSProviderBasis) bool {
	return provider == "" && basis == "" || provider != "" && basis != "" && ValidTLSProviderBasis(basis)
}

func compareNetworkImplementationObservations(left, right NetworkImplementationObservation) int {
	for _, pair := range [][2]string{
		{left.ID, right.ID},
		{string(left.Kind), string(right.Kind)},
		{left.SubjectNodeID, right.SubjectNodeID},
		{left.ScopeID, right.ScopeID},
		{left.Architecture, right.Architecture},
	} {
		if compared := strings.Compare(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	if compared := compareStrings(left.OperationIDs, right.OperationIDs); compared != 0 {
		return compared
	}
	for _, pair := range [][2]string{
		{left.APIOrTool, right.APIOrTool},
		{left.HTTPImplementation, right.HTTPImplementation},
		{left.TLSProvider, right.TLSProvider},
		{string(left.TLSProviderBasis), string(right.TLSProviderBasis)},
		{left.TLSProfileFamily, right.TLSProfileFamily},
		{string(left.Support), string(right.Support)},
	} {
		if compared := strings.Compare(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	for index := 0; index < min(len(left.SecurityProperties), len(right.SecurityProperties)); index++ {
		if compared := strings.Compare(string(left.SecurityProperties[index]), string(right.SecurityProperties[index])); compared != 0 {
			return compared
		}
	}
	if compared := len(left.SecurityProperties) - len(right.SecurityProperties); compared != 0 {
		return compared
	}
	for _, pair := range [][2][]string{
		{left.UnresolvedProperties, right.UnresolvedProperties},
		{left.EvidenceIDs, right.EvidenceIDs},
		{left.Execution.ExecutionRootIDs, right.Execution.ExecutionRootIDs},
		{left.Execution.InvokedTargetIDs, right.Execution.InvokedTargetIDs},
	} {
		if compared := compareStrings(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	return strings.Compare(string(left.Execution.Connectivity), string(right.Execution.Connectivity))
}
