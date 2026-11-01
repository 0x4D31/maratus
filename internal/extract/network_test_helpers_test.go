package extract

import (
	"sort"

	"github.com/0x4D31/maratus/internal/behavior"
)

func networkOperationDestinations(graph behavior.Graph) []string {
	seen := make(map[string]struct{})
	for _, operation := range graph.Operations {
		if operation.Kind != behavior.OperationNetworkConnect && operation.Kind != behavior.OperationNetworkDownload && operation.Kind != behavior.OperationNetworkUpload {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Resource.Value == "" {
				continue
			}
			switch binding.Role {
			case behavior.ResourceRoleRemoteDestination, behavior.ResourceRoleRemoteSource:
				seen[binding.Resource.Value] = struct{}{}
			}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func hasNetworkOperationDestination(graph behavior.Graph, want string) bool {
	for _, value := range networkOperationDestinations(graph) {
		if value == want {
			return true
		}
	}
	return false
}
