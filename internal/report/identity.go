package report

import (
	"encoding/binary"
	"sort"

	"github.com/0x4D31/maratus/internal/behavior"
)

// semanticIdentityKey returns an unambiguous byte identity for an ordered set
// of strings. Length framing preserves field boundaries even when values
// contain NULs, invalid UTF-8, or bytes that look like delimiters.
func semanticIdentityKey(fields ...string) string {
	encoded := make([]byte, 0)
	for _, field := range fields {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(len(field)))
		encoded = append(encoded, field...)
	}
	return string(encoded)
}

func executionContextIdentityKey(context behavior.ExecutionContext) string {
	roots := append([]string(nil), context.ExecutionRootIDs...)
	targets := append([]string(nil), context.InvokedTargetIDs...)
	sort.Strings(roots)
	sort.Strings(targets)
	return semanticIdentityKey(
		string(executionConnectivity(context)),
		semanticIdentityKey(roots...),
		semanticIdentityKey(targets...),
	)
}

func executionConnectivity(context behavior.ExecutionContext) behavior.Connectivity {
	if context.Connectivity == "" {
		return behavior.ConnectivityUnknown
	}
	return context.Connectivity
}
