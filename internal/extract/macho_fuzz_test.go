package extract

import (
	"testing"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func FuzzExtractMachO(f *testing.F) {
	f.Add([]byte{0xcf, 0xfa, 0xed, 0xfe})
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		var graph behavior.Graph
		ExtractMachO(&graph, artifact.Content{
			NodeID:      "node-0001",
			LogicalPath: "fuzz",
			Kind:        "macho",
			Data:        data,
		}, artifact.Options{}.Normalized())
	})
}
