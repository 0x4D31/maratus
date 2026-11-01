package extract

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxPyTorchVersionBytes         = 16
	maxPyTorchSerializationIDBytes = 64
)

type pyTorchZIPRecord struct {
	node    artifact.Node
	content artifact.Content
}

type pyTorchZIPRecognition struct {
	archive       artifact.Node
	pickle        pyTorchZIPRecord
	version       pyTorchZIPRecord
	versionValue  string
	protocol      byte
	corroborator  pyTorchZIPRecord
	corroboration string
	evidenceKind  string
	offsetKnown   bool
}

// addPyTorchZIPProperties recognizes a bounded modern PyTorch ZIP
// serialization structure. It inventories the representation and its
// unsupported Pickle boundary; it never loads the archive, interprets
// Pickle opcodes, or emits executable behavior.
func addPyTorchZIPProperties(
	graph *behavior.Graph,
	artifacts artifact.Graph,
	contents []artifact.Content,
	scopeByNode map[string]string,
) {
	contentByNode := make(map[string]artifact.Content, len(contents))
	for _, content := range contents {
		contentByNode[content.NodeID] = content
	}
	childrenByParent := make(map[string][]artifact.Node)
	var candidates []artifact.Node
	for _, node := range artifacts.Nodes {
		if node.ParentID != "" {
			childrenByParent[node.ParentID] = append(childrenByParent[node.ParentID], node)
		}
		if completeZIPFamilyNode(node) {
			candidates = append(candidates, node)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	for _, candidate := range candidates {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		recognition, ok := recognizePyTorchZIP(candidate, childrenByParent[candidate.ID], contentByNode)
		if !ok {
			continue
		}
		if !emitPyTorchZIPProperty(graph, recognition, scopeByNode) && graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
	}
}

func recognizePyTorchZIP(
	archive artifact.Node,
	children []artifact.Node,
	contentByNode map[string]artifact.Content,
) (pyTorchZIPRecognition, bool) {
	if !completeZIPFamilyNode(archive) || len(children) < 3 {
		return pyTorchZIPRecognition{}, false
	}
	sort.Slice(children, func(i, j int) bool {
		if children[i].LogicalPath != children[j].LogicalPath {
			return children[i].LogicalPath < children[j].LogicalPath
		}
		return children[i].ID < children[j].ID
	})

	records := make(map[string]pyTorchZIPRecord, len(children))
	rootPrefix := ""
	for _, child := range children {
		content, retained := contentByNode[child.ID]
		if child.AnalyzeStatus != "analyzed" || !retained {
			return pyTorchZIPRecognition{}, false
		}
		entry, ok := directZIPEntryName(archive.LogicalPath, child.LogicalPath)
		if !ok {
			return pyTorchZIPRecognition{}, false
		}
		separator := strings.IndexByte(entry, '/')
		if separator <= 0 || separator == len(entry)-1 {
			return pyTorchZIPRecognition{}, false
		}
		prefix, name := entry[:separator], entry[separator+1:]
		if rootPrefix == "" {
			rootPrefix = prefix
		} else if rootPrefix != prefix {
			return pyTorchZIPRecognition{}, false
		}
		if _, duplicate := records[name]; duplicate {
			return pyTorchZIPRecognition{}, false
		}
		records[name] = pyTorchZIPRecord{node: child, content: content}
	}

	pickle, pickleOK := records["data.pkl"]
	version, versionOK := records["version"]
	if !pickleOK || !versionOK || len(pickle.content.Data) < 2 ||
		pickle.content.Data[0] != 0x80 ||
		pickle.content.Data[1] < 2 ||
		pickle.content.Data[1] > 5 {
		return pyTorchZIPRecognition{}, false
	}
	versionValue, ok := positiveDecimalMetadata(version.content.Data, maxPyTorchVersionBytes)
	if !ok {
		return pyTorchZIPRecognition{}, false
	}

	recognition := pyTorchZIPRecognition{
		archive:      archive,
		pickle:       pickle,
		version:      version,
		versionValue: versionValue,
		protocol:     pickle.content.Data[1],
	}
	if byteorder, exists := records["byteorder"]; exists {
		value, valid := byteOrderMetadata(byteorder.content.Data)
		if !valid {
			return pyTorchZIPRecognition{}, false
		}
		recognition.corroborator = byteorder
		recognition.corroboration = value
		recognition.evidenceKind = "pytorch-byteorder"
		recognition.offsetKnown = true
	}
	if serializationID, exists := records[".data/serialization_id"]; exists {
		value, valid := boundedDecimalMetadata(serializationID.content.Data, maxPyTorchSerializationIDBytes)
		if !valid {
			return pyTorchZIPRecognition{}, false
		}
		if recognition.evidenceKind == "" {
			recognition.corroborator = serializationID
			recognition.corroboration = value
			recognition.evidenceKind = "pytorch-serialization-id"
			recognition.offsetKnown = true
		}
	}

	var storageNames []string
	for name := range records {
		if !strings.HasPrefix(name, "data/") {
			continue
		}
		index := strings.TrimPrefix(name, "data/")
		if index == "" || strings.ContainsRune(index, '/') || !decimalASCII(index) {
			return pyTorchZIPRecognition{}, false
		}
		storageNames = append(storageNames, name)
	}
	sort.Strings(storageNames)
	if recognition.evidenceKind == "" && len(storageNames) > 0 {
		recognition.corroborator = records[storageNames[0]]
		recognition.corroboration = storageNames[0]
		recognition.evidenceKind = "pytorch-storage-record"
	}
	if recognition.evidenceKind == "" {
		return pyTorchZIPRecognition{}, false
	}
	return recognition, true
}

func emitPyTorchZIPProperty(
	graph *behavior.Graph,
	recognition pyTorchZIPRecognition,
	scopeByNode map[string]string,
) bool {
	evidence := []struct {
		record      pyTorchZIPRecord
		kind        string
		value       string
		offsetKnown bool
	}{
		{
			record:      recognition.pickle,
			kind:        "pickle-protocol",
			value:       fmt.Sprintf("protocol=%d", recognition.protocol),
			offsetKnown: true,
		},
		{
			record:      recognition.version,
			kind:        "pytorch-serialization-version",
			value:       recognition.versionValue,
			offsetKnown: true,
		},
		{
			record:      recognition.corroborator,
			kind:        recognition.evidenceKind,
			value:       recognition.corroboration,
			offsetKnown: recognition.offsetKnown,
		},
	}
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return false
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      item.record.node.ID,
			ScopeID:     scopeByNode[item.record.node.ID],
			Logical:     item.record.node.LogicalPath,
			Offset:      0,
			OffsetKnown: item.offsetKnown,
			Method:      "pytorch-zip-recognizer",
			Kind:        item.kind,
			Value:       item.value,
		})
		if evidenceID == "" {
			graph.MarkWorkOmitted()
			return false
		}
		evidenceIDs = append(evidenceIDs, evidenceID)
	}

	if !graph.AddCoverage(behavior.Coverage{
		NodeID:       recognition.pickle.node.ID,
		AnalysisArea: "pytorch-pickle-semantics",
		Status:       "partial",
		Detail:       "PyTorch ZIP serialization was structurally recognized; Pickle opcodes, reducers, persistent IDs, and object reconstruction were not decoded, so no deserialization behavior or capability is claimed",
	}) {
		graph.MarkWorkOmitted()
		return false
	}
	if !graph.AddArtifactProperty(behavior.ArtifactProperty{
		NodeID:      recognition.archive.ID,
		Kind:        "serialization-format",
		Value:       "pytorch-zip",
		EvidenceIDs: evidenceIDs,
		Support:     behavior.SupportCorroborated,
	}) {
		graph.MarkWorkOmitted()
		return false
	}
	return true
}

func completeZIPFamilyNode(node artifact.Node) bool {
	return node.MediaType == "application/zip" &&
		node.AnalyzeStatus == "analyzed" &&
		node.CoverageDetail == ""
}

func directZIPEntryName(archiveLogical, childLogical string) (string, bool) {
	prefix := archiveLogical + "!"
	if archiveLogical == "" || !strings.HasPrefix(childLogical, prefix) {
		return "", false
	}
	entry := strings.TrimPrefix(childLogical, prefix)
	if entry == "" || strings.ContainsRune(entry, '!') {
		return "", false
	}
	return entry, true
}

func positiveDecimalMetadata(data []byte, maxBytes int) (string, bool) {
	value, ok := boundedDecimalMetadata(data, maxBytes)
	if !ok {
		return "", false
	}
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || number == 0 {
		return "", false
	}
	return strconv.FormatUint(number, 10), true
}

func boundedDecimalMetadata(data []byte, maxBytes int) (string, bool) {
	if len(data) == 0 || len(data) > maxBytes {
		return "", false
	}
	value := strings.Trim(string(data), " \t\r\n")
	return value, value != "" && decimalASCII(value)
}

func byteOrderMetadata(data []byte) (string, bool) {
	if len(data) == 0 || len(data) > len("little")+2 {
		return "", false
	}
	value := strings.Trim(string(data), " \t\r\n")
	return value, value == "little" || value == "big"
}

func decimalASCII(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range []byte(value) {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
