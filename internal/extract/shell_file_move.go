package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const maxFileMoveSources = behavior.MaxOperationResourceBindings - 1

type fileMoveCommand struct {
	sources     []string
	destination string
	reason      string
}

func parseFileMoveCommand(fields []string) fileMoveCommand {
	if len(fields) == 0 || fields[0] != "mv" {
		return fileMoveCommand{}
	}
	operands := make([]string, 0, min(len(fields)-1, maxFileMoveSources+1))
	options := true
	explicitDelimiter := false
	for _, field := range fields[1:] {
		switch {
		case options && field == "--":
			options = false
			explicitDelimiter = true
		case options && strings.HasPrefix(field, "--"):
			return fileMoveCommand{reason: "unsupported mv long option; file move semantics were not modeled"}
		case options && strings.HasPrefix(field, "-") && field != "-":
			if strings.Trim(field[1:], "fhinv") != "" {
				return fileMoveCommand{reason: "unsupported mv short option; file move semantics were not modeled"}
			}
		default:
			options = false
			if !explicitDelimiter && strings.HasPrefix(field, "-") && field != "-" {
				return fileMoveCommand{reason: "mv operand beginning with '-' requires an explicit -- terminator; file move semantics were not modeled"}
			}
			if len(operands) >= maxFileMoveSources+1 {
				return fileMoveCommand{reason: "mv source count exceeds the operation limit; file move semantics were not modeled"}
			}
			operands = append(operands, field)
		}
	}
	if len(operands) < 2 {
		return fileMoveCommand{}
	}
	return fileMoveCommand{
		sources:     append([]string(nil), operands[:len(operands)-1]...),
		destination: operands[len(operands)-1],
	}
}

func handleFileMove(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	parsed := parseFileMoveCommand(fields)
	if parsed.reason != "" {
		addPartialCoverageOnce(graph, content.NodeID, "shell-file-move-analysis", parsed.reason)
		return
	}
	if len(parsed.sources) == 0 {
		return
	}
	evidenceIDs := shellOperationEvidence(content, evidenceID)
	var qualifiers map[string]string
	if destination := staticShellResource(parsed.destination); destination != "" {
		qualifiers = map[string]string{"destination_operand": destination}
	}
	for _, source := range parsed.sources {
		// POSIX/BSD mv treats the last operand as either a new pathname or an
		// existing directory. Without filesystem state, the resulting target
		// identity is not exact. Preserve the operand in evidence but leave the
		// typed target unresolved; the exact source identity is still removed.
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID,
			ScopeID:       content.ScopeID,
			Kind:          behavior.OperationFileMove,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, classifiedFileResource(staticShellResource(source)), evidenceIDs...),
				behavior.Bind(behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, ""), evidenceIDs...),
			),
			Qualifiers:   qualifiers,
			EvidenceIDs:  evidenceIDs,
			Support:      behavior.SupportCorroborated,
			Execution:    execution,
			Architecture: content.Architecture,
			Line:         lineNo,
		})
	}
}
