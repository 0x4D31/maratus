package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const maxFileCopySources = behavior.MaxOperationResourceBindings - 1

type fileCopyParseDisposition uint8

const (
	fileCopyMalformed fileCopyParseDisposition = iota
	fileCopyRecognized
	fileCopyUnsupported
)

type fileCopyCommand struct {
	disposition fileCopyParseDisposition
	sources     []string
	destination string
	reason      string
}

func parseFileCopyCommand(fields []string) fileCopyCommand {
	if len(fields) == 0 || fields[0] != "cp" {
		return fileCopyCommand{disposition: fileCopyMalformed}
	}
	operands := make([]string, 0, min(len(fields)-1, maxFileCopySources+1))
	options := true
	explicitDelimiter := false
	for _, field := range fields[1:] {
		switch {
		case options && field == "--":
			options = false
			explicitDelimiter = true
		case options && strings.HasPrefix(field, "--"):
			if !supportedFileCopyLongOption(field) {
				return unsupportedFileCopyCommand("unsupported cp long option")
			}
		case options && strings.HasPrefix(field, "-") && field != "-":
			if !supportedFileCopyShortOptions(field) {
				return unsupportedFileCopyCommand("unsupported cp short option")
			}
		default:
			options = false
			if !explicitDelimiter && strings.HasPrefix(field, "-") && field != "-" {
				return unsupportedFileCopyCommand("cp operand beginning with '-' requires an explicit -- terminator")
			}
			if len(operands) >= maxFileCopySources+1 {
				return unsupportedFileCopyCommand("cp source count exceeds the typed resource-binding limit")
			}
			operands = append(operands, field)
		}
	}
	if len(operands) < 2 {
		return fileCopyCommand{disposition: fileCopyMalformed}
	}
	return fileCopyCommand{
		disposition: fileCopyRecognized,
		sources:     append([]string(nil), operands[:len(operands)-1]...),
		destination: operands[len(operands)-1],
	}
}

func unsupportedFileCopyCommand(reason string) fileCopyCommand {
	return fileCopyCommand{
		disposition: fileCopyUnsupported,
		reason:      reason + "; file copy semantics were not modeled",
	}
}

func supportedFileCopyShortOptions(field string) bool {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") || len(field) < 2 {
		return false
	}
	const flags = "RrHLPfinapvXclx"
	return strings.Trim(field[1:], flags) == ""
}

func supportedFileCopyLongOption(field string) bool {
	switch field {
	case "--archive", "--copy-contents", "--dereference", "--force", "--interactive",
		"--no-clobber", "--no-dereference", "--one-file-system", "--parents",
		"--recursive", "--remove-destination", "--strip-trailing-slashes", "--verbose":
		return true
	}
	for _, prefix := range []string{"--no-preserve=", "--preserve=", "--reflink=", "--sparse="} {
		if strings.HasPrefix(field, prefix) && len(field) > len(prefix) {
			return true
		}
	}
	return false
}

func handleFileCopy(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	parsed := parseFileCopyCommand(fields)
	if parsed.disposition == fileCopyUnsupported {
		addPartialCoverageOnce(graph, content.NodeID, "shell-file-copy-analysis", parsed.reason)
		return
	}
	if parsed.disposition != fileCopyRecognized {
		return
	}
	evidenceIDs := shellOperationEvidence(content, evidenceID)
	bindings := make([]behavior.ResourceBinding, 0, len(parsed.sources)+1)
	for _, source := range parsed.sources {
		bindings = append(bindings, behavior.Bind(
			behavior.ResourceRoleSource,
			classifiedFileResource(staticShellResource(source)),
			evidenceIDs...,
		))
	}
	bindings = append(bindings, behavior.Bind(
		behavior.ResourceRoleLocalOutput,
		classifiedFileResource(staticShellResource(parsed.destination)),
		evidenceIDs...,
	))
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationFileCopy,
		ResourceBindings: bindings,
		EvidenceIDs:      evidenceIDs,
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
}
