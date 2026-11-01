package extract

import (
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const maxScreenCaptureOutputs = behavior.MaxOperationResourceBindings - 1

type screenCaptureCommand struct {
	outputs      []string
	video        bool
	ignoreFiles  bool
	partial      bool
	unsafeSyntax bool
}

// parseScreenCaptureCommand implements the bounded short-option grammar in
// screencapture(1). Capture itself remains known when output attribution is
// incomplete; only exact, static positional files become local_output
// resources.
func parseScreenCaptureCommand(fields []string) screenCaptureCommand {
	var result screenCaptureCommand
	if len(fields) == 0 {
		result.partial = true
		return result
	}
	options := true
	for index := 1; index < len(fields); index++ {
		field := fields[index]
		if options && field == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(field, "--") {
			result.partial = true
			result.unsafeSyntax = true
			continue
		}
		if options && len(field) > 1 && field[0] == '-' {
			cluster := field[1:]
			for optionIndex := 0; optionIndex < len(cluster); optionIndex++ {
				option := cluster[optionIndex]
				switch option {
				case 'c', 'p', 'u':
					result.ignoreFiles = true
				case 'v':
					result.video = true
				case 'S', 'W', 'C', 'T', 'M', 'P', 'i', 'm', 's', 'w', 'x', 'o', 'b', 'd', 'a', 'r', 'g', 'k', 'U':
					// Exact flag with no value.
				case 'D', 'B', 'J', 't', 'l', 'R', 'V', 'G':
					value := cluster[optionIndex+1:]
					if value == "" {
						if index+1 >= len(fields) {
							result.partial = true
							result.unsafeSyntax = true
							result.outputs = nil
							return result
						}
						index++
						value = fields[index]
					}
					if option == 'J' && value == "video" {
						result.video = true
					}
					optionIndex = len(cluster)
				default:
					result.partial = true
					result.unsafeSyntax = true
				}
			}
			continue
		}
		if result.ignoreFiles {
			continue
		}
		output := staticShellResource(field)
		if output == "" {
			result.partial = true
			continue
		}
		if len(result.outputs) == maxScreenCaptureOutputs {
			result.partial = true
			continue
		}
		result.outputs = append(result.outputs, output)
	}
	if result.ignoreFiles || result.unsafeSyntax {
		result.outputs = nil
	}
	return result
}

func handleScreenCapture(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	parsed := parseScreenCaptureCommand(fields)
	bindings := behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceScreen, "")),
	)
	for _, output := range parsed.outputs {
		resource := behavior.NewResource(behavior.ResourceFile, output)
		if !parsed.video {
			resource.Classifications = []behavior.ResourceClassification{behavior.ResourceClassScreenshot}
		}
		bindings = append(bindings, behavior.Bind(behavior.ResourceRoleLocalOutput, resource))
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationScreenCapture,
		ResourceBindings: bindings, EvidenceIDs: shellOperationEvidence(content, evidenceID),
		Support: behavior.SupportCorroborated, Execution: execution, Architecture: content.Architecture, Line: lineNo,
	})
	if parsed.partial {
		addPartialCoverageOnce(graph, content.NodeID, "screencapture-output-analysis", "screencapture used an unsupported, malformed, dynamic, or over-limit output form; capture was modeled but incomplete output files were not bound")
	}
}
