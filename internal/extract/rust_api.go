package extract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxRustAPIMatches        = 1024
	maxRustAPIStatementBytes = 16 << 10
	maxRustCommandArguments  = 32
)

type rustAPIEvent struct {
	offset                   int
	line                     int
	statement                string
	api                      string
	kind                     behavior.OperationKind
	argument                 string
	secondArgument           string
	argumentRole             behavior.ResourceRole
	secondRole               behavior.ResourceRole
	commandArguments         []string
	commandArgumentsComplete bool
	network                  bool
	terminal                 string
	receiverProof            string
}

type rustResolvedString struct {
	value         string
	bindingOffset int
	bindingKind   string
	local         bool
}

type rustCommandChain struct {
	terminal            string
	argumentExpressions []string
	argumentsComplete   bool
}

type rustUnaryAPISpec struct {
	api     string
	kind    behavior.OperationKind
	argc    int
	pattern *regexp.Regexp
}

type rustBinaryAPISpec struct {
	api        string
	kind       behavior.OperationKind
	firstRole  behavior.ResourceRole
	secondRole behavior.ResourceRole
	pattern    *regexp.Regexp
}

var (
	rustUreqReturn = regexp.MustCompile(`\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^\n)]*\)\s*->\s*ureq\s*::\s*Agent\s*\{`)
)

var rustUnaryAPISpecs = []rustUnaryAPISpec{
	rustUnaryFileSpec("std::fs::File::create", behavior.OperationFileWrite, 1),
	rustUnaryFileSpec("std::fs::File::create_new", behavior.OperationFileWrite, 1),
	rustUnaryFileSpec("std::fs::File::open", behavior.OperationFileOpen, 1),
	rustUnaryFileSpec("std::fs::canonicalize", behavior.OperationFileMetadataQuery, 1),
	rustUnaryFileSpec("std::fs::create_dir", behavior.OperationDirectoryCreate, 1),
	rustUnaryFileSpec("std::fs::create_dir_all", behavior.OperationDirectoryCreate, 1),
	rustUnaryFileSpec("std::fs::exists", behavior.OperationFileMetadataQuery, 1),
	rustUnaryFileSpec("std::fs::metadata", behavior.OperationFileMetadataQuery, 1),
	rustUnaryFileSpec("std::fs::read", behavior.OperationFileRead, 1),
	rustUnaryFileSpec("std::fs::read_dir", behavior.OperationFileEnumerate, 1),
	rustUnaryFileSpec("std::fs::read_link", behavior.OperationFileMetadataQuery, 1),
	rustUnaryFileSpec("std::fs::read_to_string", behavior.OperationFileRead, 1),
	rustUnaryFileSpec("std::fs::remove_dir", behavior.OperationFileDelete, 1),
	rustUnaryFileSpec("std::fs::remove_dir_all", behavior.OperationFileDelete, 1),
	rustUnaryFileSpec("std::fs::remove_file", behavior.OperationFileDelete, 1),
	rustUnaryFileSpec("std::fs::set_permissions", behavior.OperationFilePermissionModify, 2),
	rustUnaryFileSpec("std::fs::symlink_metadata", behavior.OperationFileMetadataQuery, 1),
	rustUnaryFileSpec("std::fs::write", behavior.OperationFileWrite, 2),
}

var rustBinaryAPISpecs = []rustBinaryAPISpec{
	rustBinaryFileSpec("std::fs::copy", behavior.OperationFileCopy, behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput),
	rustBinaryFileSpec("std::fs::rename", behavior.OperationFileMove, behavior.ResourceRoleSource, behavior.ResourceRoleTarget),
}

func rustUnaryFileSpec(api string, kind behavior.OperationKind, argc int) rustUnaryAPISpec {
	return rustUnaryAPISpec{api: api, kind: kind, argc: argc, pattern: regexp.MustCompile(`\b` + rustFlexiblePathPattern(api) + `\s*\(`)}
}

func rustBinaryFileSpec(api string, kind behavior.OperationKind, firstRole, secondRole behavior.ResourceRole) rustBinaryAPISpec {
	return rustBinaryAPISpec{api: api, kind: kind, firstRole: firstRole, secondRole: secondRole, pattern: regexp.MustCompile(`\b` + rustFlexiblePathPattern(api) + `\s*\(`)}
}

// extractRustSourceAPIs emits only neutral operations for a small closed set
// of stable Rust APIs. The API spelling, import/return-type proof, constructor,
// and execution terminal must all be present in bounded source. Support stays
// HEURISTIC because Maratus deliberately does not run rustc name resolution or
// macro expansion; these operations therefore cannot satisfy capability rules.
func extractRustSourceAPIs(graph *behavior.Graph, content artifact.Content, source string) {
	mask, maskLimited := rustSourceCodeMask(source)
	lineStarts := rustLineStarts(source)
	extractRustConstantObservations(graph, content, source, mask)
	events, eventLimited := rustSourceAPIEvents(source, mask)
	if maskLimited || eventLimited {
		addPartialCoverageOnce(graph, content.NodeID, "rust-source-api-analysis", fmt.Sprintf("Rust source API analysis reached a bounded lexical limit (%d events or %d bytes per fluent statement); excess or ambiguous calls were not modeled", maxRustAPIMatches, maxRustAPIStatementBytes))
	}
	for _, event := range events {
		if graph.WorkLimitReached() {
			graph.MarkWorkOmitted()
			return
		}
		scope, ok := uniqueRustFunctionScopeAtLine(graph.Scopes, content.NodeID, event.line)
		if !ok {
			addPartialCoverageOnce(graph, content.NodeID, "rust-source-api-analysis", "a recognized Rust API call could not be assigned to one exact retained function scope; the operation was omitted")
			continue
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      content.NodeID,
			ScopeID:     scope.ID,
			Logical:     content.LogicalPath,
			Physical:    content.PhysicalPath,
			Function:    scope.Function,
			Line:        event.line,
			Offset:      int64(event.offset),
			OffsetKnown: true,
			Method:      "rust-source-api",
			Kind:        "rust-api-call",
			Value:       compactTextEvidenceValue(event.statement),
		})
		if evidenceID == "" {
			return
		}
		evidenceIDs := []string{evidenceID}
		resolved := resolveRustStringArgument(source, mask, event.argument, event.offset, scope)
		primaryBindingEvidenceID := ""
		if resolved.bindingOffset >= 0 {
			bindingScopeID := ""
			bindingFunction := ""
			if resolved.local {
				bindingScopeID = scope.ID
				bindingFunction = scope.Function
			}
			bindingEvidenceID := graph.AddEvidence(behavior.Evidence{
				NodeID: content.NodeID, ScopeID: bindingScopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
				Function: bindingFunction, Line: rustLineForOffset(lineStarts, resolved.bindingOffset),
				Offset: int64(resolved.bindingOffset), OffsetKnown: true,
				Method: "rust-source-binding", Kind: resolved.bindingKind, Value: resolved.value,
			})
			if bindingEvidenceID == "" {
				return
			}
			primaryBindingEvidenceID = bindingEvidenceID
			evidenceIDs = append(evidenceIDs, bindingEvidenceID)
		}
		secondary := rustResolvedString{bindingOffset: -1}
		secondaryBindingEvidenceID := ""
		if event.secondArgument != "" {
			secondary = resolveRustStringArgument(source, mask, event.secondArgument, event.offset, scope)
			if secondary.bindingOffset >= 0 {
				bindingScopeID := ""
				bindingFunction := ""
				if secondary.local {
					bindingScopeID = scope.ID
					bindingFunction = scope.Function
				}
				bindingEvidenceID := graph.AddEvidence(behavior.Evidence{
					NodeID: content.NodeID, ScopeID: bindingScopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
					Function: bindingFunction, Line: rustLineForOffset(lineStarts, secondary.bindingOffset),
					Offset: int64(secondary.bindingOffset), OffsetKnown: true,
					Method: "rust-source-binding", Kind: secondary.bindingKind, Value: secondary.value,
				})
				if bindingEvidenceID == "" {
					return
				}
				secondaryBindingEvidenceID = bindingEvidenceID
				evidenceIDs = append(evidenceIDs, bindingEvidenceID)
			}
		}
		commandArguments := make([]string, 0, len(event.commandArguments))
		commandArgumentEvidenceIDs := make([]string, 0, len(event.commandArguments))
		commandArgumentsComplete := event.commandArgumentsComplete
		if event.kind == behavior.OperationProcessExecute && commandArgumentsComplete {
			for _, expression := range event.commandArguments {
				argument := resolveRustStringArgument(source, mask, expression, event.offset, scope)
				if argument.value == "" {
					commandArgumentsComplete = false
					break
				}
				commandArguments = append(commandArguments, argument.value)
				if argument.bindingOffset < 0 {
					continue
				}
				bindingScopeID := ""
				bindingFunction := ""
				if argument.local {
					bindingScopeID = scope.ID
					bindingFunction = scope.Function
				}
				bindingEvidenceID := graph.AddEvidence(behavior.Evidence{
					NodeID: content.NodeID, ScopeID: bindingScopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
					Function: bindingFunction, Line: rustLineForOffset(lineStarts, argument.bindingOffset),
					Offset: int64(argument.bindingOffset), OffsetKnown: true,
					Method: "rust-source-binding", Kind: argument.bindingKind, Value: argument.value,
				})
				if bindingEvidenceID == "" {
					return
				}
				commandArgumentEvidenceIDs = append(commandArgumentEvidenceIDs, bindingEvidenceID)
				evidenceIDs = append(evidenceIDs, bindingEvidenceID)
			}
		}
		graph.AddFeature(behavior.Feature{
			NodeID: content.NodeID, ScopeID: scope.ID, SourceFunction: scope.Function,
			Key: "source.api_call", Value: event.api,
			Qualifiers:  map[string]string{"language": "rust", "receiver_proof": event.receiverProof, "terminal": event.terminal},
			EvidenceIDs: []string{evidenceID}, Support: behavior.SupportDirect,
			Execution: unknownExecutionContext(),
		})
		agentInvocation, agentInvocationOK := recognizeLocalAgentInvocation(append([]string{resolved.value}, commandArguments...))
		resource := rustEventResource(event.kind, resolved.value)
		if event.kind == behavior.OperationProcessExecute && commandArgumentsComplete && agentInvocationOK {
			executableValue := ""
			if strings.Contains(resolved.value, "/") {
				executableValue = resolved.value
			}
			resource = behavior.NewResource(behavior.ResourceFile, executableValue, behavior.ResourceClassAgentRuntime)
		}
		bindings := requiredResourceBindings(event.kind, resource)
		if event.argumentRole != "" && event.secondRole != "" {
			bindings = behavior.Bindings(
				behavior.Bind(event.argumentRole, resource, optionalEvidenceID(primaryBindingEvidenceID)...),
				behavior.Bind(event.secondRole, behavior.NewResource(behavior.ResourceFile, secondary.value), optionalEvidenceID(secondaryBindingEvidenceID)...),
			)
		} else if resolved.bindingOffset >= 0 {
			for index := range bindings {
				bindings[index].EvidenceIDs = []string{primaryBindingEvidenceID}
			}
		}
		qualifiers := map[string]string{
			"api": event.api, "api_identity": "bounded-lexical-proof", "name_resolution": "unresolved-without-rustc",
		}
		if event.kind == behavior.OperationProcessExecute {
			if agentInvocationOK {
				qualifiers["agent_profile"] = localAgentCLIProfile
				qualifiers["agent_product"] = agentInvocation.command.product
				qualifiers["agent_tool"] = agentInvocation.command.tool
				qualifiers["path_resolution"] = "runtime PATH lookup not authenticated"
				if len(agentInvocation.reducedSafeguards) > 0 {
					qualifiers["reduced_safeguards"] = strings.Join(agentInvocation.reducedSafeguards, "; ")
				}
			}
			if commandArgumentsComplete {
				qualifiers["argument_coverage"] = "exact-static-argv"
				if len(commandArguments) > 0 {
					encoded, err := json.Marshal(commandArguments)
					if err != nil {
						return
					}
					argumentClassifications := []behavior.ResourceClassification(nil)
					if len(agentInvocation.reducedSafeguards) > 0 {
						argumentClassifications = []behavior.ResourceClassification{behavior.ResourceClassAgentReducedSafeguards}
					}
					bindings = append(bindings, behavior.Bind(
						behavior.ResourceRoleArguments,
						behavior.NewResource(behavior.ResourceCommand, string(encoded), argumentClassifications...),
						append([]string{evidenceID}, commandArgumentEvidenceIDs...)...,
					))
					qualifiers["argument_encoding"] = "json-array"
				}
			} else {
				qualifiers["argument_coverage"] = "executable-only"
				qualifiers["unresolved_arguments"] = "dynamic or unsupported argv"
			}
		}
		operationID := graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: scope.ID, SourceFunction: scope.Function,
			Kind: event.kind, ResourceBindings: bindings,
			Qualifiers:  qualifiers,
			EvidenceIDs: evidenceIDs, Support: behavior.SupportHeuristic,
			Execution: unknownExecutionContext(), Line: event.line,
		})
		if operationID != "" && event.kind == behavior.OperationProcessExecute && resolved.value != "" && commandArgumentsComplete {
			commandContent := content
			commandContent.ScopeID = scope.ID
			commandContent.Function = scope.Function
			handleSharedResolvedCommandSemantics(
				graph,
				commandContent,
				append([]string{resolved.value}, commandArguments...),
				event.line,
				unknownExecutionContext(),
				evidenceIDs,
				behavior.SupportHeuristic,
			)
		}
		if event.network && operationID != "" {
			observation := networkImplementationObservation(operationID, artifact.Content{
				NodeID: content.NodeID, ScopeID: scope.ID, LogicalPath: content.LogicalPath,
				PhysicalPath: content.PhysicalPath, Function: scope.Function,
			}, "rust-source", evidenceID)
			observation.EvidenceIDs = append([]string(nil), evidenceIDs...)
			observation.APIOrTool = "ureq::Agent"
			observation.HTTPImplementation = "ureq"
			observation.TLSProvider = "ureq-selected TLS provider"
			observation.TLSProfileFamily = "ureq-configuration-dependent"
			observation.Support = behavior.SupportHeuristic
			graph.AddNetworkImplementation(observation)
		}
	}
}

func rustSourceAPIEvents(source string, mask []bool) ([]rustAPIEvent, bool) {
	lineStarts := rustLineStarts(source)
	events := make([]rustAPIEvent, 0, 16)
	limited := false
	stdUnshadowed := !rustPathRootShadowed(source, "std")
	ureqUnshadowed := !rustPathRootShadowed(source, "ureq")
	add := func(event rustAPIEvent) bool {
		if len(events) >= maxRustAPIMatches {
			limited = true
			return false
		}
		event.line = rustLineForOffset(lineStarts, event.offset)
		events = append(events, event)
		return true
	}

	for _, spec := range rustUnaryAPISpecs {
		if !stdUnshadowed {
			break
		}
		for _, match := range spec.pattern.FindAllStringIndex(source, maxRustAPIMatches+1) {
			if len(match) != 2 || !rustCodeAt(mask, match[0]) || rustBarePathQualified(source, match[0]) {
				continue
			}
			close, ok := rustCallClose(source, mask, match[1]-1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			arguments, truncated := rustCallArguments(source, mask, match[1], close, spec.argc+1)
			if truncated || len(arguments) != spec.argc || arguments[0] == "" {
				continue
			}
			argument := arguments[0]
			if !add(rustAPIEvent{offset: match[0], statement: source[match[0] : close+1], api: spec.api, kind: spec.kind, argument: argument, terminal: "call", receiverProof: "fully-qualified-path"}) {
				break
			}
		}
	}

	for _, spec := range rustBinaryAPISpecs {
		if !stdUnshadowed {
			break
		}
		for _, match := range spec.pattern.FindAllStringIndex(source, maxRustAPIMatches+1) {
			if len(match) != 2 || !rustCodeAt(mask, match[0]) || rustBarePathQualified(source, match[0]) {
				continue
			}
			close, ok := rustCallClose(source, mask, match[1]-1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			arguments, truncated := rustCallArguments(source, mask, match[1], close, 3)
			if truncated || len(arguments) != 2 || arguments[0] == "" || arguments[1] == "" {
				continue
			}
			if !add(rustAPIEvent{
				offset: match[0], statement: source[match[0] : close+1], api: spec.api, kind: spec.kind,
				argument: arguments[0], secondArgument: arguments[1], argumentRole: spec.firstRole, secondRole: spec.secondRole,
				terminal: "call", receiverProof: "fully-qualified-path",
			}) {
				break
			}
		}
	}

	commandNames := rustImportedCommandNames(source, mask)
	if stdUnshadowed {
		commandNames = append(commandNames, "std::process::Command")
	}
	for _, commandName := range rustSortedUniqueStrings(commandNames) {
		if !strings.Contains(commandName, "::") && rustTypeNameShadowed(source, commandName) {
			continue
		}
		pattern := regexp.MustCompile(`\b` + rustFlexiblePathPattern(commandName) + `\s*::\s*new\s*\(`)
		for _, match := range pattern.FindAllStringIndex(source, maxRustAPIMatches+1) {
			if len(match) != 2 || !rustCodeAt(mask, match[0]) || !strings.Contains(commandName, "::") && rustBarePathQualified(source, match[0]) {
				continue
			}
			close, ok := rustCallClose(source, mask, match[1]-1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			end, ok := rustStatementEnd(source, mask, close+1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			statement := source[match[0] : end+1]
			chain, chainLimited := rustCommandChainAfter(source, mask, close+1, end)
			limited = limited || chainLimited
			if chain.terminal == "" {
				continue
			}
			constructorArguments, truncated := rustCallArguments(source, mask, match[1], close, 2)
			if truncated || len(constructorArguments) != 1 || constructorArguments[0] == "" {
				continue
			}
			argument := constructorArguments[0]
			proof := "std-process-import"
			if strings.Contains(commandName, "::") {
				proof = "fully-qualified-path"
			}
			if !add(rustAPIEvent{
				offset: match[0], statement: statement, api: "std::process::Command::new", kind: behavior.OperationProcessExecute,
				argument: argument, commandArguments: chain.argumentExpressions, commandArgumentsComplete: chain.argumentsComplete,
				terminal: chain.terminal, receiverProof: proof,
			}) {
				break
			}
		}
	}

	agents := []string(nil)
	if ureqUnshadowed {
		agents = rustUreqAgentFactories(source, mask)
	}
	for _, factory := range append(agents, "ureq::get") {
		if !ureqUnshadowed {
			break
		}
		pattern := regexp.MustCompile(`\b` + rustFlexiblePathPattern(factory) + `\s*\(`)
		for _, match := range pattern.FindAllStringIndex(source, maxRustAPIMatches+1) {
			if len(match) != 2 || !rustCodeAt(mask, match[0]) || rustPrecededByFunctionKeyword(source, match[0]) {
				continue
			}
			close, ok := rustCallClose(source, mask, match[1]-1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			end, ok := rustStatementEnd(source, mask, close+1, maxRustAPIStatementBytes)
			if !ok {
				limited = true
				continue
			}
			statement := source[match[0] : end+1]
			argument := ""
			if factory == "ureq::get" {
				if !rustExactFluentMethod(source, mask, close+1, end, "call") {
					continue
				}
				argument = rustFirstCallArgument(source, mask, match[1], close)
			} else {
				getOpen, getClose, valid := rustExactFluentCall(source, mask, close+1, end, "get")
				if !valid || !rustExactFluentMethod(source, mask, getClose+1, end, "call") {
					continue
				}
				argument = rustFirstCallArgument(source, mask, getOpen+1, getClose)
			}
			proof := "ureq-agent-return-type"
			if factory == "ureq::get" {
				proof = "fully-qualified-path"
			}
			if !add(rustAPIEvent{offset: match[0], statement: statement, api: "ureq::Agent::get().call", kind: behavior.OperationNetworkDownload, argument: argument, network: true, terminal: "call", receiverProof: proof}) {
				break
			}
		}
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].offset != events[j].offset {
			return events[i].offset < events[j].offset
		}
		if events[i].kind != events[j].kind {
			return events[i].kind < events[j].kind
		}
		return events[i].api < events[j].api
	})
	deduplicated := events[:0]
	for _, event := range events {
		if len(deduplicated) > 0 {
			prior := deduplicated[len(deduplicated)-1]
			if prior.offset == event.offset && prior.kind == event.kind && prior.api == event.api {
				continue
			}
		}
		deduplicated = append(deduplicated, event)
	}
	return deduplicated, limited
}

func rustImportedCommandNames(source string, mask []bool) []string {
	var names []string
	direct := regexp.MustCompile(`(?m)^use[ \t]+std\s*::\s*process\s*::\s*Command(?:[ \t]+as[ \t]+([A-Za-z_][A-Za-z0-9_]*))?[ \t]*;`)
	for _, match := range direct.FindAllStringSubmatchIndex(source, 8) {
		if len(match) < 2 || !rustCodeAt(mask, match[0]) {
			continue
		}
		name := "Command"
		if len(match) >= 4 && match[2] >= 0 {
			name = source[match[2]:match[3]]
		}
		names = append(names, name)
	}
	group := regexp.MustCompile(`(?ms)^use[ \t]+std\s*::\s*process\s*::\s*\{([^}]{1,1000})\}[ \t]*;`)
	for _, match := range group.FindAllStringSubmatchIndex(source, 8) {
		if len(match) < 4 || !rustCodeAt(mask, match[0]) {
			continue
		}
		for _, item := range strings.Split(source[match[2]:match[3]], ",") {
			fields := strings.Fields(strings.TrimSpace(item))
			switch {
			case len(fields) == 1 && fields[0] == "Command":
				names = append(names, "Command")
			case len(fields) == 3 && fields[0] == "Command" && fields[1] == "as" && identifierName(fields[2]):
				names = append(names, fields[2])
			}
		}
	}
	return names
}

func rustPathRootShadowed(source, name string) bool {
	quoted := regexp.QuoteMeta(name)
	patterns := []string{
		`(?m)^[ \t]*(?:pub[ \t]+)?mod[ \t]+` + quoted + `\b`,
		`(?m)^[ \t]*(?:pub[ \t]+)?(?:extern[ \t]+crate|use)[^;\n]*[ \t]+as[ \t]+` + quoted + `[ \t]*;`,
	}
	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(source) {
			return true
		}
	}
	return false
}

func rustTypeNameShadowed(source, name string) bool {
	quoted := regexp.QuoteMeta(name)
	return regexp.MustCompile(`(?m)^[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?(?:struct|enum|union|type|trait|mod)[ \t]+` + quoted + `\b`).MatchString(source)
}

func rustBarePathQualified(source string, offset int) bool {
	for offset > 0 && (source[offset-1] == ' ' || source[offset-1] == '\t') {
		offset--
	}
	return offset >= 2 && source[offset-2:offset] == "::"
}

func rustPrecededByFunctionKeyword(source string, offset int) bool {
	lineStart := strings.LastIndex(source[:offset], "\n") + 1
	prefix := strings.TrimSpace(source[lineStart:offset])
	return strings.HasSuffix(prefix, "fn") || strings.Contains(prefix, "fn ")
}

func rustUreqAgentFactories(source string, mask []bool) []string {
	var names []string
	for _, match := range rustUreqReturn.FindAllStringSubmatchIndex(source, maxRustAPIMatches+1) {
		if len(match) < 4 || !rustCodeAt(mask, match[0]) {
			continue
		}
		names = append(names, source[match[2]:match[3]])
	}
	return rustSortedUniqueStrings(names)
}

func rustSourceCodeMask(source string) ([]bool, bool) {
	mask := make([]bool, len(source))
	blockDepth := 0
	lineComment := false
	quote := byte(0)
	escaped := false
	rawHashes := -1
	limited := false
	for index := 0; index < len(source); index++ {
		current := source[index]
		if lineComment {
			if current == '\n' {
				lineComment = false
				mask[index] = true
			}
			continue
		}
		if blockDepth > 0 {
			if index+1 < len(source) && source[index:index+2] == "/*" {
				blockDepth++
				if blockDepth > 64 {
					// Do not cap and resume: doing so would eventually expose bytes
					// that are still inside a deeper comment as executable source.
					// The zero-value suffix stays masked and coverage records the
					// unsupported lexical remainder.
					return mask, true
				}
				index++
			} else if index+1 < len(source) && source[index:index+2] == "*/" {
				blockDepth--
				index++
			}
			continue
		}
		if rawHashes >= 0 {
			if current == '"' {
				end := index + 1 + rawHashes
				if end <= len(source) && strings.Trim(source[index+1:end], "#") == "" && end-index-1 == rawHashes {
					index = end - 1
					rawHashes = -1
				}
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == quote {
				quote = 0
			}
			continue
		}
		if index+1 < len(source) && source[index:index+2] == "//" {
			lineComment = true
			index++
			continue
		}
		if index+1 < len(source) && source[index:index+2] == "/*" {
			blockDepth = 1
			index++
			continue
		}
		if current == 'r' {
			hashes := 0
			cursor := index + 1
			for cursor < len(source) && source[cursor] == '#' && hashes <= 64 {
				hashes++
				cursor++
			}
			if cursor < len(source) && source[cursor] == '"' {
				rawHashes = hashes
				index = cursor
				continue
			}
		}
		if current == '\'' && rustCharLiteralClose(source, index) > index {
			quote = current
			continue
		}
		if current == '"' {
			quote = current
			continue
		}
		mask[index] = true
	}
	if blockDepth > 0 || quote != 0 || rawHashes >= 0 {
		limited = true
	}
	return mask, limited
}

func rustCharLiteralClose(source string, start int) int {
	escaped := false
	for index := start + 1; index < len(source) && index-start <= 16; index++ {
		switch {
		case source[index] == '\n' || source[index] == '\r':
			return -1
		case escaped:
			escaped = false
		case source[index] == '\\':
			escaped = true
		case source[index] == '\'':
			return index
		}
	}
	return -1
}

func rustCallClose(source string, mask []bool, open, limit int) (int, bool) {
	if open < 0 || open >= len(source) || source[open] != '(' || !rustCodeAt(mask, open) {
		return 0, false
	}
	depth := 0
	end := min(len(source), open+limit)
	for index := open; index < end; index++ {
		if !rustCodeAt(mask, index) {
			continue
		}
		switch source[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return 0, false
}

func rustStatementEnd(source string, mask []bool, start, limit int) (int, bool) {
	end := min(len(source), start+limit)
	for index := start; index < end; index++ {
		if rustCodeAt(mask, index) && source[index] == ';' {
			return index, true
		}
	}
	return 0, false
}

func rustFirstCallArgument(source string, mask []bool, start, close int) string {
	arguments, _ := rustCallArguments(source, mask, start, close, 1)
	if len(arguments) == 0 {
		return ""
	}
	return arguments[0]
}

func rustCallArguments(source string, mask []bool, start, close, limit int) ([]string, bool) {
	if start < 0 || close > len(source) || start > close {
		return nil, false
	}
	if limit <= 0 {
		return nil, true
	}
	arguments := make([]string, 0, min(limit, 4))
	argumentStart := start
	depth := 0
	for index := start; index < close; index++ {
		if !rustCodeAt(mask, index) {
			continue
		}
		switch source[index] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				arguments = append(arguments, strings.TrimSpace(source[argumentStart:index]))
				if len(arguments) >= limit {
					return arguments, true
				}
				argumentStart = index + 1
			}
		}
	}
	last := strings.TrimSpace(source[argumentStart:close])
	if last != "" || len(arguments) > 0 {
		arguments = append(arguments, last)
	}
	return arguments, len(arguments) > limit
}

func optionalEvidenceID(evidenceID string) []string {
	if evidenceID == "" {
		return nil
	}
	return []string{evidenceID}
}

func exactRustString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value[0] != '"' || strings.Contains(value, "\\") {
		return ""
	}
	decoded, end, ok, oversized := readSourceStringLiteralLimited(value, 0, '"', maxTextDerivedValueBytes)
	if !ok || oversized || strings.TrimSpace(value[end+1:]) != "" {
		return ""
	}
	return decoded
}

func resolveRustStringArgument(source string, mask []bool, expression string, useOffset int, scope behavior.Scope) rustResolvedString {
	if value := exactRustString(expression); value != "" {
		return rustResolvedString{value: value, bindingOffset: -1}
	}
	name := strings.TrimSpace(expression)
	name = strings.TrimSpace(strings.TrimPrefix(name, "&"))
	if !identifierName(name) {
		return rustResolvedString{bindingOffset: -1}
	}
	starts := rustLineStarts(source)
	scopeStart := 0
	if scope.LineStart > 1 && scope.LineStart-1 < len(starts) {
		scopeStart = starts[scope.LineStart-1]
	}
	scopeEnd := len(source)
	if scope.LineEnd > 0 && scope.LineEnd < len(starts) {
		scopeEnd = starts[scope.LineEnd]
	}
	if useOffset < scopeStart || useOffset > scopeEnd {
		return rustResolvedString{bindingOffset: -1}
	}
	localPattern := regexp.MustCompile(`\blet\s+` + regexp.QuoteMeta(name) + `(?:\s*:[^=;\n]{1,1000})?\s*=`)
	allLocalDeclarations := regexp.MustCompile(`\blet\s+(?:mut\s+)?` + regexp.QuoteMeta(name) + `\b`)
	localDeclarations := allLocalDeclarations.FindAllStringIndex(source[scopeStart:useOffset], 3)
	if len(localDeclarations) > 0 {
		matches := localPattern.FindAllStringIndex(source[scopeStart:useOffset], 3)
		if len(localDeclarations) != 1 || len(matches) != 1 {
			return rustResolvedString{bindingOffset: -1}
		}
		match := matches[0]
		absoluteStart := scopeStart + match[0]
		initializer := scopeStart + match[1]
		if !rustCodeAt(mask, absoluteStart) {
			return rustResolvedString{bindingOffset: -1}
		}
		end, ok := rustConstantInitializerEnd(source, mask, initializer)
		if !ok || end >= useOffset {
			return rustResolvedString{bindingOffset: -1}
		}
		fragments, ok := parseRustConstantStringSequence(source, initializer, end)
		if !ok || len(fragments) != 1 {
			return rustResolvedString{bindingOffset: -1}
		}
		assignment := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*=`)
		for _, candidate := range assignment.FindAllStringIndex(source[end+1:useOffset], 1) {
			if rustCodeAt(mask, end+1+candidate[0]) {
				return rustResolvedString{bindingOffset: -1}
			}
		}
		return rustResolvedString{value: fragments[0].value, bindingOffset: fragments[0].offset, bindingKind: "immutable-local-string", local: true}
	}

	resolved := rustResolvedString{bindingOffset: -1}
	for _, match := range rustConstantDeclaration.FindAllStringSubmatchIndex(source, maxRustConstantDeclarations+1) {
		if len(match) < 4 || source[match[2]:match[3]] != name || !rustCodeAt(mask, match[0]) || rustOffsetInsideMacroDefinition(source, mask, match[0]) {
			continue
		}
		if resolved.bindingOffset >= 0 {
			return rustResolvedString{bindingOffset: -1}
		}
		end, ok := rustConstantInitializerEnd(source, mask, match[1])
		if !ok {
			return rustResolvedString{bindingOffset: -1}
		}
		fragments, ok := parseRustConstantStringSequence(source, match[1], end)
		if !ok || len(fragments) != 1 {
			return rustResolvedString{bindingOffset: -1}
		}
		resolved = rustResolvedString{value: fragments[0].value, bindingOffset: fragments[0].offset, bindingKind: "immutable-constant-string"}
	}
	return resolved
}

func rustEventResource(kind behavior.OperationKind, value string) behavior.Resource {
	if kind == behavior.OperationNetworkDownload || kind == behavior.OperationNetworkConnect || kind == behavior.OperationNetworkUpload {
		return networkResource(destinations(value))
	}
	return classifiedFileResource(value)
}

func rustCommandChainAfter(source string, mask []bool, start, end int) (rustCommandChain, bool) {
	allowed := map[string]bool{
		"arg": true, "args": true, "env": true, "envs": true, "env_clear": true,
		"current_dir": true, "stdin": true, "stdout": true, "stderr": true,
		"uid": true, "gid": true, "process_group": true, "creation_flags": true,
		"raw_arg": true, "force_quotes": true, "show_window": true,
	}
	chain := rustCommandChain{argumentsComplete: true}
	limited := false
	position := start
	for steps := 0; steps < 64; steps++ {
		method, open, close, ok := rustNextFluentCall(source, mask, position, end)
		if !ok {
			return rustCommandChain{}, limited
		}
		switch method {
		case "spawn", "status", "output":
			arguments, truncated := rustCallArguments(source, mask, open+1, close, 1)
			if truncated || len(arguments) != 0 {
				return rustCommandChain{}, limited
			}
			chain.terminal = method
			return chain, limited
		case "arg":
			arguments, truncated := rustCallArguments(source, mask, open+1, close, 2)
			if truncated || len(arguments) != 1 || arguments[0] == "" {
				chain.argumentsComplete = false
			} else if len(chain.argumentExpressions) >= maxRustCommandArguments {
				chain.argumentsComplete = false
				limited = true
			} else {
				chain.argumentExpressions = append(chain.argumentExpressions, arguments[0])
			}
		case "args":
			arguments, truncated := rustCallArguments(source, mask, open+1, close, 2)
			if truncated || len(arguments) != 1 || arguments[0] == "" {
				chain.argumentsComplete = false
				break
			}
			values, exact, valuesLimited := exactRustArrayArgumentExpressions(arguments[0], maxRustCommandArguments-len(chain.argumentExpressions))
			limited = limited || valuesLimited
			if !exact {
				chain.argumentsComplete = false
			} else {
				chain.argumentExpressions = append(chain.argumentExpressions, values...)
			}
		case "raw_arg":
			// This platform-specific builder mutates argv but has semantics that
			// are not portable to macOS. Keep execution, but never claim a
			// complete argument vector through it.
			chain.argumentsComplete = false
		default:
			if !allowed[method] {
				return rustCommandChain{}, limited
			}
		}
		position = close + 1
	}
	return rustCommandChain{}, true
}

func exactRustArrayArgumentExpressions(expression string, limit int) ([]string, bool, bool) {
	expression = strings.TrimSpace(expression)
	expression = strings.TrimSpace(strings.TrimPrefix(expression, "&"))
	if len(expression) < 2 || expression[0] != '[' || expression[len(expression)-1] != ']' {
		return nil, false, false
	}
	if limit < 0 {
		return nil, false, true
	}
	mask, maskLimited := rustSourceCodeMask(expression)
	if maskLimited {
		return nil, false, true
	}
	values, truncated := rustCallArguments(expression, mask, 1, len(expression)-1, limit+1)
	if truncated || len(values) > limit {
		return nil, false, true
	}
	for _, value := range values {
		if value == "" {
			return nil, false, false
		}
	}
	return values, true, false
}

func rustExactFluentCall(source string, mask []bool, start, end int, want string) (int, int, bool) {
	method, open, close, ok := rustNextFluentCall(source, mask, start, end)
	return open, close, ok && method == want
}

func rustExactFluentMethod(source string, mask []bool, start, end int, want string) bool {
	method, _, _, ok := rustNextFluentCall(source, mask, start, end)
	return ok && method == want
}

func rustNextFluentCall(source string, mask []bool, start, end int) (string, int, int, bool) {
	position := start
	for position < end && (source[position] == ' ' || source[position] == '\t' || source[position] == '\r' || source[position] == '\n') {
		position++
	}
	if position >= end || source[position] != '.' || !rustCodeAt(mask, position) {
		return "", 0, 0, false
	}
	nameStart := position + 1
	nameEnd := nameStart
	for nameEnd < end && (source[nameEnd] == '_' || source[nameEnd] >= '0' && source[nameEnd] <= '9' || source[nameEnd] >= 'A' && source[nameEnd] <= 'Z' || source[nameEnd] >= 'a' && source[nameEnd] <= 'z') {
		nameEnd++
	}
	if nameEnd == nameStart {
		return "", 0, 0, false
	}
	position = nameEnd
	for position < end && (source[position] == ' ' || source[position] == '\t' || source[position] == '\r' || source[position] == '\n') {
		position++
	}
	if position >= end || source[position] != '(' || !rustCodeAt(mask, position) {
		return "", 0, 0, false
	}
	close, ok := rustCallClose(source, mask, position, min(maxRustAPIStatementBytes, end-position+1))
	if !ok || close > end {
		return "", 0, 0, false
	}
	return source[nameStart:nameEnd], position, close, true
}

func rustFlexiblePathPattern(value string) string {
	parts := strings.Split(value, "::")
	for index := range parts {
		parts[index] = regexp.QuoteMeta(parts[index])
	}
	return strings.Join(parts, `\s*::\s*`)
}

func rustCodeAt(mask []bool, index int) bool {
	return index >= 0 && index < len(mask) && mask[index]
}

func rustLineStarts(source string) []int {
	starts := []int{0}
	for index := 0; index < len(source); index++ {
		if source[index] == '\n' {
			starts = append(starts, index+1)
		}
	}
	return starts
}

func rustLineForOffset(starts []int, offset int) int {
	return sort.Search(len(starts), func(index int) bool { return starts[index] > offset })
}

func uniqueRustFunctionScopeAtLine(scopes []behavior.Scope, nodeID string, line int) (behavior.Scope, bool) {
	var selected behavior.Scope
	for _, scope := range scopes {
		if scope.NodeID != nodeID || scope.Kind != "function" || scope.Function == "" || line < scope.LineStart || line > scope.LineEnd {
			continue
		}
		if selected.ID != "" {
			return behavior.Scope{}, false
		}
		selected = scope
	}
	return selected, selected.ID != ""
}

func rustSortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value == "" || len(result) > 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}
