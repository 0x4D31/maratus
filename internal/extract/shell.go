package extract

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/osacli"
	"github.com/0x4D31/maratus/internal/shellparse"
)

const (
	maxShellExpansionDepth    = 4
	maxShellStatementsPerLine = 4096
	maxShellPipelineParts     = 64
)

type shellSourceOrder struct {
	group     int
	next      int
	uncertain bool
}

func AnalyzeShellLine(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	analyzeShellLineWithSourceOrderUncertainty(graph, content, line, lineNo, execution, evidenceID, false)
}

func analyzeShellLineWithSourceOrderUncertainty(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string, uncertain bool) {
	order := &shellSourceOrder{group: graph.NewSourceOrderGroup(), uncertain: uncertain}
	if uncertain {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "conditional or alternative shell control flow is present; operation ordering across its branches was not inferred")
	}
	analyzeShellLine(graph, content, line, lineNo, execution, evidenceID, 0, order)
}

func analyzeShellLine(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string, expansionDepth int, order *shellSourceOrder) {
	analyzeShellLineVariables(graph, content, line, lineNo, execution, evidenceID, expansionDepth, order, newTextVariableState(), "")
}

func analyzeShellLineVariables(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string, expansionDepth int, order *shellSourceOrder, variables *textVariableState, variableScope string) {
	if order == nil {
		order = &shellSourceOrder{group: graph.NewSourceOrderGroup()}
	}
	if order.uncertain {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "conditional or alternative shell control flow is present; operation ordering across its branches was not inferred")
	}

	operationStart := len(graph.Operations)
	defer func() {
		if order.uncertain {
			markShellSourceOrderUncertain(graph, operationStart, order.group)
		}
	}()
	if foreground, ok := stripTerminalBackgroundOperator(line); ok {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "the command or pipeline is scheduled in the background; scheduling and later synchronization were not modeled")
		order.uncertain = true
		line = foreground
	}
	hasSubstitution, unsupportedGrouping, unsupportedExpansion, malformedStructure := shellSubstitutionStatus(line)
	if hasSubstitution {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"shell-analysis",
			"command or process substitution is present; substitution behavior was not analyzed",
		)
	}
	if unsupportedGrouping {
		invalidateAllShellBindings(variables, variableScope)
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell grouping/subshell syntax is present; grouped execution was not modeled")
	}
	if unsupportedExpansion {
		invalidateAllShellBindings(variables, variableScope)
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "braced shell parameter expansion is present; expansion contents and surrounding execution were not modeled")
		return
	}
	if malformedStructure {
		invalidateAllShellBindings(variables, variableScope)
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "malformed or unclosed shell substitution/grouping was not analyzed")
		return
	}
	malformedOperators, unsupportedPipeBoth, unsupportedBackground, unsupportedBraceGroup := shellTopLevelOperatorStatus(line)
	if unsupportedPipeBoth {
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "the |& combined stdout/stderr pipeline operator is present; that pipeline was not modeled")
		return
	}
	if unsupportedBackground {
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "a background-command separator is present; background execution and surrounding commands were not modeled")
		return
	}
	if unsupportedBraceGroup {
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell brace-group syntax is present; grouped execution and surrounding commands were not modeled")
		return
	}
	if malformedOperators {
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "a shell pipeline or conditional operator has a missing operand; the malformed command was not analyzed")
		return
	}
	if shellSourceOrderHasAlternativeControlFlow(line) {
		order.uncertain = true
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "conditional or alternative shell control flow is present; operation ordering across its branches was not inferred")
	}
	statements := 0
	statementLimitHit := false
	fieldLimitHit := false
	graphLimitHit := false
	visitCommands(line, func(command string) bool {
		if statements >= maxShellStatementsPerLine {
			statementLimitHit = true
			return false
		}
		if graph.WorkLimitReached() {
			graphLimitHit = true
			return false
		}
		statements++
		order.next++
		statementOrdinal := order.next
		operationStart := len(graph.Operations)
		defer annotateShellOperationOrder(graph, operationStart, order.group, statementOrdinal, order.uncertain)
		context := variables.directoryContext(graph, variableScope)
		fields, raw, err := shellCommandFieldsRaw(command)
		defer func() { annotateShellPathContexts(graph, operationStart, context, fields, raw) }()
		if shellFieldLimitReached(err) {
			variables.invalidateDirectoryContext(variableScope, true, true)
			fieldLimitHit = true
			return false
		}
		if err == nil {
			if assignments, ok := shellAssignments(fields); ok {
				for index, assignment := range assignments {
					name, value := assignment.name, assignment.value
					if name == "HOME" {
						variables.invalidateDirectoryContext(variableScope, false, true)
					}
					word := raw[len(fields)-len(assignments)+index]
					tilde := shellWordExpandsHome(strings.TrimPrefix(word, name+"="))
					if order.uncertain || !safeShellVarValue(value) || tilde {
						variables.invalidateVariable(variableScope, name)
					} else {
						if variables.setVariable(variableScope, name, value) {
							variables.shellOrigins[shellVariableKey{variableScope, name}] = evidenceID
						}
					}
				}
				if shellAssignmentMayExecute(fields) {
					addPartialCoverageOnce(
						graph,
						content.NodeID,
						"shell-analysis",
						"assignment contains command or process substitution; the dynamic substitution was not analyzed",
					)
				}
				return true
			}
		}
		invalidateShellMutation(command, variables, variableScope)
		variables.usedShellOrigins = nil
		view := variables.variables(variableScope)
		view.localOnly = variableScope != ""
		command = expandSimpleVars("shell", command, view)
		commandContent := content
		commandContent.SupportingEvidenceIDs = append(append([]string(nil), content.SupportingEvidenceIDs...), variables.usedShellOrigins...)
		if len(variables.usedShellOrigins) > 0 && 1+len(commandContent.SupportingEvidenceIDs) > maxShellOperationEvidenceIDs {
			variables.invalidateDirectoryContext(variableScope, true, true)
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "variable expansion evidence limit reached; command semantics were not inferred")
			return true
		}
		if variables.limited {
			addPartialCoverageOnce(graph, content.NodeID, "text-variable-analysis", variables.coverageDetail())
			return false
		}
		if strings.Contains(command, "|") && handlePipeline(graph, commandContent, command, lineNo, execution, evidenceID, expansionDepth, order) {
			return true
		}
		fields, raw, err = shellCommandFieldsRaw(command)
		if shellFieldLimitReached(err) {
			variables.invalidateDirectoryContext(variableScope, true, true)
			fieldLimitHit = true
			return false
		}
		if err != nil {
			variables.invalidateDirectoryContext(variableScope, true, true)
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "malformed shell syntax was not analyzed")
			return true
		}
		if len(fields) == 0 {
			return true
		}
		working, home := shellDirectoryEffects(fields)
		defer variables.invalidateDirectoryContext(variableScope, working, home)
		analyzeShellFields(graph, commandContent, fields, lineNo, execution, evidenceID, expansionDepth, order)
		return true
	})
	if statementLimitHit {
		variables.invalidateDirectoryContext(variableScope, true, true)
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"shell-analysis",
			fmt.Sprintf("shell statement limit %d reached on one line; remaining statements were not analyzed", maxShellStatementsPerLine),
		)
	}
	if fieldLimitHit {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"shell-analysis",
			"shell argv field or decoded-byte limit reached; the oversized command and remaining statements on the line were not analyzed",
		)
	}
	if graphLimitHit {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "behavior graph limit reached; remaining shell statements were not analyzed")
		graph.MarkWorkOmitted()
	}
}

func annotateShellOperationOrder(graph *behavior.Graph, start, group, ordinal int, uncertain bool) {
	for index := start; index < len(graph.Operations); index++ {
		if graph.Operations[index].SourceOrderGroup == 0 && graph.Operations[index].SourceOrdinal == 0 {
			graph.Operations[index].SourceOrderGroup = group
			graph.Operations[index].SourceOrdinal = ordinal
		}
		graph.Operations[index].SourceOrderUncertain =
			graph.Operations[index].SourceOrderUncertain || uncertain
	}
}

func markShellSourceOrderUncertain(graph *behavior.Graph, start, group int) {
	for index := start; index < len(graph.Operations); index++ {
		if graph.Operations[index].SourceOrderGroup == group {
			graph.Operations[index].SourceOrderUncertain = true
		}
	}
}

func stripTerminalBackgroundOperator(command string) (string, bool) {
	command = strings.TrimSpace(stripInlineComment("shell", command))
	if command == "" || command[len(command)-1] != '&' {
		return command, false
	}
	index := len(command) - 1
	if index > 0 && strings.ContainsRune("&|><", rune(command[index-1])) {
		return command, false
	}
	scanner := newShellSyntaxScanner()
	for current := 0; current < len(command); {
		if current == index {
			if !scanner.topLevel() {
				return command, false
			}
			foreground := strings.TrimSpace(command[:index])
			if foreground == "" {
				return command, false
			}
			return foreground, true
		}
		current += scanner.advance(command, current)
	}
	return command, false
}

type shellSyntaxContext struct {
	terminator byte
	quote      byte
	parenDepth int
	arithmetic bool
}

type shellSyntaxScanner struct {
	contexts               []shellSyntaxContext
	escaped                bool
	executableSubstitution bool
	unsupportedGrouping    bool
	unsupportedExpansion   bool
	unexpectedClosing      bool
}

func newShellSyntaxScanner() shellSyntaxScanner {
	return shellSyntaxScanner{contexts: []shellSyntaxContext{{}}}
}

func (scanner *shellSyntaxScanner) topLevel() bool {
	return len(scanner.contexts) == 1 && scanner.contexts[0].quote == 0 && !scanner.escaped
}

func (scanner *shellSyntaxScanner) advance(command string, index int) int {
	context := &scanner.contexts[len(scanner.contexts)-1]
	current := command[index]
	if scanner.escaped {
		scanner.escaped = false
		return 1
	}
	if current == '\\' && context.quote != '\'' {
		scanner.escaped = true
		return 1
	}
	if context.quote == '\'' {
		if current == '\'' {
			context.quote = 0
		}
		return 1
	}
	if context.quote == '"' && current != '$' && current != '`' && current != '"' {
		return 1
	}
	if context.terminator == '`' && current == '`' {
		scanner.contexts = scanner.contexts[:len(scanner.contexts)-1]
		return 1
	}
	if current == '`' {
		scanner.executableSubstitution = true
		scanner.contexts = append(scanner.contexts, shellSyntaxContext{terminator: '`'})
		return 1
	}
	if current == '$' && index+1 < len(command) && command[index+1] == '(' {
		depth := 1
		width := 2
		if index+2 < len(command) && command[index+2] == '(' {
			depth = 2
			width = 3
		} else {
			scanner.executableSubstitution = true
		}
		scanner.contexts = append(scanner.contexts, shellSyntaxContext{terminator: ')', parenDepth: depth, arithmetic: width == 3})
		return width
	}
	if current == '$' && index+1 < len(command) && command[index+1] == '{' {
		end := index + 2
		for end < len(command) && isIdentifierByte(command[end]) {
			end++
		}
		if end < len(command) && command[end] == '}' && identifierName(command[index+2:end]) {
			return end - index + 1
		}
		scanner.unsupportedExpansion = true
		scanner.contexts = append(scanner.contexts, shellSyntaxContext{terminator: '}'})
		return 2
	}
	if context.quote == 0 && (current == '<' || current == '>') && index+1 < len(command) && command[index+1] == '(' {
		scanner.executableSubstitution = true
		scanner.contexts = append(scanner.contexts, shellSyntaxContext{terminator: ')', parenDepth: 1})
		return 2
	}
	if current == '"' {
		switch context.quote {
		case '"':
			context.quote = 0
		case 0:
			context.quote = '"'
		}
		return 1
	}
	if current == '\'' && context.quote == 0 {
		context.quote = '\''
		return 1
	}
	if context.quote == 0 && context.terminator == ')' {
		switch current {
		case '(':
			context.parenDepth++
		case ')':
			context.parenDepth--
			if context.parenDepth == 0 {
				scanner.contexts = scanner.contexts[:len(scanner.contexts)-1]
			}
		}
		return 1
	}
	if context.quote == 0 && context.terminator == '}' && current == '}' {
		scanner.contexts = scanner.contexts[:len(scanner.contexts)-1]
		return 1
	}
	if context.quote == 0 && current == '(' {
		scanner.unsupportedGrouping = true
		scanner.contexts = append(scanner.contexts, shellSyntaxContext{terminator: ')', parenDepth: 1})
	} else if context.quote == 0 && current == ')' {
		scanner.unexpectedClosing = true
	}
	return 1
}

func (scanner *shellSyntaxScanner) malformed() bool {
	return scanner.escaped || scanner.unexpectedClosing || len(scanner.contexts) != 1 || scanner.contexts[0].quote != 0
}

func shellSubstitutionStatus(command string) (bool, bool, bool, bool) {
	scanner := newShellSyntaxScanner()
	for index := 0; index < len(command); {
		index += scanner.advance(command, index)
	}
	return scanner.executableSubstitution, scanner.unsupportedGrouping, scanner.unsupportedExpansion, scanner.malformed()
}

// shellTopLevelOperatorStatus rejects incomplete binary shell operators before
// the lightweight command visitor can discard their empty operands. It also
// identifies |&, whose stderr-merging semantics are intentionally left
// unresolved instead of being mistaken for an ordinary stdout-only pipeline.
func shellTopLevelOperatorStatus(command string) (malformed, unsupportedPipeBoth, unsupportedBackground, unsupportedBraceGroup bool) {
	scanner := newShellSyntaxScanner()
	segmentHasContent := false
	expectingOperand := false
	for index := 0; index < len(command); {
		if scanner.topLevel() {
			current := command[index]
			if (current == '{' || current == '}') && standaloneShellControlByte(command, index) {
				unsupportedBraceGroup = true
			}
			switch {
			case current == '|' && index+1 < len(command) && command[index+1] == '&':
				if !segmentHasContent {
					malformed = true
				}
				unsupportedPipeBoth = true
				segmentHasContent = false
				expectingOperand = true
				index += 2
				continue
			case (current == '|' || current == '&') && index+1 < len(command) && command[index+1] == current:
				if !segmentHasContent {
					malformed = true
				}
				segmentHasContent = false
				expectingOperand = true
				index += 2
				continue
			case current == '|':
				if !segmentHasContent {
					malformed = true
				}
				segmentHasContent = false
				expectingOperand = true
				index++
				continue
			case current == '&' && !shellRedirectionAmpersand(command, index):
				if !segmentHasContent {
					malformed = true
				}
				unsupportedBackground = true
				segmentHasContent = false
				expectingOperand = false
				index++
				continue
			case current == ';':
				if expectingOperand {
					malformed = true
				}
				segmentHasContent = false
				expectingOperand = false
				index++
				continue
			case current != ' ' && current != '\t' && current != '\r' && current != '\n':
				segmentHasContent = true
				expectingOperand = false
			}
		}
		index += scanner.advance(command, index)
	}
	if expectingOperand {
		malformed = true
	}
	return malformed, unsupportedPipeBoth, unsupportedBackground, unsupportedBraceGroup
}

// shellSourceOrderHasAlternativeControlFlow identifies forms where lexical
// order alone cannot establish that one operation consumes bytes produced by
// another. Individual commands remain observable, but the relation linker must
// not turn mutually exclusive branches or negated status tests into a proved
// operation path.
func shellSourceOrderHasAlternativeControlFlow(command string) bool {
	scanner := newShellSyntaxScanner()
	for index := 0; index < len(command); {
		if scanner.topLevel() && command[index] == '|' &&
			index+1 < len(command) && command[index+1] == '|' {
			return true
		}
		index += scanner.advance(command, index)
	}
	alternative := false
	visitCommands(command, func(part string) bool {
		fields, err := CommandFields(part)
		if err != nil || len(fields) == 0 {
			return true
		}
		switch strings.ToLower(fields[0]) {
		case "if", "elif", "else", "while", "until", "for", "case", "select",
			"then", "do", "!":
			alternative = true
			return false
		default:
			return true
		}
	})
	return alternative
}

func shellRedirectionAmpersand(command string, index int) bool {
	return index > 0 && (command[index-1] == '>' || command[index-1] == '<') ||
		index+1 < len(command) && command[index+1] == '>'
}

func standaloneShellControlByte(command string, index int) bool {
	leftBoundary := index == 0 || shellControlBoundaryByte(command[index-1])
	rightBoundary := index+1 == len(command) || shellControlBoundaryByte(command[index+1])
	return leftBoundary && rightBoundary
}

func shellControlBoundaryByte(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || strings.ContainsRune(";|&()", rune(value))
}

func analyzeShellFields(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string, expansionDepth int, order *shellSourceOrder) {
	var err error
	fields, err = normalizeCommandFieldsChecked(fields)
	if shellFieldLimitReached(err) {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell argv field or decoded-byte limit reached in a wrapped command; the oversized command was not analyzed")
		return
	}
	if errors.Is(err, shellparse.ErrUnsupportedSyntax) {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell command or wrapper syntax could not be normalized safely; the unsupported command was not analyzed")
		return
	}
	if err != nil {
		return
	}
	if len(fields) == 0 {
		return
	}
	tool := filepath.Base(fields[0])
	handleLaunchdPathWrite(graph, content, tool, fields, lineNo, execution, evidenceID)
	handleShellProfileWrite(graph, content, tool, fields, lineNo, execution, evidenceID)
	if tool == "zip" || tool == "unzip" || tool == "tar" || tool == "ditto" {
		handleArchiveCommand(graph, content, tool, fields, lineNo, execution, evidenceID)
		return
	}
	handleSensitiveFileRead(graph, content, tool, fields, lineNo, execution, evidenceID)
	handleSharedShellCommandSemantics(graph, content, fields, lineNo, execution, evidenceID)
	if addLocalAgentInvocationOperation(graph, content, fields, lineNo, execution, evidenceID) != "" {
		return
	}
	switch tool {
	case "curl", "wget":
		handleDownloader(graph, content, tool, fields, lineNo, execution, evidenceID)
	case "cp":
		handleFileCopy(graph, content, fields, lineNo, execution, evidenceID)
	case "mv":
		handleFileMove(graph, content, fields, lineNo, execution, evidenceID)
	case "chmod":
		handleChmod(graph, content, fields, lineNo, execution, evidenceID)
	case "sh", "bash", "zsh", "python", "python3", "node", "deno":
		handleInterpreter(graph, content, tool, fields, lineNo, execution, evidenceID)
		if tool == "sh" || tool == "bash" || tool == "zsh" {
			handleShellCommandString(graph, content, fields, lineNo, execution, expansionDepth, order)
		}
		if language, code := interpreterInlineCode(tool, fields); code != "" {
			AnalyzeInlineCode(graph, content, language, code, execution, evidenceID)
		}
	case "osascript":
		handleInterpreter(graph, content, tool, fields, lineNo, execution, evidenceID)
		handleOSAScript(graph, content, fields, lineNo, execution)
	case "launchctl":
		if target := launchctlPersistenceTarget(fields); target != "" {
			addSimpleOperation(graph, content, behavior.OperationLaunchdJobLoad, launchdJobResource(target), lineNo, execution, evidenceID)
		}
	case "security":
		if securityReadsCredentialStore(fields) {
			addSimpleOperation(graph, content, behavior.OperationCredentialStoreRead, behavior.NewResource(behavior.ResourceCredentialStore, securityResourceTarget(fields), behavior.ResourceClassKeychain), lineNo, execution, evidenceID)
		}
	case "dscl":
		if dsclAuthOnlyAction(fields) {
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID:    content.NodeID,
				ScopeID:          content.ScopeID,
				Kind:             behavior.OperationCredentialValidate,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleCredential, behavior.NewResource(behavior.ResourceCredential, ""))),
				Qualifiers:       map[string]string{"mechanism": "dscl authonly"},
				EvidenceIDs:      shellOperationEvidence(content, evidenceID),
				Support:          behavior.SupportCorroborated,
				Execution:        execution,
				Architecture:     content.Architecture,
				Line:             lineNo,
			})
		}
	case "installer":
		if fields[0] != "installer" && fields[0] != "/usr/sbin/installer" {
			// A third-party executable can also be named installer. Only the bare
			// macOS command (including sudo-normalized input) and its canonical
			// absolute path support the typed package-install semantics.
			if looksExecutable(fields[0]) {
				addProcessExecuteOperation(graph, content, fields, lineNo, execution, evidenceID)
			}
			break
		}
		if target, ok := installerPackageTarget(fields); ok {
			addSimpleOperation(graph, content, behavior.OperationPackageInstall, behavior.NewResource(behavior.ResourceFile, target, behavior.ResourceClassPackage), lineNo, execution, evidenceID)
		} else if looksExecutable(fields[0]) {
			// Preserve the generic execution fallback for path-qualified installer
			// commands whose package argument cannot be resolved statically.
			addProcessExecuteOperation(graph, content, fields, lineNo, execution, evidenceID)
		}
	case "xattr":
		if xattrRemovesQuarantine(fields) {
			addSimpleOperation(graph, content, behavior.OperationQuarantineAttributeRemove, behavior.NewResource(behavior.ResourceFile, strings.Join(fields, " ")), lineNo, execution, evidenceID)
		}
	case "spctl":
		if containsField(fields, "--master-disable") {
			addSimpleOperation(graph, content, behavior.OperationGatekeeperConfigurationModify, behavior.NewResource(behavior.ResourceConfiguration, strings.Join(fields, " ")), lineNo, execution, evidenceID)
		}
	case "screencapture":
		handleScreenCapture(graph, content, fields, lineNo, execution, evidenceID)
	case "pbpaste":
		addSimpleOperation(graph, content, behavior.OperationClipboardRead, behavior.NewResource(behavior.ResourceClipboard, "pbpaste"), lineNo, execution, evidenceID)
	case "open":
		dest, limited := delegatedURLDestinationsWithStatus(strings.Join(fields[1:], " "))
		if limited {
			addPartialCoverageOnce(graph, content.NodeID, "shell-network-analysis", "network destination match or retained-byte limit reached; excess destinations were not analyzed")
		}
		if len(dest) > 0 {
			addDelegatedNetworkOperation(graph, content, "open", dest, lineNo, execution, evidenceID)
		}
	default:
		if looksExecutable(fields[0]) {
			addProcessExecuteOperation(graph, content, fields, lineNo, execution, evidenceID)
		}
	}
}

func handleArchiveCommand(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	result := parseArchiveCommand(tool, fields)
	if result.Disposition == archiveParseUnsupported {
		addPartialCoverageOnce(graph, content.NodeID, "shell-archive-analysis", result.CoverageDetail)
		return
	}
	if result.Disposition != archiveParseRecognized {
		return
	}
	if result.ReadsLocalSources {
		handleSensitiveFileReadTargets(graph, content, result.LocalSources, lineNo, execution, evidenceID)
	}
	if result.CreatesOutput {
		bindings := behavior.Bindings(behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, result.OutputPath, behavior.ResourceClassArchive)))
		for _, source := range result.LocalSources {
			if len(bindings) >= behavior.MaxOperationResourceBindings {
				addPartialCoverageOnce(graph, content.NodeID, "shell-archive-analysis", "archive source binding limit reached; excess source operands were not retained")
				break
			}
			if source = staticShellResource(source); source != "" {
				bindings = append(bindings, behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source)))
			}
		}
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationArchiveCreate,
			ResourceBindings: bindings, EvidenceIDs: shellOperationEvidence(content, evidenceID),
			Support: behavior.SupportCorroborated, Execution: execution, Architecture: content.Architecture, Line: lineNo,
		})
	}
	if result.ExtractsArchive {
		source := staticShellResource(result.InputPath)
		target := staticShellResource(result.ExtractionTarget)
		qualifiers := map[string]string{"tool": tool, "source_binding": "unresolved", "destination_binding": "runtime-working-directory"}
		if result.TargetProvided {
			qualifiers["destination_binding"] = "unresolved"
		}
		if source != "" {
			qualifiers["source_binding"] = "exact-static"
		}
		if target != "" {
			qualifiers["destination_binding"] = "exact-static"
		}
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, Kind: behavior.OperationArchiveExtract,
			ResourceBindings: behavior.Bindings(
				behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source, behavior.ResourceClassArchive)),
				behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, target)),
			),
			Qualifiers: qualifiers, EvidenceIDs: shellOperationEvidence(content, evidenceID),
			Support: behavior.SupportCorroborated, Execution: execution, Architecture: content.Architecture, Line: lineNo,
		})
	}
}

func dsclAuthOnlyAction(fields []string) bool {
	if len(fields) < 3 {
		return false
	}
	index := 1
	for index < len(fields) {
		switch fields[index] {
		case "-u", "-P", "-f":
			if index+1 >= len(fields) {
				return false
			}
			index += 2
		case "-p", "-q", "-raw", "-plist", "-url", "-localonly", "-mcx":
			index++
		default:
			if strings.HasPrefix(fields[index], "-") {
				return false
			}
			if index+1 >= len(fields) {
				return false
			}
			return fields[index+1] == "authonly" || fields[index+1] == "-authonly"
		}
	}
	return false
}

func FirstShellCommand(line string) string {
	fields := FirstShellCommandFields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// FirstShellCommandFields returns argv-like fields for the first non-assignment
// command in a shell line.
func FirstShellCommandFields(line string) []string {
	var result []string
	visitCommands(line, func(command string) bool {
		if first := firstPipelinePart(command); first != "" {
			command = first
		}
		fields, err := shellCommandFields(command)
		if err != nil || len(fields) == 0 {
			return true
		}
		if _, ok := shellAssignments(fields); ok {
			return true
		}
		fields = normalizeCommandFields(fields)
		if len(fields) == 0 {
			return true
		}
		result = fields
		return false
	})
	return result
}

func interpreterInlineCode(tool string, fields []string) (string, string) {
	if len(fields) < 2 {
		return "", ""
	}
	language := ""
	switch tool {
	case "python", "python3":
		language = "python"
	case "node":
		language = "javascript"
	}
	if language == "" {
		return "", ""
	}
	return language, parsedInterpreterInlineCode(tool, fields[1:])
}

func securityResourceTarget(fields []string) string {
	subcommand, commandIndex := securitySubcommand(fields)
	if commandIndex < 0 {
		return ""
	}
	commandFields := fields[commandIndex+1:]
	for _, field := range commandFields {
		if looksKeychainPath(field) {
			return field
		}
	}
	if subcommand == "find-generic-password" || subcommand == "find-internet-password" {
		if value := optionValue(commandFields, "-s"); value != "" {
			return subcommand + " service=" + value
		}
		if value := optionValue(commandFields, "-a"); value != "" {
			return subcommand + " account=" + value
		}
	}
	return ""
}

func securityReadsCredentialStore(fields []string) bool {
	command, index := securitySubcommand(fields)
	switch command {
	case "dump-keychain", "find-generic-password", "find-internet-password", "find-identity":
		return true
	case "find-key":
		return securityFindKeyIncludesCredentials(fields[index+1:])
	case "export":
		return securityExportIncludesCredentialItems(fields[index+1:])
	default:
		return false
	}
}

func securitySubcommand(fields []string) (string, int) {
	for index := 1; index < len(fields); index++ {
		field := fields[index]
		if field == "-p" {
			if index+1 >= len(fields) {
				return "", -1
			}
			index++
			continue
		}
		if strings.HasPrefix(field, "-p") && len(field) > 2 {
			continue
		}
		if strings.HasPrefix(field, "-") {
			options := strings.TrimPrefix(field, "-")
			if options != "" && strings.Trim(options, "lqv") == "" {
				continue
			}
			// Help and interactive modes do not establish a statically
			// supplied command. Unknown global options remain unsupported.
			return "", -1
		}
		return field, index
	}
	return "", -1
}

func securityFindKeyIncludesCredentials(fields []string) bool {
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if field == "-t" {
			if index+1 >= len(fields) {
				return false
			}
			return fields[index+1] == "private" || fields[index+1] == "symmetric"
		}
		if strings.HasPrefix(field, "-t") && len(field) > 2 {
			value := strings.TrimPrefix(field, "-t")
			return value == "private" || value == "symmetric"
		}
	}
	return true
}

func securityExportIncludesCredentialItems(fields []string) bool {
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if field == "-t" {
			if index+1 >= len(fields) {
				return false
			}
			return securityExportTypeIncludesCredentials(fields[index+1])
		}
		if strings.HasPrefix(field, "-t") && len(field) > 2 {
			return securityExportTypeIncludesCredentials(strings.TrimPrefix(field, "-t"))
		}
	}
	// The documented default exports all item types, including private keys
	// and identities.
	return true
}

func securityExportTypeIncludesCredentials(value string) bool {
	switch value {
	case "all", "allKeys", "privKeys", "identities":
		return true
	case "certs", "pubKeys":
		return false
	default:
		return false
	}
}

func installerPackageTarget(fields []string) (string, bool) {
	var target string
	found := false
	for i := 1; i < len(fields); i++ {
		if fields[i] != "-pkg" {
			continue
		}
		// Duplicate package options are ambiguous, and a following option is
		// not a package operand. In either case, retain only the generic process
		// model rather than claiming a well-formed package installation.
		if found || i+1 >= len(fields) || strings.HasPrefix(fields[i+1], "-") {
			return "", false
		}
		found = true
		target = fields[i+1]
	}
	if !found {
		return "", false
	}
	if !safeShellVarValue(target) {
		// The installer operation is still statically visible even when its
		// package operand is resolved only at runtime. Keep the typed operation and
		// leave the concrete resource empty instead of inventing a path.
		return "", true
	}
	return staticShellResource(target), true
}

func optionValue(fields []string, option string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == option {
			return fields[i+1]
		}
	}
	return ""
}

func looksKeychainPath(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "/keychains/") || strings.HasSuffix(lower, ".keychain") || strings.HasSuffix(lower, ".keychain-db")
}

type shellAssignment struct{ name, value string }

func shellAssignments(fields []string) ([]shellAssignment, bool) {
	if len(fields) == 0 {
		return nil, false
	}
	start := 0
	if fields[0] == "export" {
		start = 1
	}
	if start >= len(fields) {
		return nil, false
	}
	assignments := []shellAssignment{}
	for _, field := range fields[start:] {
		name, value, ok := splitShellAssignment(field)
		if !ok {
			return nil, false
		}
		assignments = append(assignments, shellAssignment{name, value})
	}
	return assignments, true
}

func shellAssignmentMayExecute(fields []string) bool {
	if len(fields) > 0 && fields[0] == "export" {
		fields = fields[1:]
	}
	for _, field := range fields {
		_, value, ok := splitShellAssignment(field)
		if !ok {
			continue
		}
		if strings.Contains(value, "$(") || strings.Contains(value, "<(") || strings.Contains(value, ">(") || strings.Contains(value, "`") {
			return true
		}
	}
	return false
}

// shellCommandFields recognizes grammar only from exact unquoted source words.
// Decoded argv from launchd or native calls must never pass through this step.
func shellCommandFields(command string) ([]string, error) {
	fields, _, err := shellCommandFieldsRaw(command)
	return fields, err
}

func shellCommandFieldsRaw(command string) ([]string, []string, error) {
	fields, raw, err := shellparse.FieldsWithRaw(command)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) != len(raw) {
		return nil, nil, shellparse.ErrUnsupportedSyntax
	}
	for len(fields) > 0 && raw[0] == fields[0] {
		switch fields[0] {
		case "if", "elif", "while", "until", "then", "do", "else", "!":
			fields, raw = fields[1:], raw[1:]
		case "fi", "done", "esac":
			return nil, nil, nil
		default:
			goto ready
		}
	}
ready:
	// An assignment-looking executable with a quoted/escaped name is not a
	// shell assignment. The argv normalizer cannot preserve that distinction.
	for i, field := range fields {
		if name, _, ok := splitShellAssignment(field); ok && !strings.HasPrefix(raw[i], name+"=") {
			return nil, nil, shellparse.ErrUnsupportedSyntax
		}
	}
	return fields, raw, nil
}

func splitShellAssignment(field string) (string, string, bool) {
	return shellparse.Assignment(field)
}

func safeShellVarValue(value string) bool {
	if value == "" {
		return true
	}
	return !strings.ContainsAny(value, "$`*?[]{}")
}

func normalizeCommandFields(fields []string) []string {
	return shellparse.NormalizeFields(fields)
}

func normalizeCommandFieldsChecked(fields []string) ([]string, error) {
	return shellparse.NormalizeFieldsChecked(fields)
}

func handleShellCommandString(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, expansionDepth int, order *shellSourceOrder) {
	if expansionDepth >= maxShellExpansionDepth {
		return
	}
	snippet := shellCommandString(fields)
	if snippet == "" {
		return
	}
	snippetEvidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Line:     lineNo,
		Method:   "shell",
		Kind:     "shell-command-string",
		Value:    snippet,
	})
	analyzeShellLine(graph, content, snippet, lineNo, execution, snippetEvidenceID, expansionDepth+1, order)
}

func shellCommandString(fields []string) string {
	if len(fields) < 2 {
		return ""
	}
	return parsedInterpreterInlineCode(filepath.Base(fields[0]), fields[1:])
}

func handleSensitiveFileRead(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	handleSensitiveFileReadTargets(graph, content, sensitiveReadTargets(tool, fields), lineNo, execution, evidenceID)
}

func handleSensitiveFileReadTargets(graph *behavior.Graph, content artifact.Content, targets []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	state := newTextDerivedBudget()
	budget := state.line()
	for _, target := range targets {
		if resource, ok := sensitiveResourceBudget(target, budget); ok {
			graph.AddOperation(behavior.ModeledOperation{
				SubjectNodeID:    content.NodeID,
				ScopeID:          content.ScopeID,
				Kind:             behavior.OperationFileRead,
				ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, resource)),
				EvidenceIDs:      shellOperationEvidence(content, evidenceID),
				Support:          behavior.SupportCorroborated,
				Execution:        execution,
				Architecture:     content.Architecture,
				Line:             lineNo,
			})
		}
		if budget.limited {
			break
		}
	}
	if state.limited {
		addPartialCoverageOnce(graph, content.NodeID, "shell-sensitive-resource-analysis", "sensitive-resource match or retained-byte limit reached; excess or oversized shell targets were not analyzed completely")
	}
}

func sensitiveReadTargets(tool string, fields []string) []string {
	switch tool {
	case "cat", "sqlite3", "plutil", "strings":
		return nonFlagArgs(fields[1:])
	case "cp":
		args := nonFlagArgs(fields[1:])
		if len(args) > 1 {
			return args[:len(args)-1]
		}
	case "curl", "wget":
		if source := uploadPath(fields); source != "" {
			return []string{source}
		}
	}
	return nil
}

func nonFlagArgs(fields []string) []string {
	var out []string
	for _, field := range fields {
		if field == "" || strings.HasPrefix(field, "-") {
			continue
		}
		out = append(out, field)
	}
	return out
}

func handleOSAScript(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext) {
	language, code, ok := osaInlineProgram(fields)
	if !ok {
		return
	}
	snippetEvidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		ScopeID: content.ScopeID,
		Logical: content.LogicalPath,
		Method:  "shell",
		Kind:    "osascript-snippet",
		Value:   code,
	})
	content.SupportingEvidenceIDs = append(append([]string(nil), content.SupportingEvidenceIDs...), snippetEvidenceID)
	AnalyzeInlineCode(graph, content, language, code, execution, snippetEvidenceID)
}

// -e arguments are successive lines of one program, not independent scripts.
// After a positional program/argument, later -e text is data rather than code.
func osaInlineProgram(fields []string) (string, string, bool) {
	if len(fields) == 0 {
		return "", "", false
	}
	parsed := osacli.Parse(fields[1:])
	if !parsed.Executes() || parsed.Source != osacli.Inline {
		return "", "", false
	}
	return parsed.Language, strings.Join(parsed.Lines, "\n"), true
}

func handleLaunchdPathWrite(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	target := launchdWriteTarget(tool, fields)
	if target == "" {
		return
	}
	category, ok := launchdInstallPathCategory(target)
	if !ok {
		return
	}
	value := staticShellResource(target)
	var qualifiers map[string]string
	if tool == "cp" || tool == "mv" || tool == "install" || value == "" {
		// These utilities accept either a filename or an existing directory as
		// their last operand. The command still targets a canonical launchd
		// location, but filesystem state decides the final job identity.
		value = ""
		qualifiers = map[string]string{"destination_operand": target}
	}
	classification := behavior.ResourceClassLaunchAgent
	if category == "launch-daemon" {
		classification = behavior.ResourceClassLaunchDaemon
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID,
		ScopeID:       content.ScopeID,
		Kind:          behavior.OperationLaunchdJobInstall,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			behavior.ResourceRoleJob,
			behavior.NewResource(behavior.ResourceLaunchdJob, value, classification),
		)),
		Qualifiers:   qualifiers,
		EvidenceIDs:  shellOperationEvidence(content, evidenceID),
		Support:      behavior.SupportCorroborated,
		Execution:    execution,
		Architecture: content.Architecture,
		Line:         lineNo,
	})
}

func launchdWriteTarget(tool string, fields []string) string {
	if target := pathWriteTarget(tool, fields); isLaunchdPath(target) {
		return target
	}
	return ""
}

func handleShellProfileWrite(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	target := shellProfileWriteTarget(tool, fields)
	if target == "" {
		return
	}
	value := staticShellResource(target)
	var qualifiers map[string]string
	if tool == "cp" || tool == "mv" || tool == "install" || value == "" {
		value = ""
		qualifiers = map[string]string{"destination_operand": target}
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID,
		ScopeID:       content.ScopeID,
		Kind:          behavior.OperationShellProfileModify,
		ResourceBindings: behavior.Bindings(behavior.Bind(
			behavior.ResourceRoleTarget,
			behavior.NewResource(behavior.ResourceFile, value, behavior.ResourceClassShellProfile),
		)),
		Qualifiers:   qualifiers,
		EvidenceIDs:  shellOperationEvidence(content, evidenceID),
		Support:      behavior.SupportCorroborated,
		Execution:    execution,
		Architecture: content.Architecture,
		Line:         lineNo,
	})
}

func shellProfileWriteTarget(tool string, fields []string) string {
	if target := pathWriteTarget(tool, fields); isShellProfilePath(target) {
		return target
	}
	return ""
}

func pathWriteTarget(tool string, fields []string) string {
	switch tool {
	case "cp", "mv", "install", "tee":
		return lastNonFlag(fields)
	case "cat", "printf", "echo":
		return redirectionTarget(fields)
	default:
		return ""
	}
}

func redirectionTarget(fields []string) string {
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if isRedirectionOperator(field) && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(field, ">") && len(field) > 1 {
			return strings.TrimLeft(field, ">")
		}
	}
	return ""
}

func isRedirectionOperator(field string) bool {
	switch field {
	case ">", ">>", "1>", "1>>":
		return true
	default:
		return false
	}
}

func isLaunchdPath(value string) bool {
	_, ok := launchdInstallPathCategory(value)
	return ok
}

// launchdInstallPathCategory accepts only a plist directly below a documented
// system or user launchd directory. Substring matching would turn staged trees
// such as /tmp/root/Library/LaunchAgents into installed persistence, while a
// nested directory is not part of launchd's ordinary job-discovery location.
func launchdInstallPathCategory(value string) (string, bool) {
	// The argv parser already removed shell quoting. Remaining whitespace and
	// quote bytes are part of the filename, not presentation syntax.
	if value == "" {
		return "", false
	}
	cleaned := strings.ToLower(filepath.ToSlash(filepath.Clean(value)))
	roots := []struct {
		path     string
		category string
	}{
		{"/library/launchagents", "launch-agent"},
		{"/library/launchdaemons", "launch-daemon"},
		{"/system/library/launchagents", "launch-agent"},
		{"/system/library/launchdaemons", "launch-daemon"},
		{"/var/root/library/launchagents", "launch-agent"},
		{"/private/var/root/library/launchagents", "launch-agent"},
		{"~/library/launchagents", "launch-agent"},
		{"$home/library/launchagents", "launch-agent"},
		{"${home}/library/launchagents", "launch-agent"},
	}
	if strings.HasPrefix(cleaned, "/users/") {
		remainder := strings.TrimPrefix(cleaned, "/users/")
		if separator := strings.IndexByte(remainder, '/'); separator > 0 {
			roots = append(roots, struct {
				path     string
				category string
			}{"/users/" + remainder[:separator] + "/library/launchagents", "launch-agent"})
		}
	}
	for _, root := range roots {
		prefix := root.path + "/"
		if !strings.HasPrefix(cleaned, prefix) {
			continue
		}
		name := strings.TrimPrefix(cleaned, prefix)
		if name != "" && !strings.ContainsRune(name, '/') && strings.HasSuffix(name, ".plist") {
			return root.category, true
		}
	}
	return "", false
}

func isShellProfilePath(value string) bool {
	// Preserve literal filename bytes after argv decoding, as above.
	if value == "" {
		return false
	}
	cleaned := strings.ToLower(filepath.ToSlash(filepath.Clean(value)))
	switch cleaned {
	case "/etc/zshrc", "/etc/zprofile", "/etc/zlogin", "/etc/zshenv",
		"/etc/bashrc", "/etc/profile", "/etc/fish/config.fish",
		"/usr/local/etc/fish/config.fish", "/opt/homebrew/etc/fish/config.fish":
		return true
	}
	homeRoots := []string{"~", "$home", "${home}", "/var/root", "/private/var/root"}
	if strings.HasPrefix(cleaned, "/users/") {
		remainder := strings.TrimPrefix(cleaned, "/users/")
		if separator := strings.IndexByte(remainder, '/'); separator > 0 {
			homeRoots = append(homeRoots, "/users/"+remainder[:separator])
		}
	}
	profiles := []string{
		".zshrc", ".zprofile", ".zlogin", ".zshenv",
		".bash_profile", ".bashrc", ".bash_login", ".profile",
		".config/fish/config.fish",
	}
	for _, root := range homeRoots {
		for _, profile := range profiles {
			if cleaned == root+"/"+profile {
				return true
			}
		}
	}
	return false
}

func launchdResourceCategory(value string) string {
	lower := strings.TrimSpace(strings.ToLower(filepath.ToSlash(value)))
	switch {
	case strings.Contains(lower, "launchdaemons"), lower == "system", strings.HasPrefix(lower, "system/"):
		return "launch-daemon"
	case strings.Contains(lower, "launchagents"),
		lower == "gui", strings.HasPrefix(lower, "gui/"),
		lower == "user", strings.HasPrefix(lower, "user/"),
		lower == "login", strings.HasPrefix(lower, "login/"):
		return "launch-agent"
	default:
		return "launchd-service"
	}
}

func launchdJobResource(value string) behavior.Resource {
	classification := behavior.ResourceClassLaunchAgent
	if launchdResourceCategory(value) == "launch-daemon" {
		classification = behavior.ResourceClassLaunchDaemon
	}
	return behavior.NewResource(behavior.ResourceLaunchdJob, value, classification)
}

func launchctlPersistenceTarget(fields []string) string {
	if len(fields) < 2 {
		return ""
	}
	subcommand := fields[1]
	switch subcommand {
	case "load":
		return lastNonFlag(fields[1:])
	case "bootstrap":
		return lastNonFlag(fields[2:])
	case "enable":
		return lastNonFlag(fields[1:])
	default:
		return ""
	}
}

func xattrRemovesQuarantine(fields []string) bool {
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if field == "--" {
			return false
		}
		if field == "-d" || field == "--delete" {
			return i+1 < len(fields) && fields[i+1] == "com.apple.quarantine"
		}
		if strings.HasPrefix(field, "--delete=") {
			return strings.TrimPrefix(field, "--delete=") == "com.apple.quarantine"
		}
		if strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--") {
			options := field[1:]
			if strings.Contains(options, "c") {
				return true
			}
			if strings.Contains(options, "d") {
				return i+1 < len(fields) && fields[i+1] == "com.apple.quarantine"
			}
		}
	}
	return false
}

func handlePipeline(graph *behavior.Graph, content artifact.Content, line string, lineNo int, execution behavior.ExecutionContext, evidenceID string, expansionDepth int, order *shellSourceOrder) bool {
	parts, truncated := splitPipelineLimited(line, maxShellPipelineParts)
	if truncated {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			"shell-analysis",
			fmt.Sprintf("shell pipeline segment limit %d reached; remaining segments were not analyzed", maxShellPipelineParts),
		)
	}
	if len(parts) < 2 {
		return false
	}
	parsed := make([][]string, len(parts))
	for index, part := range parts {
		fields, err := shellCommandFields(strings.TrimSpace(part))
		if shellFieldLimitReached(err) {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell argv field or decoded-byte limit reached in a pipeline; the pipeline was not analyzed")
			return true
		}
		if err != nil {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "malformed shell pipeline syntax was not analyzed")
			return true
		}
		fields, err = normalizeCommandFieldsChecked(fields)
		if shellFieldLimitReached(err) {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell argv field or decoded-byte limit reached in a wrapped pipeline command; the pipeline was not analyzed")
			return true
		}
		if errors.Is(err, shellparse.ErrUnsupportedSyntax) {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "shell command or wrapper syntax could not be normalized safely; the pipeline was not analyzed")
			return true
		}
		if err != nil {
			return true
		}
		parsed[index] = fields
	}
	consumed := make([]bool, len(parsed))
	base64Windows := 0
	for index := 0; index+2 < len(parts); index++ {
		if handleBase64DecodePipeline(graph, content, parts[index:index+3], lineNo, execution, expansionDepth, order) {
			consumed[index] = true
			consumed[index+1] = true
			consumed[index+2] = true
			base64Windows++
		}
	}
	for index := 0; index+2 < len(parsed); index++ {
		if consumed[index] || consumed[index+1] || consumed[index+2] {
			continue
		}
		if base64DecodeCommand(parsed[index+1]) && shellPipelineInterpreter(parsed[index+2]) {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "base64 pipeline input was dynamic or invalid; the decoded program was not analyzed")
		}
	}
	for index := 0; index+1 < len(parsed); index++ {
		if consumed[index] || consumed[index+1] {
			continue
		}
		if handleDownloadInterpreterFields(graph, content, parsed[index], parsed[index+1], lineNo, execution, evidenceID) {
			consumed[index] = true
			consumed[index+1] = true
		}
	}
	if base64Windows > 0 && len(parts) > 3 {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "literal base64 decode window was analyzed, but surrounding pipeline relations were not modeled")
	}
	for index, fields := range parsed {
		if consumed[index] || len(fields) == 0 {
			continue
		}
		analyzeShellFields(graph, content, fields, lineNo, execution, evidenceID, expansionDepth, order)
		if index > 0 && shellPipelineInterpreter(fields) {
			addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "an interpreter reads from a pipeline whose program content was not statically recovered")
		}
	}
	for left := 0; left < len(parsed); left++ {
		if !shellPipelineDownloader(parsed[left]) {
			continue
		}
		for right := left + 2; right < len(parsed); right++ {
			if shellPipelineInterpreter(parsed[right]) {
				addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "pipeline contains intermediate commands between a downloader and interpreter; individual operations were analyzed but the end-to-end relation was not established")
				return true
			}
		}
	}
	return true
}

func shellPipelineDownloader(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	tool := filepath.Base(fields[0])
	return (tool == "curl" || tool == "wget") && downloaderHasRequestOperand(tool, fields)
}

func downloaderWritesBodyToStdout(tool string, fields []string) bool {
	if hasStdoutRedirection(fields[1:]) {
		return false
	}
	switch tool {
	case "curl":
		for index := 1; index < len(fields); index++ {
			field := fields[index]
			if method, ok := curlShortOptionValue(field, 'X', nextShellField(fields, index)); ok && strings.EqualFold(method, "HEAD") {
				return false
			}
			switch {
			case field == "-o" || field == "--output":
				if index+1 >= len(fields) || fields[index+1] != "-" {
					return false
				}
				index++
			case strings.HasPrefix(field, "--output="):
				if strings.TrimPrefix(field, "--output=") != "-" {
					return false
				}
			case field == "-O" || field == "--remote-name" || field == "--remote-name-all" || field == "-I" || field == "--head":
				return false
			case field == "-X" || field == "--request":
				if index+1 >= len(fields) || strings.EqualFold(fields[index+1], "HEAD") {
					return false
				}
				index++
			case strings.HasPrefix(field, "--request="):
				if strings.EqualFold(strings.TrimPrefix(field, "--request="), "HEAD") {
					return false
				}
			case strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--"):
				stdout, relevant, consumesNext := curlShortOutputToStdout(field, nextShellField(fields, index))
				if consumesNext {
					index++
				}
				if relevant && !stdout {
					return false
				}
			}
		}
		return true
	case "wget":
		stdout := false
		for index := 1; index < len(fields); index++ {
			field := fields[index]
			switch {
			case field == "-O" || field == "--output-document":
				if index+1 >= len(fields) || fields[index+1] != "-" {
					return false
				}
				stdout = true
				index++
			case strings.HasPrefix(field, "--output-document="):
				if strings.TrimPrefix(field, "--output-document=") != "-" {
					return false
				}
				stdout = true
			case strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--"):
				value, found, consumesNext := wgetShortOutputValue(field, nextShellField(fields, index))
				if consumesNext {
					index++
				}
				if found {
					if value != "-" {
						return false
					}
					stdout = true
				}
			}
		}
		return stdout
	default:
		return false
	}
}

func nextShellField(fields []string, index int) string {
	if index+1 >= len(fields) {
		return ""
	}
	return fields[index+1]
}

func curlShortOutputToStdout(field, next string) (stdout, relevant, consumesNext bool) {
	cluster := strings.TrimPrefix(field, "-")
	const valueOptions = "AbCcDdEeFHmoPQrTtUuwxXyYz"
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if option == 'O' || option == 'I' {
			return false, true, false
		}
		if !strings.ContainsRune(valueOptions, rune(option)) {
			continue
		}
		value := cluster[index+1:]
		if value == "" {
			value = next
			consumesNext = true
		}
		if option == 'o' {
			return value == "-", true, consumesNext
		}
		if option == 'X' && strings.EqualFold(value, "HEAD") {
			return false, true, consumesNext
		}
		return false, false, consumesNext
	}
	return false, false, false
}

func curlShortOptionValue(field string, target byte, next string) (string, bool) {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
		return "", false
	}
	cluster := strings.TrimPrefix(field, "-")
	const valueOptions = "AbCcDdEeFHKmoPQrTtUuwxXyYz"
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if !strings.ContainsRune(valueOptions, rune(option)) {
			continue
		}
		value := cluster[index+1:]
		if value == "" {
			value = next
		}
		if option == target {
			return value, true
		}
		return "", false
	}
	return "", false
}

func wgetShortOutputValue(field, next string) (value string, found, consumesNext bool) {
	cluster := strings.TrimPrefix(field, "-")
	const valueOptions = "AIBlOQRTUWXaeioptw"
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if !strings.ContainsRune(valueOptions, rune(option)) {
			continue
		}
		value = cluster[index+1:]
		if value == "" {
			value = next
			consumesNext = true
		}
		return value, option == 'O', consumesNext
	}
	return "", false, false
}

func hasStdoutRedirection(args []string) bool {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, ">") || strings.HasPrefix(trimmed, "1>") || strings.HasPrefix(trimmed, "&>") {
			return true
		}
	}
	return false
}

func handleDownloadInterpreterFields(graph *behavior.Graph, content artifact.Content, leftFields, rightFields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) bool {
	if len(leftFields) == 0 || len(rightFields) == 0 {
		return false
	}
	if !shellPipelineDownloader(leftFields) {
		return false
	}
	if !downloaderPipelineOptionsSafe(filepath.Base(leftFields[0]), leftFields) {
		addPartialCoverageOnce(graph, content.NodeID, "shell-analysis", "downloader configuration can change pipeline output semantics; the end-to-end interpreter relation was not established")
		return false
	}
	if !downloaderWritesBodyToStdout(filepath.Base(leftFields[0]), leftFields) {
		return false
	}
	interp := filepath.Base(rightFields[0])
	if !shellPipelineInterpreter(rightFields) {
		return false
	}
	dest := downloaderDestinations(filepath.Base(leftFields[0]), leftFields)
	downloadID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationNetworkDownload,
		ResourceBindings: networkOperationBindings(behavior.OperationNetworkDownload, dest, "", ""),
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportDirect,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
	execID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, interp, behavior.ResourceClassInterpreter))),
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportDirect,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
	graph.AddNetworkImplementation(shellNetworkImplementation(downloadID, content, execution, behavior.SupportDirect, filepath.Base(leftFields[0]), networkSecurity(leftFields), evidenceID, true))
	graph.AddRelation(behavior.OperationRelation{
		Kind:         behavior.RelationPipesTo,
		From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, downloadID),
		To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, execID),
		EvidenceIDs:  shellOperationEvidence(content, evidenceID),
		Support:      behavior.SupportDirect,
		Execution:    execution,
		Architecture: content.Architecture,
	})
	return true
}

func handleBase64DecodePipeline(graph *behavior.Graph, content artifact.Content, parts []string, lineNo int, execution behavior.ExecutionContext, expansionDepth int, order *shellSourceOrder) bool {
	if expansionDepth >= maxShellExpansionDepth || len(parts) < 3 {
		return false
	}
	source, ok := literalBase64PipelineSource(parts[0])
	if !ok {
		return false
	}
	base64Fields, err := CommandFields(strings.TrimSpace(parts[1]))
	if err != nil || !base64PipelineDecoder(base64Fields) {
		return false
	}
	interpFields, err := CommandFields(strings.TrimSpace(parts[2]))
	if err != nil {
		return false
	}
	interpFields = UnwrapCommandWrappers(interpFields)
	if !shellPipelineInterpreter(interpFields) {
		return false
	}
	decoded, ok := decodeBase64Literal(source)
	if !ok {
		return false
	}
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		ScopeID: content.ScopeID,
		Logical: content.LogicalPath,
		Method:  "shell",
		Kind:    "base64-decoded-script",
		Value:   evidenceSnippet(decoded),
	})
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         "shell.base64_decoded_script",
		Value:       "literal base64 pipeline",
		EvidenceIDs: shellOperationEvidence(content, ev),
		Support:     behavior.SupportCorroborated,
	})
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID,
		ScopeID:       content.ScopeID,
		Kind:          behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, filepath.Base(interpFields[0]), behavior.ResourceClassInterpreter)),
			behavior.Bind(behavior.ResourceRoleStandardInput, behavior.NewResource(behavior.ResourceCommand, "decoded base64")),
		),
		EvidenceIDs:  shellOperationEvidence(content, ev),
		Support:      behavior.SupportCorroborated,
		Execution:    execution,
		Architecture: content.Architecture,
		Line:         lineNo,
	})
	switch filepath.Base(interpFields[0]) {
	case "sh", "bash", "zsh":
		analyzeShellLine(graph, content, decoded, lineNo, execution, ev, expansionDepth+1, order)
	case "python", "python3":
		AnalyzeInlineCode(graph, content, "python", decoded, execution, ev)
	case "node":
		AnalyzeInlineCode(graph, content, "javascript", decoded, execution, ev)
	case "osascript":
		AnalyzeInlineCode(graph, content, "applescript", decoded, execution, ev)
	}
	return true
}

func literalBase64PipelineSource(command string) (string, bool) {
	fields, err := CommandFields(strings.TrimSpace(command))
	if err != nil || len(fields) == 0 {
		return "", false
	}
	fields = normalizeCommandFields(fields)
	if len(fields) == 0 || hasStdoutRedirection(fields[1:]) || containsField(fields[1:], "&") {
		return "", false
	}
	// Stderr-only redirections do not change the bytes delivered to the next
	// pipeline segment, but they are shell syntax rather than literal payload.
	fields = stripPipelineOutputRedirections(fields)
	if len(fields) == 0 {
		return "", false
	}
	switch filepath.Base(fields[0]) {
	case "echo":
		values := fields[1:]
		for len(values) > 0 && echoOption(values[0]) {
			values = values[1:]
		}
		return base64LiteralFromFields(values)
	case "printf":
		if len(fields) < 3 || !simplePrintfFormat(fields[1]) {
			return "", false
		}
		return base64LiteralFromFields(fields[2:])
	default:
		return "", false
	}
}

func echoOption(field string) bool {
	switch field {
	case "-n", "-e", "-E":
		return true
	default:
		return false
	}
}

func simplePrintfFormat(field string) bool {
	switch field {
	case "%s", "%s\n", "%s\\n":
		return true
	default:
		return false
	}
}

func base64LiteralFromFields(fields []string) (string, bool) {
	if len(fields) == 0 {
		return "", false
	}
	value := strings.Join(fields, "")
	if len(value) > 128*1024 {
		return "", false
	}
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '+', '/', '=', '\r', '\n', '\t', ' ':
			continue
		default:
			return "", false
		}
	}
	return value, true
}

func base64DecodeCommand(fields []string) bool {
	fields = normalizeCommandFields(fields)
	if len(fields) == 0 || filepath.Base(fields[0]) != "base64" {
		return false
	}
	for _, field := range fields[1:] {
		switch field {
		case "-d", "-D", "--decode":
			return true
		}
		if strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--") && (strings.Contains(field[1:], "d") || strings.Contains(field[1:], "D")) {
			return true
		}
	}
	return false
}

// base64PipelineDecoder recognizes only decoder invocations whose input still
// comes from the preceding pipeline segment and whose decoded bytes still go
// to the following segment. BSD base64 uses -i/-o on macOS; positional inputs
// are rejected because they are not valid input syntax for the macOS utility.
func base64PipelineDecoder(fields []string) bool {
	fields = normalizeCommandFields(fields)
	if len(fields) == 0 || filepath.Base(fields[0]) != "base64" {
		return false
	}
	if hasStdinRedirection(fields[1:]) || hasStdoutRedirection(fields[1:]) || containsField(fields[1:], "&") {
		return false
	}
	fields = stripPipelineOutputRedirections(fields)
	if len(fields) == 0 {
		return false
	}

	decode := false
	stdinOperand := false
	args := fields[1:]
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--":
			return false
		case arg == "--decode":
			decode = true
		case arg == "--ignore-garbage":
			continue
		case arg == "--input" || arg == "--output":
			if index+1 >= len(args) || args[index+1] != "-" {
				return false
			}
			if arg == "--input" {
				if stdinOperand {
					return false
				}
				stdinOperand = true
			}
			index++
		case strings.HasPrefix(arg, "--input=") || strings.HasPrefix(arg, "--output="):
			name, value, _ := strings.Cut(arg, "=")
			if value != "-" {
				return false
			}
			if name == "--input" {
				if stdinOperand {
					return false
				}
				stdinOperand = true
			}
		case arg == "--wrap" || arg == "--break":
			if index+1 >= len(args) || !decimalShellOptionValue(args[index+1]) {
				return false
			}
			index++
		case strings.HasPrefix(arg, "--wrap=") || strings.HasPrefix(arg, "--break="):
			_, value, _ := strings.Cut(arg, "=")
			if !decimalShellOptionValue(value) {
				return false
			}
		case arg == "-":
			// BSD base64 on macOS does not accept a positional input file,
			// including "-"; stdin is already the default or explicit -i -.
			return false
		case strings.HasPrefix(arg, "-"):
			cluster := strings.TrimPrefix(arg, "-")
			if cluster == "" {
				return false
			}
			for offset := 0; offset < len(cluster); offset++ {
				switch cluster[offset] {
				case 'd', 'D':
					decode = true
				case 'i', 'o', 'b', 'w':
					value := cluster[offset+1:]
					if value == "" {
						if index+1 >= len(args) {
							return false
						}
						index++
						value = args[index]
					}
					if cluster[offset] == 'i' || cluster[offset] == 'o' {
						if value != "-" || cluster[offset] == 'i' && stdinOperand {
							return false
						}
						if cluster[offset] == 'i' {
							stdinOperand = true
						}
					} else if !decimalShellOptionValue(value) {
						return false
					}
					offset = len(cluster)
				default:
					return false
				}
			}
		default:
			// A positional BSD/GNU input file replaces pipeline stdin.
			return false
		}
	}
	return decode
}

func decimalShellOptionValue(value string) bool {
	if value == "" {
		return false
	}
	for _, current := range value {
		if current < '0' || current > '9' {
			return false
		}
	}
	return true
}

func shellPipelineInterpreter(fields []string) bool {
	fields = normalizeCommandFields(fields)
	if len(fields) == 0 {
		return false
	}
	if hasStdinRedirection(fields[1:]) {
		return false
	}
	fields = stripPipelineOutputRedirections(fields)
	if len(fields) == 0 {
		return false
	}
	tool := filepath.Base(fields[0])
	args := fields[1:]
	switch tool {
	case "sh", "bash", "zsh":
		return shellReadsProgramFromStdin(args)
	case "python", "python3", "node":
		return len(args) == 0 || len(args) == 1 && args[0] == "-"
	case "osascript":
		return osascriptReadsProgramFromStdin(args)
	default:
		return false
	}
}

func stripPipelineOutputRedirections(fields []string) []string {
	out := make([]string, 0, len(fields))
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if field == "&" || field == "2>&1" || field == "1>&2" {
			continue
		}
		if field == ">" || field == ">>" || field == "1>" || field == "1>>" || field == "2>" || field == "2>>" {
			index++
			continue
		}
		if strings.HasPrefix(field, ">") || strings.HasPrefix(field, "1>") || strings.HasPrefix(field, "2>") {
			continue
		}
		out = append(out, field)
	}
	return out
}

func osascriptReadsProgramFromStdin(args []string) bool {
	parsed := osacli.Parse(args)
	return parsed.Executes() && parsed.Source == osacli.Stdin
}

func hasStdinRedirection(args []string) bool {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "0<") {
			return true
		}
	}
	return false
}

func shellReadsProgramFromStdin(args []string) bool {
	stdinMode := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			return stdinMode || index == len(args)-1
		}
		shortOptions := strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--")
		if arg == "-c" || shortOptions && strings.Contains(strings.TrimPrefix(arg, "-"), "c") {
			return false
		}
		if arg == "-s" || shortOptions && strings.Contains(strings.TrimPrefix(arg, "-"), "s") {
			stdinMode = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if !stdinMode {
			return false
		}
	}
	return true
}

func decodeBase64Literal(value string) (string, bool) {
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, value)
	if value == "" {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
	}
	if err != nil || len(decoded) == 0 || len(decoded) > 64*1024 || !mostlyText(decoded) {
		return "", false
	}
	return string(decoded), true
}

func mostlyText(data []byte) bool {
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	return printable*100/len(data) >= 90
}

func evidenceSnippet(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 512 {
		return value
	}
	return value[:512] + "..."
}

func handleDownloader(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	if _, understood := downloaderRequestOperands(tool, fields); !understood {
		addPartialCoverageOnce(graph, content.NodeID, "shell-network-analysis", "curl/wget options could not be interpreted without ambiguity; request operands were not modeled")
		return
	}
	dest, limited := downloaderDestinationsWithStatus(tool, fields)
	if limited {
		addPartialCoverageOnce(graph, content.NodeID, "shell-network-analysis", "network destination match or retained-byte limit reached; excess destinations were not analyzed")
	}
	if uploadPath(fields) != "" {
		operationID := graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID:    content.NodeID,
			ScopeID:          content.ScopeID,
			Kind:             behavior.OperationNetworkUpload,
			ResourceBindings: networkOperationBindings(behavior.OperationNetworkUpload, dest, "", uploadPath(fields)),
			EvidenceIDs:      shellOperationEvidence(content, evidenceID),
			Support:          behavior.SupportCorroborated,
			Execution:        execution,
			Architecture:     content.Architecture,
			Line:             lineNo,
		})
		graph.AddNetworkImplementation(shellNetworkImplementation(operationID, content, execution, behavior.SupportCorroborated, tool, networkSecurity(fields), evidenceID, false))
		return
	}
	if !downloaderHasRequestOperand(tool, fields) {
		return
	}
	target := downloadOutput(tool, fields)
	kind := behavior.OperationNetworkConnect
	if target != "" {
		kind = behavior.OperationNetworkDownload
	}
	operationID := graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             kind,
		ResourceBindings: networkOperationBindings(kind, dest, target, ""),
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
	graph.AddNetworkImplementation(shellNetworkImplementation(operationID, content, execution, behavior.SupportCorroborated, tool, networkSecurity(fields), evidenceID, false))
}

func downloaderDestinations(tool string, fields []string) []string {
	destinations, _ := downloaderDestinationsWithStatus(tool, fields)
	return destinations
}

func downloaderDestinationsWithStatus(tool string, fields []string) ([]string, bool) {
	values, understood := downloaderRequestOperands(tool, fields)
	if !understood {
		return nil, false
	}
	return destinationsWithStatus(strings.Join(values, " "))
}

func downloaderHasRequestOperand(tool string, fields []string) bool {
	operands, understood := downloaderRequestOperands(tool, fields)
	return understood && len(operands) > 0
}

// downloaderRequestOperands returns only request operands after a conservative
// parse of curl/wget options. Unknown options are rejected because treating a
// following option value as a URL can turn a command with no request into a
// proven download-to-interpreter chain.
func downloaderRequestOperands(tool string, fields []string) ([]string, bool) {
	if len(fields) == 0 || filepath.Base(fields[0]) != tool {
		return nil, false
	}
	var operands []string
	for index := 1; index < len(fields); index++ {
		field := fields[index]
		if field == "--" {
			operands = append(operands, fields[index+1:]...)
			return operands, true
		}
		if field == "-" || !strings.HasPrefix(field, "-") {
			operands = append(operands, field)
			continue
		}
		if strings.HasPrefix(field, "--") {
			name, inlineValue, inline := strings.Cut(field, "=")
			if tool == "curl" && name == "--url" {
				if inline {
					if inlineValue == "" {
						return nil, false
					}
					operands = append(operands, inlineValue)
					continue
				}
				if index+1 >= len(fields) {
					return nil, false
				}
				index++
				operands = append(operands, fields[index])
				continue
			}
			if downloaderAmbiguousLongOption(tool, name) {
				return nil, false
			}
			if downloaderLongValueOption(tool, name) {
				if !inline {
					if index+1 >= len(fields) {
						return nil, false
					}
					index++
				}
				continue
			}
			if !inline && downloaderLongFlagOption(tool, name) {
				continue
			}
			return nil, false
		}
		consumesNext, known := downloaderShortOption(tool, field)
		if !known {
			return nil, false
		}
		if consumesNext {
			if index+1 >= len(fields) {
				return nil, false
			}
			index++
		}
	}
	return operands, true
}

func downloaderAmbiguousLongOption(tool, name string) bool {
	return tool == "curl" && name == "--next" ||
		tool == "wget" && (name == "--execute" || name == "--input-file")
}

func downloaderLongValueOption(tool, name string) bool {
	switch tool {
	case "curl":
		switch name {
		case "--alt-svc", "--aws-sigv4", "--cacert", "--cert", "--cert-type", "--ciphers", "--config",
			"--connect-timeout", "--connect-to", "--cookie", "--cookie-jar", "--crlfile", "--data",
			"--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--dump-header",
			"--etag-compare", "--etag-save", "--expect100-timeout", "--form", "--form-string",
			"--ftp-account", "--ftp-alternative-to-user", "--ftp-method", "--happy-eyeballs-timeout-ms",
			"--header", "--hostpubmd5", "--hsts", "--interface", "--json", "--keepalive-time",
			"--key", "--key-type", "--limit-rate", "--local-port", "--login-options", "--mail-auth",
			"--mail-from", "--mail-rcpt", "--max-filesize", "--max-redirs", "--max-time", "--noproxy",
			"--oauth2-bearer", "--output", "--output-dir", "--parallel-max", "--pass", "--pinnedpubkey",
			"--proto", "--proto-default", "--proto-redir", "--proxy", "--proxy-cacert", "--proxy-cert",
			"--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile", "--proxy-header", "--proxy-key",
			"--proxy-key-type", "--proxy-pass", "--proxy-service-name", "--proxy-tls13-ciphers",
			"--proxy-tlsauthtype", "--proxy-tlspassword", "--proxy-tlsuser", "--proxy-user", "--pubkey",
			"--quote", "--range", "--rate", "--referer", "--request", "--request-target", "--resolve",
			"--retry", "--retry-delay", "--retry-max-time", "--sasl-authzid", "--service-name",
			"--speed-limit", "--speed-time", "--stderr", "--telnet-option", "--time-cond", "--tls-max",
			"--tls13-ciphers", "--tlsauthtype", "--tlspassword", "--tlsuser", "--unix-socket",
			"--upload-file", "--user", "--user-agent", "--variable", "--write-out":
			return true
		}
	case "wget":
		switch name {
		case "--accept", "--accept-regex", "--base", "--bind-address", "--body-data", "--body-file",
			"--ca-certificate", "--certificate", "--certificate-type", "--connect-timeout", "--cut-dirs",
			"--directory-prefix", "--dns-timeout", "--domains", "--exclude-directories", "--exclude-domains",
			"--header", "--http-password", "--http-user", "--include-directories",
			"--level", "--limit-rate", "--load-cookies", "--method", "--output-document", "--output-file",
			"--password", "--post-data", "--post-file", "--private-key", "--progress", "--remote-encoding",
			"--proxy-password", "--proxy-user", "--quota", "--read-timeout", "--referer", "--reject",
			"--reject-regex", "--save-cookies", "--secure-protocol", "--timeout", "--tries", "--user",
			"--user-agent", "--wait", "--waitretry":
			return true
		}
	}
	return false
}

func downloaderLongFlagOption(tool, name string) bool {
	switch tool {
	case "curl":
		switch name {
		case "--anyauth", "--basic", "--compressed", "--digest", "--disable", "--fail", "--fail-early",
			"--fail-with-body", "--ftp-create-dirs", "--ftp-pasv", "--get", "--globoff", "--head",
			"--http0.9", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
			"--ignore-content-length", "--insecure", "--ipv4", "--ipv6", "--junk-session-cookies",
			"--location", "--location-trusted", "--netrc", "--netrc-optional", "--no-buffer",
			"--no-progress-meter", "--parallel", "--path-as-is", "--progress-bar", "--proxy-anyauth",
			"--proxy-basic", "--proxy-digest", "--proxy-insecure", "--proxy-negotiate", "--proxy-ntlm",
			"--remote-header-name", "--remote-name", "--remote-name-all", "--retry-all-errors",
			"--retry-connrefused", "--show-error", "--silent", "--ssl", "--ssl-reqd", "--styled-output",
			"--tcp-nodelay", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3",
			"--tr-encoding", "--verbose":
			return true
		}
	case "wget":
		switch name {
		case "--adjust-extension", "--auth-no-challenge", "--background", "--backup-converted", "--cache",
			"--check-certificate", "--content-disposition", "--continue", "--debug", "--delete-after",
			"--directories", "--directory-prefixes", "--force-directories", "--force-html", "--https-only",
			"--ignore-case", "--ignore-length", "--inet4-only", "--inet6-only", "--keep-session-cookies", "--mirror", "--no-cache",
			"--no-check-certificate", "--no-clobber", "--no-cookies", "--no-directories", "--no-host-directories",
			"--no-parent", "--no-proxy", "--no-remove-listing", "--no-verbose", "--page-requisites",
			"--passive-ftp", "--protocol-directories", "--quiet", "--recursive", "--server-response", "--span-hosts",
			"--timestamping", "--trust-server-names", "--verbose":
			return true
		}
	}
	return false
}

func downloaderShortOption(tool, field string) (consumesNext, known bool) {
	cluster := strings.TrimPrefix(field, "-")
	if cluster == "" {
		return false, false
	}
	valueOptions := ""
	flagOptions := ""
	ambiguousOptions := ""
	switch tool {
	case "curl":
		valueOptions = "AbCcDdEeFHKmoPQrTtUuwxXyYz"
		flagOptions = "012346aBfgGijIJklLNOnpqRsSvZ#"
		ambiguousOptions = "hMV:"
	case "wget":
		valueOptions = "AIBlOQRTUWXaeioptw"
		flagOptions = "bcdEFHkKnpqSvw"
		ambiguousOptions = "ei"
	default:
		return false, false
	}
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if strings.ContainsRune(ambiguousOptions, rune(option)) {
			return false, false
		}
		if strings.ContainsRune(valueOptions, rune(option)) {
			return index == len(cluster)-1, true
		}
		if !strings.ContainsRune(flagOptions, rune(option)) {
			return false, false
		}
	}
	return false, true
}

func downloaderPipelineOptionsSafe(tool string, fields []string) bool {
	for _, field := range fields[1:] {
		if tool == "curl" {
			if field == "--config" || strings.HasPrefix(field, "--config=") || curlShortClusterHasOption(field, 'K') {
				return false
			}
		}
		if tool == "wget" {
			if field == "--execute" || strings.HasPrefix(field, "--execute=") ||
				field == "--input-file" || strings.HasPrefix(field, "--input-file=") ||
				wgetShortClusterHasOption(field, 'e') || wgetShortClusterHasOption(field, 'i') {
				return false
			}
		}
	}
	return true
}

func curlShortClusterHasOption(field string, target byte) bool {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
		return false
	}
	cluster := strings.TrimPrefix(field, "-")
	const valueOptions = "AbCcDdEeFHKmoPQrTtUuwxXyYz"
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if option == target {
			return true
		}
		if strings.ContainsRune(valueOptions, rune(option)) {
			return false
		}
	}
	return false
}

func wgetShortClusterHasOption(field string, target byte) bool {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
		return false
	}
	cluster := strings.TrimPrefix(field, "-")
	const valueOptions = "AIBlOQRTUWXaeioptw"
	for index := 0; index < len(cluster); index++ {
		option := cluster[index]
		if option == target {
			return true
		}
		if strings.ContainsRune(valueOptions, rune(option)) {
			return false
		}
	}
	return false
}

func handleChmod(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	if !chmodMakesExecutable(fields) {
		return
	}
	target := lastNonFlag(fields)
	if target == "" {
		return
	}
	addSimpleOperation(graph, content, behavior.OperationFileMakeExecutable, behavior.NewResource(behavior.ResourceFile, target), lineNo, execution, evidenceID)
}

func chmodMakesExecutable(fields []string) bool {
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if field == "--" {
			continue
		}
		if field == "--reference" {
			i++
			continue
		}
		if chmodOption(field) {
			continue
		}
		return chmodModeMakesExecutable(field)
	}
	return false
}

func chmodOption(field string) bool {
	switch field {
	case "-R", "-f", "-v", "-h", "--recursive", "--force", "--verbose", "--changes", "--preserve-root", "--no-preserve-root":
		return true
	}
	if strings.HasPrefix(field, "--reference=") {
		return true
	}
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
		return false
	}
	for _, r := range field[1:] {
		if !strings.ContainsRune("Rfvh", r) {
			return false
		}
	}
	return len(field) > 1
}

func chmodModeMakesExecutable(mode string) bool {
	if numericChmodMode(mode) {
		return numericModeMakesExecutable(mode)
	}
	for _, clause := range strings.Split(mode, ",") {
		for i, r := range clause {
			if r != '+' && r != '=' {
				continue
			}
			if strings.ContainsRune(clause[i+1:], 'x') {
				return true
			}
		}
	}
	return false
}

func numericChmodMode(mode string) bool {
	if mode == "" {
		return false
	}
	for _, r := range mode {
		if r < '0' || r > '7' {
			return false
		}
	}
	return true
}

func numericModeMakesExecutable(mode string) bool {
	start := 0
	if len(mode) > 3 {
		start = len(mode) - 3
	}
	for _, r := range mode[start:] {
		if (r-'0')&1 == 1 {
			return true
		}
	}
	return false
}

func handleInterpreter(graph *behavior.Graph, content artifact.Content, tool string, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	concrete := quotedInvocationArguments(fields[1:])
	bindings := behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, concrete)),
		behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, tool, behavior.ResourceClassInterpreter)),
	)
	if localInput, incomplete := interpreterLocalInput(tool, fields[1:]); localInput != "" {
		bindings = append(bindings, behavior.Bind(behavior.ResourceRoleLocalInput, behavior.NewResource(behavior.ResourceFile, localInput)))
	} else if incomplete != "" {
		addPartialCoverageOnce(graph, content.NodeID, "interpreter-input-analysis", incomplete)
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationInterpreterInvoke,
		ResourceBindings: bindings,
		Qualifiers:       map[string]string{"argument_encoding": "shell-quoted"},
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
}

func addSimpleOperation(graph *behavior.Graph, content artifact.Content, kind behavior.OperationKind, resource behavior.Resource, lineNo int, execution behavior.ExecutionContext, evidenceID string) string {
	resource.Value = staticShellResource(resource.Value)
	if resource.Kind == behavior.ResourceFile && len(resource.Classifications) == 0 && resource.Value != "" {
		resource = classifiedFileResource(resource.Value)
	}
	return graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             kind,
		ResourceBindings: requiredResourceBindings(kind, resource),
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
}

func addProcessExecuteOperation(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) string {
	if len(fields) == 0 {
		return ""
	}
	bindings := behavior.Bindings(
		behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, staticShellResource(fields[0]))),
	)
	if arguments := quotedInvocationArguments(fields[1:]); arguments != "" {
		bindings = append(bindings, behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(behavior.ResourceCommand, arguments)))
	}
	return graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID:    content.NodeID,
		ScopeID:          content.ScopeID,
		Kind:             behavior.OperationProcessExecute,
		ResourceBindings: bindings,
		Qualifiers:       map[string]string{"argument_encoding": "shell-quoted"},
		EvidenceIDs:      shellOperationEvidence(content, evidenceID),
		Support:          behavior.SupportCorroborated,
		Execution:        execution,
		Architecture:     content.Architecture,
		Line:             lineNo,
	})
}

// quotedInvocationArguments is a lossless presentation of an already parsed
// argv. Only consumers checking argument_encoding may decode it back to argv;
// ordinary display strings and executable resources are never shell programs.
func quotedInvocationArguments(args []string) string {
	quoted := make([]string, len(args))
	for index, arg := range args {
		safe := arg != ""
		for _, c := range arg {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-=:+,%@", c)) {
				safe = false
				break
			}
		}
		quoted[index] = arg
		if !safe {
			quoted[index] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(quoted, " ")
}

const maxShellOperationEvidenceIDs = 32

func shellOperationEvidence(content artifact.Content, primary string) []string {
	out := make([]string, 0, min(1+len(content.SupportingEvidenceIDs), maxShellOperationEvidenceIDs))
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		for _, existing := range out {
			if candidate == existing {
				return
			}
		}
		out = append(out, candidate)
	}
	add(primary)
	for _, candidate := range content.SupportingEvidenceIDs {
		if len(out) >= maxShellOperationEvidenceIDs {
			break
		}
		add(candidate)
	}
	return out
}

func staticShellResource(value string) string {
	if value == "" || !safeShellVarValue(value) || shellResourceHasRuntimePlaceholder(value) {
		return ""
	}
	return value
}

func shellResourceHasRuntimePlaceholder(value string) bool {
	for _, marker := range []string{"%@", "%s", "%d", "%i", "%u", "$@", "$*"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func shellNetworkImplementation(operationID string, content artifact.Content, execution behavior.ExecutionContext, support behavior.Support, tool string, security []behavior.NetworkSecurityProperty, evidenceID string, pipe bool) behavior.NetworkImplementationObservation {
	http := tool
	tls := "command-selected TLS provider"
	family := "command-dependent"
	if tool == "curl" {
		http = "curl/libcurl"
		tls = "libcurl-selected TLS backend"
		family = "libcurl backend-dependent"
	}
	if tool == "wget" {
		http = "wget"
		tls = "wget TLS backend"
	}
	detail := behavior.NetworkImplementationObservation{
		Kind:                 behavior.NetworkImplementationToolInvocation,
		SubjectNodeID:        content.NodeID,
		ScopeID:              content.ScopeID,
		Architecture:         content.Architecture,
		OperationIDs:         []string{operationID},
		APIOrTool:            tool,
		HTTPImplementation:   http,
		TLSProvider:          tls,
		TLSProviderBasis:     behavior.TLSProviderBasisToolRuntime,
		TLSProfileFamily:     family,
		SecurityProperties:   security,
		UnresolvedProperties: []string{"tool version", "TLS backend", "proxy policy", "ALPN", "session state"},
		EvidenceIDs:          []string{evidenceID},
		Support:              support,
		Execution:            execution,
	}
	if pipe {
		detail.UnresolvedProperties = append(detail.UnresolvedProperties, "downloaded content is not inspected")
	}
	return detail
}

func networkSecurity(fields []string) []behavior.NetworkSecurityProperty {
	if certificateVerificationDisabled(fields) {
		return []behavior.NetworkSecurityProperty{behavior.NetworkSecurityTLSCertificateVerificationDisabled}
	}
	return nil
}

func certificateVerificationDisabled(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	switch filepath.Base(fields[0]) {
	case "curl":
		for _, field := range fields[1:] {
			if field == "--" {
				return false
			}
			if field == "--insecure" {
				return true
			}
			if strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--") && strings.Contains(field[1:], "k") {
				return true
			}
		}
	case "wget":
		for _, field := range fields[1:] {
			if field == "--" {
				return false
			}
			if field == "--no-check-certificate" {
				return true
			}
		}
	}
	return false
}

func splitCommands(line string) []string {
	return splitShellTopLevel(line, commandSeparator)
}

func visitCommands(line string, visit func(string) bool) bool {
	return visitShellTopLevel(line, commandSeparator, visit)
}

func splitPipeline(line string) []string {
	return splitShellTopLevel(line, pipelineSeparator)
}

func splitPipelineLimited(line string, limit int) ([]string, bool) {
	var out []string
	truncated := false
	visitShellTopLevel(line, pipelineSeparator, func(part string) bool {
		if len(out) >= limit {
			truncated = true
			return false
		}
		out = append(out, part)
		return true
	})
	return out, truncated
}

func firstPipelinePart(line string) string {
	var first string
	visitShellTopLevel(line, pipelineSeparator, func(part string) bool {
		first = part
		return false
	})
	return first
}

func commandSeparator(line string, i int) (int, bool) {
	switch line[i] {
	case ';':
		return 1, true
	case '&':
		if i+1 < len(line) && line[i+1] == '&' {
			return 2, true
		}
	case '|':
		if i+1 < len(line) && line[i+1] == '|' {
			return 2, true
		}
	}
	return 0, false
}

func pipelineSeparator(line string, i int) (int, bool) {
	if line[i] != '|' {
		return 0, false
	}
	if (i > 0 && line[i-1] == '|') || (i+1 < len(line) && line[i+1] == '|') {
		return 0, false
	}
	return 1, true
}

func splitShellTopLevel(line string, separator func(string, int) (int, bool)) []string {
	var out []string
	visitShellTopLevel(line, separator, func(part string) bool {
		out = append(out, part)
		return true
	})
	return out
}

func visitShellTopLevel(line string, separator func(string, int) (int, bool), visit func(string) bool) bool {
	start := 0
	scanner := newShellSyntaxScanner()
	for index := 0; index < len(line); {
		if scanner.topLevel() {
			if width, ok := separator(line, index); ok {
				if !visitShellPart(line[start:index], visit) {
					return false
				}
				index += width
				start = index
				continue
			}
		}
		index += scanner.advance(line, index)
	}
	return visitShellPart(line[start:], visit)
}

func visitShellPart(part string, visit func(string) bool) bool {
	part = strings.TrimSpace(part)
	if part != "" {
		return visit(part)
	}
	return true
}

func CommandFields(command string) ([]string, error) {
	return shellparse.Fields(command)
}

func shellFieldLimitReached(err error) bool {
	return errors.Is(err, shellparse.ErrFieldLimit)
}

// UnwrapCommandWrappers returns the command payload after static wrappers such
// as sudo, env, and the shell command builtin.
func UnwrapCommandWrappers(fields []string) []string {
	return shellparse.UnwrapCommandWrappers(fields)
}

func downloadOutput(tool string, fields []string) string {
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		switch field {
		case "-o", "--output":
			if i+1 < len(fields) {
				return fields[i+1]
			}
		case "-O":
			if tool == "wget" && i+1 < len(fields) {
				return fields[i+1]
			}
		case "--output-document":
			if tool == "wget" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
		if strings.HasPrefix(field, "--output=") {
			return strings.TrimPrefix(field, "--output=")
		}
		if tool == "wget" && strings.HasPrefix(field, "--output-document=") {
			return strings.TrimPrefix(field, "--output-document=")
		}
		if target, ok := shortOutputTarget(tool, field, fields, i); ok {
			return target
		}
	}
	return ""
}

func shortOutputTarget(tool, field string, fields []string, index int) (string, bool) {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") {
		return "", false
	}
	if field == "-O" {
		return "", false
	}
	if tool == "curl" && strings.HasPrefix(field, "-o") && len(field) > 2 {
		return strings.TrimPrefix(field, "-o"), true
	}
	if tool == "wget" && strings.HasPrefix(field, "-O") && len(field) > 2 {
		return strings.TrimPrefix(field, "-O"), true
	}
	for i := 1; i < len(field); i++ {
		if !isShortOutputOption(tool, field[i]) {
			continue
		}
		if i+1 < len(field) {
			return field[i+1:], true
		}
		if index+1 < len(fields) {
			return fields[index+1], true
		}
		return "", false
	}
	return "", false
}

func isShortOutputOption(tool string, option byte) bool {
	switch tool {
	case "curl":
		return option == 'o'
	case "wget":
		return option == 'O'
	default:
		return false
	}
}

func uploadPath(fields []string) string {
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if field == "--" {
			return ""
		}
		if field == "--upload-file" && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(field, "--upload-file=") {
			return strings.TrimPrefix(field, "--upload-file=")
		}
		if field == "-T" && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(field, "-T") && len(field) > 2 {
			return strings.TrimPrefix(field, "-T")
		}
		if source := curlDataUploadPath(fields, i); source != "" {
			return source
		}
		if source := curlFormUploadPath(fields, i); source != "" {
			return source
		}
	}
	return ""
}

func curlDataUploadPath(fields []string, index int) string {
	if len(fields) == 0 || filepath.Base(fields[0]) != "curl" {
		return ""
	}
	field := fields[index]
	switch {
	case field == "-d" || field == "--data" || field == "--data-ascii" || field == "--data-binary" || field == "--data-urlencode":
		if index+1 < len(fields) {
			return curlDataUploadValue(field, fields[index+1])
		}
	case strings.HasPrefix(field, "--data="):
		return curlDataUploadValue("--data", strings.TrimPrefix(field, "--data="))
	case strings.HasPrefix(field, "--data-ascii="):
		return curlDataUploadValue("--data-ascii", strings.TrimPrefix(field, "--data-ascii="))
	case strings.HasPrefix(field, "--data-binary="):
		return curlDataUploadValue("--data-binary", strings.TrimPrefix(field, "--data-binary="))
	case strings.HasPrefix(field, "--data-urlencode="):
		return curlDataUploadValue("--data-urlencode", strings.TrimPrefix(field, "--data-urlencode="))
	case strings.HasPrefix(field, "-d") && len(field) > 2:
		return curlDataUploadValue("-d", strings.TrimPrefix(field, "-d"))
	}
	return ""
}

func curlDataUploadValue(option, value string) string {
	if option == "--data-urlencode" {
		return curlDataURLEncodePath(value)
	}
	if strings.HasPrefix(value, "@") && len(value) > 1 {
		return strings.TrimPrefix(value, "@")
	}
	return ""
}

func curlDataURLEncodePath(value string) string {
	if strings.HasPrefix(value, "@") && len(value) > 1 {
		return strings.TrimPrefix(value, "@")
	}
	idx := strings.IndexByte(value, '@')
	if idx > 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	return ""
}

func curlFormUploadPath(fields []string, index int) string {
	if len(fields) == 0 || filepath.Base(fields[0]) != "curl" {
		return ""
	}
	field := fields[index]
	switch {
	case field == "-F" || field == "--form":
		if index+1 < len(fields) {
			return curlFormUploadValue(fields[index+1])
		}
	case strings.HasPrefix(field, "--form="):
		return curlFormUploadValue(strings.TrimPrefix(field, "--form="))
	case strings.HasPrefix(field, "-F") && len(field) > 2:
		return curlFormUploadValue(strings.TrimPrefix(field, "-F"))
	}
	return ""
}

func curlFormUploadValue(value string) string {
	for _, marker := range []string{"=@", "=<"} {
		idx := strings.Index(value, marker)
		if idx >= 0 && idx+len(marker) < len(value) {
			return value[idx+len(marker):]
		}
	}
	return ""
}

func lastNonFlag(fields []string) string {
	for i := len(fields) - 1; i >= 1; i-- {
		if strings.HasPrefix(fields[i], "-") || strings.HasPrefix(fields[i], "+") {
			continue
		}
		return fields[i]
	}
	return ""
}

func containsField(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

func looksExecutable(value string) bool {
	if strings.HasPrefix(value, "$(") {
		return false
	}
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, "$")
}

// Namespace-changing builtins are outside the literal assignment model. Drop
// retained values before any later use rather than reusing stale bindings.
func invalidateShellMutation(command string, state *textVariableState, scope string) {
	fields, err := shellCommandFields(command)
	if err != nil || len(fields) == 0 {
		return
	}
	for _, field := range fields {
		if index := strings.Index(field, "+="); index > 0 && identifierName(field[:index]) {
			state.invalidateVariable(scope, field[:index])
		}
	}
	switch fields[0] {
	case "unset", "read", "getopts", "let", "declare", "typeset", "local", "eval", ".", "source":
		invalidateAllShellBindings(state, scope)
	}
}

func invalidateAllShellBindings(state *textVariableState, scope string) {
	for name := range state.globals {
		state.invalidateVariable("", name)
	}
	for name := range state.locals[scope] {
		state.invalidateVariable(scope, name)
	}
}

func retainStandaloneShellAssignments(line string, state *textVariableState, scope string, uncertain bool, graph *behavior.Graph, content artifact.Content, lineNo int) {
	var assignments []shellAssignment
	var assignmentWords []string
	count := 0
	visitCommands(line, func(command string) bool {
		count++
		if count > 1 {
			return false
		}
		fields, raw, err := shellCommandFieldsRaw(command)
		if err == nil {
			assignments, _ = shellAssignments(fields)
			assignmentWords = raw[len(fields)-len(assignments):]
		}
		return true
	})
	if count != 1 {
		return
	}
	evidenceID := ""
	if len(assignments) > 0 {
		evidenceID = addLineEvidence(graph, content, lineNo, "shell-variable-assignment", line)
	}
	for index, assignment := range assignments {
		if assignment.name == "HOME" {
			state.invalidateDirectoryContext(scope, false, true)
		}
		tilde := shellWordExpandsHome(strings.TrimPrefix(assignmentWords[index], assignment.name+"="))
		if uncertain || !safeShellVarValue(assignment.value) || tilde {
			state.invalidateVariable(scope, assignment.name)
		} else {
			if evidenceID != "" && state.setVariable(scope, assignment.name, assignment.value) {
				state.shellOrigins[shellVariableKey{scope, assignment.name}] = evidenceID
			} else {
				state.invalidateVariable(scope, assignment.name)
			}
		}
	}
}
