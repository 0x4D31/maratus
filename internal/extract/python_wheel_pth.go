package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxPythonWheelPTHFiles           = 64
	maxPythonWheelPTHLines           = 4096
	maxPythonWheelPTHExecutableLines = 64
	maxPythonWheelPTHStatements      = 64
	maxPythonWheelPTHImportItems     = 32
	maxPythonWheelPTHCallArguments   = 8
	maxPythonWheelPTHNesting         = 64
	maxPythonWheelPTHBytes           = 1 << 20
	maxPythonWheelRecordRows         = 65536
	maxPythonWheelHeaderBytes        = 64 << 10
	maxPythonWheelHeaderLines        = 256

	pythonWheelPTHAnalysisArea = "python-wheel-pth-startup"
)

type pythonWheelMember struct {
	content  artifact.Content
	relative string
}

type pythonPTHLine struct {
	number     int
	text       string
	evidenceID string
}

type pythonPTHLines struct {
	executable         []pythonPTHLine
	partials           []string
	semanticsTruncated bool
}

type pythonWheelMetadata struct {
	stem          string
	record        pythonWheelMember
	wheelEvidence []behavior.Evidence
	recordProofs  map[string]pythonRecordProof
}

type pythonRecordProof struct {
	line   int
	hash   string
	valid  bool
	reason string
}

type pythonWheelHeaders struct {
	version           string
	rootIsPurelib     bool
	versionLine       int
	rootIsPurelibLine int
}

// preparePythonWheelPTH retains executable .pth lines before noisy package
// contents can exhaust the evidence budget. A root requires exact wheel
// placement plus matching WHEEL and RECORD metadata; directly observed lines
// survive as UNKNOWN Features when that stronger proof fails.
func preparePythonWheelPTH(graph *behavior.Graph, artifacts artifact.Graph, contents []artifact.Content) map[string]bool {
	handled := map[string]bool{}
	nodes := make(map[string]artifact.Node, len(artifacts.Nodes))
	for _, node := range artifacts.Nodes {
		nodes[node.ID] = node
	}

	membersByWheel := map[string][]pythonWheelMember{}
	memberPathCountsByWheel := map[string]map[string]int{}
	wheels := map[string]artifact.Node{}
	for _, node := range artifacts.Nodes {
		wheel, relative, ok := owningPythonWheel(node.ID, node.LogicalPath, nodes)
		if !ok {
			continue
		}
		if strings.HasSuffix(relative, ".pth") && node.AnalyzeStatus != "analyzed" {
			addPartialCoverageOnce(
				graph,
				node.ID,
				pythonWheelPTHAnalysisArea,
				"retained wheel inventory identified a .pth member, but its bytes were unavailable; executable-line and site-startup analysis was not performed",
			)
		}
		if memberPathCountsByWheel[wheel.ID] == nil {
			memberPathCountsByWheel[wheel.ID] = map[string]int{}
		}
		memberPathCountsByWheel[wheel.ID][relative]++
	}
	for _, content := range contents {
		wheel, relative, ok := owningPythonWheel(content.NodeID, content.LogicalPath, nodes)
		if !ok {
			continue
		}
		wheels[wheel.ID] = wheel
		membersByWheel[wheel.ID] = append(membersByWheel[wheel.ID], pythonWheelMember{
			content:  content,
			relative: relative,
		})
	}

	wheelIDs := make([]string, 0, len(membersByWheel))
	for wheelID := range membersByWheel {
		wheelIDs = append(wheelIDs, wheelID)
	}
	sort.Strings(wheelIDs)
	for _, wheelID := range wheelIDs {
		members := membersByWheel[wheelID]
		sort.SliceStable(members, func(i, j int) bool {
			if members[i].relative != members[j].relative {
				return members[i].relative < members[j].relative
			}
			return members[i].content.NodeID < members[j].content.NodeID
		})
		preparePythonWheelPTHMembers(graph, wheels[wheelID], members, memberPathCountsByWheel[wheelID], handled)
	}
	return handled
}

func owningPythonWheel(nodeID, logical string, nodes map[string]artifact.Node) (artifact.Node, string, bool) {
	current, ok := nodes[nodeID]
	for depth := 0; ok && depth < 64; depth++ {
		if current.Kind == "python-wheel" {
			prefix := current.LogicalPath + "!"
			if !strings.HasPrefix(logical, prefix) {
				return artifact.Node{}, "", false
			}
			relative := strings.TrimPrefix(logical, prefix)
			if relative == "" || strings.Contains(relative, "!") {
				return artifact.Node{}, "", false
			}
			return current, filepath.ToSlash(relative), true
		}
		if current.ParentID == "" {
			break
		}
		current, ok = nodes[current.ParentID]
	}
	return artifact.Node{}, "", false
}

func preparePythonWheelPTHMembers(graph *behavior.Graph, wheel artifact.Node, members []pythonWheelMember, memberPathCounts map[string]int, handled map[string]bool) {
	var candidates []pythonWheelMember
	for _, member := range members {
		if !strings.HasSuffix(member.relative, ".pth") {
			continue
		}
		if member.content.RawFeaturesOnly {
			addPartialCoverageOnce(
				graph,
				member.content.NodeID,
				pythonWheelPTHAnalysisArea,
				"the .pth member was retained only as uninterpreted bytes; executable-line and site-startup analysis was not performed",
			)
			continue
		}
		candidates = append(candidates, member)
		handled[member.content.NodeID] = true
	}
	if len(candidates) == 0 {
		return
	}
	if len(candidates) > maxPythonWheelPTHFiles {
		addPartialCoverageOnce(
			graph,
			wheel.ID,
			pythonWheelPTHAnalysisArea,
			fmt.Sprintf("candidate .pth file limit %d reached; remaining files were not analyzed", maxPythonWheelPTHFiles),
		)
		candidates = candidates[:maxPythonWheelPTHFiles]
	}

	parsed := make(map[string]pythonPTHLines, len(candidates))
	for _, candidate := range candidates {
		lines := parsePythonPTHLines(candidate.content.Data)
		for _, detail := range lines.partials {
			addPartialCoverageOnce(graph, candidate.content.NodeID, pythonWheelPTHAnalysisArea, detail)
		}
		if len(lines.executable) == 0 {
			continue
		}
		for index := range lines.executable {
			line := &lines.executable[index]
			line.evidenceID = graph.AddEvidence(behavior.Evidence{
				NodeID:   candidate.content.NodeID,
				ScopeID:  candidate.content.ScopeID,
				Logical:  candidate.content.LogicalPath,
				Physical: candidate.content.PhysicalPath,
				Line:     line.number,
				Method:   "python-wheel-pth",
				Kind:     "python-pth-executable-line",
				Value:    compactTextEvidenceValue(line.text),
			})
			if line.evidenceID == "" {
				continue
			}
			graph.AddFeature(behavior.Feature{
				NodeID:      candidate.content.NodeID,
				ScopeID:     candidate.content.ScopeID,
				Key:         "python.site.pth.import-line",
				Value:       compactTextEvidenceValue(line.text),
				EvidenceIDs: []string{line.evidenceID},
				Support:     behavior.SupportDirect,
				Execution:   unknownExecutionContext(),
			})
		}
		parsed[candidate.content.NodeID] = lines
		addPartialCoverageOnce(
			graph,
			candidate.content.NodeID,
			pythonWheelPTHAnalysisArea,
			"only one exact same-line subprocess.Popen([sys.executable, \"-c\", <literal>], ...), an exact unqualified exec(<literal Python>) stage, and the literal base64-exec wrapper can be interpreted from an executable .pth file; other code semantics, cross-line state, data flow, dynamic argv, and unmatched nested stages remain unmodeled",
		)
	}
	if len(parsed) == 0 {
		return
	}
	// Artifact code and installation-backed activation are separate claims. An
	// exact executable line can retain neutral UNKNOWN operations even when
	// malformed or unverifiable wheel metadata prevents a site-startup root.
	// If a root is proven below, the normal execution-ownership pass promotes
	// only operations whose retained scope is reachable from that node.
	for _, candidate := range candidates {
		lines, ok := parsed[candidate.content.NodeID]
		if !ok || lines.semanticsTruncated {
			continue
		}
		analyzePythonPTHInvocations(
			graph,
			candidate.content,
			lines.executable,
			unknownExecutionContext(),
		)
	}
	if wheel.AnalyzeStatus != "analyzed" {
		addPartialCoverageOnce(
			graph,
			wheel.ID,
			pythonWheelPTHAnalysisArea,
			"wheel member inventory is incomplete; executable .pth lines were retained as Features, but member uniqueness and site-startup execution were not connected",
		)
		return
	}

	metadata, reason := parsePythonWheelMetadata(wheel, members, candidates, memberPathCounts)
	if reason != "" {
		addPartialCoverageOnce(graph, wheel.ID, pythonWheelPTHAnalysisArea, reason)
		return
	}
	destinationCounts := map[string]int{}
	for relative, count := range memberPathCounts {
		if destination, ok := pythonPTHInstallDestination(relative, metadata.stem); ok {
			destinationCounts[destination] += count
		}
	}
	var wheelEvidenceIDs []string
	wheelEvidenceUnavailable := false
	for _, candidate := range candidates {
		lines, ok := parsed[candidate.content.NodeID]
		if !ok || len(lines.executable) == 0 {
			continue
		}
		if memberPathCounts[candidate.relative] != 1 {
			addPartialCoverageOnce(
				graph,
				candidate.content.NodeID,
				pythonWheelPTHAnalysisArea,
				"duplicate wheel member path made .pth identity ambiguous; site-startup execution was not connected",
			)
			continue
		}
		destination, installsAtSiteRoot := pythonPTHInstallDestination(candidate.relative, metadata.stem)
		if !installsAtSiteRoot {
			graph.AddCoverage(behavior.Coverage{
				NodeID:       candidate.content.NodeID,
				AnalysisArea: pythonWheelPTHAnalysisArea,
				Status:       "analyzed",
				Detail:       "executable .pth line retained, but the member does not install directly at a supported site root; no startup root was created",
			})
			continue
		}
		if destinationCounts[destination] != 1 {
			addPartialCoverageOnce(
				graph,
				candidate.content.NodeID,
				pythonWheelPTHAnalysisArea,
				"multiple wheel members map to the same installed .pth destination; site-startup identity is ambiguous and execution was not connected",
			)
			continue
		}
		proof := metadata.recordProofs[candidate.relative]
		if !proof.valid {
			addPartialCoverageOnce(graph, candidate.content.NodeID, pythonWheelPTHAnalysisArea, proof.reason)
			continue
		}
		lineEvidenceID := ""
		for _, line := range lines.executable {
			if line.evidenceID != "" {
				lineEvidenceID = line.evidenceID
				break
			}
		}
		if lineEvidenceID == "" {
			continue
		}
		if !executionRootAllowed(candidate.content) {
			graph.AddCoverage(behavior.Coverage{
				NodeID:       candidate.content.NodeID,
				AnalysisArea: pythonWheelPTHAnalysisArea,
				Status:       "analyzed",
				Detail:       "executable .pth line retained inside a carrier that cannot declare an independent execution root; execution remains UNKNOWN",
			})
			continue
		}
		if wheelEvidenceUnavailable {
			continue
		}
		if len(wheelEvidenceIDs) == 0 {
			for _, item := range metadata.wheelEvidence {
				evidenceID := graph.AddEvidence(item)
				if evidenceID == "" {
					wheelEvidenceUnavailable = true
					addPartialCoverageOnce(
						graph,
						wheel.ID,
						pythonWheelPTHAnalysisArea,
						"wheel metadata evidence could not be retained within the analysis budget; site-startup execution was not connected",
					)
					break
				}
				wheelEvidenceIDs = append(wheelEvidenceIDs, evidenceID)
			}
			if wheelEvidenceUnavailable {
				continue
			}
		}
		recordEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:   metadata.record.content.NodeID,
			ScopeID:  metadata.record.content.ScopeID,
			Logical:  metadata.record.content.LogicalPath,
			Physical: metadata.record.content.PhysicalPath,
			Line:     proof.line,
			Method:   "python-wheel-record",
			Kind:     "verified-python-pth-member",
			Value:    candidate.relative + " sha256=" + proof.hash,
		})
		if recordEvidenceID == "" {
			continue
		}
		rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
			Kind:              "python-site-startup",
			DeclarationNodeID: candidate.content.NodeID,
			StartNodeID:       candidate.content.NodeID,
			StartScopeID:      candidate.content.ScopeID,
			Name:              filepath.Base(candidate.relative),
			Interpreter:       "python",
			EvidenceIDs:       append(append([]string{lineEvidenceID}, wheelEvidenceIDs...), recordEvidenceID),
		})
		if rootID == "" {
			continue
		}
		graph.AddAnalysisSelection(behavior.AnalysisSelection{
			NodeID:  candidate.content.NodeID,
			Reasons: []behavior.SelectionReason{behavior.SelectionReasonExecutionRoot},
		})
		addPartialCoverageOnce(
			graph,
			candidate.content.NodeID,
			pythonWheelPTHAnalysisArea,
			"executable .pth lines were modeled as a conditional Python site-startup root; activation depends on installation into an active site directory and a Python runtime policy that processes legacy executable .pth lines",
		)
	}
}

func analyzePythonPTHInvocations(graph *behavior.Graph, content artifact.Content, lines []pythonPTHLine, execution behavior.ExecutionContext) {
	if len(lines) != 1 {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonWheelPTHAnalysisArea,
			"literal invocation analysis requires exactly one executable .pth line; multi-line execution and exception ordering remain unmodeled",
		)
		return
	}
	derivedBudget := newTextDerivedBudget()
	defer addTextDerivedCoverageOnce(graph, content, derivedBudget)
	line := lines[0]
	statements, limited, malformed := boundedPythonPTHStatements(line.text)
	if limited {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonWheelPTHAnalysisArea,
			fmt.Sprintf("executable .pth statement or nesting limit reached on line %d; remaining statements on that line were not analyzed", line.number),
		)
		return
	}
	if malformed {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonWheelPTHAnalysisArea,
			fmt.Sprintf("executable .pth statement structure was malformed on line %d; literal invocation analysis was not performed for that line", line.number),
		)
		return
	}
	lineBudget := derivedBudget.line()
	if literal, matched, limited := pythonPTHExactLiteralExec(line.text, lineBudget); limited {
		return
	} else if matched {
		analyzePythonPTHLiteralExecStage(graph, content, literal, line.number, execution, line.evidenceID)
	}
	imports := map[string]bool{}
	code := ""
	launchSeen := false
	for _, statement := range statements {
		modules, isImport, importLimited, importSupported := pythonPTHImportStatement(statement)
		if isImport {
			if importLimited {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonWheelPTHAnalysisArea,
					fmt.Sprintf("executable .pth import item limit %d reached on line %d; literal invocation analysis was not performed for that line", maxPythonWheelPTHImportItems, line.number),
				)
				return
			}
			if launchSeen || !importSupported {
				addPartialCoverageOnce(
					graph,
					content.NodeID,
					pythonWheelPTHAnalysisArea,
					fmt.Sprintf("executable .pth line %d did not match the closed supported import-then-Popen statement grammar; literal invocation analysis was not performed for that line", line.number),
				)
				return
			}
			for _, module := range modules {
				imports[module] = true
			}
			continue
		}
		if launchSeen {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonWheelPTHAnalysisArea,
				fmt.Sprintf("executable .pth line %d contained statements after the supported Popen call; literal invocation analysis was not performed for that line", line.number),
			)
			return
		}
		candidate, matched, callLimited, callMalformed := pythonPTHCurrentInterpreterCode(statement, imports, lineBudget)
		if callLimited {
			return
		}
		if !matched || callMalformed || candidate == "" {
			addPartialCoverageOnce(
				graph,
				content.NodeID,
				pythonWheelPTHAnalysisArea,
				fmt.Sprintf("executable .pth line %d did not match the closed supported import-then-Popen statement grammar; literal invocation analysis was not performed for that line", line.number),
			)
			return
		}
		launchSeen = true
		code = candidate
	}
	if derivedBudget.limited || !launchSeen || code == "" {
		return
	}
	addPythonPTHInterpreterInvocation(graph, content, code, line.number, execution, line.evidenceID)
	encoded, wrapperOK := pythonPTHLiteralBase64Wrapper(code)
	if !wrapperOK {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonWheelPTHAnalysisArea,
			"the literal Python -c program did not match the bounded base64-exec wrapper; the interpreter invocation was retained, but nested code semantics were not analyzed",
		)
		return
	}
	decoded, decodedOK := decodePythonB64decodeLiteral(encoded)
	if !decodedOK || len(decoded) == 0 || len(decoded) > maxDecodedInlineBytes ||
		!utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 || !mostlyText(decoded) {
		addPartialCoverageOnce(
			graph,
			content.NodeID,
			pythonWheelPTHAnalysisArea,
			"the exact literal base64-exec wrapper contained invalid standard Base64, empty, oversized, NUL-containing, non-UTF-8, or non-text payload bytes; the interpreter invocation was retained, but nested code semantics were not analyzed",
		)
		return
	}
	analyzePythonPTHDecodedStage(graph, content, decoded, execution, line.evidenceID)
}

// pythonPTHExactLiteralExec recognizes one unqualified built-in-style
// exec(<literal>) call outside strings and comments. It deliberately rejects
// an earlier unqualified use of the exec name, attribute calls, dynamic
// arguments, concatenation, prefixes, and multiple candidates. This is a
// lexical closed subset, not a general Python evaluator.
func pythonPTHExactLiteralExec(line string, budget *textLineBudget) (literal string, matched, limited bool) {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(line), "Python .pth literal exec") {
		return "", false, true
	}
	if _, statementLimited, malformed := boundedPythonPTHStatements(line); statementLimited {
		budget.markLimited("Python .pth literal exec statement or nesting limit reached", false)
		return "", false, true
	} else if malformed {
		return "", false, false
	}
	for index := 0; index < len(line); {
		current := line[index]
		if current == '\'' || current == '"' {
			next, ok := skipPythonQuoted(line, index)
			if !ok {
				return "", false, false
			}
			index = next
			continue
		}
		if current == '#' {
			break
		}
		if !strings.HasPrefix(line[index:], "exec") ||
			index > 0 && (pythonIdentifierByte(line[index-1]) || line[index-1] == '.') ||
			index+4 < len(line) && pythonIdentifierByte(line[index+4]) {
			index++
			continue
		}
		afterName := index + len("exec")
		open := afterName
		for open < len(line) && (line[open] == ' ' || line[open] == '\t') {
			open++
		}
		// The first unqualified use controls the result. This rejects prior
		// rebinding/import uses instead of searching forward for a convenient
		// later call that may no longer resolve to the built-in.
		if open >= len(line) || line[open] != '(' {
			return "", false, false
		}
		close, ok := exactPythonMatchingClose(line, open)
		if !ok {
			return "", false, false
		}
		arguments, argumentLimited, argumentMalformed := boundedPythonPTHArguments(
			line[open+1:close],
			"Python .pth literal exec arguments",
			2,
			budget,
		)
		if argumentLimited {
			return "", false, true
		}
		if argumentMalformed || len(arguments) != 1 {
			return "", false, false
		}
		decoded, ok := exactPythonStringLiteral(arguments[0])
		if !ok || decoded == "" || len(decoded) > maxDecodedInlineBytes ||
			!utf8.ValidString(decoded) || strings.IndexByte(decoded, 0) >= 0 || !mostlyText([]byte(decoded)) {
			return "", false, false
		}
		if !budget.retainMatch(len(decoded), "Python .pth literal exec payload") {
			return "", false, true
		}
		// A second unqualified exec occurrence makes name state and ordering
		// outside this intentionally small grammar ambiguous.
		for suffix := close + 1; suffix < len(line); {
			if line[suffix] == '\'' || line[suffix] == '"' {
				next, quoted := skipPythonQuoted(line, suffix)
				if !quoted {
					return "", false, false
				}
				suffix = next
				continue
			}
			if line[suffix] == '#' {
				break
			}
			if strings.HasPrefix(line[suffix:], "exec") &&
				(suffix == 0 || !pythonIdentifierByte(line[suffix-1]) && line[suffix-1] != '.') &&
				(suffix+4 == len(line) || !pythonIdentifierByte(line[suffix+4])) {
				return "", false, false
			}
			suffix++
		}
		return decoded, true, false
	}
	return "", false, false
}

func analyzePythonPTHLiteralExecStage(
	graph *behavior.Graph,
	content artifact.Content,
	code string,
	line int,
	execution behavior.ExecutionContext,
	parentEvidenceID string,
) {
	digest := sha256.Sum256([]byte(code))
	value := fmt.Sprintf("literal exec sha256=%x bytes=%d", digest, len(code))
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Line:     line,
		Method:   "python-wheel-pth",
		Kind:     "python-literal-exec-script",
		Value:    value,
	})
	evidenceIDs := mergeEvidenceIDs(evidenceID, parentEvidenceID)
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         "python.literal_exec_script",
		Value:       value,
		EvidenceIDs: evidenceIDs,
		Support:     behavior.SupportDirect,
		Execution:   execution,
	})
	if detail := unsupportedPythonPTHDecodedSource([]byte(code)); detail != "" {
		addPartialCoverageOnce(graph, content.NodeID, pythonWheelPTHAnalysisArea, detail)
		return
	}
	derivedScopeID := graph.AddScope(behavior.Scope{
		NodeID:     content.NodeID,
		ParentID:   content.ScopeID,
		Kind:       "decoded-inline-code",
		Name:       "python literal exec",
		SourceRole: content.Role,
	})
	if derivedScopeID == "" {
		return
	}
	derivedContent := content
	derivedContent.ScopeID = derivedScopeID
	derivedContent.Kind = "script"
	derivedContent.MediaType = "text/plain"
	derivedContent.SemanticLanguage = "python"
	derivedContent.LogicalPath = inlineLogicalPath(content.LogicalPath, "python", "literal-exec")
	derivedContent.Data = []byte(normalizeInlineCode("python", code))
	derivedContent.SupportingEvidenceIDs = mergeEvidenceIDs(append(derivedContent.SupportingEvidenceIDs, evidenceIDs...)...)
	start := graphPosition(graph)
	ExtractText(graph, derivedContent)
	for index := start.operations; index < len(graph.Operations); index++ {
		graph.Operations[index].EvidenceIDs = mergeEvidenceIDs(append(graph.Operations[index].EvidenceIDs, evidenceIDs...)...)
	}
	promoteInlineGraphRange(graph, start, execution)
}

// decodePythonB64decodeLiteral implements a conservative subset of
// base64.b64decode(value) with its default alphabet. ASCII whitespace is
// accepted, but URL-safe alphabet characters, implicit padding, and other
// ignored non-alphabet bytes are rejected so static semantics are promoted
// only when Go and Python decode the same retained literal.
func decodePythonB64decodeLiteral(value string) ([]byte, bool) {
	if len(value) > maxEncodedInlineBytes+maxInlineWhitespaceBytes {
		return nil, false
	}
	cleaned := make([]byte, 0, min(len(value), maxEncodedInlineBytes))
	whitespace := 0
	for index := 0; index < len(value); index++ {
		current := value[index]
		switch current {
		case ' ', '\n', '\r', '\t':
			whitespace++
			if whitespace > maxInlineWhitespaceBytes {
				return nil, false
			}
		default:
			if current != '+' && current != '/' && current != '=' &&
				(current < 'A' || current > 'Z') &&
				(current < 'a' || current > 'z') &&
				(current < '0' || current > '9') {
				return nil, false
			}
			if len(cleaned) >= maxEncodedInlineBytes {
				return nil, false
			}
			cleaned = append(cleaned, current)
		}
	}
	if len(cleaned) == 0 || len(cleaned)%4 != 0 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(string(cleaned))
	if err != nil || len(decoded) > maxDecodedInlineBytes {
		return nil, false
	}
	return decoded, true
}

func boundedPythonPTHStatements(line string) (statements []string, limited, malformed bool) {
	start := 0
	quote := byte(0)
	escaped := false
	var delimiters []byte
	appendStatement := func(end int, requireNonempty bool) (limited, malformed bool) {
		statement := strings.TrimSpace(line[start:end])
		if statement == "" {
			return false, requireNonempty
		}
		if len(statements) >= maxPythonWheelPTHStatements {
			return true, false
		}
		statements = append(statements, statement)
		return false, false
	}
	for index := 0; index < len(line); index++ {
		current := line[index]
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			if index+2 < len(line) && line[index+1] == current && line[index+2] == current {
				return statements, false, true
			}
			quote = current
			continue
		}
		switch current {
		case '(', '[', '{':
			if len(delimiters) >= maxPythonWheelPTHNesting {
				return statements, true, false
			}
			delimiters = append(delimiters, current)
		case ')', ']', '}':
			if len(delimiters) == 0 || !pythonDelimiterPair(delimiters[len(delimiters)-1], current) {
				return statements, false, true
			}
			delimiters = delimiters[:len(delimiters)-1]
		case '#':
			if len(delimiters) != 0 {
				return statements, false, true
			}
			if limited, malformed := appendStatement(index, false); limited || malformed {
				return statements, limited, malformed
			}
			return statements, false, false
		case ';':
			if len(delimiters) == 0 {
				if limited, malformed := appendStatement(index, true); limited || malformed {
					return statements, limited, malformed
				}
				start = index + 1
			}
		}
	}
	if quote != 0 || escaped || len(delimiters) != 0 {
		return statements, false, true
	}
	if limited, malformed := appendStatement(len(line), false); limited || malformed {
		return statements, limited, malformed
	}
	return statements, false, false
}

func pythonPTHImportStatement(statement string) (modules []string, isImport, limited, supported bool) {
	if !strings.HasPrefix(statement, "import ") && !strings.HasPrefix(statement, "import\t") {
		return nil, false, false, false
	}
	items, limited, malformed := boundedPythonPTHImportItems(strings.TrimSpace(statement[len("import"):]))
	if limited || malformed || len(items) == 0 {
		return nil, true, limited, false
	}
	for _, item := range items {
		if !identifierName(item) {
			return nil, true, false, false
		}
		switch item {
		case "os", "subprocess", "sys":
			modules = append(modules, item)
		default:
			return nil, true, false, false
		}
	}
	return modules, true, false, true
}

func boundedPythonPTHImportItems(value string) (items []string, limited, malformed bool) {
	if value == "" {
		return nil, false, true
	}
	start := 0
	for index := 0; index <= len(value); index++ {
		if index < len(value) && value[index] != ',' {
			continue
		}
		item := strings.TrimSpace(value[start:index])
		if item == "" {
			return nil, false, true
		}
		if len(items) >= maxPythonWheelPTHImportItems {
			return nil, true, false
		}
		items = append(items, item)
		start = index + 1
	}
	return items, false, false
}

func pythonPTHCurrentInterpreterCode(statement string, imports map[string]bool, budget *textLineBudget) (code string, matched, limited, malformed bool) {
	const callName = "subprocess.Popen"
	if !strings.HasPrefix(statement, callName) {
		return "", false, false, false
	}
	rest := strings.TrimLeft(statement[len(callName):], " \t")
	if !strings.HasPrefix(rest, "(") {
		return "", false, false, false
	}
	if !imports["subprocess"] {
		return "", true, false, false
	}
	open := len(statement) - len(rest)
	close, ok := exactPythonMatchingClose(statement, open)
	if !ok || strings.TrimSpace(statement[close+1:]) != "" {
		return "", true, false, true
	}
	args, limited, malformed := boundedPythonPTHArguments(
		statement[open+1:close],
		"Python .pth Popen arguments",
		maxPythonWheelPTHCallArguments,
		budget,
	)
	if limited || malformed {
		return "", true, limited, malformed
	}
	if len(args) == 0 || !pythonPTHSafePopenOptions(args[1:]) {
		return "", true, false, false
	}
	argv := strings.TrimSpace(args[0])
	if len(argv) < 2 || argv[0] != '[' || argv[len(argv)-1] != ']' {
		return "", true, false, false
	}
	elements, limited, malformed := boundedPythonPTHArguments(
		argv[1:len(argv)-1],
		"Python .pth Popen argv",
		4,
		budget,
	)
	if limited || malformed {
		return "", true, limited, malformed
	}
	if len(elements) != 3 || strings.TrimSpace(elements[0]) != "sys.executable" || !imports["sys"] {
		return "", true, false, false
	}
	flag, ok := exactPythonStringLiteral(elements[1])
	if !ok || flag != "-c" {
		return "", true, false, false
	}
	code, ok = exactPythonStringLiteral(elements[2])
	if !ok || code == "" || len(code) > maxDecodedInlineBytes {
		return "", true, false, false
	}
	return code, true, false, false
}

func boundedPythonPTHArguments(value, kind string, maxArguments int, budget *textLineBudget) (arguments []string, limited, malformed bool) {
	budget = textBudgetOrStandalone(budget)
	if !budget.chargeScan(len(value), kind) {
		return nil, true, false
	}
	arguments, limited, malformed = exactPythonArguments(value, maxArguments)
	if limited {
		budget.markLimited(
			fmt.Sprintf("%s argument or nesting limit reached (arguments=%d, nesting=%d)", kind, maxArguments, maxTextStringExpressionDepth),
			false,
		)
		return nil, true, false
	}
	if malformed {
		return nil, false, true
	}
	for _, argument := range arguments {
		if !budget.retainMatch(len(argument), kind) {
			return nil, true, false
		}
	}
	return arguments, false, false
}

func pythonPTHSafePopenOptions(options []string) bool {
	seen := map[string]bool{}
	for _, option := range options {
		key, value, ok := strings.Cut(option, "=")
		if !ok {
			return false
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if seen[key] {
			return false
		}
		switch key {
		case "stdout", "stderr":
			if value != "subprocess.DEVNULL" {
				return false
			}
		case "start_new_session":
			if value != "True" {
				return false
			}
		default:
			return false
		}
		seen[key] = true
	}
	return true
}

func pythonPTHLiteralBase64Wrapper(code string) (string, bool) {
	if strings.ContainsAny(code, "\r\n") {
		return "", false
	}
	statements, limited, malformed := boundedPythonPTHStatements(code)
	if limited || malformed || len(statements) != 2 || strings.TrimSpace(statements[0]) != "import base64" {
		return "", false
	}
	const outer = "exec"
	statement := strings.TrimSpace(statements[1])
	if !strings.HasPrefix(statement, outer) {
		return "", false
	}
	rest := strings.TrimLeft(statement[len(outer):], " \t")
	if !strings.HasPrefix(rest, "(") {
		return "", false
	}
	open := len(statement) - len(rest)
	close, ok := exactPythonMatchingClose(statement, open)
	if !ok || strings.TrimSpace(statement[close+1:]) != "" {
		return "", false
	}
	outerArgs, limited, malformed := exactPythonArguments(statement[open+1:close], 2)
	if limited || malformed || len(outerArgs) != 1 {
		return "", false
	}
	inner := strings.TrimSpace(outerArgs[0])
	const decoder = "base64.b64decode"
	if !strings.HasPrefix(inner, decoder) {
		return "", false
	}
	rest = strings.TrimLeft(inner[len(decoder):], " \t")
	if !strings.HasPrefix(rest, "(") {
		return "", false
	}
	open = len(inner) - len(rest)
	close, ok = exactPythonMatchingClose(inner, open)
	if !ok || strings.TrimSpace(inner[close+1:]) != "" {
		return "", false
	}
	innerArgs, limited, malformed := exactPythonArguments(inner[open+1:close], 2)
	if limited || malformed || len(innerArgs) != 1 {
		return "", false
	}
	encoded, ok := exactPythonStringLiteral(innerArgs[0])
	return encoded, ok && encoded != "" && len(encoded) <= maxEncodedInlineBytes+maxInlineWhitespaceBytes
}

func analyzePythonPTHDecodedStage(graph *behavior.Graph, content artifact.Content, decoded []byte, execution behavior.ExecutionContext, parentEvidenceID string) {
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Method:   "python-wheel-pth",
		Kind:     "python-base64-decoded-script",
		Value:    "literal base64 exec",
	})
	evidenceIDs := []string{evidenceID}
	if parentEvidenceID != "" {
		evidenceIDs = append(evidenceIDs, parentEvidenceID)
	}
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         "python.base64_decoded_script",
		Value:       "literal base64 exec",
		EvidenceIDs: evidenceIDs,
		Support:     behavior.SupportDirect,
		Execution:   execution,
	})
	if detail := unsupportedPythonPTHDecodedSource(decoded); detail != "" {
		addPartialCoverageOnce(graph, content.NodeID, pythonWheelPTHAnalysisArea, detail)
		return
	}
	decodedScopeID := graph.AddScope(behavior.Scope{
		NodeID:     content.NodeID,
		ParentID:   content.ScopeID,
		Kind:       "decoded-inline-code",
		Name:       "python base64 exec",
		SourceRole: content.Role,
	})
	if decodedScopeID == "" {
		return
	}
	decodedCode := normalizeInlineCode("python", string(decoded))
	decodedContent := content
	decodedContent.ScopeID = decodedScopeID
	decodedContent.Kind = "script"
	decodedContent.MediaType = "text/plain"
	decodedContent.SemanticLanguage = "python"
	decodedContent.LogicalPath = inlineLogicalPath(content.LogicalPath, "python", "decoded-base64")
	decodedContent.Data = []byte(decodedCode)
	start := graphPosition(graph)
	ExtractText(graph, decodedContent)
	promoteInlineGraphRange(graph, start, execution)
}

func unsupportedPythonPTHDecodedSource(decoded []byte) string {
	if bytes.HasPrefix(decoded, []byte{0xef, 0xbb, 0xbf}) {
		return "the decoded Python stage used a UTF-8 BOM; source-decoding semantics are unsupported, so nested code semantics were not analyzed"
	}
	source := string(decoded)
	start := 0
	for lineNumber := 1; lineNumber <= 2 && start < len(source); lineNumber++ {
		end, next := pythonPTHLineBoundary(source, start)
		if pythonPTHSourceEncodingCookie(source[start:end]) {
			return "the decoded Python stage used a source-encoding cookie; source-decoding semantics are unsupported, so nested code semantics were not analyzed"
		}
		if next <= start {
			break
		}
		start = next
	}
	return ""
}

func pythonPTHSourceEncodingCookie(line string) bool {
	line = strings.TrimLeft(line, " \t\f")
	if !strings.HasPrefix(line, "#") {
		return false
	}
	lower := strings.ToLower(line[1:])
	for offset := 0; offset < len(lower); {
		relative := strings.Index(lower[offset:], "coding")
		if relative < 0 {
			return false
		}
		end := offset + relative + len("coding")
		if end < len(lower) && (lower[end] == ':' || lower[end] == '=') {
			end++
			for end < len(lower) && (lower[end] == ' ' || lower[end] == '\t') {
				end++
			}
			if end < len(lower) && pythonPTHEncodingNameByte(lower[end]) {
				return true
			}
		}
		offset += relative + len("coding")
	}
	return false
}

func pythonPTHEncodingNameByte(value byte) bool {
	return pythonIdentifierByte(value) || value == '-' || value == '.'
}

func addPythonPTHInterpreterInvocation(graph *behavior.Graph, content artifact.Content, code string, line int, execution behavior.ExecutionContext, evidenceID string) {
	digest := sha256.Sum256([]byte(code))
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID,
		ScopeID:       content.ScopeID,
		Kind:          behavior.OperationInterpreterInvoke,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleExecutable, behavior.NewResource(behavior.ResourceFile, "python", behavior.ResourceClassInterpreter)),
			behavior.Bind(behavior.ResourceRoleArguments, behavior.NewResource(
				behavior.ResourceCommand,
				fmt.Sprintf("-c <literal python sha256=%x bytes=%d>", digest, len(code)),
			)),
		),
		EvidenceIDs:  shellOperationEvidence(content, evidenceID),
		Support:      behavior.SupportCorroborated,
		Execution:    execution,
		Architecture: content.Architecture,
		Line:         line,
	})
}

func parsePythonPTHLines(data []byte) pythonPTHLines {
	result := pythonPTHLines{}
	if len(data) > maxPythonWheelPTHBytes {
		result.partials = append(result.partials, fmt.Sprintf("only the first %d .pth bytes were inspected", maxPythonWheelPTHBytes))
		result.semanticsTruncated = true
		data = data[:maxPythonWheelPTHBytes]
		for trim := 0; trim < utf8.UTFMax-1 && !utf8.Valid(data); trim++ {
			data = data[:len(data)-1]
		}
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		result.partials = append(result.partials, "non-UTF-8 or NUL-containing .pth content was not interpreted; locale-dependent decoding is unsupported")
		return result
	}

	source := string(data)
	start := 0
	for lineNumber := 1; start < len(source); lineNumber++ {
		if lineNumber > maxPythonWheelPTHLines {
			result.partials = append(result.partials, fmt.Sprintf("only the first %d .pth lines were inspected", maxPythonWheelPTHLines))
			result.semanticsTruncated = true
			break
		}
		end, next := pythonPTHLineBoundary(source, start)
		line := source[start:end]
		executable := strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t")
		if executable && len(result.executable) < maxPythonWheelPTHExecutableLines {
			result.executable = append(result.executable, pythonPTHLine{number: lineNumber, text: line})
		} else if executable {
			result.semanticsTruncated = true
			detail := fmt.Sprintf("executable .pth line limit %d reached; remaining executable lines were not analyzed", maxPythonWheelPTHExecutableLines)
			if len(result.partials) == 0 || result.partials[len(result.partials)-1] != detail {
				result.partials = append(result.partials, detail)
			}
		}
		start = next
	}
	return result
}

// pythonPTHLineBoundary matches the universal-newline boundaries produced by
// the TextIOWrapper that CPython's site module iterates for .pth files. Unicode
// separators recognized by str.splitlines are ordinary line bytes here and
// must not manufacture a later executable import line.
func pythonPTHLineBoundary(source string, start int) (end, next int) {
	for index := start; index < len(source); {
		current, size := utf8.DecodeRuneInString(source[index:])
		switch current {
		case '\n':
			return index, index + size
		case '\r':
			next = index + size
			if next < len(source) && source[next] == '\n' {
				next++
			}
			return index, next
		}
		index += size
	}
	return len(source), len(source)
}

func parsePythonWheelMetadata(wheel artifact.Node, members, candidates []pythonWheelMember, memberPathCounts map[string]int) (pythonWheelMetadata, string) {
	var wheelMembers, recordMembers []pythonWheelMember
	for _, member := range members {
		if strings.Count(member.relative, "/") != 1 {
			continue
		}
		switch {
		case strings.HasSuffix(member.relative, ".dist-info/WHEEL"):
			wheelMembers = append(wheelMembers, member)
		case strings.HasSuffix(member.relative, ".dist-info/RECORD"):
			recordMembers = append(recordMembers, member)
		}
	}
	if len(wheelMembers) != 1 || len(recordMembers) != 1 ||
		memberPathCounts[wheelMembers[0].relative] != 1 ||
		memberPathCounts[recordMembers[0].relative] != 1 {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but the wheel lacks one unambiguous .dist-info/WHEEL and RECORD pair; site-startup execution was not connected"
	}
	wheelDir := strings.TrimSuffix(wheelMembers[0].relative, "/WHEEL")
	recordDir := strings.TrimSuffix(recordMembers[0].relative, "/RECORD")
	if wheelDir != recordDir {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but WHEEL and RECORD do not share one .dist-info directory; site-startup execution was not connected"
	}
	stem := strings.TrimSuffix(wheelDir, ".dist-info")
	if stem == "" {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but wheel metadata identity was malformed; site-startup execution was not connected"
	}
	headers, headerReason := parseWheelHeaders(wheelMembers[0].content.Data)
	if headerReason != "" {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but " + headerReason + "; site-startup execution was not connected"
	}
	filenameTag, filenameReason := pythonWheelFilenameTag(wheel.LogicalPath)
	if filenameReason != "" {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but " + filenameReason + "; site-startup execution was not connected"
	}

	wanted := map[string]artifact.Content{
		wheelMembers[0].relative:  wheelMembers[0].content,
		recordMembers[0].relative: recordMembers[0].content,
	}
	for _, candidate := range candidates {
		wanted[candidate.relative] = candidate.content
	}
	proofs, ok := parsePythonWheelRecord(recordMembers[0].content.Data, wanted, recordMembers[0].relative)
	if !ok || !proofs[wheelMembers[0].relative].valid || !proofs[recordMembers[0].relative].valid {
		return pythonWheelMetadata{}, "executable .pth lines were retained, but RECORD metadata was malformed, unsupported, or did not verify required wheel metadata; site-startup execution was not connected"
	}

	evidence := []behavior.Evidence{
		{
			NodeID:  wheel.ID,
			Logical: wheel.LogicalPath,
			Method:  "python-wheel-filename",
			Kind:    "python-wheel-platform-filename-tag",
			Value:   filenameTag,
		},
		{
			NodeID:   wheelMembers[0].content.NodeID,
			ScopeID:  wheelMembers[0].content.ScopeID,
			Logical:  wheelMembers[0].content.LogicalPath,
			Physical: wheelMembers[0].content.PhysicalPath,
			Line:     headers.versionLine,
			Method:   "python-wheel-metadata",
			Kind:     "python-wheel-version",
			Value:    headers.version,
		},
		{
			NodeID:   wheelMembers[0].content.NodeID,
			ScopeID:  wheelMembers[0].content.ScopeID,
			Logical:  wheelMembers[0].content.LogicalPath,
			Physical: wheelMembers[0].content.PhysicalPath,
			Line:     headers.rootIsPurelibLine,
			Method:   "python-wheel-metadata",
			Kind:     "python-wheel-site-layout",
			Value:    strconv.FormatBool(headers.rootIsPurelib),
		},
		{
			NodeID:   recordMembers[0].content.NodeID,
			ScopeID:  recordMembers[0].content.ScopeID,
			Logical:  recordMembers[0].content.LogicalPath,
			Physical: recordMembers[0].content.PhysicalPath,
			Line:     proofs[wheelMembers[0].relative].line,
			Method:   "python-wheel-record",
			Kind:     "verified-python-wheel-metadata",
			Value:    wheelMembers[0].relative + " sha256=" + proofs[wheelMembers[0].relative].hash,
		},
	}
	return pythonWheelMetadata{
		stem:          stem,
		record:        recordMembers[0],
		wheelEvidence: evidence,
		recordProofs:  proofs,
	}, ""
}

func parseWheelHeaders(data []byte) (pythonWheelHeaders, string) {
	headers := pythonWheelHeaders{}
	if len(data) == 0 || len(data) > maxPythonWheelHeaderBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return headers, "WHEEL metadata was malformed or exceeded the header-byte limit"
	}
	seenVersion, seenPurelib := false, false
	headerBlockEnded := false
	for start, lineNumber := 0, 1; start < len(data); lineNumber++ {
		if lineNumber > maxPythonWheelHeaderLines {
			return pythonWheelHeaders{}, "WHEEL metadata exceeded the header-line limit"
		}
		end := len(data)
		next := len(data)
		if relative := bytes.IndexByte(data[start:], '\n'); relative >= 0 {
			end = start + relative
			next = end + 1
		}
		raw := data[start:end]
		raw = bytes.TrimSuffix(raw, []byte{'\r'})
		line := string(raw)
		if line == "" {
			headerBlockEnded = true
			start = next
			continue
		}
		if headerBlockEnded {
			return pythonWheelHeaders{}, "WHEEL metadata contained content after the header block"
		}
		key, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(key) != key || strings.TrimSpace(key) == "" {
			return pythonWheelHeaders{}, "WHEEL metadata contained a malformed header"
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "wheel-version":
			if seenVersion || !supportedWheelVersion(value) {
				return pythonWheelHeaders{}, "WHEEL metadata declared a duplicate or unsupported Wheel-Version"
			}
			seenVersion, headers.version, headers.versionLine = true, value, lineNumber
		case "root-is-purelib":
			if seenPurelib {
				return pythonWheelHeaders{}, "WHEEL metadata declared Root-Is-Purelib more than once"
			}
			switch strings.ToLower(value) {
			case "true":
				headers.rootIsPurelib = true
			case "false":
				headers.rootIsPurelib = false
			default:
				return pythonWheelHeaders{}, "WHEEL metadata declared an invalid Root-Is-Purelib value"
			}
			seenPurelib, headers.rootIsPurelibLine = true, lineNumber
		}
		start = next
	}
	if !seenVersion || !seenPurelib {
		return pythonWheelHeaders{}, "WHEEL metadata omitted Wheel-Version or Root-Is-Purelib"
	}
	return headers, ""
}

func pythonWheelFilenameTagSupportsMacOS(value string) (compatible, valid bool) {
	parts := strings.Split(value, "-")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false, false
	}
	for _, group := range parts {
		for _, component := range strings.Split(group, ".") {
			if !validPythonWheelTagComponent(component) {
				return false, false
			}
		}
	}
	for _, platform := range strings.Split(parts[2], ".") {
		if platform == "any" || validMacOSWheelPlatform(platform) {
			compatible = true
		}
	}
	return compatible, true
}

func validPythonWheelTagComponent(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != '_' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func validMacOSWheelPlatform(value string) bool {
	parts := strings.Split(value, "_")
	if len(parts) < 4 || parts[0] != "macosx" || !asciiDigits(parts[1]) || !asciiDigits(parts[2]) {
		return false
	}
	switch strings.Join(parts[3:], "_") {
	case "arm64", "x86_64", "i386", "intel", "fat", "fat3", "fat32", "fat64", "universal", "universal2", "ppc", "ppc64":
		return true
	default:
		return false
	}
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func pythonWheelFilenameTag(logical string) (string, string) {
	if separator := strings.LastIndex(logical, "!"); separator >= 0 {
		logical = logical[separator+1:]
	}
	name := filepath.Base(logical)
	if !strings.HasSuffix(name, ".whl") {
		return "", "the outer wheel filename was malformed"
	}
	parts := strings.Split(strings.TrimSuffix(name, ".whl"), "-")
	if len(parts) < 5 {
		return "", "the outer wheel filename did not contain a complete compatibility tag"
	}
	tag := strings.Join(parts[len(parts)-3:], "-")
	compatible, valid := pythonWheelFilenameTagSupportsMacOS(tag)
	if !valid {
		return "", "the outer wheel filename contained a malformed compatibility tag"
	}
	if !compatible {
		return "", "the outer wheel filename did not declare a macOS or platform-independent platform tag"
	}
	return tag, ""
}

func supportedWheelVersion(value string) bool {
	major, minor, ok := strings.Cut(value, ".")
	if !ok || major != "1" || minor == "" {
		return false
	}
	_, err := strconv.ParseUint(minor, 10, 32)
	return err == nil
}

func parsePythonWheelRecord(data []byte, wanted map[string]artifact.Content, recordPath string) (map[string]pythonRecordProof, bool) {
	proofs := make(map[string]pythonRecordProof, len(wanted))
	if len(data) == 0 || len(data) > maxStructuredDocumentBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return proofs, false
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = 3
	reader.ReuseRecord = true
	for rows := 0; ; rows++ {
		if rows >= maxPythonWheelRecordRows {
			return proofs, false
		}
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return proofs, false
		}
		path := filepath.ToSlash(record[0])
		content, needed := wanted[path]
		if !needed {
			continue
		}
		if _, duplicate := proofs[path]; duplicate {
			return proofs, false
		}
		line, _ := reader.FieldPos(0)
		proof := pythonRecordProof{line: line}
		if path == recordPath {
			proof.valid = record[1] == "" && record[2] == ""
			if !proof.valid {
				proof.reason = "the RECORD self-entry was not unhashed as required"
				proofs[path] = proof
				return proofs, false
			}
			proofs[path] = proof
			continue
		}
		proof.valid, proof.hash, proof.reason = verifyPythonRecordMember(content.Data, record[1], record[2])
		proofs[path] = proof
	}
	for path := range wanted {
		if _, ok := proofs[path]; !ok {
			proofs[path] = pythonRecordProof{reason: "the member is absent from RECORD; site-startup execution was not connected"}
		}
	}
	if !proofs[recordPath].valid {
		return proofs, false
	}
	return proofs, true
}

func verifyPythonRecordMember(data []byte, hashField, sizeField string) (bool, string, string) {
	algorithm, encoded, ok := strings.Cut(hashField, "=")
	if !ok || algorithm != "sha256" || encoded == "" {
		return false, "", "the member lacks a supported RECORD SHA-256 proof; site-startup execution was not connected"
	}
	digest, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		return false, "", "the member has a malformed RECORD SHA-256 proof; site-startup execution was not connected"
	}
	size, err := strconv.ParseInt(sizeField, 10, 64)
	if err != nil || size < 0 || size != int64(len(data)) {
		return false, "", "the member size does not match RECORD; site-startup execution was not connected"
	}
	actual := sha256.Sum256(data)
	if !bytes.Equal(digest, actual[:]) {
		return false, "", "the member digest does not match RECORD; site-startup execution was not connected"
	}
	return true, encoded, ""
}

func pythonPTHInstallDestination(relative, stem string) (string, bool) {
	if filepath.Base(relative) != relative {
		prefixes := []string{
			stem + ".data/purelib/",
			stem + ".data/platlib/",
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(relative, prefix) {
				installed := strings.TrimPrefix(relative, prefix)
				if pythonSitePTHBase(installed) {
					return "site/" + installed, true
				}
				return "", false
			}
		}
		return "", false
	}
	if !pythonSitePTHBase(relative) {
		return "", false
	}
	return "site/" + relative, true
}

func pythonSitePTHBase(value string) bool {
	return value != "" && filepath.Base(value) == value && !strings.HasPrefix(value, ".") && strings.HasSuffix(value, ".pth")
}
