package extract

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxDecodedInlineBytes    = 256 * 1024
	maxEncodedInlineBytes    = ((maxDecodedInlineBytes + 2) / 3) * 4
	maxInlineWhitespaceBytes = 64 * 1024
)

func AnalyzeInlineCode(graph *behavior.Graph, content artifact.Content, language, code string, execution behavior.ExecutionContext, evidenceID string) {
	originalCode := code
	code = strings.TrimSpace(code)
	if code == "" {
		return
	}
	if language == "python" {
		code = originalCode
	}
	code = normalizeInlineCode(language, code)
	if normalized, err := behavior.NormalizeExecutionContext(execution); err == nil {
		execution = normalized
	} else {
		execution = unknownExecutionContext()
	}
	start := graphPosition(graph)
	content.Kind = "script"
	content.MediaType = "text/plain"
	// Inline programs can cross a language boundary (for example a shell
	// artifact invoking `python -c` or `node -e`). Do not inherit the carrier's
	// forced language, which would parse the recovered program as shell text.
	content.SemanticLanguage = language
	content.LogicalPath = inlineLogicalPath(content.LogicalPath, language, "inline")
	content.Data = []byte(code)
	if language == "applescript" || language == "jxa" {
		content = contentWithExecutionContext(content, execution)
		ExtractText(graph, content)
		return
	}
	ExtractText(graph, content)
	if language == "python" {
		analyzePythonBase64Exec(graph, content, originalCode, execution, evidenceID, 0)
	}
	promoteInlineGraphRange(graph, start, execution)
}

func normalizeInlineCode(language, code string) string {
	if language != "python" && language != "javascript" {
		return code
	}
	if language == "python" {
		// In Python, indentation and a one-line compound suite own every
		// semicolon on that line. Inserting a column-zero newline can turn a
		// dormant function body into a module statement. Only format a simple,
		// unindented single-line program; preserve all other source verbatim.
		if strings.ContainsAny(code, "\r\n") || strings.TrimLeft(code, " \t") != code {
			return code
		}
		words := strings.Fields(code)
		if len(words) != 0 {
			switch strings.TrimSuffix(words[0], ":") {
			case "def", "class", "async", "if", "elif", "else", "for", "while", "with", "try", "except", "finally", "match", "case":
				return code
			}
		}
	}
	return splitTopLevelSemicolonStatements(code, language == "python")
}

func splitTopLevelSemicolonStatements(code string, pythonComments bool) string {
	var parts []string
	start := 0
	var quote rune
	escaped := false
	lineComment := false
	depth := 0
	for i, r := range code {
		if lineComment {
			if r == '\n' || r == '\r' {
				lineComment = false
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			continue
		}
		if pythonComments && r == '#' {
			lineComment = true
			continue
		}
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				appendInlineStatement(&parts, code[start:i])
				start = i + len(string(r))
			}
		}
	}
	appendInlineStatement(&parts, code[start:])
	if len(parts) == 0 {
		return code
	}
	return strings.Join(parts, "\n")
}

func appendInlineStatement(parts *[]string, statement string) {
	statement = strings.TrimSpace(statement)
	if statement != "" {
		*parts = append(*parts, statement)
	}
}

type graphPositionSnapshot struct {
	operations int
	features   int
}

func graphPosition(graph *behavior.Graph) graphPositionSnapshot {
	return graphPositionSnapshot{operations: len(graph.Operations), features: len(graph.Features)}
}

func promoteInlineGraphRange(graph *behavior.Graph, start graphPositionSnapshot, execution behavior.ExecutionContext) {
	for i := start.operations; i < len(graph.Operations); i++ {
		if graph.Operations[i].SourceFunction != "" {
			continue
		}
		graph.Operations[i].Execution = execution
	}
	for i := start.features; i < len(graph.Features); i++ {
		if graph.Features[i].SourceFunction == "" {
			graph.Features[i].Execution = execution
		}
	}
}

func analyzePythonBase64Exec(graph *behavior.Graph, content artifact.Content, code string, execution behavior.ExecutionContext, parentEvidenceID string, depth int) {
	// Reuse the closed .pth-stage grammar against the original program, before
	// formatting normalization. Substring matching cannot establish that exec
	// is called: comments, strings, dormant functions and rebound names are inert.
	if strings.TrimLeft(code, " \t") != code {
		return
	}
	encoded, ok := pythonPTHLiteralBase64Wrapper(code)
	if !ok {
		return
	}
	if depth >= 2 {
		addPartialCoverageOnce(graph, content.NodeID, "python-inline-decoding", "literal Base64 wrapper depth limit 2 reached; deeper nested semantics were not analyzed")
		return
	}
	decoded, ok := decodePythonB64decodeLiteral(encoded)
	if !ok || len(decoded) == 0 || !utf8.Valid(decoded) || !mostlyText(decoded) || strings.ContainsRune(string(decoded), 0) || unsupportedPythonPTHDecodedSource(decoded) != "" {
		addPartialCoverageOnce(graph, content.NodeID, "python-inline-decoding", "the literal Base64 wrapper had invalid or unsupported decoded Python source; nested semantics were not analyzed")
		return
	}
	ev := graph.AddEvidence(behavior.Evidence{
		NodeID:   content.NodeID,
		ScopeID:  content.ScopeID,
		Logical:  content.LogicalPath,
		Physical: content.PhysicalPath,
		Method:   "text",
		Kind:     "python-base64-decoded-script",
		Value:    "literal base64 exec",
	})
	evidenceIDs := []string{ev}
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
	decodedScope := graph.AddScope(behavior.Scope{
		NodeID:     content.NodeID,
		ParentID:   content.ScopeID,
		Kind:       "decoded-inline-code",
		Name:       "python base64 exec",
		SourceRole: content.Role,
	})
	if decodedScope == "" {
		return
	}
	decodedContent := content
	decodedContent.ScopeID = decodedScope
	decodedContent.LogicalPath = inlineLogicalPath(content.LogicalPath, "python", "decoded-base64")
	decodedContent.Data = decoded
	start := graphPosition(graph)
	ExtractText(graph, decodedContent)
	analyzePythonBase64Exec(graph, decodedContent, string(decoded), execution, ev, depth+1)
	promoteInlineGraphRange(graph, start, execution)
}

func decodeLiteralBase64(value string) ([]byte, bool) {
	// Reject oversized literals before allocating a cleaned copy. Whitespace is
	// accepted for common wrapped literals, but gets a separate small budget so
	// an attacker cannot hide an enormous input behind a tiny decoded payload.
	if len(value) > maxEncodedInlineBytes+maxInlineWhitespaceBytes {
		return nil, false
	}
	cleaned := make([]byte, 0, min(len(value), maxEncodedInlineBytes))
	whitespace := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\n', '\r', '\t':
			whitespace++
			if whitespace > maxInlineWhitespaceBytes {
				return nil, false
			}
		default:
			if len(cleaned) >= maxEncodedInlineBytes {
				return nil, false
			}
			cleaned = append(cleaned, value[i])
		}
	}
	encoded := string(cleaned)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil && len(decoded) <= maxDecodedInlineBytes {
			return decoded, true
		}
	}
	return nil, false
}

func inlineLogicalPath(logical, language, label string) string {
	ext := ".txt"
	switch language {
	case "python":
		ext = ".py"
	case "javascript", "jxa":
		ext = ".js"
	case "applescript":
		ext = ".applescript"
	case "shell":
		ext = ".sh"
	}
	base := strings.TrimSuffix(filepath.ToSlash(logical), ext)
	return base + "#" + label + ext
}
