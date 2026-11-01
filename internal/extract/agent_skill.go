package extract

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxAgentSkillBytes          = 1 << 20
	maxAgentSkillLines          = 16384
	maxAgentSkillFrontmatter    = 256
	maxAgentSkillMetadataValue  = 8192
	maxAgentSkillAllowedTools   = 128
	maxAgentSkillExternalLinks  = 512
	maxAgentSkillShellBlocks    = 128
	maxAgentSkillShellBlockSize = 8192
)

var (
	agentSkillNamePattern        = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	agentSkillLinkPattern        = regexp.MustCompile(`(?i)\[[^\]\r\n]*\]\((https?://[^)\s]+)\)`)
	agentSkillMetadataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type agentSkillLine struct {
	text   string
	line   int
	offset int
}

type agentSkillMetadataValue struct {
	value  string
	line   int
	offset int
}

type agentSkillMetadata struct {
	name         agentSkillMetadataValue
	description  agentSkillMetadataValue
	allowedTools agentSkillMetadataValue
	bodyStart    int
	valid        bool
	detail       string
}

// ExtractAgentSkill inventories bounded, directly observable instruction
// facts. A SKILL.md is not an execution declaration: this extractor never
// invokes generic source or shell analysis and never emits executable IR.
func ExtractAgentSkill(graph *behavior.Graph, content artifact.Content) {
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: "agent-instruction-semantics",
		Status:       "partial",
		Detail:       "retained instructions do not establish user or policy approval, agent tool dispatch, external retrieval, or operating-system execution",
	})

	data := content.Data
	limited := false
	if len(data) > maxAgentSkillBytes {
		data = data[:maxAgentSkillBytes]
		limited = true
	}
	if len(data) == 0 || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "agent-skill-frontmatter",
			Status:       "partial",
			Detail:       "SKILL.md content is empty or is not retained NUL-free UTF-8 text",
		})
		return
	}

	lines, lineLimited := splitAgentSkillLines(string(data), maxAgentSkillLines)
	limited = limited || lineLimited
	metadata := parseAgentSkillMetadata(lines, content)
	if metadata.detail == "" {
		metadata.detail = "closed bounded Agent Skills metadata subset analyzed"
	}
	status := "analyzed"
	if !metadata.valid {
		status = "partial"
	}
	if limited {
		status = "partial"
		metadata.valid = false
		metadata.detail = appendAgentSkillDetail(metadata.detail, "retained byte or line limit reached")
	}
	if len(strings.Fields(metadata.allowedTools.value)) > maxAgentSkillAllowedTools {
		status = "partial"
		metadata.detail = appendAgentSkillDetail(metadata.detail, fmt.Sprintf("only the first %d declared allowed tools were retained", maxAgentSkillAllowedTools))
	}

	nameEvidence := addAgentSkillMetadataFeature(graph, content, "agent.skill.name", "name", metadata.name)
	descriptionEvidence := addAgentSkillMetadataFeature(graph, content, "agent.skill.description", "description", metadata.description)
	addAgentSkillAllowedTools(graph, content, metadata.allowedTools)
	if metadata.valid && nameEvidence != "" && descriptionEvidence != "" {
		graph.AddArtifactProperty(behavior.ArtifactProperty{
			NodeID:      content.NodeID,
			Kind:        "agent-skill-format",
			Value:       "agentskills.io/SKILL.md",
			EvidenceIDs: []string{nameEvidence, descriptionEvidence},
			Support:     behavior.SupportDirect,
		})
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: "agent-skill-frontmatter",
		Status:       status,
		Detail:       metadata.detail,
	})

	instructionDetail := ""
	if metadata.bodyStart < 0 || metadata.bodyStart > len(lines) {
		instructionDetail = "instruction body was not inspected because a closing frontmatter boundary was not established"
	} else {
		instructionDetail = extractAgentSkillInstructions(graph, content, lines[metadata.bodyStart:])
	}
	if limited {
		instructionDetail = appendAgentSkillDetail(instructionDetail, "retained byte or line limit reached")
	}
	instructionStatus := "partial"
	if instructionDetail == "" {
		instructionDetail = "only simple inline Markdown links whose literal HTTP(S) destination contains no whitespace or closing parenthesis, and triple-backtick fences whose first info token is sh, bash, zsh, or shell, were inventoried; other Markdown forms remain unsupported"
	}
	graph.AddCoverage(behavior.Coverage{
		NodeID:       content.NodeID,
		AnalysisArea: "agent-skill-instruction-extraction",
		Status:       instructionStatus,
		Detail:       instructionDetail,
	})
}

func splitAgentSkillLines(source string, limit int) ([]agentSkillLine, bool) {
	lines := make([]agentSkillLine, 0, min(limit, 256))
	offset := 0
	lineNumber := 1
	for offset <= len(source) && len(lines) < limit {
		end := strings.IndexByte(source[offset:], '\n')
		if end < 0 {
			lines = append(lines, agentSkillLine{text: strings.TrimSuffix(source[offset:], "\r"), line: lineNumber, offset: offset})
			offset = len(source) + 1
			break
		}
		end += offset
		lines = append(lines, agentSkillLine{text: strings.TrimSuffix(source[offset:end], "\r"), line: lineNumber, offset: offset})
		offset = end + 1
		lineNumber++
	}
	return lines, offset <= len(source)
}

func parseAgentSkillMetadata(lines []agentSkillLine, content artifact.Content) agentSkillMetadata {
	result := agentSkillMetadata{bodyStart: -1}
	if len(lines) == 0 || lines[0].text != "---" {
		result.detail = "required opening YAML frontmatter delimiter was not found"
		return result
	}
	end := -1
	for index := 1; index < len(lines) && index <= maxAgentSkillFrontmatter; index++ {
		if lines[index].text == "---" {
			end = index
			break
		}
	}
	if end < 0 {
		result.detail = fmt.Sprintf("closing YAML frontmatter delimiter was not found within %d lines", maxAgentSkillFrontmatter)
		return result
	}
	result.bodyStart = end + 1

	values := map[string]agentSkillMetadataValue{}
	unsupported := false
	detail := ""
	for index := 1; index < end; index++ {
		line := lines[index]
		if strings.TrimSpace(line.text) == "" || strings.HasPrefix(strings.TrimSpace(line.text), "#") {
			continue
		}
		if len(line.text) > 0 && (line.text[0] == ' ' || line.text[0] == '\t') {
			unsupported = true
			detail = appendAgentSkillDetail(detail, fmt.Sprintf("unsupported nested metadata at line %d", line.line))
			continue
		}
		colon := strings.IndexByte(line.text, ':')
		if colon <= 0 {
			unsupported = true
			detail = appendAgentSkillDetail(detail, fmt.Sprintf("malformed metadata at line %d", line.line))
			continue
		}
		key := strings.TrimSpace(line.text[:colon])
		raw := strings.TrimSpace(line.text[colon+1:])
		if _, duplicate := values[key]; duplicate {
			unsupported = true
			detail = appendAgentSkillDetail(detail, fmt.Sprintf("duplicate metadata key %q", key))
			continue
		}
		if !agentSkillTopLevelKey(key) {
			unsupported = true
			detail = appendAgentSkillDetail(detail, fmt.Sprintf("metadata key %q is outside the Agent Skills frontmatter vocabulary", key))
			continue
		}
		if key == "metadata" {
			if raw != "" {
				unsupported = true
				detail = appendAgentSkillDetail(detail, "metadata must be a string-to-string mapping")
				continue
			}
			next, ok := parseAgentSkillMetadataMap(lines, index+1, end)
			values[key] = agentSkillMetadataValue{value: "mapping", line: line.line, offset: line.offset}
			index = next - 1
			if !ok {
				unsupported = true
				detail = appendAgentSkillDetail(detail, "metadata is outside the bounded string-to-string mapping subset")
			}
			continue
		}
		if raw == "|" || raw == ">" {
			if key != "name" && key != "description" {
				unsupported = true
				detail = appendAgentSkillDetail(detail, fmt.Sprintf("unsupported block scalar for metadata key %q", key))
				continue
			}
			value, next, ok := parseAgentSkillBlockScalar(lines, index+1, end, raw == ">")
			if !ok {
				unsupported = true
				detail = appendAgentSkillDetail(detail, fmt.Sprintf("malformed or oversized block scalar for metadata key %q", key))
				continue
			}
			values[key] = agentSkillMetadataValue{value: value, line: line.line, offset: line.offset}
			index = next - 1
			continue
		}
		value, ok := parseAgentSkillScalar(raw)
		if !ok || len(value) > maxAgentSkillMetadataValue {
			unsupported = true
			detail = appendAgentSkillDetail(detail, fmt.Sprintf("unsupported or oversized scalar for metadata key %q", key))
			continue
		}
		values[key] = agentSkillMetadataValue{value: value, line: line.line, offset: line.offset}
	}

	result.name = values["name"]
	result.description = values["description"]
	result.allowedTools = values["allowed-tools"]
	if result.name.value == "" || result.description.value == "" {
		result.detail = appendAgentSkillDetail(detail, "required name and description metadata were not both present")
		return result
	}
	if len(result.name.value) > 64 || !agentSkillNamePattern.MatchString(result.name.value) {
		result.detail = appendAgentSkillDetail(detail, "name does not satisfy the Agent Skills identifier grammar")
		return result
	}
	if utf8.RuneCountInString(result.description.value) > 1024 {
		result.detail = appendAgentSkillDetail(detail, "description exceeds the Agent Skills length limit")
		return result
	}
	if compatibility, present := values["compatibility"]; present &&
		(compatibility.value == "" || utf8.RuneCountInString(compatibility.value) > 500) {
		result.detail = appendAgentSkillDetail(detail, "compatibility must contain 1-500 characters")
		return result
	}
	if license, present := values["license"]; present && license.value == "" {
		result.detail = appendAgentSkillDetail(detail, "license must be a string when present")
		return result
	}
	if allowedTools, present := values["allowed-tools"]; present && allowedTools.value == "" {
		result.detail = appendAgentSkillDetail(detail, "allowed-tools must be a space-separated string when present")
		return result
	}
	parent, parentKnown := agentSkillParentName(content)
	if !parentKnown {
		result.detail = appendAgentSkillDetail(detail, "containing skill directory was not established")
		return result
	}
	if parent != result.name.value {
		result.detail = appendAgentSkillDetail(detail, fmt.Sprintf("name %q does not match containing skill directory %q", result.name.value, parent))
		return result
	}
	result.valid = !unsupported
	result.detail = detail
	return result
}

func agentSkillTopLevelKey(key string) bool {
	switch key {
	case "name", "description", "license", "compatibility", "metadata", "allowed-tools":
		return true
	default:
		return false
	}
}

func parseAgentSkillMetadataMap(lines []agentSkillLine, start, end int) (int, bool) {
	indent := -1
	entries := 0
	keys := map[string]bool{}
	index := start
	for ; index < end; index++ {
		text := lines[index].text
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		currentIndent := len(text) - len(strings.TrimLeft(text, " "))
		if currentIndent == 0 {
			break
		}
		if strings.HasPrefix(text, "\t") {
			return index, false
		}
		if indent < 0 {
			indent = currentIndent
		}
		if currentIndent != indent || entries >= maxAgentSkillFrontmatter {
			return index, false
		}
		entry := text[indent:]
		colon := strings.IndexByte(entry, ':')
		if colon <= 0 {
			return index, false
		}
		key := strings.TrimSpace(entry[:colon])
		raw := strings.TrimSpace(entry[colon+1:])
		if !agentSkillMetadataKeyPattern.MatchString(key) || keys[key] || raw == "" {
			return index, false
		}
		value, ok := parseAgentSkillScalar(raw)
		if !ok || len(value) > maxAgentSkillMetadataValue || value == "" && raw != `""` && raw != "''" {
			return index, false
		}
		keys[key] = true
		entries++
	}
	return index, indent > 0 && entries > 0
}

func parseAgentSkillBlockScalar(lines []agentSkillLine, start, end int, folded bool) (string, int, bool) {
	if start >= end {
		return "", start, false
	}
	indent := -1
	var parts []string
	total := 0
	index := start
	for ; index < end; index++ {
		text := lines[index].text
		if strings.TrimSpace(text) == "" {
			if indent < 0 {
				continue
			}
			parts = append(parts, "")
			continue
		}
		currentIndent := len(text) - len(strings.TrimLeft(text, " "))
		if currentIndent == 0 {
			break
		}
		if strings.HasPrefix(text, "\t") {
			return "", index, false
		}
		if indent < 0 {
			indent = currentIndent
		}
		if currentIndent < indent {
			break
		}
		if currentIndent != indent {
			return "", index, false
		}
		part := text[indent:]
		total += len(part) + 1
		if total > maxAgentSkillMetadataValue {
			return "", index, false
		}
		parts = append(parts, part)
	}
	if indent < 0 {
		return "", index, false
	}
	if folded {
		return foldAgentSkillBlock(parts), index, true
	}
	return strings.TrimSpace(strings.Join(parts, "\n")), index, true
}

func foldAgentSkillBlock(parts []string) string {
	var result strings.Builder
	for index, part := range parts {
		if index > 0 {
			if parts[index-1] == "" || part == "" {
				result.WriteByte('\n')
			} else {
				result.WriteByte(' ')
			}
		}
		result.WriteString(part)
	}
	return strings.TrimSpace(result.String())
}

func parseAgentSkillScalar(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	switch raw[0] {
	case '&', '*', '!', '[', '{', ']', '}', ',', '|', '>', '%', '@', '`':
		return "", false
	}
	if raw[0] == '"' {
		if raw[len(raw)-1] != '"' {
			return "", false
		}
		value, err := strconv.Unquote(raw)
		return value, err == nil && utf8.ValidString(value)
	}
	if raw[0] == '\'' {
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", false
		}
		var value strings.Builder
		inner := raw[1 : len(raw)-1]
		for index := 0; index < len(inner); index++ {
			if inner[index] != '\'' {
				value.WriteByte(inner[index])
				continue
			}
			if index+1 >= len(inner) || inner[index+1] != '\'' {
				return "", false
			}
			value.WriteByte('\'')
			index++
		}
		return value.String(), true
	}
	if strings.HasPrefix(raw, "#") {
		return "", false
	}
	if strings.Contains(raw, " #") {
		raw = strings.TrimSpace(raw[:strings.Index(raw, " #")])
	}
	if raw == "" || strings.Contains(raw, ": ") || strings.HasSuffix(raw, ":") ||
		strings.HasPrefix(raw, "- ") || strings.HasPrefix(raw, "? ") || strings.HasPrefix(raw, ": ") {
		return "", false
	}
	return raw, true
}

func agentSkillParentName(content artifact.Content) (string, bool) {
	inner := content.LogicalPath
	if separator := strings.LastIndexByte(inner, '!'); separator >= 0 {
		inner = inner[separator+1:]
	}
	inner = strings.TrimPrefix(strings.ReplaceAll(inner, "\\", "/"), "/")
	if inner == "SKILL.md" {
		if content.PhysicalPath == "" || filepath.Base(content.PhysicalPath) != "SKILL.md" {
			return "", false
		}
		parent := filepath.Base(filepath.Dir(content.PhysicalPath))
		return parent, parent != "" && parent != "." && parent != string(filepath.Separator)
	}
	parent := path.Base(path.Dir(inner))
	if parent == "." || parent == "/" {
		return "", false
	}
	return parent, true
}

func addAgentSkillMetadataFeature(graph *behavior.Graph, content artifact.Content, key, kind string, metadata agentSkillMetadataValue) string {
	if metadata.value == "" {
		return ""
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Logical:     content.LogicalPath,
		Physical:    content.PhysicalPath,
		Line:        metadata.line,
		Offset:      int64(metadata.offset),
		OffsetKnown: true,
		Method:      "agent-skill-frontmatter",
		Kind:        kind,
		Value:       compactTextEvidenceValue(metadata.value),
	})
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         key,
		Value:       metadata.value,
		EvidenceIDs: []string{evidenceID},
		Support:     behavior.SupportDirect,
		Execution:   unknownExecutionContext(),
	})
	return evidenceID
}

func addAgentSkillAllowedTools(graph *behavior.Graph, content artifact.Content, metadata agentSkillMetadataValue) {
	if metadata.value == "" {
		return
	}
	tools := strings.Fields(metadata.value)
	if len(tools) > maxAgentSkillAllowedTools {
		tools = tools[:maxAgentSkillAllowedTools]
	}
	for _, tool := range tools {
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:      content.NodeID,
			ScopeID:     content.ScopeID,
			Logical:     content.LogicalPath,
			Physical:    content.PhysicalPath,
			Line:        metadata.line,
			Offset:      int64(metadata.offset),
			OffsetKnown: true,
			Method:      "agent-skill-frontmatter",
			Kind:        "allowed-tool",
			Value:       compactTextEvidenceValue(tool),
		})
		graph.AddFeature(behavior.Feature{
			NodeID:      content.NodeID,
			ScopeID:     content.ScopeID,
			Key:         "agent.skill.allowed_tool",
			Value:       tool,
			EvidenceIDs: []string{evidenceID},
			Support:     behavior.SupportDirect,
			Execution:   unknownExecutionContext(),
		})
	}
}

func extractAgentSkillInstructions(graph *behavior.Graph, content artifact.Content, lines []agentSkillLine) string {
	detail := ""
	linkCount := 0
	blockCount := 0
	inFence := false
	fenceLanguage := ""
	fenceStart := agentSkillLine{}
	var fenceBody strings.Builder
	fenceOversized := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line.text)
		if strings.HasPrefix(trimmed, "```") {
			info := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			if !inFence {
				inFence = true
				if fields := strings.Fields(info); len(fields) > 0 {
					fenceLanguage = strings.ToLower(fields[0])
				} else {
					fenceLanguage = ""
				}
				fenceStart = line
				fenceBody.Reset()
				fenceOversized = false
			} else if info == "" {
				if agentSkillShellFence(fenceLanguage) {
					if blockCount >= maxAgentSkillShellBlocks {
						detail = appendAgentSkillDetail(detail, fmt.Sprintf("only the first %d shell-language fenced blocks were retained", maxAgentSkillShellBlocks))
					} else if fenceOversized {
						detail = appendAgentSkillDetail(detail, fmt.Sprintf("shell-language fenced block at line %d exceeded %d bytes", fenceStart.line, maxAgentSkillShellBlockSize))
					} else if value := strings.TrimSpace(fenceBody.String()); value != "" {
						addAgentSkillInstructionFeature(graph, content, "agent.skill.shell_code_block", "shell-code-block", value, fenceStart)
						blockCount++
					}
				}
				inFence = false
				fenceLanguage = ""
				continue
			}
		} else if inFence && agentSkillShellFence(fenceLanguage) {
			if fenceBody.Len()+len(line.text)+1 > maxAgentSkillShellBlockSize {
				fenceOversized = true
			} else if !fenceOversized {
				fenceBody.WriteString(line.text)
				fenceBody.WriteByte('\n')
			}
		}
		if inFence {
			continue
		}

		remainingLinks := maxAgentSkillExternalLinks - linkCount
		if remainingLinks <= 0 {
			if agentSkillLinkPattern.MatchString(line.text) {
				detail = appendAgentSkillDetail(detail, fmt.Sprintf("only the first %d external Markdown links were retained", maxAgentSkillExternalLinks))
			}
			continue
		}
		matches := agentSkillLinkPattern.FindAllStringSubmatchIndex(line.text, remainingLinks+1)
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}
			if linkCount >= maxAgentSkillExternalLinks {
				detail = appendAgentSkillDetail(detail, fmt.Sprintf("only the first %d external Markdown links were retained", maxAgentSkillExternalLinks))
				break
			}
			value := line.text[match[2]:match[3]]
			location := line
			location.offset += match[2]
			addAgentSkillInstructionFeature(graph, content, "agent.skill.external_link", "external-link", value, location)
			linkCount++
		}
	}
	if inFence {
		detail = appendAgentSkillDetail(detail, fmt.Sprintf("unterminated fenced block beginning at line %d", fenceStart.line))
	}
	return detail
}

func agentSkillShellFence(language string) bool {
	switch language {
	case "sh", "bash", "zsh", "shell":
		return true
	default:
		return false
	}
}

func addAgentSkillInstructionFeature(graph *behavior.Graph, content artifact.Content, key, kind, value string, location agentSkillLine) {
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Logical:     content.LogicalPath,
		Physical:    content.PhysicalPath,
		Line:        location.line,
		Offset:      int64(location.offset),
		OffsetKnown: true,
		Method:      "agent-skill-instructions",
		Kind:        kind,
		Value:       compactTextEvidenceValue(value),
	})
	graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Key:         key,
		Value:       value,
		EvidenceIDs: []string{evidenceID},
		Support:     behavior.SupportDirect,
		Execution:   unknownExecutionContext(),
	})
}

func appendAgentSkillDetail(detail, addition string) string {
	if addition == "" || strings.Contains(detail, addition) {
		return detail
	}
	if detail == "" {
		return addition
	}
	return detail + "; " + addition
}
