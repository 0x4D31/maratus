package extract

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

const (
	maxStaticObservationInputBytes = 16 << 20
	maxEmbeddedPlistBytes          = 4 << 20
	maxEmbeddedPlistCandidates     = 64
	maxPrivateKeyBytes             = 1 << 20
	maxPrivateKeyCandidates        = 32
	maxCertificateBytes            = 1 << 20
	maxCertificateCandidates       = 64
	maxDerivedBase64Candidates     = 256
	maxDerivedBase64Bytes          = 4 << 20
)

var assignedBase64Literal = regexp.MustCompile(`(?m)^[ \t]*(?:(?:const|let|var|export)[ \t]+)?[A-Za-z_][A-Za-z0-9_]*(?:[ \t]*:[^=;\n]{1,256})?[ \t]*=[ \t]*["']([A-Za-z0-9+/]{12,}={0,2})["']([^\n]*)$`)

// extractStaticContentObservations retains exact, bounded data observations.
// It intentionally creates Features only: a literal configuration, key, URL,
// or path is not proof that the artifact used it at runtime.
func extractStaticContentObservations(graph *behavior.Graph, content artifact.Content, data []byte, method, arch string, byteOffsetBase int64) {
	if len(data) == 0 || graph.WorkLimitReached() {
		return
	}
	scan := data
	if len(scan) > maxStaticObservationInputBytes {
		scan = scan[:maxStaticObservationInputBytes]
		addPartialCoverageOnce(graph, content.NodeID, "static-observations", fmt.Sprintf("static observation scanning capped at %d bytes per analyzed content region", maxStaticObservationInputBytes))
	}
	extractEmbeddedLaunchdObservations(graph, content, scan, method, arch, byteOffsetBase)
	extractPrivateKeyObservations(graph, content, scan, method, arch, byteOffsetBase)
	extractCertificateObservations(graph, content, scan, method, arch, byteOffsetBase)
	if method == "source-static-observation" && !strings.EqualFold(filepath.Ext(content.LogicalPath), ".rs") {
		extractAssignedBase64Observations(graph, content, scan, byteOffsetBase)
	}
}

func extractAssignedBase64Observations(graph *behavior.Graph, content artifact.Content, data []byte, byteOffsetBase int64) {
	matches := assignedBase64Literal.FindAllSubmatchIndex(data, maxDerivedBase64Candidates+1)
	if len(matches) == 0 {
		return
	}
	codeMask, lexicalLimited, supported := assignedBase64SourceCodeMask(content, data)
	if !supported {
		return
	}
	candidateLimited := len(matches) > maxDerivedBase64Candidates
	limited := candidateLimited || lexicalLimited
	if candidateLimited {
		matches = matches[:maxDerivedBase64Candidates]
	}
	seen := map[string]bool{}
	encodedBytes := 0
	decodedBytes := 0
	for _, match := range matches {
		if len(match) < 6 || match[0] < 0 || match[0] >= len(codeMask) || !codeMask[match[0]] || !assignedBase64SuffixValid(content, data[match[4]:match[5]]) {
			continue
		}
		encoded := string(data[match[2]:match[3]])
		if len(encoded) > maxDerivedBase64Bytes-encodedBytes {
			limited = true
			break
		}
		if len(encoded)%4 != 0 {
			continue
		}
		encodedBytes += len(encoded)
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != encoded {
			continue
		}
		if len(decoded) > maxDerivedBase64Bytes-decodedBytes {
			limited = true
			break
		}
		decodedBytes += len(decoded)
		decodedText := string(decoded)
		urls := make([]string, 0)
		ips := make([]string, 0)
		pending := map[string]bool{}
		for _, candidate := range firstLimitedMatches(reURL, decodedText, maxMachORegexMatches) {
			value, ok := normalizeStaticURL(decodedText[candidate[0]:candidate[1]])
			key := "url\x00" + value
			if ok && !seen[key] && !pending[key] {
				pending[key] = true
				urls = append(urls, value)
			}
		}
		for _, candidate := range validatedIPv4MatchIndexes(decodedText, firstLimitedMatches(reIP, decodedText, maxMachORegexMatches)) {
			value, ok := validatedIPv4Match(decodedText, candidate)
			key := "ip\x00" + value
			if ok && !seen[key] && !pending[key] {
				pending[key] = true
				ips = append(ips, value)
			}
		}
		if len(urls) == 0 && len(ips) == 0 {
			continue
		}
		sourceDigest := sha256.Sum256([]byte(encoded))
		evidenceID := addStaticObservationEvidence(graph, content, "source-constant-base64", "base64-literal", fmt.Sprintf("sha256:%s length:%d", hex.EncodeToString(sourceDigest[:]), len(encoded)), "", byteOffsetBase+int64(match[2]))
		if evidenceID == "" {
			return
		}
		decodedDigest := sha256.Sum256(decoded)
		qualifiers := map[string]string{
			"decoded_sha256": hex.EncodeToString(decodedDigest[:]), "decoded_size": fmt.Sprintf("%d", len(decoded)),
			"runtime_use": "not-established", "transformation": "canonical-base64-assignment",
		}
		addStaticObservationFeature(graph, content, "", "derived.base64.content", "sha256:"+hex.EncodeToString(decodedDigest[:]), qualifiers, evidenceID)
		for _, value := range urls {
			seen["url\x00"+value] = true
			addStaticObservationFeature(graph, content, "", "network.url", value, qualifiers, evidenceID)
		}
		for _, value := range ips {
			seen["ip\x00"+value] = true
			addStaticObservationFeature(graph, content, "", "network.ip", value, qualifiers, evidenceID)
		}
	}
	if limited {
		addPartialCoverageOnce(graph, content.NodeID, "derived-base64-observations", fmt.Sprintf("assigned canonical Base64 observation scanning capped at %d candidates and %d cumulative encoded and decoded bytes", maxDerivedBase64Candidates, maxDerivedBase64Bytes))
	}
}

func assignedBase64SuffixValid(content artifact.Content, suffix []byte) bool {
	language := staticObservationSourceLanguage(content)
	value := strings.TrimSpace(string(suffix))
	semicolon := false
	if strings.HasPrefix(value, ";") {
		semicolon = true
		value = strings.TrimSpace(value[1:])
	}
	switch language {
	case "javascript", "jxa", "native-source", "java-source":
		return value == "" || strings.HasPrefix(value, "//")
	case "python", "shell":
		return value == "" || strings.HasPrefix(value, "#")
	case "toml":
		return !semicolon && (value == "" || strings.HasPrefix(value, "#"))
	default:
		return false
	}
}

// assignedBase64SourceCodeMask proves that an assignment starts in source
// code, rather than in a comment, quoted example, docstring, or shell heredoc.
// It is intentionally syntax-bounded: unknown source formats do not receive
// derived observations merely because their bytes resemble an assignment.
func assignedBase64SourceCodeMask(content artifact.Content, data []byte) ([]bool, bool, bool) {
	language := staticObservationSourceLanguage(content)
	switch language {
	case "javascript", "jxa", "native-source", "java-source":
		mask, limited := slashSourceCodeMask(data)
		return mask, limited, true
	case "python":
		mask, limited := pythonSourceCodeMask(data)
		return mask, limited, true
	case "shell":
		mask, limited := shellSourceCodeMask(data)
		return mask, limited, true
	case "toml":
		mask, limited := hashQuotedSourceCodeMask(data, true)
		return mask, limited, true
	default:
		return nil, false, false
	}
}

func staticObservationSourceLanguage(content artifact.Content) string {
	if content.SemanticLanguage != "" {
		return content.SemanticLanguage
	}
	return artifact.Language(content.LogicalPath)
}

func hashQuotedSourceCodeMask(data []byte, allowTriple bool) ([]bool, bool) {
	mask := make([]bool, len(data))
	quote := byte(0)
	triple := false
	escaped := false
	for index := 0; index < len(data); index++ {
		if quote != 0 {
			if triple {
				if index+2 < len(data) && data[index] == quote && data[index+1] == quote && data[index+2] == quote && !sourceByteEscaped(data, index) {
					index += 2
					quote = 0
					triple = false
				}
				continue
			}
			if escaped {
				escaped = false
			} else if quote == '"' && data[index] == '\\' {
				escaped = true
			} else if data[index] == quote {
				quote = 0
			}
			continue
		}
		if data[index] == '#' {
			for index < len(data) && data[index] != '\n' {
				index++
			}
			if index < len(data) {
				mask[index] = true
			}
			continue
		}
		if data[index] == '\'' || data[index] == '"' {
			quote = data[index]
			triple = allowTriple && index+2 < len(data) && data[index+1] == quote && data[index+2] == quote
			if triple {
				index += 2
			}
			continue
		}
		mask[index] = true
	}
	return mask, quote != 0
}

func slashSourceCodeMask(data []byte) ([]bool, bool) {
	mask := make([]bool, len(data))
	blockDepth := 0
	lineComment := false
	quote := byte(0)
	triple := false
	escaped := false
	for index := 0; index < len(data); index++ {
		if lineComment {
			if data[index] == '\n' {
				lineComment = false
				mask[index] = true
			}
			continue
		}
		if blockDepth > 0 {
			switch {
			case index+1 < len(data) && data[index] == '/' && data[index+1] == '*':
				blockDepth++
				if blockDepth > 64 {
					return mask, true
				}
				index++
			case index+1 < len(data) && data[index] == '*' && data[index+1] == '/':
				blockDepth--
				index++
			}
			continue
		}
		if quote != 0 {
			if triple {
				if index+2 < len(data) && data[index] == quote && data[index+1] == quote && data[index+2] == quote && !sourceByteEscaped(data, index) {
					index += 2
					quote = 0
					triple = false
				}
				continue
			}
			if escaped {
				escaped = false
			} else if data[index] == '\\' {
				escaped = true
			} else if data[index] == quote {
				quote = 0
			}
			continue
		}
		switch {
		case index+1 < len(data) && data[index] == '/' && data[index+1] == '/':
			lineComment = true
			index++
		case index+1 < len(data) && data[index] == '/' && data[index+1] == '*':
			blockDepth = 1
			index++
		case data[index] == '\'' || data[index] == '"' || data[index] == '`':
			quote = data[index]
			triple = quote == '"' && index+2 < len(data) && data[index+1] == quote && data[index+2] == quote
			if triple {
				index += 2
			}
		default:
			mask[index] = true
		}
	}
	return mask, blockDepth != 0 || quote != 0
}

func pythonSourceCodeMask(data []byte) ([]bool, bool) {
	lines := strings.Split(string(data), "\n")
	multiline := maskPythonMultilineStrings(lines)
	mask := make([]bool, len(data))
	offset := 0
	for lineIndex, line := range lines {
		maskedLine := ""
		if lineIndex < len(multiline.lines) {
			maskedLine = multiline.lines[lineIndex]
		}
		lineMask := lineCommentSourceCodeMask([]byte(maskedLine), "#", false)
		for index := 0; index < len(line) && index < len(maskedLine); index++ {
			// Triple-quoted contents are replaced with spaces. Requiring the
			// masked byte to equal the original keeps an assignment identifier
			// inside that content from becoming code, while ordinary code stays
			// addressable at its original byte offset.
			mask[offset+index] = lineMask[index] && maskedLine[index] == line[index]
		}
		offset += len(line)
		if lineIndex < len(lines)-1 && offset < len(mask) {
			mask[offset] = true
			offset++
		}
	}
	return mask, multiline.limited || multiline.unterminated || multiline.formattedExpression
}

func shellSourceCodeMask(data []byte) ([]bool, bool) {
	mask := lineCommentSourceCodeMask(data, "#", true)
	lines := strings.Split(string(data), "\n")
	offset := 0
	var heredocs shellHeredocState
	limited := false
	for lineIndex, line := range lines {
		lineLength := len(line)
		if heredocs.consumeBodyLine(line) {
			for index := offset; index < offset+lineLength && index < len(mask); index++ {
				mask[index] = false
			}
		} else {
			_, suppress := heredocs.observeCommandLine(line, lineIndex+1)
			limited = limited || suppress
		}
		offset += lineLength
		if lineIndex < len(lines)-1 {
			offset++
		}
	}
	return mask, limited || heredocs.incompleteDetail() != ""
}

func lineCommentSourceCodeMask(data []byte, marker string, shellBoundary bool) []bool {
	mask := make([]bool, len(data))
	markerBytes := []byte(marker)
	quote := byte(0)
	escaped := false
	for index := 0; index < len(data); index++ {
		current := data[index]
		if current == '\n' {
			quote = 0
			escaped = false
			mask[index] = true
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
		if current == '\'' || current == '"' || current == '`' {
			quote = current
			continue
		}
		if bytes.HasPrefix(data[index:], markerBytes) && (!shellBoundary || index == 0 || data[index-1] == ' ' || data[index-1] == '\t' || data[index-1] == '\n') {
			for index < len(data) && data[index] != '\n' {
				index++
			}
			if index < len(data) {
				mask[index] = true
			}
			continue
		}
		mask[index] = true
	}
	return mask
}

func sourceByteEscaped(data []byte, index int) bool {
	backslashes := 0
	for index--; index >= 0 && data[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func extractEmbeddedLaunchdObservations(graph *behavior.Graph, content artifact.Content, data []byte, method, arch string, byteOffsetBase int64) {
	const opening = "<plist"
	const closing = "</plist>"
	searchAt := 0
	candidates := 0
	for searchAt < len(data) && candidates < maxEmbeddedPlistCandidates && !graph.WorkLimitReached() {
		relative := bytes.Index(data[searchAt:], []byte(opening))
		if relative < 0 {
			break
		}
		start := searchAt + relative
		candidates++
		remaining := data[start:]
		closeAt := bytes.Index(remaining, []byte(closing))
		if closeAt < 0 || closeAt+len(closing) > maxEmbeddedPlistBytes {
			searchAt = start + len(opening)
			continue
		}
		end := start + closeAt + len(closing)
		span := data[start:end]
		plist, err := plistx.Decode(span)
		if err != nil {
			if !utf8.Valid(span) {
				extractEmbeddedLaunchdTemplateObservation(graph, content, span, method, arch, byteOffsetBase+int64(start))
			}
			searchAt = start + len(opening)
			continue
		}
		label := plistx.String(plist, "Label")
		command, _ := launchdCommand(plist)
		if label == "" || len(command) == 0 {
			searchAt = end
			continue
		}
		digest := sha256.Sum256(span)
		evidenceValue := "launchd plist sha256:" + hex.EncodeToString(digest[:])
		evidenceID := addStaticObservationEvidence(graph, content, method, "embedded-launchd-plist", evidenceValue, arch, byteOffsetBase+int64(start))
		if evidenceID == "" {
			return
		}
		qualifiers := map[string]string{
			"data_only":      "true",
			"format":         "xml-plist",
			"persistence":    "not-established",
			"transformation": "bounded-plist-decode",
		}
		addStaticObservationFeature(graph, content, arch, "embedded.launchd.configuration", label, qualifiers, evidenceID)
		addStaticObservationFeature(graph, content, arch, "embedded.launchd.label", label, qualifiers, evidenceID)
		addStaticObservationFeature(graph, content, arch, "embedded.launchd.program", strings.Join(command, " "), qualifiers, evidenceID)
		for _, trigger := range embeddedLaunchdTriggers(plist) {
			addStaticObservationFeature(graph, content, arch, "embedded.launchd.trigger", trigger, qualifiers, evidenceID)
		}
		searchAt = end
	}
	if candidates == maxEmbeddedPlistCandidates && bytes.Contains(data[searchAt:], []byte(opening)) {
		addPartialCoverageOnce(graph, content.NodeID, "embedded-launchd-configurations", fmt.Sprintf("embedded plist candidate scanning capped at %d candidates", maxEmbeddedPlistCandidates))
	}
}

// extractEmbeddedLaunchdTemplateObservation retains only fields that remain
// exact when an otherwise complete XML plist contains non-UTF-8 runtime
// placeholders. This is common in compiled string templates. The observation
// is explicitly incomplete and never establishes installation, loading, or
// persistence.
func extractEmbeddedLaunchdTemplateObservation(graph *behavior.Graph, content artifact.Content, span []byte, method, arch string, offset int64) {
	sanitized := bytes.ToValidUTF8(span, []byte("\xef\xbf\xbd"))
	plist, err := plistx.Decode(sanitized)
	if err != nil {
		return
	}
	command, _ := launchdCommand(plist)
	if len(command) == 0 || strings.ContainsRune(command[0], utf8.RuneError) {
		return
	}
	digest := sha256.Sum256(span)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])
	evidenceID := addStaticObservationEvidence(graph, content, method, "embedded-launchd-template", fingerprint, arch, offset)
	if evidenceID == "" {
		return
	}
	qualifiers := map[string]string{
		"arguments_complete": "false",
		"complete":           "false",
		"data_only":          "true",
		"format":             "xml-plist-template",
		"persistence":        "not-established",
		"transformation":     "invalid-utf8-placeholder-redaction",
	}
	addStaticObservationFeature(graph, content, arch, "embedded.launchd.template", fingerprint, qualifiers, evidenceID)
	addStaticObservationFeature(graph, content, arch, "embedded.launchd.program", command[0], qualifiers, evidenceID)
	for _, trigger := range embeddedLaunchdTriggers(plist) {
		addStaticObservationFeature(graph, content, arch, "embedded.launchd.trigger", trigger, qualifiers, evidenceID)
	}
}

func embeddedLaunchdTriggers(plist plistx.Dict) []string {
	triggers := make([]string, 0, 2)
	if value, ok := plist["RunAtLoad"]; ok && plistx.StringValue(value) == "true" {
		triggers = append(triggers, "RunAtLoad")
	}
	if _, ok := plist["KeepAlive"]; ok {
		triggers = append(triggers, "KeepAlive")
	}
	return triggers
}

func extractPrivateKeyObservations(graph *behavior.Graph, content artifact.Content, data []byte, method, arch string, byteOffsetBase int64) {
	const beginMarker = "-----BEGIN "
	searchAt := 0
	candidates := 0
	for searchAt < len(data) && candidates < maxPrivateKeyCandidates && !graph.WorkLimitReached() {
		relative := bytes.Index(data[searchAt:], []byte(beginMarker))
		if relative < 0 {
			break
		}
		start := searchAt + relative
		candidates++
		block, consumed, limited := decodeExactPEMSpan(data[start:], maxPrivateKeyBytes)
		if limited {
			addPartialCoverageOnce(graph, content.NodeID, "private-key-observations", fmt.Sprintf("private-key candidate scanning capped at %d bytes per candidate", maxPrivateKeyBytes))
		}
		if block == nil || !supportedPrivateKeyPEMType(block.Type) {
			searchAt = start + len(beginMarker)
			continue
		}
		if consumed <= 0 {
			searchAt = start + len(beginMarker)
			continue
		}
		fingerprint, fingerprintKind, valid := privateKeyFingerprint(block)
		if !valid {
			if block.Type == "OPENSSH PRIVATE KEY" {
				addPartialCoverageOnce(graph, content.NodeID, "private-key-observations", "OpenSSH PEM candidate was not promoted: complete OpenSSH private-key validation is unsupported")
			}
			searchAt = start + consumed
			continue
		}
		value := block.Type + " " + fingerprintKind + ":" + fingerprint
		evidenceID := addStaticObservationEvidence(graph, content, method, "complete-private-key", value, arch, byteOffsetBase+int64(start))
		if evidenceID == "" {
			return
		}
		addStaticObservationFeature(graph, content, arch, "cryptographic.private_key", value, map[string]string{
			"complete":         "true",
			"fingerprint":      fingerprint,
			"fingerprint_kind": fingerprintKind,
			"key_type":         block.Type,
			"secret_bytes":     "redacted",
		}, evidenceID)
		searchAt = start + consumed
	}
	if candidates == maxPrivateKeyCandidates && bytes.Contains(data[searchAt:], []byte(beginMarker)) {
		addPartialCoverageOnce(graph, content.NodeID, "private-key-observations", fmt.Sprintf("private-key candidate scanning capped at %d candidates", maxPrivateKeyCandidates))
	}
}

// PEM material in pooled binary data may end immediately before an unrelated
// constant. Isolate its original marker-delimited bytes before decoding so the
// footer need not be the end of the surrounding binary line. A nested BEGIN
// line makes this candidate malformed: pem.Decode must never skip it and
// silently attribute a later block to this candidate's source offset.
func decodeExactPEMSpan(data []byte, byteLimit int) (*pem.Block, int, bool) {
	const beginPrefix = "-----BEGIN "
	if byteLimit <= 0 {
		return nil, 0, len(data) != 0
	}
	bounded := len(data) > byteLimit
	data = data[:min(len(data), byteLimit)]
	if !bytes.HasPrefix(data, []byte(beginPrefix)) {
		return nil, 0, false
	}
	headerEnd := bytes.IndexByte(data, '\n')
	if headerEnd < 0 {
		return nil, 0, bounded
	}
	header := bytes.TrimRight(bytes.TrimSuffix(data[:headerEnd], []byte{'\r'}), " \t")
	if !bytes.HasSuffix(header, []byte("-----")) || len(header) <= len(beginPrefix)+5 {
		return nil, 0, false
	}
	blockType := string(header[len(beginPrefix) : len(header)-5])
	endMarker := []byte("-----END " + blockType + "-----")
	footer := bytes.Index(data[headerEnd+1:], endMarker)
	if footer < 0 {
		return nil, 0, bounded
	}
	footer += headerEnd + 1
	if bytes.Contains(data[1:footer], []byte("\n"+beginPrefix)) {
		return nil, 0, false
	}
	consumed := footer + len(endMarker)
	block, rest := pem.Decode(data[:consumed])
	if block == nil || block.Type != blockType || len(rest) != 0 {
		return nil, 0, false
	}
	return block, consumed, false
}

func supportedPrivateKeyPEMType(keyType string) bool {
	switch keyType {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY":
		return true
	default:
		return false
	}
}

func privateKeyFingerprint(block *pem.Block) (string, string, bool) {
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err == nil && key != nil {
		if publicKey := publicKeyForPrivateKey(key); publicKey != nil {
			if encoded, marshalErr := x509.MarshalPKIXPublicKey(publicKey); marshalErr == nil {
				digest := sha256.Sum256(encoded)
				return hex.EncodeToString(digest[:]), "spki-sha256", true
			}
		}
	}
	return "", "", false
}

func extractCertificateObservations(graph *behavior.Graph, content artifact.Content, data []byte, method, arch string, byteOffsetBase int64) {
	const beginMarker = "-----BEGIN CERTIFICATE-----"
	searchAt := 0
	candidates := 0
	for searchAt < len(data) && candidates < maxCertificateCandidates && !graph.WorkLimitReached() {
		relative := bytes.Index(data[searchAt:], []byte(beginMarker))
		if relative < 0 {
			break
		}
		start := searchAt + relative
		candidates++
		block, consumed, limited := decodeExactPEMSpan(data[start:], maxCertificateBytes)
		if limited {
			addPartialCoverageOnce(graph, content.NodeID, "certificate-observations", fmt.Sprintf("certificate candidate scanning capped at %d bytes per candidate", maxCertificateBytes))
		}
		if block == nil || block.Type != "CERTIFICATE" {
			searchAt = start + len(beginMarker)
			continue
		}
		if consumed <= 0 {
			searchAt = start + len(beginMarker)
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || len(certificate.Raw) == 0 {
			searchAt = start + consumed
			continue
		}
		digest := sha256.Sum256(certificate.Raw)
		fingerprint := hex.EncodeToString(digest[:])
		value := "x509-certificate sha256:" + fingerprint
		evidenceID := addStaticObservationEvidence(graph, content, method, "complete-x509-certificate", value, arch, byteOffsetBase+int64(start))
		if evidenceID == "" {
			return
		}
		qualifiers := map[string]string{
			"complete":         "true",
			"fingerprint":      fingerprint,
			"fingerprint_kind": "certificate-der-sha256",
			"format":           "pem-x509",
			"runtime_use":      "not-established",
			"trust":            "not-evaluated",
		}
		if subject := evidenceSnippet(certificate.Subject.String()); subject != "" {
			qualifiers["subject"] = subject
		}
		if issuer := evidenceSnippet(certificate.Issuer.String()); issuer != "" {
			qualifiers["issuer"] = issuer
		}
		if certificate.SerialNumber != nil {
			if serial := evidenceSnippet(certificate.SerialNumber.Text(16)); serial != "" {
				qualifiers["serial_number"] = serial
			}
		}
		qualifiers["not_before"] = certificate.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
		qualifiers["not_after"] = certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
		addStaticObservationFeature(graph, content, arch, "cryptographic.certificate", value, qualifiers, evidenceID)
		searchAt = start + consumed
	}
	if candidates == maxCertificateCandidates && bytes.Contains(data[searchAt:], []byte(beginMarker)) {
		addPartialCoverageOnce(graph, content.NodeID, "certificate-observations", fmt.Sprintf("certificate candidate scanning capped at %d candidates", maxCertificateCandidates))
	}
}

func publicKeyForPrivateKey(key any) any {
	if provider, ok := key.(crypto.Signer); ok {
		return provider.Public()
	}
	return nil
}

func addStaticObservationEvidence(graph *behavior.Graph, content artifact.Content, method, kind, value, arch string, offset int64) string {
	return graph.AddEvidence(behavior.Evidence{
		NodeID:      content.NodeID,
		ScopeID:     content.ScopeID,
		Logical:     content.LogicalPath,
		Physical:    content.PhysicalPath,
		Offset:      offset,
		OffsetKnown: offset >= 0,
		Arch:        arch,
		Method:      method,
		Kind:        kind,
		Value:       value,
	})
}

func addStaticObservationFeature(graph *behavior.Graph, content artifact.Content, arch, key, value string, qualifiers map[string]string, evidenceID string) {
	if evidenceID == "" || value == "" {
		return
	}
	graph.AddFeature(behavior.Feature{
		NodeID:       content.NodeID,
		ScopeID:      content.ScopeID,
		Architecture: arch,
		Key:          key,
		Value:        value,
		Qualifiers:   qualifiers,
		EvidenceIDs:  []string{evidenceID},
		Support:      behavior.SupportDirect,
		Execution:    executionContextForContent(content),
	})
}
