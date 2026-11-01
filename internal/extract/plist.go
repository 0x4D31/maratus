package extract

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/plistx"
)

const maxATSExceptionDomains = 1024

var (
	atsGlobalBooleanKeys = []string{
		"NSAllowsArbitraryLoads",
		"NSAllowsArbitraryLoadsForMedia",
		"NSAllowsArbitraryLoadsInWebContent",
		"NSAllowsLocalNetworking",
	}
	atsDomainBooleanKeys = []string{
		"NSExceptionAllowsInsecureHTTPLoads",
		"NSExceptionRequiresForwardSecrecy",
		"NSIncludesSubdomains",
		"NSRequiresCertificateTransparency",
		"NSTemporaryExceptionAllowsInsecureHTTPLoads",
		"NSTemporaryExceptionRequiresForwardSecrecy",
		"NSThirdPartyExceptionAllowsInsecureHTTPLoads",
		"NSThirdPartyExceptionRequiresForwardSecrecy",
	}
	atsDomainStringKeys = []string{
		"NSExceptionMinimumTLSVersion",
		"NSTemporaryExceptionMinimumTLSVersion",
		"NSThirdPartyExceptionMinimumTLSVersion",
	}
)

// PlistExecutionStart is the app executable resolved from artifact structure.
// It is intentionally absent for a loose plist: a declaration alone does not
// prove what macOS would start for a URL or document handler.
type PlistExecutionStart struct {
	NodeID  string
	ScopeID string
}

func ExtractPlist(graph *behavior.Graph, content artifact.Content, appStart PlistExecutionStart) {
	data, ok := boundedStructuredDocument(graph, content, "plist", content.Data)
	if !ok {
		return
	}
	plist, err := plistx.Decode(data)
	if err != nil {
		graph.AddCoverage(behavior.Coverage{
			NodeID:       content.NodeID,
			AnalysisArea: "plist",
			Status:       "partial",
			Detail:       "plist decode failed: " + err.Error(),
		})
		return
	}
	if executable, ok := plist["CFBundleExecutable"].(string); ok && executable != "" {
		addPlistFeature(graph, content, "bundle.executable", executable)
	}
	if id := plistx.String(plist, "CFBundleIdentifier"); id != "" {
		addPlistFeature(graph, content, "bundle.identifier", id)
	}
	if minOS := plistx.String(plist, "LSMinimumSystemVersion"); minOS != "" {
		addPlistFeature(graph, content, "bundle.minimum_os", minOS)
	}
	extractAppTransportSecurityProperties(graph, content, plist)
	extractURLHandlers(graph, content, appStart, plist)
	extractDocumentHandlers(graph, content, appStart, plist)
	if value, declared := plist["Label"]; declared {
		label, valid := value.(string)
		if !valid || label == "" || strings.ContainsRune(label, 0) {
			addPartialCoverageOnce(graph, content.NodeID, "launchd-command", "launchd Label is not a nonempty literal string")
			return
		}
		command, err := launchdCommand(plist)
		if err != nil {
			addPartialCoverageOnce(graph, content.NodeID, "launchd-command", err.Error())
			return
		}
		if len(command) == 0 {
			return
		}
		if !launchdExecutionRootContext(content) || !executionRootAllowed(content) {
			if strings.Contains(content.LogicalPath, "!") {
				addPartialCoverageOnce(graph, content.NodeID, "launchd-install-context", "archived launchd declaration retained without an execution root because no exact supported installed location and eligible root context were established")
			}
			evidenceID := addPlistFeature(graph, content, "launchd.program", strings.Join(command, " "))
			if evidenceID != "" {
				// The plist directly declares this command even when the retained
				// model cannot prove that the plist is installed or loaded. Preserve
				// the command's semantic operations under the content's non-connected
				// execution context; do not manufacture an execution root.
				analyzeLaunchdCommand(graph, content, command, executionContextForContent(content), evidenceID)
			}
			return
		}
		evidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Method:  "plist",
			Kind:    "launchd-program",
			Value:   strings.Join(command, " "),
		})
		rootID := graph.AddExecutionRoot(behavior.ExecutionRoot{
			Kind:              "launchd-program",
			DeclarationNodeID: content.NodeID,
			StartNodeID:       content.NodeID,
			StartScopeID:      content.ScopeID,
			Name:              label,
			Arguments:         command,
			EvidenceIDs:       []string{evidenceID},
		})
		if rootID == "" {
			return
		}
		execution := connectedExecutionContext([]string{rootID}, nil)
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID:    content.NodeID,
			Kind:             behavior.OperationLaunchdJobDeclare,
			ResourceBindings: requiredResourceBindings(behavior.OperationLaunchdJobDeclare, serviceOperationResource(launchdResourceCategory(content.LogicalPath), label)),
			EvidenceIDs:      []string{evidenceID},
			Support:          behavior.SupportDirect,
			Execution:        execution,
		})
		analyzeLaunchdCommand(graph, content, command, execution, evidenceID)
	}
}

func extractAppTransportSecurityProperties(graph *behavior.Graph, content artifact.Content, plist plistx.Dict) {
	ats, ok := plist["NSAppTransportSecurity"].(plistx.Dict)
	if !ok {
		return
	}
	for _, key := range atsGlobalBooleanKeys {
		value, ok := ats[key].(bool)
		if ok && !addATSPolicyProperty(graph, content, key+"="+strconv.FormatBool(value)) {
			return
		}
	}

	exceptions, ok := ats["NSExceptionDomains"].(plistx.Dict)
	if !ok {
		return
	}
	domains := make([]string, 0, len(exceptions))
	for domain, value := range exceptions {
		if _, ok := value.(plistx.Dict); ok {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	if len(domains) > maxATSExceptionDomains {
		addPartialCoverageOnce(graph, content.NodeID, "app-transport-security", fmt.Sprintf("only the first %d sorted exception domains were considered", maxATSExceptionDomains))
		domains = domains[:maxATSExceptionDomains]
	}
	for _, domain := range domains {
		settings := exceptions[domain].(plistx.Dict)
		prefix := "NSExceptionDomains[" + strconv.Quote(domain) + "]."
		for _, key := range atsDomainBooleanKeys {
			value, ok := settings[key].(bool)
			if ok && !addATSPolicyProperty(graph, content, prefix+key+"="+strconv.FormatBool(value)) {
				return
			}
		}
		for _, key := range atsDomainStringKeys {
			value, ok := settings[key].(string)
			value = strings.TrimSpace(value)
			if ok && value != "" && !addATSPolicyProperty(graph, content, prefix+key+"="+value) {
				return
			}
		}
	}
}

func addATSPolicyProperty(graph *behavior.Graph, content artifact.Content, value string) bool {
	if graph.WorkLimitReached() {
		graph.MarkWorkOmitted()
		return false
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "plist",
		Kind:    "app-transport-security",
		Value:   value,
	})
	if evidenceID == "" {
		graph.MarkWorkOmitted()
		return false
	}
	return graph.AddArtifactProperty(behavior.ArtifactProperty{
		NodeID:      content.NodeID,
		Kind:        "app-transport-security",
		Value:       value,
		EvidenceIDs: []string{evidenceID},
		Support:     behavior.SupportDirect,
	})
}

func launchdCommand(plist plistx.Dict) ([]string, error) {
	var program string
	if value, present := plist["Program"]; present {
		var ok bool
		program, ok = value.(string)
		if !ok || program == "" || strings.ContainsRune(program, 0) || !strings.HasPrefix(program, "/") {
			return nil, fmt.Errorf("launchd Program must be a literal absolute executable path")
		}
	}
	if value, present := plist["ProgramArguments"]; present {
		items, ok := value.([]any)
		if !ok || len(items) == 0 {
			return nil, fmt.Errorf("launchd ProgramArguments must be a nonempty string array")
		}
		args := make([]string, len(items))
		for i, item := range items {
			args[i], ok = item.(string)
			if !ok || strings.ContainsRune(args[i], 0) {
				return nil, fmt.Errorf("launchd ProgramArguments contains a non-string or NUL argument")
			}
		}
		// Program selects the executable independently of argv[0]. The
		// semantic command view uses that path followed by argv[1:], never
		// prepends argv[0] as an extra argument or lets it select another image.
		if program != "" {
			args[0] = program
		} else if args[0] == "" {
			return nil, fmt.Errorf("launchd ProgramArguments does not select an executable")
		}
		return args, nil
	}
	if program != "" {
		return []string{program}, nil
	}
	return nil, fmt.Errorf("launchd declaration has no Program or ProgramArguments")
}

func launchdExecutionRootContext(content artifact.Content) bool {
	lower := strings.ToLower(filepath.ToSlash(content.LogicalPath))
	for _, marker := range []string{
		".app/contents/",
		".appex/contents/",
		".bundle/contents/",
		".framework/",
		".xpc/contents/",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	// A package member is an execution root only when the package adapter paired
	// it with a bounded PackageInfo install-location and derived a canonical
	// installed launchd path. An attacker-controlled archive member name is not
	// installation evidence.
	if strings.Contains(lower, "!") {
		return canonicalInstalledLaunchdPlist(content.PackageInstallPath)
	}
	return true
}

func canonicalInstalledLaunchdPlist(value string) bool {
	lower := strings.ToLower(filepath.ToSlash(value))
	if !strings.HasSuffix(lower, ".plist") {
		return false
	}
	for _, directory := range []string{
		"/library/launchagents/",
		"/library/launchdaemons/",
		"/system/library/launchagents/",
		"/system/library/launchdaemons/",
		"/var/root/library/launchagents/",
		"/private/var/root/library/launchagents/",
	} {
		if strings.HasPrefix(lower, directory) && !strings.Contains(strings.TrimPrefix(lower, directory), "/") {
			return true
		}
	}
	if strings.HasPrefix(lower, "/users/") {
		parts := strings.Split(strings.TrimPrefix(lower, "/users/"), "/")
		return len(parts) == 4 && parts[0] != "" && parts[1] == "library" && parts[2] == "launchagents" && strings.HasSuffix(parts[3], ".plist")
	}
	return false
}

func analyzeLaunchdCommand(graph *behavior.Graph, content artifact.Content, command []string, execution behavior.ExecutionContext, evidenceID string) {
	if script := launchdShellCommand(command); script != "" {
		scriptEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Method:  "plist",
			Kind:    "launchd-shell-command",
			Value:   script,
		})
		AnalyzeShellLine(graph, content, script, 0, execution, scriptEvidenceID)
		return
	}
	if language, code := launchdInlineInterpreterCode(command); code != "" {
		inlineEvidenceID := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Method:  "plist",
			Kind:    "launchd-inline-code",
			Value:   inlineCodeEvidenceValue(language, code),
		})
		inlineScopeID := graph.AddScope(behavior.Scope{
			NodeID:     content.NodeID,
			ParentID:   content.ScopeID,
			Kind:       "launchd-inline-code",
			Name:       language + " inline code",
			SourceRole: content.Role,
		})
		inlineContent := content
		inlineContent.ScopeID = inlineScopeID
		AnalyzeInlineCode(graph, inlineContent, language, code, execution, inlineEvidenceID)
		return
	}
	analyzeShellFields(graph, content, command, 0, execution, evidenceID, 0, nil)
}

func launchdShellCommand(command []string) string {
	if len(command) < 3 {
		return ""
	}
	command = UnwrapCommandWrappers(command)
	if len(command) < 3 {
		return ""
	}
	switch filepath.Base(command[0]) {
	case "sh", "bash", "zsh":
	default:
		return ""
	}
	return shellCommandString(command)
}

func launchdInlineInterpreterCode(command []string) (string, string) {
	command = UnwrapCommandWrappers(command)
	if len(command) < 2 {
		return "", ""
	}
	return interpreterInlineCode(filepath.Base(command[0]), command)
}

func inlineCodeEvidenceValue(language, code string) string {
	return strings.TrimSpace(language + " inline " + compactTextEvidenceValue(code))
}

func addPlistFeature(graph *behavior.Graph, content artifact.Content, key, value string) string {
	if value == "" {
		return ""
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID:  content.NodeID,
		Logical: content.LogicalPath,
		Method:  "plist",
		Kind:    key,
		Value:   value,
	})
	if evidenceID == "" {
		return ""
	}
	if graph.AddFeature(behavior.Feature{
		NodeID:      content.NodeID,
		Key:         key,
		Value:       value,
		EvidenceIDs: []string{evidenceID},
		Support:     behavior.SupportDirect,
	}) == "" {
		return ""
	}
	return evidenceID
}

func extractURLHandlers(graph *behavior.Graph, content artifact.Content, appStart PlistExecutionStart, plist plistx.Dict) {
	seen := map[string]bool{}
	for _, item := range plistx.Dicts(plist, "CFBundleURLTypes") {
		schemes := plistx.StringsValue(item["CFBundleURLSchemes"])
		sort.Strings(schemes)
		for _, scheme := range schemes {
			scheme = strings.TrimSpace(scheme)
			if scheme == "" || seen[scheme] {
				continue
			}
			seen[scheme] = true
			ev := graph.AddEvidence(behavior.Evidence{
				NodeID:  content.NodeID,
				Logical: content.LogicalPath,
				Method:  "plist",
				Kind:    "bundle.url_scheme",
				Value:   scheme,
			})
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Key: "bundle.url_scheme", Value: scheme, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
			addPlistHandlerExecutionRoot(graph, content, appStart, "url-handler", scheme, ev)
		}
	}
}

func extractDocumentHandlers(graph *behavior.Graph, content artifact.Content, appStart PlistExecutionStart, plist plistx.Dict) {
	seen := map[string]bool{}
	for _, item := range plistx.Dicts(plist, "CFBundleDocumentTypes") {
		name := strings.TrimSpace(plistx.StringValue(item["CFBundleTypeName"]))
		extensions := plistx.StringsValue(item["CFBundleTypeExtensions"])
		sort.Strings(extensions)
		role := strings.TrimSpace(plistx.StringValue(item["CFBundleTypeRole"]))
		if name == "" && len(extensions) == 0 {
			continue
		}
		entryName := name
		if entryName == "" {
			entryName = strings.Join(extensions, ",")
		}
		value := entryName
		if len(extensions) > 0 {
			value += " extensions=" + strings.Join(extensions, ",")
		}
		if role != "" {
			value += " role=" + role
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		ev := graph.AddEvidence(behavior.Evidence{
			NodeID:  content.NodeID,
			Logical: content.LogicalPath,
			Method:  "plist",
			Kind:    "bundle.document_type",
			Value:   value,
		})
		graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Key: "bundle.document_type", Value: entryName, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		for _, ext := range extensions {
			graph.AddFeature(behavior.Feature{NodeID: content.NodeID, Key: "bundle.document_extension", Value: ext, EvidenceIDs: []string{ev}, Support: behavior.SupportDirect})
		}
		addPlistHandlerExecutionRoot(graph, content, appStart, "document-handler", entryName, ev)
	}
}

func addPlistHandlerExecutionRoot(graph *behavior.Graph, content artifact.Content, appStart PlistExecutionStart, kind, name, evidenceID string) string {
	if !executionRootAllowed(content) || appStart.NodeID == "" || evidenceID == "" {
		return ""
	}
	return graph.AddExecutionRoot(behavior.ExecutionRoot{
		Kind:              kind,
		DeclarationNodeID: content.NodeID,
		StartNodeID:       appStart.NodeID,
		StartScopeID:      appStart.ScopeID,
		Name:              name,
		EvidenceIDs:       []string{evidenceID},
	})
}
