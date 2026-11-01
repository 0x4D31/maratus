package report

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const presentationNotableFeatureLimit = 8

type notableFeatureView struct {
	feature       behavior.Feature
	category      string
	architectures []string
	evidenceIDs   []string
}

func (p *presentation) notableStaticFeatures() {
	if p.options.Verbosity >= TextVeryVerbose {
		return
	}
	items := notableUnlinkedFeatures(p.report)
	if len(items) == 0 {
		return
	}
	visible := boundedNotableFeatures(items, presentationNotableFeatureLimit)
	shown := len(visible)
	count := countLabel(len(items), "unlinked feature")
	if shown < len(items) {
		count = fmt.Sprintf("%d shown · %s retained", shown, countLabel(len(items), "unlinked feature"))
	}
	p.section("NOTABLE FEATURES", count)
	p.println("  Retained static observations not linked to a modeled operation or capability match; presence alone does not establish access, use, or execution connectivity.")
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	annotateSources := len(nodeLabels) > 1
	for _, item := range visible {
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(notableFeatureTitle(item), textLineRuneLimit))
		p.detail("    ", "interpretation", notableFeatureInterpretation(item.feature))
		p.detail("    ", "feature", item.feature.Key)
		p.detail("    ", "support", string(item.feature.Support))
		if annotateSources && nodeLabels[item.feature.NodeID] != "" {
			p.detail("    ", "source", nodeLabels[item.feature.NodeID])
		}
		if item.feature.SourceFunction != "" {
			p.detail("    ", "source function", displayFunctionName(item.feature.SourceFunction))
		}
		if len(item.architectures) > 0 {
			p.detail("    ", "architecture", strings.Join(item.architectures, ", "))
		}
		if p.options.Verbosity >= TextVerbose {
			for j, evidenceID := range item.evidenceIDs {
				if j >= textEvidenceLimit {
					p.detail("    ", "evidence", fmt.Sprintf("... %d more", len(item.evidenceIDs)-j))
					break
				}
				if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
					p.detail("    ", "evidence", evidenceText(*evidence))
				}
			}
		}
	}
	if shown < len(items) {
		p.omitted(len(items)-shown, "unlinked Features")
	}
}

func notableUnlinkedFeatures(rep Report) []notableFeatureView {
	type groupKey struct {
		key            string
		value          string
		nodeID         string
		category       string
		sourceFunction string
		execution      string
	}
	groups := map[groupKey]int{}
	var out []notableFeatureView
	visibleNetworkIndicators := defaultVisibleNetworkIndicatorIndex(rep)
	for _, feature := range uniqueFeatures(rep.Features) {
		category, ok := notableFeatureCategory(feature)
		if !ok || visibleNetworkIndicators.contains(feature) || notableFeatureLinkedToBehavior(feature, category, rep) {
			continue
		}
		key := groupKey{
			key: feature.Key, value: feature.Value, nodeID: feature.NodeID, category: category,
			sourceFunction: feature.SourceFunction, execution: executionContextIdentityKey(feature.Execution),
		}
		architecture := strings.TrimSpace(feature.Architecture)
		if index, exists := groups[key]; exists {
			out[index].architectures = appendUniqueNotableValue(out[index].architectures, architecture)
			out[index].evidenceIDs = appendUniqueNotableValues(out[index].evidenceIDs, feature.EvidenceIDs...)
			continue
		}
		groups[key] = len(out)
		out = append(out, notableFeatureView{
			feature: feature, category: category,
			architectures: appendUniqueNotableValue(nil, architecture),
			evidenceIDs:   appendUniqueNotableValues(nil, feature.EvidenceIDs...),
		})
	}
	for i := range out {
		sort.Strings(out[i].architectures)
		sort.Strings(out[i].evidenceIDs)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := notableFeaturePriority(out[i].feature), notableFeaturePriority(out[j].feature)
		if left != right {
			return left < right
		}
		if out[i].category != out[j].category {
			return out[i].category < out[j].category
		}
		if out[i].feature.Value != out[j].feature.Value {
			return out[i].feature.Value < out[j].feature.Value
		}
		if out[i].feature.NodeID != out[j].feature.NodeID {
			return out[i].feature.NodeID < out[j].feature.NodeID
		}
		return out[i].feature.SourceFunction < out[j].feature.SourceFunction
	})
	return out
}

func notableFeatureCategory(feature behavior.Feature) (string, bool) {
	switch feature.Key {
	case "artifact.packaging_technology":
		return "packaging technology", strings.TrimSpace(feature.Value) != ""
	case "agent.skill.external_link":
		return "agent instruction link", strings.TrimSpace(feature.Value) != ""
	case "agent.skill.shell_code_block":
		return "agent shell code block", strings.TrimSpace(feature.Value) != ""
	case "package.dependency":
		return "VCS/URL dependency", remotePackageDependencySpecifier(feature.Qualifiers["specifier"])
	case "javascript.module_specifier":
		return "bundled CommonJS module", feature.Qualifiers["form"] == "bundled-commonjs-wrapper" && strings.TrimSpace(feature.Value) != ""
	case "network.url":
		if metadataNamespaceURL(feature.Value) {
			return "", false
		}
		if rawByteURLCandidate(feature) {
			return "URL candidate", strings.TrimSpace(feature.Value) != ""
		}
		return "URL", strings.TrimSpace(feature.Value) != ""
	case "network.ip":
		return "IP address", strings.TrimSpace(feature.Value) != ""
	case "network.domain":
		return "domain", strings.TrimSpace(feature.Value) != ""
	case "macho.sensitive_resource", "script.sensitive_resource":
		category := strings.TrimSpace(feature.Qualifiers["category"])
		if category == "" {
			category = "sensitive resource"
		}
		return category, strings.TrimSpace(feature.Value) != ""
	case "embedded.launchd.configuration":
		return "embedded launchd configuration", strings.TrimSpace(feature.Value) != ""
	case "embedded.launchd.template":
		return "embedded launchd template (incomplete data)", strings.TrimSpace(feature.Value) != ""
	case "embedded.launchd.label":
		return "embedded launchd label", strings.TrimSpace(feature.Value) != ""
	case "embedded.launchd.program":
		return "embedded launchd program (data only)", strings.TrimSpace(feature.Value) != ""
	case "embedded.launchd.trigger":
		return "embedded launchd trigger (data only)", strings.TrimSpace(feature.Value) != ""
	case "cryptographic.private_key":
		return "complete private key fingerprint", strings.TrimSpace(feature.Value) != ""
	case "cryptographic.certificate":
		return "complete X.509 certificate fingerprint", strings.TrimSpace(feature.Value) != ""
	case "derived.base64.content":
		return "base64-derived content fingerprint", strings.TrimSpace(feature.Value) != ""
	case "script.browser_credential_store":
		return "browser credential store", strings.TrimSpace(feature.Value) != ""
	case "macho.security_api_import":
		if feature.Qualifiers["category"] == "input-event-monitoring" {
			return "input-event-monitoring API import", strings.TrimSpace(feature.Value) != ""
		}
	case "macho.rpath":
		return "Mach-O runtime search path", strings.TrimSpace(feature.Value) != ""
	case "macho.dylib":
		return "Mach-O non-system dependency", notableMachODylib(feature.Value)
	case "objc.message_argument":
		return "configured executable path",
			feature.Qualifiers["selector"] == "setLaunchPath:" &&
				feature.Qualifiers["argument_index"] == "0" &&
				feature.Qualifiers["representation"] == "static-cfstring" &&
				strings.TrimSpace(feature.Value) != ""
	}
	return "", false
}

func notableMachODylib(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, prefix := range []string{"/System/", "/usr/lib/", "/Library/Apple/System/"} {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	return true
}

func metadataNamespaceURL(value string) bool {
	switch value {
	case "http://www.w3.org/1999/xhtml",
		"http://www.w3.org/1999/xlink",
		"http://www.w3.org/2000/svg",
		"http://www.w3.org/2001/XMLSchema",
		"http://www.w3.org/XML/1998/namespace":
		return true
	default:
		return false
	}
}

func notableFeaturePriority(feature behavior.Feature) int {
	switch feature.Key {
	case "artifact.packaging_technology", "network.url", "network.ip", "network.domain":
		return 0
	case "macho.security_api_import", "package.dependency", "javascript.module_specifier", "macho.rpath", "macho.dylib", "objc.message_argument":
		return 1
	case "macho.sensitive_resource", "script.sensitive_resource", "script.browser_credential_store":
		return 2
	default:
		return 3
	}
}

func notableFeatureTitle(item notableFeatureView) string {
	return item.category + ": " + notableFeatureDisplayValue(item.feature)
}

func notableFeatureInterpretation(feature behavior.Feature) string {
	if rawByteURLCandidate(feature) {
		return "heuristic URL candidate from undecoded bytes; exact string boundary and behavior not established"
	}
	switch feature.Key {
	case "agent.skill.external_link":
		return "agent instructions containing an external link do not establish retrieval, approval, tool dispatch, or OS execution"
	case "agent.skill.shell_code_block":
		return "agent instructions containing shell code blocks may be examples and do not establish retrieval, approval, tool dispatch, or OS execution"
	case "package.dependency":
		return "direct package-manifest declaration; dependency resolution, retrieval, installation, and execution are not established"
	case "javascript.module_specifier":
		return "exact module name from a supported bundled CommonJS wrapper; loader selection, alias use, and module behavior are not established"
	case "embedded.launchd.template":
		return "incomplete launchd-shaped data template; installation, loading, persistence, and dynamic fields are not established"
	case "embedded.launchd.configuration", "embedded.launchd.label", "embedded.launchd.program", "embedded.launchd.trigger":
		return "embedded launchd data only; installation, loading, and persistence are not established"
	case "cryptographic.certificate":
		return "complete PEM X.509 certificate fingerprint; trust, current validity, signing relationships, and runtime use are not established"
	case "macho.rpath":
		return "exact LC_RPATH loader search path; dependency resolution and loading at runtime are not established"
	case "macho.dylib":
		linkage := strings.TrimSpace(feature.Qualifiers["linkage"])
		if linkage == "" {
			linkage = "load"
		}
		return "exact Mach-O " + linkage + " dependency declaration; file presence, resolution, and loading at runtime are not established"
	case "objc.message_argument":
		return "exact static CFString passed to setLaunchPath:; receiver identity and a later launch of that same object are not established"
	}
	return "unlinked observation; behavior not established"
}

func notableFeatureDisplayValue(feature behavior.Feature) string {
	if feature.Key != "package.dependency" {
		return feature.Value
	}
	name := strings.TrimSpace(feature.Value)
	specifier := sanitizedRemotePackageDependencySpecifier(feature.Qualifiers["specifier"])
	if name == "" || specifier == "" {
		return name
	}
	return name + " -> " + specifier
}

func remotePackageDependencySpecifier(specifier string) bool {
	specifier = strings.TrimSpace(specifier)
	lower := strings.ToLower(specifier)
	for _, prefix := range []string{"github:", "gitlab:", "bitbucket:"} {
		if strings.HasPrefix(lower, prefix) {
			reference := specifier[len(prefix):]
			return validHostedRepositoryReference(reference)
		}
	}
	if strings.HasPrefix(lower, "git@") {
		at, colon := strings.IndexByte(specifier, '@'), strings.IndexByte(specifier, ':')
		return at > 0 && colon > at+1 && validHostedRepositoryReference(specifier[colon+1:])
	}
	rawURL := specifier
	if strings.HasPrefix(lower, "git+") {
		rawURL = specifier[len("git+"):]
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "git", "http", "https", "ssh":
		return true
	default:
		return false
	}
}

func validHostedRepositoryReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.ContainsAny(reference, " \t\r\n") {
		return false
	}
	path, _, _ := strings.Cut(reference, "#")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}

func sanitizedRemotePackageDependencySpecifier(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	prefix := ""
	rawURL := specifier
	if strings.HasPrefix(strings.ToLower(rawURL), "git+") {
		prefix = rawURL[:len("git+")]
		rawURL = rawURL[len("git+"):]
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User == nil {
		return specifier
	}
	parsed.User = nil
	return prefix + parsed.String()
}

func rawByteURLCandidate(feature behavior.Feature) bool {
	return feature.Key == "network.url" && strings.EqualFold(strings.TrimSpace(feature.Qualifiers["origin"]), "raw-bytes")
}

func staticFeatureDisplayKey(feature behavior.Feature) string {
	if rawByteURLCandidate(feature) {
		return feature.Key + " candidate"
	}
	return feature.Key
}

func notableFeatureLinkedToBehavior(feature behavior.Feature, category string, rep Report) bool {
	if rawByteURLCandidate(feature) {
		return false
	}
	for _, operation := range rep.Operations {
		if operation.SubjectNodeID != feature.NodeID || !notableFeatureOperationCompatible(feature, category, operation) {
			continue
		}
		resourceMatch := false
		for _, binding := range operation.ResourceBindings {
			if notableFeatureMatchesResource(feature, category, binding.Resource) {
				resourceMatch = true
				break
			}
		}
		if resourceMatch || stringSlicesIntersect(feature.EvidenceIDs, operation.EvidenceIDs) {
			return true
		}
	}
	for _, capabilityMatch := range rep.Capabilities {
		if capabilityMatch.SubjectNodeID != feature.NodeID {
			continue
		}
		for _, resource := range capabilityMatch.AffectedResources {
			if notableFeatureMatchesResource(feature, category, resource) {
				return true
			}
		}
	}
	return false
}

func notableFeatureOperationCompatible(feature behavior.Feature, category string, operation behavior.ModeledOperation) bool {
	switch {
	case notableNetworkFeature(feature):
		return strings.HasPrefix(string(operation.Kind), "network.")
	case feature.Key == "macho.security_api_import" && category == "input-event-monitoring API import":
		return strings.HasPrefix(string(operation.Kind), "input.")
	case sensitiveResourceFeature(feature):
		return operation.Kind == "credential.store.read" || operation.Kind == "file.read" || operation.Kind == "archive.create" || operation.Kind == "network.upload"
	default:
		return false
	}
}

func notableFeatureMatchesResource(feature behavior.Feature, category string, resource behavior.Resource) bool {
	value := strings.TrimSpace(feature.Value)
	if value == "" || value != strings.TrimSpace(resource.Value) {
		return false
	}
	if notableNetworkFeature(feature) {
		return resource.Kind == behavior.ResourceURL || resource.Kind == behavior.ResourceNetworkEndpoint
	}
	if sensitiveResourceFeature(feature) {
		featureCategory := strings.TrimSpace(feature.Qualifiers["category"])
		return resourceMatchesFeatureCategory(resource, featureCategory)
	}
	return false
}

func resourceMatchesFeatureCategory(resource behavior.Resource, category string) bool {
	want := map[string]behavior.ResourceClassification{
		"keychain":               behavior.ResourceClassKeychain,
		"browser.cookies":        behavior.ResourceClassBrowserCookieStore,
		"browser.password-store": behavior.ResourceClassBrowserPasswordStore,
		"crypto-wallet":          behavior.ResourceClassCryptoWalletStore,
		"ssh-private-key":        behavior.ResourceClassSSHPrivateKey,
		"cloud-credentials":      behavior.ResourceClassCloudCredentialStore,
		"developer-token":        behavior.ResourceClassDeveloperTokenStore,
	}[category]
	return want != "" && resource.HasClassification(want)
}

func notableNetworkFeature(feature behavior.Feature) bool {
	return feature.Key == "network.url" || feature.Key == "network.ip" || feature.Key == "network.domain"
}

func sensitiveResourceFeature(feature behavior.Feature) bool {
	return feature.Key == "macho.sensitive_resource" || feature.Key == "script.sensitive_resource" || feature.Key == "script.browser_credential_store"
}

func boundedNotableFeatures(items []notableFeatureView, limit int) []notableFeatureView {
	if limit <= 0 || len(items) == 0 {
		return nil
	}
	if len(items) <= limit {
		return items
	}
	buckets := make([][]notableFeatureView, 3)
	for _, item := range items {
		bucket := 2
		if notableNetworkFeature(item.feature) {
			bucket = 0
		} else if item.feature.Key == "macho.security_api_import" {
			bucket = 1
		}
		buckets[bucket] = append(buckets[bucket], item)
	}
	positions := make([]int, len(buckets))
	out := make([]notableFeatureView, 0, limit)
	for len(out) < limit {
		added := false
		for index := range buckets {
			if positions[index] >= len(buckets[index]) {
				continue
			}
			out = append(out, buckets[index][positions[index]])
			positions[index]++
			added = true
			if len(out) == limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

type visibleNetworkIndicatorIndex struct {
	byEvidence map[string]bool
	byNode     map[string]bool
}

func defaultVisibleNetworkIndicatorIndex(rep Report) visibleNetworkIndicatorIndex {
	index := visibleNetworkIndicatorIndex{byEvidence: map[string]bool{}, byNode: map[string]bool{}}
	evidence := evidenceMap(rep.Evidence)
	for _, item := range visibleNetwork(rep, false) {
		if len(normalizedNetworkOperationIDs(item)) != 0 {
			continue
		}
		for _, destination := range item.Destinations {
			destination = strings.TrimSpace(destination)
			if destination == "" {
				continue
			}
			for _, evidenceID := range item.EvidenceIDs {
				index.byEvidence[semanticIdentityKey(destination, evidenceID)] = true
				if itemEvidence, ok := evidence[evidenceID]; ok && itemEvidence.NodeID != "" {
					index.byNode[semanticIdentityKey(destination, itemEvidence.NodeID)] = true
				}
			}
		}
	}
	return index
}

func (index visibleNetworkIndicatorIndex) contains(feature behavior.Feature) bool {
	if !notableNetworkFeature(feature) {
		return false
	}
	value := strings.TrimSpace(feature.Value)
	if value == "" {
		return false
	}
	if feature.NodeID != "" && index.byNode[semanticIdentityKey(value, feature.NodeID)] {
		return true
	}
	for _, evidenceID := range feature.EvidenceIDs {
		if index.byEvidence[semanticIdentityKey(value, evidenceID)] {
			return true
		}
	}
	return false
}

func stringSlicesIntersect(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	seen := make(map[string]bool, len(left))
	for _, value := range left {
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range right {
		if seen[value] {
			return true
		}
	}
	return false
}

func appendUniqueNotableValue(values []string, addition string) []string {
	if addition == "" {
		return values
	}
	for _, value := range values {
		if value == addition {
			return values
		}
	}
	return append(values, addition)
}

func appendUniqueNotableValues(values []string, additions ...string) []string {
	for _, addition := range additions {
		values = appendUniqueNotableValue(values, addition)
	}
	return values
}
