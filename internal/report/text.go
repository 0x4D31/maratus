package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/terminal"
)

const (
	textSectionLimit          = 40
	textArtifactPropertyLimit = 20
	textEvidenceLimit         = 4
	textDestinationLimit      = 8
	textSourceLimit           = 8
	textSecurityDetailLimit   = 8
	textQualifierLimit        = 12
	textDetailLabelRuneLimit  = 32
	textFieldRuneLimit        = 120
	textLineRuneLimit         = 240
	maxNetworkOperationIDs    = 64
)

func artifactPropertyDisplayValue(item behavior.ArtifactProperty) string {
	if item.Kind != "code-signature-flags" {
		return item.Value
	}
	// These are the CodeDirectory-compatible CS_* bits published by Apple in
	// XNU's osfmk/kern/cs_blobs.h. This display annotation decodes declared
	// structure only; it does not validate the signature or runtime policy.
	flags, err := strconv.ParseUint(strings.TrimSpace(item.Value), 0, 32)
	if err != nil {
		return item.Value
	}
	definitions := []struct {
		bit  uint64
		name string
	}{
		{0x00000002, "ad-hoc"},
		{0x00000100, "hard"},
		{0x00000200, "kill-on-invalid-code"},
		{0x00000400, "check-expiration"},
		{0x00000800, "restricted"},
		{0x00001000, "enforcement"},
		{0x00002000, "require-library-validation"},
		{0x00010000, "hardened-runtime"},
		{0x00020000, "linker-signed"},
	}
	known := uint64(0)
	names := make([]string, 0, len(definitions)+1)
	for _, definition := range definitions {
		known |= definition.bit
		if flags&definition.bit != 0 {
			names = append(names, definition.name)
		}
	}
	if unknown := flags &^ known; unknown != 0 {
		names = append(names, fmt.Sprintf("unknown-bits=%#x", unknown))
	}
	if len(names) == 0 {
		names = append(names, "none")
	}
	return fmt.Sprintf("%s (CodeDirectory declares: %s)", item.Value, strings.Join(names, ", "))
}

func uniqueExecutionRoots(roots []behavior.ExecutionRoot) []behavior.ExecutionRoot {
	seen := map[string]bool{}
	var out []behavior.ExecutionRoot
	for _, root := range roots {
		// Fat slices of one binary can describe the same logical root, but
		// identically named roots in different bundled artifacts must stay
		// distinct in the human inventory.
		key := semanticIdentityKey(root.DeclarationNodeID, root.StartNodeID, root.StartScopeID, root.Kind, root.Name, root.Interpreter, semanticIdentityKey(root.Arguments...))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, root)
	}
	return out
}

func executionRootTextLines(roots []behavior.ExecutionRoot, nodeLabels map[string]string) []string {
	type entryLine struct {
		base    string
		context string
	}
	var entryLines []entryLine
	var documentTypes []string
	documentTypeSeen := map[string]bool{}
	for _, root := range roots {
		name := compact(root.Name)
		if name == "" {
			name = compactJoin(append([]string{root.Interpreter}, root.Arguments...), " ")
		}
		if root.Kind == "document-handler" {
			if name != "" && !documentTypeSeen[name] {
				documentTypeSeen[name] = true
				documentTypes = append(documentTypes, name)
			}
			continue
		}
		entryLines = append(entryLines, entryLine{
			base:    compact(fmt.Sprintf("%s -> %s", compact(root.Kind), name)),
			context: executionRootContext(root, name, nodeLabels),
		})
	}
	var lines []string
	for _, entry := range entryLines {
		line := entry.base
		if entry.context != "" {
			line += " (" + compact(entry.context) + ")"
		}
		lines = append(lines, line)
	}
	if len(documentTypes) == 1 {
		lines = append(lines, "document-handler -> "+documentTypes[0])
	} else if len(documentTypes) > 1 {
		lines = append(lines, fmt.Sprintf("document-handler -> %d registered document types", len(documentTypes)))
	}
	return lines
}

func executionRootContext(root behavior.ExecutionRoot, name string, nodeLabels map[string]string) string {
	var values []string
	if context := compactJoin(append([]string{root.Interpreter}, root.Arguments...), " "); context != "" && context != name {
		values = append(values, context)
	}
	declaration := nodeLabels[root.DeclarationNodeID]
	start := nodeLabels[root.StartNodeID]
	if declaration != "" && start != "" && declaration != start {
		values = append(values, "declared by "+declaration, "starts "+start)
	} else if start != "" {
		values = append(values, start)
	} else if declaration != "" {
		values = append(values, declaration)
	}
	if root.StartScopeID != "" {
		values = append(values, "scope "+root.StartScopeID)
	}
	return compactJoin(values, " · ")
}

type capabilityMatchTextGroup struct {
	capabilityMatch behavior.CapabilityMatch
	evidenceIDs     []string
	count           int
}

type capabilityMatchTextSeen struct {
	evidence      map[string]bool
	architectures map[string]bool
}

func groupCapabilityMatches(capabilityMatches []behavior.CapabilityMatch) []capabilityMatchTextGroup {
	byKey := map[string]int{}
	var groups []capabilityMatchTextGroup
	var seenByGroup []capabilityMatchTextSeen
	for _, capabilityMatch := range capabilityMatches {
		key := semanticIdentityKey(
			capabilityMatch.RuleID,
			capabilityMatch.Title,
			string(capabilityMatch.Support),
			executionContextIdentityKey(capabilityMatch.Execution),
			capabilityMatch.SubjectNodeID,
			resourcesKey(capabilityMatch.AffectedResources),
		)
		if idx, ok := byKey[key]; ok {
			groups[idx].count++
			seen := seenByGroup[idx]
			groups[idx].evidenceIDs = appendStringsWithSeen(groups[idx].evidenceIDs, seen.evidence, capabilityMatch.EvidenceIDs)
			groups[idx].capabilityMatch.ArchitectureScopes = appendStringsWithSeen(groups[idx].capabilityMatch.ArchitectureScopes, seen.architectures, capabilityMatch.ArchitectureScopes)
			continue
		}
		byKey[key] = len(groups)
		seen := capabilityMatchTextSeen{
			evidence:      map[string]bool{},
			architectures: map[string]bool{},
		}
		capabilityMatch.ArchitectureScopes = appendStringsWithSeen(nil, seen.architectures, capabilityMatch.ArchitectureScopes)
		groups = append(groups, capabilityMatchTextGroup{
			capabilityMatch: capabilityMatch,
			evidenceIDs:     appendStringsWithSeen(nil, seen.evidence, capabilityMatch.EvidenceIDs),
			count:           1,
		})
		seenByGroup = append(seenByGroup, seen)
	}
	return groups
}

func capabilityTitle(group capabilityMatchTextGroup) string {
	title := group.capabilityMatch.Title
	if resource := singleConcreteResource(group.capabilityMatch.AffectedResources); resource != "" {
		title += ": " + compact(resource)
	}
	if group.count > 1 {
		title = fmt.Sprintf("%s (%d matches)", title, group.count)
	}
	return title
}

func singleConcreteResource(resources []behavior.Resource) string {
	if len(resources) != 1 {
		return ""
	}
	return resources[0].Value
}

func resourcesKey(resources []behavior.Resource) string {
	parts := make([]string, 0, len(resources))
	for _, resource := range resources {
		parts = append(parts, string(resource.Key()))
	}
	sort.Strings(parts)
	return semanticIdentityKey(parts...)
}

func uniqueArtifactProperties(items []behavior.ArtifactProperty, includeFeatures bool) []behavior.ArtifactProperty {
	seen := map[string]bool{}
	strong := map[string]bool{}
	for _, item := range items {
		if item.Support != behavior.SupportHeuristic {
			strong[artifactPropertiesKey(item, false)] = true
		}
	}
	var out []behavior.ArtifactProperty
	for _, item := range items {
		if item.Support == behavior.SupportHeuristic && !includeFeatures {
			continue
		}
		if item.Support == behavior.SupportHeuristic && strong[artifactPropertiesKey(item, false)] {
			continue
		}
		key := artifactPropertiesKey(item, true)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func artifactPropertiesKey(item behavior.ArtifactProperty, includeSupport bool) string {
	fields := []string{item.NodeID, item.Kind, item.Value}
	if includeSupport {
		fields = append(fields, string(item.Support))
	}
	return semanticIdentityKey(fields...)
}

type sourceLabelCandidate struct {
	id   string
	path string
}

const (
	maxSourceLabelComponents               = 256
	maxSourceLabelComponentBytes           = 4096
	maxSourceLabelDisambiguationComponents = 65_536
)

func artifactPropertiesSourceLabels(report Report) map[string]string {
	groups := map[string][]sourceLabelCandidate{}
	for _, node := range report.ArtifactNodes {
		if node.ID == "" || node.LogicalPath == "" {
			continue
		}
		label := boundedSourceLabel(filepath.Base(node.LogicalPath))
		if label == "." || label == string(filepath.Separator) {
			label = boundedSourceLabel(node.LogicalPath)
		}
		groups[label] = append(groups[label], sourceLabelCandidate{id: node.ID, path: node.LogicalPath})
	}
	out := map[string]string{}
	labels := make([]string, 0, len(groups))
	for label := range groups {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	remainingComponents := maxSourceLabelDisambiguationComponents
	for _, label := range labels {
		candidates := groups[label]
		if len(candidates) == 1 {
			out[candidates[0].id] = label
			continue
		}
		if remainingComponents > 0 && labelsForDuplicatePaths(out, candidates, &remainingComponents) {
			continue
		}
		// A full logical path remains useful and bounded even when adversarial
		// duplicate basenames exhaust suffix-disambiguation work.
		remainingComponents = 0
		for _, item := range candidates {
			out[item.id] = boundedSourceLabel(item.path)
		}
	}
	return out
}

type reversePathNode struct {
	count    int
	children map[string]*reversePathNode
}

func labelsForDuplicatePaths(out map[string]string, candidates []sourceLabelCandidate, remainingComponents *int) bool {
	components := make([][]string, 0, len(candidates))
	totalComponents := 0
	for _, item := range candidates {
		parts := pathComponents(item.path)
		if len(parts) > *remainingComponents-totalComponents {
			return false
		}
		totalComponents += len(parts)
		components = append(components, parts)
	}
	*remainingComponents -= totalComponents

	root := &reversePathNode{}
	for _, parts := range components {
		node := root
		for i := len(parts) - 1; i >= 0; i-- {
			if node.children == nil {
				node.children = map[string]*reversePathNode{}
			}
			child := node.children[parts[i]]
			if child == nil {
				child = &reversePathNode{}
				node.children[parts[i]] = child
			}
			child.count++
			node = child
		}
	}
	for candidateIndex, item := range candidates {
		parts := components[candidateIndex]
		node := root
		label := boundedSourceLabel(item.path)
		for depth, i := 1, len(parts)-1; i >= 0; depth, i = depth+1, i-1 {
			node = node.children[parts[i]]
			if depth >= 2 && node.count == 1 {
				label = boundedSourceLabel(strings.Join(parts[i:], "/"))
				break
			}
		}
		out[item.id] = label
	}
	return true
}

func networkSourceLabels(item networkPresentationRecord, nodeLabels map[string]string, operations map[string]behavior.ModeledOperation, evidence map[string]behavior.Evidence) []string {
	var out []string
	seen := map[string]bool{}
	add := func(label string) {
		if label == "" || seen[label] {
			return
		}
		seen[label] = true
		out = append(out, label)
	}
	for _, id := range item.EvidenceIDs {
		ev, ok := evidence[id]
		if !ok {
			continue
		}
		label := nodeLabels[ev.NodeID]
		if label == "" && ev.Logical != "" {
			label = filepath.Base(ev.Logical)
		}
		add(label)
	}
	for _, operationID := range normalizedNetworkOperationIDs(item) {
		operation, ok := operations[operationID]
		if !ok {
			continue
		}
		add(nodeLabels[operation.SubjectNodeID])
	}
	return sortedStrings(out)
}

func pathComponents(value string) []string {
	value = filepath.ToSlash(value)
	parts := make([]string, 0, min(16, maxSourceLabelComponents))
	ringStart := 0
	for start := 0; start < len(value); {
		for start < len(value) && value[start] == '/' {
			start++
		}
		if start >= len(value) {
			break
		}
		end := start
		for end < len(value) && value[end] != '/' {
			end++
		}
		part := value[start:end]
		if len(part) > maxSourceLabelComponentBytes {
			part = part[len(part)-maxSourceLabelComponentBytes:]
		}
		if len(parts) < maxSourceLabelComponents {
			parts = append(parts, part)
		} else {
			parts[ringStart] = part
			ringStart = (ringStart + 1) % maxSourceLabelComponents
		}
		start = end + 1
	}
	if len(parts) == 0 {
		return []string{"/"}
	}
	if ringStart == 0 {
		return parts
	}
	ordered := make([]string, 0, len(parts))
	ordered = append(ordered, parts[ringStart:]...)
	ordered = append(ordered, parts[:ringStart]...)
	return ordered
}

func boundedSourceLabel(value string) string {
	if len(value) <= maxSourceLabelComponentBytes {
		return value
	}
	return "..." + value[len(value)-(maxSourceLabelComponentBytes-3):]
}

func uniqueNetworkWithContext(items []networkPresentationRecord, contextKey func(networkPresentationRecord) string) []networkPresentationRecord {
	type stringSets struct {
		operations   map[string]bool
		destinations map[string]bool
		security     map[string]bool
		unresolved   map[string]bool
		evidence     map[string]bool
	}
	byKey := map[string]int{}
	var out []networkPresentationRecord
	var sets []stringSets
	for _, item := range items {
		fields := []string{
			item.SubjectNodeID,
			string(item.ImplementationKind),
			item.ObservableKey,
			item.Caller,
			item.HTTPStack,
			item.TLSOwner,
			item.TLSLinkage,
			item.Family,
			item.Direction,
			semanticIdentityKey(sortedStrings(item.Security)...),
		}
		if item.ObservableKey != "" {
			fields = append(fields, semanticIdentityKey(sortedStrings(item.Destinations)...))
		}
		if contextKey != nil {
			fields = append(fields, contextKey(item))
		}
		key := semanticIdentityKey(fields...)
		if idx, ok := byKey[key]; ok {
			out[idx].OperationIDs = appendNetworkOperationIDs(out[idx].OperationIDs, sets[idx].operations, normalizedNetworkOperationIDs(item))
			out[idx].Destinations = appendStringsWithSeen(out[idx].Destinations, sets[idx].destinations, item.Destinations)
			out[idx].Security = appendStringsWithSeen(out[idx].Security, sets[idx].security, item.Security)
			out[idx].Unresolved = appendStringsWithSeen(out[idx].Unresolved, sets[idx].unresolved, item.Unresolved)
			out[idx].EvidenceIDs = appendStringsWithSeen(out[idx].EvidenceIDs, sets[idx].evidence, item.EvidenceIDs)
			continue
		}
		byKey[key] = len(out)
		seen := stringSets{operations: map[string]bool{}, destinations: map[string]bool{}, security: map[string]bool{}, unresolved: map[string]bool{}, evidence: map[string]bool{}}
		item.OperationIDs = appendNetworkOperationIDs(nil, seen.operations, normalizedNetworkOperationIDs(item))
		item.Destinations = appendStringsWithSeen(nil, seen.destinations, item.Destinations)
		item.Security = appendStringsWithSeen(nil, seen.security, item.Security)
		item.Unresolved = appendStringsWithSeen(nil, seen.unresolved, item.Unresolved)
		item.EvidenceIDs = appendStringsWithSeen(nil, seen.evidence, item.EvidenceIDs)
		out = append(out, item)
		sets = append(sets, seen)
	}
	for i := range out {
		sort.Strings(out[i].OperationIDs)
		out[i].Destinations = sortedStrings(out[i].Destinations)
		out[i].Security = sortedStrings(out[i].Security)
		out[i].Unresolved = normalizedNetworkUnresolved(out[i].Destinations, out[i].Unresolved)
		sort.Strings(out[i].EvidenceIDs)
	}
	return out
}

type networkPresentationContext struct {
	subject       string
	operationKind string
	direction     string
}

func uniqueNetworkForPresentation(items []networkPresentationRecord, operations map[string]behavior.ModeledOperation) []networkPresentationRecord {
	items = splitNetworkByPresentationContext(items, operations)
	return uniqueNetworkWithContext(items, func(item networkPresentationRecord) string {
		contexts := networkPresentationContexts(item, operations)
		parts := make([]string, 0, len(contexts)*3)
		for _, context := range contexts {
			parts = append(parts, context.subject, context.operationKind, context.direction)
		}
		return semanticIdentityKey(parts...)
	})
}

func splitNetworkByPresentationContext(items []networkPresentationRecord, operations map[string]behavior.ModeledOperation) []networkPresentationRecord {
	var out []networkPresentationRecord
	for _, item := range items {
		groups := map[networkPresentationContext][]string{}
		for _, operationID := range normalizedNetworkOperationIDs(item) {
			operation, ok := operations[operationID]
			context := networkPresentationContext{subject: "missing-operation:" + operationID, operationKind: "unknown", direction: item.Direction}
			if ok {
				context.subject = operation.SubjectNodeID
				context.operationKind = string(operation.Kind)
			}
			groups[context] = append(groups[context], operationID)
		}
		if len(groups) <= 1 {
			out = append(out, item)
			continue
		}
		contexts := make([]networkPresentationContext, 0, len(groups))
		for context := range groups {
			contexts = append(contexts, context)
		}
		sort.Slice(contexts, func(i, j int) bool {
			if contexts[i].subject != contexts[j].subject {
				return contexts[i].subject < contexts[j].subject
			}
			if contexts[i].operationKind != contexts[j].operationKind {
				return contexts[i].operationKind < contexts[j].operationKind
			}
			return contexts[i].direction < contexts[j].direction
		})
		for _, context := range contexts {
			clone := item
			clone.OperationIDs = sortedStrings(groups[context])
			clone.Direction = context.direction
			clone.Destinations = networkDestinationsForOperations(clone.OperationIDs, operations)
			clone.EvidenceIDs = networkEvidenceForOperations(item.EvidenceIDs, clone.OperationIDs, operations)
			out = append(out, clone)
		}
	}
	return out
}

func networkPresentationContexts(item networkPresentationRecord, operations map[string]behavior.ModeledOperation) []networkPresentationContext {
	seen := map[networkPresentationContext]bool{}
	var out []networkPresentationContext
	for _, operationID := range normalizedNetworkOperationIDs(item) {
		operation, ok := operations[operationID]
		context := networkPresentationContext{subject: "missing-operation:" + operationID, operationKind: "unknown", direction: item.Direction}
		if ok {
			context.subject = operation.SubjectNodeID
			context.operationKind = string(operation.Kind)
		}
		if !seen[context] {
			seen[context] = true
			out = append(out, context)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].subject != out[j].subject {
			return out[i].subject < out[j].subject
		}
		if out[i].operationKind != out[j].operationKind {
			return out[i].operationKind < out[j].operationKind
		}
		return out[i].direction < out[j].direction
	})
	return out
}

func networkDestinationsForOperations(operationIDs []string, operations map[string]behavior.ModeledOperation) []string {
	var out []string
	for _, operationID := range operationIDs {
		operation, ok := operations[operationID]
		if !ok {
			continue
		}
		for _, binding := range operation.ResourceBindings {
			if binding.Role != behavior.ResourceRoleRemoteSource && binding.Role != behavior.ResourceRoleRemoteDestination {
				continue
			}
			if value := strings.TrimSpace(binding.Resource.Value); value != "" {
				out = append(out, value)
			}
		}
	}
	return sortedStrings(out)
}

func networkEvidenceForOperations(detailEvidence, operationIDs []string, operations map[string]behavior.ModeledOperation) []string {
	wanted := map[string]bool{}
	for _, operationID := range operationIDs {
		for _, evidenceID := range operations[operationID].EvidenceIDs {
			wanted[evidenceID] = true
		}
	}
	var out []string
	for _, evidenceID := range detailEvidence {
		if wanted[evidenceID] {
			out = append(out, evidenceID)
		}
	}
	if len(out) == 0 {
		for _, operationID := range operationIDs {
			out = append(out, operations[operationID].EvidenceIDs...)
		}
	}
	return sortedStrings(out)
}

func normalizedNetworkOperationIDs(item networkPresentationRecord) []string {
	ids := sortedStrings(item.OperationIDs)
	if len(ids) > maxNetworkOperationIDs {
		ids = ids[:maxNetworkOperationIDs]
	}
	return ids
}

func appendNetworkOperationIDs(out []string, seen map[string]bool, values []string) []string {
	for _, value := range values {
		if len(out) >= maxNetworkOperationIDs {
			break
		}
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func normalizedNetworkUnresolved(destinations, unresolved []string) []string {
	if len(destinations) == 0 {
		return sortedStrings(unresolved)
	}
	var out []string
	for _, item := range unresolved {
		if item == "destination" {
			continue
		}
		out = append(out, item)
	}
	return sortedStrings(out)
}

func visibleNetwork(report Report, includeFeatures bool) []networkPresentationRecord {
	operations := operationsByID(report.Operations)
	records := networkPresentationRecords(report)
	if includeFeatures {
		return uniqueNetworkForPresentation(records, operations)
	}
	var items []networkPresentationRecord
	for _, item := range records {
		if rustSourceNetworkObservation(item) {
			items = append(items, item)
			continue
		}
		operationIDs := normalizedNetworkOperationIDs(item)
		if len(operationIDs) == 0 {
			if metadataNamespaceNetworkObservation(item) {
				continue
			}
			if weakNetworkObservation(item) {
				continue
			}
			items = append(items, item)
			continue
		}
		for _, operationID := range operationIDs {
			operation, ok := operations[operationID]
			if !ok || executionConnectivity(operation.Execution) != behavior.ConnectivityUnknown || operation.SourceFunction != "" {
				items = append(items, item)
				break
			}
		}
	}
	return uniqueNetworkForPresentation(items, operations)
}

func metadataNamespaceNetworkObservation(
	item networkPresentationRecord,
) bool {
	if item.ObservableKey != "network.url" ||
		len(item.Destinations) == 0 {
		return false
	}
	for _, destination := range item.Destinations {
		if !metadataNamespaceURL(destination) {
			return false
		}
	}
	return true
}

func rustSourceNetworkObservation(item networkPresentationRecord) bool {
	return item.Caller == "Rust source" && len(item.Destinations) > 0
}

func weakNetworkObservation(item networkPresentationRecord) bool {
	if item.ObservableKey != "" && item.Support == behavior.SupportHeuristic {
		return true
	}
	if item.ImplementationKind == behavior.NetworkImplementationAPIImport {
		return true
	}
	for _, condition := range item.Unresolved {
		if condition == "whether imported API is reached by executable code" {
			return true
		}
	}
	return false
}

func networkContextLine(item networkPresentationRecord, operations map[string]behavior.ModeledOperation) string {
	operationIDs := normalizedNetworkOperationIDs(item)
	hasDownload, hasUpload := false, false
	for _, operationID := range operationIDs {
		switch operations[operationID].Kind {
		case "network.download":
			hasDownload = true
		case "network.upload":
			hasUpload = true
		}
	}
	download := item.Direction == "download" || (item.Direction == "" && hasDownload && !hasUpload)
	upload := item.Direction == "upload" || (item.Direction == "" && hasUpload && !hasDownload)
	if len(operationIDs) > 0 && len(item.Destinations) == 0 {
		if download {
			return "download API call; destination unresolved"
		}
		if upload {
			return "upload API call; destination unresolved"
		}
		if item.Caller == "Mach-O called API" {
			return "function-scoped API call; destination unresolved"
		}
		return "destination unresolved"
	}
	if len(operationIDs) > 0 {
		if download {
			return "download API call"
		}
		if upload {
			return "upload API call"
		}
		return ""
	}
	switch item.Caller {
	case "Mach-O called API":
		return "function-scoped API call; destination unresolved"
	case "Mach-O dynamic linkage":
		return "linked library; execution connectivity unknown"
	case "Mach-O imported API":
		return "imported API; execution connectivity unknown"
	}
	for _, condition := range item.Unresolved {
		if condition == "whether imported library is reached by executable code" {
			return "linked library; execution connectivity unknown"
		}
		if condition == "whether imported API is reached by executable code" {
			return "imported API; execution connectivity unknown"
		}
	}
	return ""
}

func operationsByID(operations []behavior.ModeledOperation) map[string]behavior.ModeledOperation {
	out := make(map[string]behavior.ModeledOperation, len(operations))
	for _, operation := range operations {
		out[operation.ID] = operation
	}
	return out
}

func uniqueFeatures(features []behavior.Feature) []behavior.Feature {
	seen := map[string]bool{}
	var out []behavior.Feature
	for _, feature := range features {
		// Keep observations from distinct artifacts and scopes separate. The
		// very-verbose view includes source attribution; collapsing only by
		// key/value would silently assign a shared observation to whichever
		// bundled binary happened to be encountered first.
		key := semanticIdentityKey(
			feature.NodeID,
			feature.ScopeID,
			feature.Architecture,
			feature.Key,
			feature.Value,
			string(feature.Support),
			feature.SourceFunction,
			executionContextIdentityKey(feature.Execution),
			stringMapKey(feature.Qualifiers),
		)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, feature)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := featureTextPriority(out[i])
		right := featureTextPriority(out[j])
		if left != right {
			return left < right
		}
		if out[i].Key == "package.dependency" && out[j].Key == "package.dependency" {
			left = packageDependencySectionPriority(out[i].Qualifiers["section"])
			right = packageDependencySectionPriority(out[j].Qualifiers["section"])
			if left != right {
				return left < right
			}
		}
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Support < out[j].Support
	})
	return out
}

func packageDependencySectionPriority(section string) int {
	switch section {
	case "dependencies":
		return 0
	case "optionalDependencies":
		return 1
	case "peerDependencies":
		return 2
	case "devDependencies":
		return 3
	default:
		return 4
	}
}

func stringMapKey(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		parts = append(parts, key, values[key])
	}
	return semanticIdentityKey(parts...)
}

func visibleFeaturesForText(features []behavior.Feature) []behavior.Feature {
	var out []behavior.Feature
	calledObjCSelectors := map[string]bool{}
	for _, feature := range uniqueFeatures(features) {
		if featureVisibleInText(feature) {
			if feature.Key == "objc.message_call" {
				calledObjCSelectors[objcSelectorFeatureName(feature.Value)] = true
			}
			out = append(out, feature)
		}
	}
	if len(calledObjCSelectors) == 0 {
		return out
	}
	filtered := out[:0]
	for _, feature := range out {
		if feature.Key == "objc.selector_ref" && calledObjCSelectors[objcSelectorFeatureName(feature.Value)] {
			continue
		}
		filtered = append(filtered, feature)
	}
	return filtered
}

func objcSelectorFeatureName(value string) string {
	if idx := strings.LastIndex(value, "->"); idx >= 0 {
		value = value[idx+2:]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func featureVisibleInText(feature behavior.Feature) bool {
	switch feature.Key {
	case "macho.sensitive_resource", "script.sensitive_resource", "script.browser_credential_store":
		return true
	case "network.url", "network.ip", "network.domain":
		return true
	case "macho.process_launch_path", "macho.shell_command_expanded":
		return true
	case "macho.shell_command":
		return shellCommandFeatureVisible(feature.Value)
	case "macho.import_call":
		return importCallFeatureVisible(feature.Value)
	case "objc.message_call", "objc.selector_ref":
		return objcFeatureVisible(feature.Value)
	case "macho.security_api_import", "package.dependency", "package.script", "xcode.build_phase.shell_script", "command.tool", "script.function_call", "native.execution.api", "python.import", "python.qualified_call":
		return true
	default:
		return false
	}
}

func objcFeatureVisible(value string) bool {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "executebash:"),
		strings.Contains(lower, "downloadthis:andexecute") ||
			strings.Contains(lower, "downloadfilefrom:andsaveatpath:"),
		strings.Contains(lower, "uploadfile:toserver:"),
		strings.Contains(lower, "isrootuser:andpassword:"),
		strings.Contains(lower, "sendsynchronousrequest:returningresponse:error:"),
		strings.Contains(lower, "datawithcontentsofurl:"),
		strings.Contains(lower, "writetofile:atomically:"),
		strings.Contains(lower, "savesysteminfoto:withrootusername:androotpassword:"):
		return true
	default:
		return false
	}
}

func importCallFeatureVisible(value string) bool {
	value = strings.TrimPrefix(value, "_")
	switch value {
	case "SecItemCopyMatching", "SecKeychainFindGenericPassword",
		"posix_spawn", "execve", "system", "popen",
		"task_for_pid", "mach_vm_read", "mach_vm_write", "thread_create_running",
		"CGWindowListCreateImage", "CGDisplayCreateImage", "CGDisplayStreamCreate", "CGGetActiveDisplayList",
		"PasteboardCopyItemFlavorData", "PasteboardPutItemFlavor", "PasteboardPutItemFlavorData", "PasteboardCreate", "PasteboardSynchronize", "OBJC_CLASS_$_NSPasteboard",
		"curl_easy_perform", "SMLoginItemSetEnabled":
		return true
	default:
		return strings.Contains(value, "URLSession") || strings.Contains(value, "nw_connection") || strings.Contains(value, "SSLHandshake")
	}
}

func shellCommandFeatureVisible(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "://") ||
		strings.Contains(lower, "security ") ||
		strings.Contains(lower, "dscl ") ||
		strings.Contains(lower, "osascript") ||
		strings.Contains(lower, "launchctl") ||
		strings.Contains(lower, "curl ") ||
		strings.Contains(lower, "wget ")
}

func featureTextPriority(feature behavior.Feature) int {
	switch feature.Key {
	case "macho.sensitive_resource", "script.sensitive_resource", "script.browser_credential_store":
		return 0
	case "network.url", "network.ip", "network.domain":
		return 1
	case "macho.import_call", "macho.process_launch_path", "macho.shell_command", "macho.shell_command_expanded":
		return 2
	case "macho.security_api_import", "package.dependency", "package.script", "command.tool":
		return 3
	case "native.execution.api":
		return 6
	case "macho.import", "macho.dylib", "macho.section":
		return 9
	default:
		return 5
	}
}

func uniqueCoverage(items []behavior.Coverage) []behavior.Coverage {
	seen := map[string]bool{}
	var out []behavior.Coverage
	for _, item := range items {
		key := semanticIdentityKey(item.AnalysisArea, item.Status, item.Detail)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func visibleCoverage(items []behavior.Coverage) []behavior.Coverage {
	var out []behavior.Coverage
	for _, item := range items {
		if item.Status == "analyzed" && item.Detail == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func diagnosticsForText(values []string) []string {
	const (
		encryptedDetail = ": encrypted zip entry not inspected"
		wrongPassword   = ": wrong zip password"
	)
	var encrypted, wrong int
	var out []string
	for _, value := range values {
		switch {
		case strings.HasSuffix(value, encryptedDetail):
			encrypted++
		case strings.HasSuffix(value, wrongPassword):
			wrong++
		default:
			out = append(out, value)
		}
	}
	if encrypted > 3 {
		out = append([]string{fmt.Sprintf("%d encrypted zip entries not inspected", encrypted)}, out...)
	} else if encrypted > 0 {
		out = appendMatchingDiagnostics(out, values, encryptedDetail)
	}
	if wrong > 3 {
		out = append([]string{fmt.Sprintf("%d encrypted zip entries skipped due to wrong password", wrong)}, out...)
	} else if wrong > 0 {
		out = appendMatchingDiagnostics(out, values, wrongPassword)
	}
	return out
}

func appendMatchingDiagnostics(out, values []string, suffix string) []string {
	for _, value := range values {
		if strings.HasSuffix(value, suffix) {
			out = append(out, value)
		}
	}
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return compactSortedStrings(out)
}

func compactSortedStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func evidenceViewByID(items map[string]behavior.Evidence, id string) *EvidenceView {
	ev, ok := items[id]
	if !ok {
		return nil
	}
	return &EvidenceView{
		Logical:     ev.Logical,
		Physical:    ev.Physical,
		Line:        ev.Line,
		Offset:      ev.Offset,
		OffsetKnown: ev.ByteOffsetKnown(),
		VA:          ev.VA,
		Function:    ev.Function,
		Arch:        ev.Arch,
		Method:      ev.Method,
		Kind:        ev.Kind,
		Value:       ev.Value,
	}
}

func evidenceMap(items []behavior.Evidence) map[string]behavior.Evidence {
	out := make(map[string]behavior.Evidence, len(items))
	for _, item := range items {
		out[item.ID] = item
	}
	return out
}

type EvidenceView struct {
	Logical     string
	Physical    string
	Line        int
	Offset      int64
	OffsetKnown bool
	VA          uint64
	Function    string
	Arch        string
	Method      string
	Kind        string
	Value       string
}

func evidenceLocation(ev EvidenceView) string {
	location := compact(ev.Logical)
	if location == "" {
		location = compact(ev.Physical)
	}
	if location == "" {
		location = compact(ev.Method)
	}
	if location == "" {
		location = "evidence"
	}
	if ev.Line > 0 {
		location = fmt.Sprintf("%s:%d", location, ev.Line)
	}
	var parts []string
	if ev.Function != "" {
		parts = append(parts, "func "+displayFunctionName(compact(ev.Function)))
	}
	if ev.VA > 0 {
		parts = append(parts, fmt.Sprintf("va 0x%x", ev.VA))
	}
	if ev.OffsetKnown || ev.Offset != 0 {
		parts = append(parts, fmt.Sprintf("offset 0x%x", ev.Offset))
	}
	if ev.Arch != "" {
		parts = append(parts, compact(ev.Arch))
	}
	if len(parts) > 0 {
		location += " [" + strings.Join(parts, ", ") + "]"
	}
	return location
}

func evidenceValue(ev EvidenceView) string {
	if ev.Value != "" {
		return ev.Value
	}
	return ev.Kind
}

func evidenceText(ev EvidenceView) string {
	location := evidenceLocation(ev)
	value := compact(evidenceValue(ev))
	if value == "" {
		return location
	}
	return location + " " + value
}

func compact(value string) string {
	return boundedText(value, textFieldRuneLimit)
}

func boundedText(value string, maxRunes int) string {
	value = terminal.EscapeTruncate(value, maxRunes)
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func compactJoin(values []string, separator string) string {
	var joined string
	for _, value := range values {
		value = compact(value)
		if value == "" {
			continue
		}
		if joined == "" {
			joined = value
		} else {
			joined = compact(joined + separator + value)
		}
		if len([]rune(joined)) >= textFieldRuneLimit {
			break
		}
	}
	return joined
}
