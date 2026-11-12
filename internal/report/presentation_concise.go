package report

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	conciseAttackLimit     = 24
	conciseCapabilityLimit = 24
	conciseCapabilityWidth = 60
	conciseContentWidth    = 100
	conciseObservableLimit = 8
	conciseNetworkLimit    = 8
	conciseSecurityLimit   = 8
)

type conciseAttackMetadata struct {
	tactic    string
	technique string
}

// Maratus reports retain stable ATT&CK identifiers. This optional presentation
// catalog supplies labels for common identifiers without making rule authoring
// depend on a second registry; unknown IDs remain identifier-only.
var conciseAttackCatalog = map[string]conciseAttackMetadata{
	"T1059":     {tactic: "EXECUTION", technique: "Command and Scripting Interpreter"},
	"T1082":     {tactic: "DISCOVERY", technique: "System Information Discovery"},
	"T1083":     {tactic: "DISCOVERY", technique: "File and Directory Discovery"},
	"T1005":     {tactic: "COLLECTION", technique: "Data from Local System"},
	"T1033":     {tactic: "DISCOVERY", technique: "System Owner/User Discovery"},
	"T1041":     {tactic: "EXFILTRATION", technique: "Exfiltration Over C2 Channel"},
	"T1053.003": {tactic: "PERSISTENCE", technique: "Cron"},
	"T1057":     {tactic: "DISCOVERY", technique: "Process Discovery"},
	"T1105":     {tactic: "COMMAND AND CONTROL", technique: "Ingress Tool Transfer"},
	"T1106":     {tactic: "EXECUTION", technique: "Native API"},
	"T1129":     {tactic: "EXECUTION", technique: "Shared Modules"},
	"T1113":     {tactic: "COLLECTION", technique: "Screen Capture"},
	"T1115":     {tactic: "COLLECTION", technique: "Clipboard Data"},
	"T1222.002": {tactic: "DEFENSE EVASION", technique: "Linux and Mac Permissions"},
	"T1543":     {tactic: "PERSISTENCE", technique: "Create or Modify System Process"},
	"T1546.004": {tactic: "PERSISTENCE", technique: "Unix Shell Configuration Modification"},
	"T1547.015": {tactic: "PERSISTENCE", technique: "Login Items"},
	"T1552":     {tactic: "CREDENTIAL ACCESS", technique: "Unsecured Credentials"},
	"T1553.001": {tactic: "DEFENSE EVASION", technique: "Gatekeeper Bypass"},
	"T1555.001": {tactic: "CREDENTIAL ACCESS", technique: "Keychain"},
	"T1555.003": {tactic: "CREDENTIAL ACCESS", technique: "Credentials from Web Browsers"},
	"T1560":     {tactic: "COLLECTION", technique: "Archive Collected Data"},
	"T1518":     {tactic: "DISCOVERY", technique: "Software Discovery"},
	"T1647":     {tactic: "PERSISTENCE", technique: "Plist File Modification"},
}

func conciseTargetLabel(report Report) string {
	rootIndex := -1
	for index, node := range report.ArtifactNodes {
		if node.ParentID != "" || strings.TrimSpace(node.LogicalPath) == "" {
			continue
		}
		if rootIndex >= 0 {
			return report.Artifact
		}
		rootIndex = index
	}
	if rootIndex >= 0 && report.ArtifactNodes[rootIndex].Kind != "command" {
		return report.ArtifactNodes[rootIndex].LogicalPath
	}
	return report.Artifact
}

type conciseAttackRow struct {
	id        string
	tactic    string
	technique string
}

func (p *presentation) conciseAttack() {
	seen := map[string]bool{}
	var rows []conciseAttackRow
	capabilities := conciseCapabilityMatchesByCategory(p.report)
	for _, capability := range append(capabilities[SummaryCapabilityBehavior], capabilities[SummaryCapabilityTechnical]...) {
		for _, id := range capability.Attack {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			metadata, ok := conciseAttackCatalog[id]
			if !ok {
				metadata = conciseAttackMetadata{}
			}
			rows = append(rows, conciseAttackRow{id: id, tactic: metadata.tactic, technique: metadata.technique})
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].tactic != rows[j].tactic {
			return rows[i].tactic < rows[j].tactic
		}
		return rows[i].id < rows[j].id
	})
	p.section("ATT&CK", countLabel(len(rows), "technique"))
	p.printf("  %s  %s\n", p.style.key(fmt.Sprintf("%-20s", "TACTIC")), p.style.key("TECHNIQUE"))
	previousTactic := ""
	shown := min(len(rows), conciseAttackLimit)
	for _, row := range rows[:shown] {
		tactic := row.tactic
		if tactic == previousTactic {
			tactic = ""
		}
		previousTactic = row.tactic
		technique := row.id
		if row.technique != "" {
			technique = fmt.Sprintf("%s [%s]", row.technique, row.id)
		}
		p.printf("  %-20s  %s\n", boundedText(tactic, 20), boundedText(technique, 76))
	}
	if shown < len(rows) {
		p.omitted(len(rows)-shown, "techniques")
	}
}

type conciseCapabilityGroup struct {
	ruleID    string
	title     string
	namespace string
	count     int
}

func conciseCapabilityImplementations(rep Report, matches []behavior.CapabilityMatch) map[string][]string {
	operations := operationsByID(rep.Operations)
	out := map[string][]string{}
	for _, match := range matches {
		for _, operationID := range match.OperationIDs {
			operation, ok := operations[operationID]
			if !ok {
				continue
			}
			for _, implementation := range summaryOperationImplementations(operation) {
				if index := strings.Index(implementation, ": "); index >= 0 {
					implementation = implementation[index+2:]
				}
				out[match.RuleID] = appendUniqueStrings(out[match.RuleID], implementation)
			}
		}
	}
	return out
}

func conciseCapabilityGroups(matches []behavior.CapabilityMatch) []conciseCapabilityGroup {
	indexes := map[string]int{}
	var groups []conciseCapabilityGroup
	for _, match := range matches {
		key := semanticIdentityKey(match.RuleID, match.Title, match.Namespace)
		index, ok := indexes[key]
		if !ok {
			index = len(groups)
			indexes[key] = index
			groups = append(groups, conciseCapabilityGroup{
				ruleID: match.RuleID, title: match.Title, namespace: namespaceLabel(match.Namespace),
			})
		}
		groups[index].count++
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].namespace != groups[j].namespace {
			return groups[i].namespace < groups[j].namespace
		}
		if groups[i].title != groups[j].title {
			return groups[i].title < groups[j].title
		}
		return groups[i].ruleID < groups[j].ruleID
	})
	return groups
}

func (p *presentation) conciseCapabilities() {
	byCategory := conciseCapabilityMatchesByCategory(p.report)
	p.conciseCapabilitySection("CAPABILITIES", byCategory[SummaryCapabilityBehavior], true, len(p.report.Capabilities) > 0)
	p.conciseCapabilitySection("TECHNICAL PRIMITIVES", byCategory[SummaryCapabilityTechnical], false, false)
	p.conciseCapabilitySection("RUNTIME / STANDARD LIBRARY SUPPORT", byCategory[SummaryCapabilityRuntimeSupport], false, false)
}

func conciseCapabilityMatchesByCategory(rep Report) map[SummaryCapabilityCategory][]behavior.CapabilityMatch {
	result := map[SummaryCapabilityCategory][]behavior.CapabilityMatch{}
	operations := operationsByID(rep.Operations)
	for _, match := range rep.Capabilities {
		category := summaryCapabilityCategory(match, operations)
		result[category] = append(result[category], match)
	}
	return result
}

func (p *presentation) conciseCapabilitySection(title string, matches []behavior.CapabilityMatch, required, hasOther bool) {
	groups := conciseCapabilityGroups(matches)
	if len(groups) == 0 && !required {
		return
	}
	implementations := conciseCapabilityImplementations(p.report, matches)
	count := fmt.Sprintf("%s · %s", countLabel(len(groups), "capability"), countLabel(len(matches), "match"))
	p.section(title, count)
	if len(groups) == 0 {
		if hasOther {
			p.println("  No higher-level behavioral capability was established; technical or runtime support inventory follows.")
		} else {
			p.println("  No capability matches are recorded in this report.")
		}
		p.println("  This is not a security verdict; unmatched behavior and analysis limits may remain.")
		return
	}
	p.printf("  %s  %s\n", p.style.key(fmt.Sprintf("%-*s", conciseCapabilityWidth, "CAPABILITY")), p.style.key("NAMESPACE"))
	shown := min(len(groups), conciseCapabilityLimit)
	for _, group := range groups[:shown] {
		suffix := ""
		if group.count > 1 {
			suffix = fmt.Sprintf(" (%d matches)", group.count)
		}
		implementationSuffix := ""
		if values := implementations[group.ruleID]; len(values) > 0 && len(values) <= 3 {
			implementationSuffix = " [" + strings.Join(values, ", ") + "]"
		}
		available := conciseCapabilityWidth - len([]rune(suffix)) - len([]rune(implementationSuffix))
		if available < 20 {
			implementationSuffix = ""
			available = conciseCapabilityWidth - len([]rune(suffix))
		}
		title := boundedText(group.title, available) + implementationSuffix + suffix
		p.printf("  %-*s  %s\n", conciseCapabilityWidth, title, boundedText(group.namespace, 32))
	}
	if shown < len(groups) {
		p.omitted(len(groups)-shown, "capabilities")
	}
	p.printf("  %s\n", p.style.faint("Match status: "+conciseMatchStatus(matches)))
	if title == "RUNTIME / STANDARD LIBRARY SUPPORT" {
		p.println("  " + p.style.faint("Bundled compiler runtime or standard-library code exposes these exact primitives."))
		p.println("  " + p.style.faint("This does not establish application intent or invocation."))
	}
}

func conciseMatchStatus(matches []behavior.CapabilityMatch) string {
	support := map[behavior.Support]int{}
	connectivity := map[behavior.Connectivity]int{}
	for _, match := range matches {
		support[match.Support]++
		connectivity[executionConnectivity(match.Execution)]++
	}
	var connectivityParts []string
	for _, item := range []struct {
		value behavior.Connectivity
		label string
	}{
		{behavior.ConnectivityConnected, "connected"},
		{behavior.ConnectivityUnconnected, "unconnected"},
		{behavior.ConnectivityUnknown, "unknown"},
	} {
		if count := connectivity[item.value]; count > 0 {
			connectivityParts = append(connectivityParts, fmt.Sprintf("%d %s", count, item.label))
		}
	}
	var supportParts []string
	for _, item := range []struct {
		value behavior.Support
		label string
	}{
		{behavior.SupportDirect, "direct"},
		{behavior.SupportCorroborated, "corroborated"},
		{behavior.SupportHeuristic, "heuristic"},
	} {
		if count := support[item.value]; count > 0 {
			supportParts = append(supportParts, fmt.Sprintf("%d %s", count, item.label))
		}
	}
	return "execution: " + strings.Join(connectivityParts, " · ") + "; support: " + strings.Join(supportParts, " · ")
}

type conciseNetworkRow struct {
	value  string
	stacks []string
	count  int
}

func conciseNetworkItems(report Report) (behaviorItems, implementationItems, observableItems []networkPresentationRecord) {
	items := visibleNetwork(report, false)
	for _, item := range items {
		if len(normalizedNetworkOperationIDs(item)) > 0 {
			behaviorItems = append(behaviorItems, item)
		} else if item.ImplementationKind != "" {
			implementationItems = append(implementationItems, item)
		} else if item.ImplementationKind == "" {
			observableItems = append(observableItems, item)
		}
	}
	observableItems = conciseNetworkObservables(behaviorItems, observableItems, operationsByID(report.Operations), evidenceMap(report.Evidence))
	return behaviorItems, implementationItems, observableItems
}

func (p *presentation) conciseNetworkBehavior() {
	behaviorItems, implementationItems, _ := conciseNetworkItems(p.report)
	items := append(append([]networkPresentationRecord(nil), behaviorItems...), implementationItems...)
	if len(items) == 0 {
		return
	}
	rowsByValue := map[string]int{}
	var rows []conciseNetworkRow
	operations := operationsByID(p.report.Operations)
	for _, item := range items {
		values := sortedStrings(item.Destinations)
		if len(values) == 0 {
			values = []string{firstPresentationValue(networkContextLine(item, operations), "destination unresolved")}
		}
		stack := joinNonEmpty([]string{item.Caller, item.HTTPStack, item.TLSOwner}, " → ")
		for _, value := range values {
			index, ok := rowsByValue[value]
			if !ok {
				index = len(rows)
				rowsByValue[value] = index
				rows = append(rows, conciseNetworkRow{value: value})
			}
			rows[index].count++
			if stack != "" && !stringSliceContains(rows[index].stacks, stack) {
				rows[index].stacks = append(rows[index].stacks, stack)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].value < rows[j].value })
	count := countLabel(len(items), "path")
	if len(rows) != len(items) {
		count += " · " + countLabel(len(rows), "destination")
	}
	p.section("NETWORK EVIDENCE", count)
	shown := min(len(rows), conciseNetworkLimit)
	for _, row := range rows[:shown] {
		value := row.value
		if row.count > 1 {
			value += fmt.Sprintf(" (%d paths)", row.count)
		}
		p.conciseBullet(value)
		if len(row.stacks) > 0 {
			p.conciseIndented("via "+strings.Join(row.stacks, "; "), true)
		}
	}
	if shown < len(rows) {
		p.omitted(len(rows)-shown, "network destinations")
	}
}

type conciseObservableRow struct {
	category    string
	value       string
	occurrences int
	priority    int
}

func (p *presentation) conciseObservables() {
	_, _, networkObservables := conciseNetworkItems(p.report)
	rowsByKey := map[string]int{}
	var rows []conciseObservableRow
	add := func(category, value string, priority int) {
		category, value = strings.TrimSpace(category), strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := semanticIdentityKey(category, value)
		if index, ok := rowsByKey[key]; ok {
			rows[index].occurrences++
			return
		}
		rowsByKey[key] = len(rows)
		rows = append(rows, conciseObservableRow{category: category, value: value, occurrences: 1, priority: priority})
	}
	for _, item := range networkObservables {
		for _, destination := range sortedStrings(item.Destinations) {
			add(conciseNetworkCategory(destination), destination, 0)
		}
	}
	for _, item := range notableUnlinkedFeatures(p.report) {
		add(conciseObservableCategory(item.category), notableFeatureDisplayValue(item.feature), notableFeaturePriority(item.feature)+1)
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].priority != rows[j].priority {
			return rows[i].priority < rows[j].priority
		}
		if rows[i].category != rows[j].category {
			return rows[i].category < rows[j].category
		}
		return rows[i].value < rows[j].value
	})
	p.section("OBSERVABLES", countLabel(len(rows), "static item"))
	p.printf("  %s  %s\n", p.style.key(fmt.Sprintf("%-30s", "TYPE")), p.style.key("VALUE"))
	// Show one representative of each host or observable type before
	// filling the remaining slots with variations from the same group.
	if len(rows) > conciseObservableLimit {
		seen := map[string]bool{}
		first, rest := make([]conciseObservableRow, 0, len(rows)), []conciseObservableRow{}
		for _, row := range rows {
			group := row.category
			if row.category == "URL" {
				if u, err := url.Parse(row.value); err == nil {
					group += ":" + strings.ToLower(u.Hostname())
				}
			}
			if seen[group] {
				rest = append(rest, row)
				continue
			}
			seen[group] = true
			first = append(first, row)
		}
		rows = append(first, rest...)
	}
	shown := min(len(rows), conciseObservableLimit)
	for _, row := range rows[:shown] {
		value := row.value
		if row.occurrences > 1 {
			value += fmt.Sprintf(" (%d occurrences)", row.occurrences)
		}
		p.printf("  %-30s  %s\n", boundedText(row.category, 30), boundedText(value, 68))
	}
	if shown < len(rows) {
		p.omitted(len(rows)-shown, "static observables")
	}
	p.println(p.style.faint("  Static observations do not by themselves establish the implied resource access or behavior."))
}

func conciseObservableCategory(category string) string {
	switch category {
	case "input-event-monitoring API import":
		return "input monitoring API"
	case "base64-derived content fingerprint":
		return "decoded content hash"
	case "embedded launchd template fingerprint":
		return "launchd config hash"
	case "embedded launchd program":
		return "launchd program"
	case "embedded launchd trigger":
		return "launchd trigger"
	}
	if strings.HasPrefix(category, "embedded launchd program") {
		return "launchd program (data)"
	}
	if strings.HasPrefix(category, "embedded launchd template") {
		return "launchd config hash (partial)"
	}
	if strings.HasPrefix(category, "embedded launchd trigger") {
		return "launchd trigger (data)"
	}
	return category
}

func conciseNetworkCategory(value string) string {
	if strings.Contains(value, "://") {
		return "URL"
	}
	if net.ParseIP(value) != nil {
		return "IP address"
	}
	return "network"
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type conciseSecurityRow struct {
	label    string
	nodeIDs  map[string]bool
	priority int
}

func (p *presentation) conciseArtifactProperty() {
	items := uniqueArtifactProperties(p.report.ArtifactProperties, false)
	rowsByLabel := map[string]int{}
	var rows []conciseSecurityRow
	add := func(label, nodeID string, priority int) {
		index, ok := rowsByLabel[label]
		if !ok {
			index = len(rows)
			rowsByLabel[label] = index
			rows = append(rows, conciseSecurityRow{label: label, nodeIDs: map[string]bool{}, priority: priority})
		}
		if nodeID != "" {
			rows[index].nodeIDs[nodeID] = true
		}
	}
	hasCodeSigningContext := false
	hasCodeSignatureStructure := false
	entitlementValues := map[string]bool{}
	entitlementNodes := map[string]bool{}
	for _, item := range items {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		switch {
		case kind == "code-directory-page-integrity":
			hasCodeSigningContext = true
			hasCodeSignatureStructure = true
			add("CodeDirectory page integrity: "+item.Value, item.NodeID, 0)
		case kind == "cms-signature-structure":
			hasCodeSigningContext = true
			hasCodeSignatureStructure = true
			label := "CMS signature structure: " + item.Value
			if item.Value == "signed-data-envelope" {
				label = "CMS SignedData envelope present"
			}
			add(label, item.NodeID, 1)
		case kind == "entitlement-context":
			hasCodeSigningContext = true
			add(item.Value, item.NodeID, 0)
		case kind == "entitlement":
			hasCodeSigningContext = true
			if item.Value != "com.apple.application-identifier" {
				entitlementValues[item.Value] = true
				if item.NodeID != "" {
					entitlementNodes[item.NodeID] = true
				}
			}
		case strings.HasPrefix(kind, "code-signature"), strings.HasPrefix(kind, "code-directory"), strings.HasPrefix(kind, "cms-signature"), strings.HasPrefix(kind, "entitlements-"):
			hasCodeSigningContext = true
			hasCodeSignatureStructure = true
		default:
			add(item.Kind+": "+artifactPropertyDisplayValue(item), item.NodeID, 1)
		}
	}
	if len(entitlementValues) > 0 {
		label := countLabel(len(entitlementValues), "entitlement")
		if len(entitlementNodes) > 0 {
			label += " across " + countLabel(len(entitlementNodes), "artifact")
		}
		add(label, "", 2)
	}
	if hasCodeSignatureStructure {
		signingNodes, adHocNodes := map[string]bool{}, map[string]bool{}
		for _, item := range items {
			kind := strings.ToLower(strings.TrimSpace(item.Kind))
			if kind == "code-signature-structure" && item.NodeID != "" {
				signingNodes[item.NodeID] = true
			}
			if kind == "code-signature-flags" && strings.Contains(artifactPropertyDisplayValue(item), "ad-hoc") && item.NodeID != "" {
				adHocNodes[item.NodeID] = true
			}
			if kind == "code-signature-kind" && item.Value == "ad-hoc" && item.NodeID != "" {
				adHocNodes[item.NodeID] = true
			}
		}
		label := "code-signature structure present"
		if len(signingNodes) > 0 {
			label += " on " + countLabel(len(signingNodes), "artifact")
		}
		if len(adHocNodes) > 0 {
			label += " · " + countLabel(len(adHocNodes), "ad-hoc declaration")
		}
		add(label, "", 3)
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].priority != rows[j].priority {
			return rows[i].priority < rows[j].priority
		}
		return rows[i].label < rows[j].label
	})
	p.section("ARTIFACT PROPERTIES", countLabel(len(rows), "summary"))
	shown := min(len(rows), conciseSecurityLimit)
	for _, row := range rows[:shown] {
		label := row.label
		if len(row.nodeIDs) > 1 {
			label += " (" + countLabel(len(row.nodeIDs), "artifact") + ")"
		}
		p.conciseBullet(label)
	}
	if shown < len(rows) {
		p.omitted(len(rows)-shown, "artifact property summaries")
	}
	if hasCodeSigningContext {
		p.println(p.style.faint("  Note: CodeDirectory page hashes cover retained bytes only."))
		p.println(p.style.faint("        CMS signatures, certificate trust, notarization, and revocation are not verified."))
	}
}

func (p *presentation) conciseBullet(value string) {
	lines := conciseWrappedLines(value, conciseContentWidth)
	for index, line := range lines {
		if index == 0 {
			p.printf("  %s %s\n", p.style.marker("◆"), line)
			continue
		}
		p.printf("    %s\n", line)
	}
}

func (p *presentation) conciseIndented(value string, faint bool) {
	for _, line := range conciseWrappedLines(value, conciseContentWidth) {
		if faint {
			line = p.style.faint(line)
		}
		p.printf("    %s\n", line)
	}
}

func (p *presentation) conciseNote(value string) {
	for _, line := range conciseWrappedLines(value, conciseContentWidth) {
		p.printf("  %s\n", p.style.faint(line))
	}
}

func conciseWrappedLines(value string, width int) []string {
	value = boundedText(value, textLineRuneLimit)
	words := strings.Fields(value)
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, 2)
	current := ""
	for _, word := range words {
		word = boundedText(word, width)
		if current == "" {
			current = word
			continue
		}
		if len([]rune(current))+1+len([]rune(word)) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
