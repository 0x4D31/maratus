package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/rules"
)

// TextVerbosity selects the amount of human-readable detail. JSON output is
// intentionally controlled by WriteJSON and is unaffected by these values.
type TextVerbosity uint8

const (
	TextConcise TextVerbosity = iota
	TextVerbose
	TextVeryVerbose
)

// TextOptions controls the presentation renderer used by the CLI. Color only
// styles structural labels; support and execution connectivity never receive semantic
// red/amber/green coloring.
type TextOptions struct {
	Verbosity TextVerbosity
	Color     bool
}

const (
	presentationCapabilityLimit   = 24
	presentationResourceLimit     = 6
	presentationNodeLimit         = 40
	presentationRelationshipLimit = 40
	presentationOperationLimit    = 40
	presentationPackagingLimit    = 6
	presentationTraceClauseLimit  = 8
)

// WriteTextWithOptions writes the layered CLI presentation.
func WriteTextWithOptions(w io.Writer, report Report, options TextOptions) error {
	if options.Verbosity == TextConcise {
		return WriteSummaryText(w, report, options)
	}
	p := newPresentation(w, report, options)
	p.header("STATIC ANALYSIS")
	p.summary()
	p.executionRootsAndTargets()
	p.capabilities()
	p.network()
	p.notableStaticFeatures()
	p.artifactProperties()
	if options.Verbosity >= TextVeryVerbose {
		p.artifactGraph()
		p.operations()
	}
	if options.Verbosity >= TextVeryVerbose {
		p.features()
		p.coverageAndNotes()
	}
	return p.output.err
}

// WriteRulesText renders the built-in rule catalog for people. WriteJSON is
// the stable interface for consumers that need the complete metadata objects.
func WriteRulesText(w io.Writer, info RuleInfo, options TextOptions) error {
	output := &trackingWriter{writer: w}
	style := presentationStyle{enabled: options.Color}
	output.printf("%s  %s\n", style.brand("MARATUS"), style.heading("RULE CATALOG"))
	output.println(style.faint(strings.Repeat("─", 64)))
	output.printf("%s%s\n", style.key(fmt.Sprintf("%-12s", "Ruleset")), boundedText(info.RulesetVersion, textLineRuneLimit))
	output.printf("%s%s\n", style.key(fmt.Sprintf("%-12s", "Catalog")), boundedText(info.RuleCatalogDigest, textLineRuneLimit))
	capabilities, libraries := 0, 0
	for _, entry := range info.Rules {
		switch entry.Kind {
		case rules.CapabilityRule:
			capabilities++
		case rules.LibraryRule:
			libraries++
		}
	}
	output.printf("%s%d built-in rules · %d capability · %d library\n", style.key(fmt.Sprintf("%-12s", "Inventory")), len(info.Rules), capabilities, libraries)

	metadata := append([]rulePresentationMetadata(nil), ruleMetadata(info)...)
	sort.SliceStable(metadata, func(i, j int) bool {
		if metadata[i].Namespace != metadata[j].Namespace {
			return metadata[i].Namespace < metadata[j].Namespace
		}
		return metadata[i].ID < metadata[j].ID
	})
	for i := 0; i < len(metadata); {
		namespace := metadata[i].Namespace
		end := i + 1
		for end < len(metadata) && metadata[end].Namespace == namespace {
			end++
		}
		output.printf("\n%s %s\n", style.section(boundedText(namespaceLabel(namespace), textFieldRuneLimit)), style.faint(fmt.Sprintf("(%d)", end-i)))
		for _, item := range metadata[i:end] {
			output.printf("  %s  %s\n", style.marker("◆"), boundedText(item.Title, textLineRuneLimit))
			output.printf("     %s %s · %s\n", style.faint("rule"), boundedText(item.ID, textLineRuneLimit), boundedText(string(item.Kind), textFieldRuneLimit))
			if options.Verbosity >= TextVerbose {
				if item.Description != "" {
					output.printf("     %s %s\n", style.faint("about"), boundedText(item.Description, textLineRuneLimit))
				}
				writeMappings(output, style, item.Attack, item.MBC, "     ")
				output.printf("     %s %s\n", style.faint("support"), boundedText(string(item.MinimumSupport), textFieldRuneLimit))
				if len(item.LibraryRuleIDs) > 0 {
					output.printf("     %s %s\n", style.faint("libraries"), boundedText(strings.Join(item.LibraryRuleIDs, ", "), textLineRuneLimit))
				}
			}
		}
		i = end
	}
	if options.Verbosity < TextVerbose {
		output.printf("\n%s\n", style.faint("Use --detail evidence for descriptions and mappings; use --format json for complete rule metadata."))
	}
	return output.err
}

type presentation struct {
	report   Report
	options  TextOptions
	output   *trackingWriter
	w        io.Writer
	style    presentationStyle
	evidence map[string]behavior.Evidence
}

func newPresentation(w io.Writer, report Report, options TextOptions) *presentation {
	output := &trackingWriter{writer: w}
	return &presentation{
		report: report, options: options, output: output, w: output,
		style: presentationStyle{enabled: options.Color}, evidence: evidenceMap(report.Evidence),
	}
}

func (p *presentation) printf(format string, args ...any) {
	p.output.printf(format, args...)
}

func (p *presentation) println(args ...any) {
	p.output.println(args...)
}

type presentationStyle struct{ enabled bool }

func (s presentationStyle) wrap(code, value string) string {
	if !s.enabled || value == "" {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (s presentationStyle) brand(value string) string   { return s.wrap("1;36", value) }
func (s presentationStyle) heading(value string) string { return s.wrap("1", value) }
func (s presentationStyle) section(value string) string { return s.wrap("1;36", value) }
func (s presentationStyle) key(value string) string     { return s.wrap("1", value) }
func (s presentationStyle) marker(value string) string  { return s.wrap("36", value) }
func (s presentationStyle) faint(value string) string   { return s.wrap("2", value) }

func (p *presentation) header(mode string) {
	p.printf("%s  %s\n", p.style.brand("MARATUS"), p.style.heading(mode))
	p.println(p.style.faint(strings.Repeat("─", 64)))
}

func (p *presentation) summary() {
	target := p.report.Artifact
	execution := presentationExecutionInventoryFor(p.report)
	if p.options.Verbosity == TextConcise {
		target = conciseTargetLabel(p.report)
	}
	p.keyValue("Input", target)
	p.keyValue("Type", artifactType(p.report))
	if packaging := packagingTechnologySummary(p.report.ArtifactNodes); packaging != "" {
		p.keyValue("Packaging", packaging)
	}
	if sha256 := presentationRootSHA256(p.report); sha256 != "" {
		p.keyValue("SHA-256", sha256)
	}
	if p.options.Verbosity == TextConcise {
		capabilities := conciseCapabilityGroups(p.report.Capabilities)
		results := fmt.Sprintf("%s · %s · %s across %s",
			countLabel(len(p.report.ArtifactNodes), "artifact"),
			executionInventoryCount(execution),
			countLabel(len(p.report.Capabilities), "match"),
			countLabel(len(capabilities), "capability"))
		p.keyValue("Results", results)
		if status := conciseAnalysisStatus(p.report); status != "" {
			p.keyValue("Analysis", status)
		}
		return
	}
	inventory := fmt.Sprintf("%s · %s · %s",
		countLabel(len(p.report.ArtifactNodes), "artifact node"),
		executionInventoryCount(execution),
		countLabel(len(p.report.Capabilities), "capability match"))
	p.keyValue("Inventory", inventory)
	p.keyValue("Analysis", analysisSummary(p.report.Analysis))
	if provenance := reportProvenanceSummary(p.report); provenance != "" {
		p.keyValue("Provenance", provenance)
	}
	if status := artifactStatusSummary(p.report); status != "" {
		p.keyValue("Node status", status)
	}
}

func conciseAnalysisStatus(report Report) string {
	var parts []string
	if limitations := CoverageLimitationCount(report.Coverage); limitations > 0 {
		parts = append(parts, countLabel(limitations, "limited scope"))
	}
	if diagnostics := len(diagnosticsForText(report.Diagnostics)); diagnostics > 0 {
		parts = append(parts, countLabel(diagnostics, "diagnostic"))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ") + "; details in canonical JSON or --detail full"
}

func presentationRootSHA256(report Report) string {
	rootCount := 0
	rootHash := ""
	for _, node := range report.ArtifactNodes {
		if node.ParentID != "" {
			continue
		}
		rootCount++
		rootHash = node.SHA256
	}
	if rootCount == 1 {
		return rootHash
	}
	return ""
}

func reportProvenanceSummary(report Report) string {
	var parts []string
	if report.Tool != "" {
		producer := report.Tool
		if report.ToolVersion != "" {
			producer += " " + report.ToolVersion
		}
		if report.ToolCommit != "" {
			commit := report.ToolCommit
			if len(commit) > 12 {
				commit = commit[:12]
			}
			if report.ToolModified {
				commit += ", modified"
			}
			producer += " (" + commit + ")"
		} else if report.ToolModified {
			producer += " (modified build)"
		}
		parts = append(parts, producer)
	}
	if report.RulesetVersion != "" {
		parts = append(parts, "rules "+report.RulesetVersion)
	}
	if report.RuleCatalogDigest != "" {
		parts = append(parts, "catalog "+shortCatalogDigest(report.RuleCatalogDigest))
	}
	return strings.Join(parts, " · ")
}

func shortCatalogDigest(value string) string {
	const length = len("sha256:") + 12
	if len(value) <= length {
		return value
	}
	return value[:length]
}

func (p *presentation) keyValue(key, value string) {
	if value == "" {
		value = "not reported"
	}
	limit := textLineRuneLimit
	if p.options.Verbosity == TextConcise {
		limit = conciseContentWidth - 12
	}
	p.printf("%s%s\n", p.style.key(fmt.Sprintf("%-12s", key)), boundedText(value, limit))
}

func (p *presentation) section(title, count string) {
	p.printf("\n%s", p.style.section(title))
	if count != "" {
		p.printf(" %s", p.style.faint("("+count+")"))
	}
	p.println()
}

func (p *presentation) executionRootsAndTargets() {
	inventory := presentationExecutionInventoryFor(p.report)
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	rootLines := executionRootTextLines(inventory.roots, nodeLabels)
	if len(inventory.roots) > 0 {
		// Several document-handler roots may intentionally collapse into one
		// readable line. Keep the heading count tied to modeled roots so it agrees
		// with Inventory.
		p.section("EXECUTION ROOTS", countLabel(len(inventory.roots), "root"))
		for i, entry := range rootLines {
			if i >= textSectionLimit {
				p.omitted(len(rootLines)-i, "execution roots")
				break
			}
			p.printf("  %s %s\n", p.style.marker("◆"), boundedText(entry, textLineRuneLimit))
		}
	}
	if len(inventory.targets) == 0 {
		return
	}
	p.section("INVOKED TARGETS", countLabel(len(inventory.targets), "target"))
	for i, target := range inventory.targets {
		if i >= textSectionLimit {
			p.omitted(len(inventory.targets)-i, "invoked targets")
			break
		}
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(invokedTargetSummary(target, p.report, nodeLabels), textLineRuneLimit))
	}
}

type presentationExecutionInventory struct {
	roots   []behavior.ExecutionRoot
	targets []behavior.InvokedTarget
}

func presentationExecutionInventoryFor(report Report) presentationExecutionInventory {
	inventory := presentationExecutionInventory{
		roots:   uniqueExecutionRoots(append([]behavior.ExecutionRoot(nil), report.ExecutionRoots...)),
		targets: append([]behavior.InvokedTarget(nil), report.InvokedTargets...),
	}
	sort.SliceStable(inventory.roots, func(i, j int) bool {
		return presentationExecutionRootSortKey(inventory.roots[i]) < presentationExecutionRootSortKey(inventory.roots[j])
	})
	sort.SliceStable(inventory.targets, func(i, j int) bool {
		return presentationInvokedTargetSortKey(inventory.targets[i]) < presentationInvokedTargetSortKey(inventory.targets[j])
	})
	return inventory
}

func presentationExecutionRootSortKey(root behavior.ExecutionRoot) string {
	return semanticIdentityKey(root.Kind, root.DeclarationNodeID, root.StartNodeID, root.StartScopeID, root.Name, root.Interpreter, semanticIdentityKey(root.Arguments...), root.ID)
}

func presentationInvokedTargetSortKey(target behavior.InvokedTarget) string {
	ordinal := "~"
	if target.Ordinal != nil {
		ordinal = fmt.Sprintf("%020d", *target.Ordinal)
	}
	return semanticIdentityKey(target.Kind, string(target.Source.Kind), target.Source.ID, ordinal, target.NodeID, target.ScopeID, target.Interpreter, semanticIdentityKey(target.Arguments...), target.ID)
}

func invokedTargetSummary(target behavior.InvokedTarget, report Report, nodeLabels map[string]string) string {
	destination := presentationNodeLabel(target.NodeID, report.ArtifactNodes, nodeLabels)
	command := compactJoin(append([]string{target.Interpreter}, target.Arguments...), " ")
	label := joinNonEmpty([]string{target.Kind, firstPresentationValue(command, destination)}, " → ")
	if target.Ordinal != nil {
		label += fmt.Sprintf(" (ordinal %d)", *target.Ordinal)
	}
	parts := []string{label, "source " + presentationEntityRefLabel(target.Source, report, nodeLabels), string(executionConnectivity(target.Execution))}
	if len(target.Execution.ExecutionRootIDs) > 0 {
		parts = append(parts, "roots "+strings.Join(target.Execution.ExecutionRootIDs, ","))
	}
	if len(target.Execution.InvokedTargetIDs) > 0 {
		parts = append(parts, "via targets "+strings.Join(target.Execution.InvokedTargetIDs, ","))
	}
	return joinNonEmpty(parts, " · ")
}

func presentationEntityRefLabel(ref behavior.EntityRef, report Report, nodeLabels map[string]string) string {
	switch ref.Kind {
	case behavior.EntityKindArtifactNode:
		return presentationNodeLabel(ref.ID, report.ArtifactNodes, nodeLabels)
	case behavior.EntityKindExecutionRoot:
		for _, root := range report.ExecutionRoots {
			if root.ID == ref.ID {
				return firstPresentationValue(root.Name, root.Kind) + " (" + root.ID + ")"
			}
		}
	case behavior.EntityKindInvokedTarget:
		for _, target := range report.InvokedTargets {
			if target.ID == ref.ID {
				return presentationNodeLabel(target.NodeID, report.ArtifactNodes, nodeLabels) + " (" + target.ID + ")"
			}
		}
	}
	return string(ref.Kind) + " " + ref.ID
}

func presentationNodeLabel(nodeID string, nodes []artifact.Node, nodeLabels map[string]string) string {
	if nodeID == "" {
		return ""
	}
	if label := nodeLabels[nodeID]; label != "" {
		return label
	}
	for _, node := range nodes {
		if node.ID == nodeID && node.LogicalPath != "" {
			return node.LogicalPath
		}
	}
	return nodeID
}

func (p *presentation) capabilities() {
	groups := sortedCapabilityMatchGroups(p.report.Capabilities)
	matchCount := len(p.report.Capabilities)
	shown := min(len(groups), presentationCapabilityLimit)
	count := countLabel(matchCount, "match")
	switch {
	case shown < len(groups) && len(groups) != matchCount:
		count = fmt.Sprintf("%d shown · %d groups · %s recorded", shown, len(groups), countLabel(matchCount, "match"))
	case shown < len(groups):
		count = fmt.Sprintf("%d shown · %s recorded", shown, countLabel(matchCount, "match"))
	case len(groups) != matchCount:
		count = fmt.Sprintf("%d groups shown · %s recorded", len(groups), countLabel(matchCount, "match"))
	}
	p.section("CAPABILITY MATCHES", count)
	if len(groups) == 0 {
		p.println("  No capability matches are recorded in this report.")
		p.println("  This is not a security verdict; unmatched behavior and analysis limits may remain.")
		return
	}
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	// Built-in descriptions and fallback mappings are valid only for reports
	// produced by this exact ruleset. A saved older report must not silently
	// acquire the current catalog's semantics while being re-rendered.
	metadata := map[string]rulePresentationMetadata{}
	if p.report.RulesetVersion == RulesetVersion && p.report.RuleCatalogDigest == rules.CatalogDigest() {
		metadata = metadataByRuleID()
	}
	for i := 0; i < len(groups); {
		namespace := namespaceLabel(groups[i].capabilityMatch.Namespace)
		end := i + 1
		for end < len(groups) && namespaceLabel(groups[end].capabilityMatch.Namespace) == namespace {
			end++
		}
		p.printf("  %s %s\n", p.style.key(boundedText(namespace, textFieldRuneLimit)), p.style.faint(fmt.Sprintf("(%d)", end-i)))
		for j := i; j < end; j++ {
			if j >= presentationCapabilityLimit {
				p.omitted(len(groups)-j, "capability groups")
				return
			}
			p.capabilityMatch(groups[j], metadata[groups[j].capabilityMatch.RuleID], nodeLabels)
		}
		i = end
	}
}

func (p *presentation) capabilityMatch(group capabilityMatchTextGroup, metadata rulePresentationMetadata, nodeLabels map[string]string) {
	capabilityMatch := group.capabilityMatch
	p.printf("    %s %s\n", p.style.marker("◆"), boundedText(capabilityTitle(group), textLineRuneLimit))
	p.detail("      ", "support", string(capabilityMatch.Support))
	p.executionContextDetails("      ", capabilityMatch.Execution)
	if len(capabilityMatch.ArchitectureScopes) > 0 {
		p.detail("      ", "architecture", strings.Join(sortedStrings(capabilityMatch.ArchitectureScopes), ", "))
	}
	if source := nodeLabels[capabilityMatch.SubjectNodeID]; source != "" && len(p.report.ArtifactNodes) > 1 {
		p.detail("      ", "source", source)
	}
	resources := sortedResources(capabilityMatch.AffectedResources)
	for i, resource := range resources {
		if i >= presentationResourceLimit {
			p.detail("      ", "resource", fmt.Sprintf("... %d more", len(resources)-i))
			break
		}
		p.detail("      ", "resource", resourceText(resource))
	}
	if p.options.Verbosity >= TextVerbose {
		p.detail("      ", "rule", capabilityMatch.RuleID)
	}
	if p.options.Verbosity < TextVerbose {
		return
	}
	if metadata.Description != "" {
		p.detail("      ", "about", metadata.Description)
	}
	attack, mbc := capabilityMatch.Attack, capabilityMatch.MBC
	if len(attack) == 0 {
		attack = metadata.Attack
	}
	if len(mbc) == 0 {
		mbc = metadata.MBC
	}
	writeMappings(p.output, p.style, attack, mbc, "      ")
	if group.count > 1 {
		p.detail("      ", "match trace", fmt.Sprintf("%d exact per-match traces are retained in report JSON", group.count))
	} else {
		for index, clause := range capabilityMatch.MatchTrace {
			if index >= presentationTraceClauseLimit {
				p.detail("      ", "match trace", fmt.Sprintf("... %d more clauses", len(capabilityMatch.MatchTrace)-index))
				break
			}
			p.detail("      ", "match trace", matchTraceClauseText(clause))
		}
	}
	for i, evidenceID := range group.evidenceIDs {
		if i >= textEvidenceLimit {
			p.detail("      ", "evidence", fmt.Sprintf("... %d more", len(group.evidenceIDs)-i))
			break
		}
		if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
			p.detail("      ", "evidence", evidenceText(*evidence))
		}
	}
}

func matchTraceClauseText(clause behavior.MatchTraceClause) string {
	var ids []string
	switch clause.Kind {
	case behavior.MatchTraceOperation:
		ids = clause.OperationIDs
	case behavior.MatchTraceFeature:
		ids = clause.FeatureIDs
	case behavior.MatchTraceExecutionRoot:
		ids = clause.ExecutionRootIDs
	case behavior.MatchTraceOperationRelation:
		ids = clause.RelationIDs
	}
	return fmt.Sprintf("%s · %s · %s", clause.Path, clause.Kind, strings.Join(ids, ", "))
}

func (p *presentation) detail(indent, key, value string) {
	key = boundedText(key, textDetailLabelRuneLimit)
	if key == "" {
		key = "detail"
	}
	p.printf("%s%s  %s\n", indent, p.style.faint(fmt.Sprintf("%-12s", key)), boundedText(value, textLineRuneLimit))
}

func (p *presentation) network() {
	includeWeak := p.options.Verbosity >= TextVeryVerbose
	items := visibleNetwork(p.report, includeWeak)
	if len(items) == 0 {
		return
	}
	var behaviorItems, implementationItems, observableItems []networkPresentationRecord
	for _, item := range items {
		if len(normalizedNetworkOperationIDs(item)) > 0 {
			behaviorItems = append(behaviorItems, item)
		} else if item.ImplementationKind != "" {
			implementationItems = append(implementationItems, item)
		} else {
			observableItems = append(observableItems, item)
		}
	}
	if p.options.Verbosity == TextConcise {
		observableItems = conciseNetworkObservables(behaviorItems, observableItems, operationsByID(p.report.Operations), p.evidence)
	}
	p.networkSection("NETWORK BEHAVIOR", behaviorItems, false)
	p.networkSection("NETWORK IMPLEMENTATION OBSERVATIONS", implementationItems, false)
	p.networkSection("NETWORK OBSERVABLES", observableItems, true)
}

// conciseNetworkObservables removes only a presentation duplicate: a static
// destination that is already shown by an operation-linked network path from the
// same artifact node. The report, JSON, and very-verbose record inventory stay
// unchanged. Observables from a different node, observables with ambiguous
// multi-node provenance, and distinct destinations remain visible.
func conciseNetworkObservables(behaviorItems, observableItems []networkPresentationRecord, operations map[string]behavior.ModeledOperation, evidence map[string]behavior.Evidence) []networkPresentationRecord {
	linked := map[string]bool{}
	for _, item := range behaviorItems {
		nodes := networkDetailOperationNodes(item, operations)
		for _, nodeID := range nodes {
			for _, destination := range item.Destinations {
				if destination = strings.TrimSpace(destination); destination != "" {
					linked[semanticIdentityKey(nodeID, destination)] = true
				}
			}
		}
	}

	out := make([]networkPresentationRecord, 0, len(observableItems))
	for _, item := range observableItems {
		nodes := networkDetailEvidenceNodes(item, evidence)
		if len(nodes) != 1 {
			out = append(out, item)
			continue
		}
		filtered := item
		filtered.Destinations = nil
		for _, destination := range item.Destinations {
			normalized := strings.TrimSpace(destination)
			if normalized != "" && linked[semanticIdentityKey(nodes[0], normalized)] {
				continue
			}
			filtered.Destinations = append(filtered.Destinations, destination)
		}
		if len(filtered.Destinations) == 0 && len(filtered.Security) == 0 {
			continue
		}
		out = append(out, filtered)
	}
	return out
}

func networkDetailOperationNodes(item networkPresentationRecord, operations map[string]behavior.ModeledOperation) []string {
	var nodes []string
	for _, operationID := range normalizedNetworkOperationIDs(item) {
		if nodeID := strings.TrimSpace(operations[operationID].SubjectNodeID); nodeID != "" {
			nodes = append(nodes, nodeID)
		}
	}
	return sortedStrings(nodes)
}

func networkDetailEvidenceNodes(item networkPresentationRecord, evidence map[string]behavior.Evidence) []string {
	var nodes []string
	for _, evidenceID := range item.EvidenceIDs {
		if nodeID := strings.TrimSpace(evidence[evidenceID].NodeID); nodeID != "" {
			nodes = append(nodes, nodeID)
		}
	}
	return sortedStrings(nodes)
}

func (p *presentation) networkSection(title string, items []networkPresentationRecord, unlinkedObservable bool) {
	if len(items) == 0 {
		return
	}
	noun := "path"
	if unlinkedObservable {
		noun = "observable"
	}
	p.section(title, countLabel(len(items), noun))
	operations := operationsByID(p.report.Operations)
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	annotateSources := len(nodeLabels) > 1
	sourceLines := 0
	omittedSources := 0
	for i, item := range items {
		if i >= textSectionLimit {
			p.omitted(len(items)-i, "network paths")
			break
		}
		stack := joinNonEmpty([]string{item.Caller, item.HTTPStack, item.TLSOwner}, " → ")
		if stack == "" {
			stack = "network behavior"
		}
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(stack, textLineRuneLimit))
		if unlinkedObservable {
			p.detail("    ", "interpretation", "not linked to a modeled network operation; network use not established")
		}
		if context := networkContextLine(item, operations); context != "" {
			p.detail("    ", "context", context)
		}
		for j, destination := range sortedStrings(item.Destinations) {
			if j >= textDestinationLimit {
				p.detail("    ", "destination", fmt.Sprintf("... %d more", len(item.Destinations)-j))
				break
			}
			p.detail("    ", "destination", destination)
		}
		security := sortedStrings(item.Security)
		for j, securityDetail := range security {
			if j >= textSecurityDetailLimit {
				p.detail("    ", "security", fmt.Sprintf("... %d more", len(security)-j))
				break
			}
			p.detail("    ", "security", securityDetail)
		}
		if annotateSources {
			sources := networkSourceLabels(item, nodeLabels, operations, p.evidence)
			for _, source := range sources {
				if sourceLines >= textSourceLimit {
					omittedSources++
					continue
				}
				p.detail("    ", "source", source)
				sourceLines++
			}
		}
		if p.options.Verbosity >= TextVerbose {
			for j, unresolved := range sortedStrings(item.Unresolved) {
				if j >= textDestinationLimit {
					p.detail("    ", "unresolved", fmt.Sprintf("... %d more", len(item.Unresolved)-j))
					break
				}
				p.detail("    ", "unresolved", unresolved)
			}
			for j, evidenceID := range item.EvidenceIDs {
				if j >= textEvidenceLimit {
					p.detail("    ", "evidence", fmt.Sprintf("... %d more", len(item.EvidenceIDs)-j))
					break
				}
				if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
					p.detail("    ", "evidence", evidenceText(*evidence))
				}
			}
		}
	}
	if omittedSources > 0 {
		p.detail("    ", "source", fmt.Sprintf("... %d more", omittedSources))
	}
}

func (p *presentation) artifactProperties() {
	includeWeak := p.options.Verbosity >= TextVeryVerbose
	items := uniqueArtifactProperties(p.report.ArtifactProperties, includeWeak)
	if len(items) == 0 {
		return
	}
	p.section("ARTIFACT PROPERTIES", countLabel(len(items), "property"))
	limit := textArtifactPropertyLimit
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	annotateSources := len(nodeLabels) > 1
	for i, item := range items {
		if i >= limit {
			p.omitted(len(items)-i, "artifact properties")
			break
		}
		line := item.Kind + ": " + artifactPropertyDisplayValue(item)
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(line, textLineRuneLimit))
		p.detail("    ", "support", string(item.Support))
		if annotateSources && nodeLabels[item.NodeID] != "" {
			p.detail("    ", "source", nodeLabels[item.NodeID])
		}
		if p.options.Verbosity >= TextVerbose {
			for j, evidenceID := range item.EvidenceIDs {
				if j >= textEvidenceLimit {
					p.detail("    ", "evidence", fmt.Sprintf("... %d more", len(item.EvidenceIDs)-j))
					break
				}
				if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
					p.detail("    ", "evidence", evidenceText(*evidence))
				}
			}
		}
	}
	if hasCodeSigningArtifactProperty(items) {
		p.println(p.style.faint("  Note: CodeDirectory page hashes cover retained bytes only."))
		p.println(p.style.faint("        CMS signatures, certificate trust, notarization, and revocation are not verified."))
	}
}

func hasCodeSigningArtifactProperty(items []behavior.ArtifactProperty) bool {
	for _, item := range items {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		if strings.HasPrefix(kind, "code-signature") ||
			strings.HasPrefix(kind, "code-directory") ||
			strings.HasPrefix(kind, "cms-signature") ||
			strings.HasPrefix(kind, "entitlement") {
			return true
		}
	}
	return false
}

func (p *presentation) artifactGraph() {
	if len(p.report.ArtifactNodes) == 0 {
		return
	}
	count := countLabel(len(p.report.ArtifactNodes), "node") + " · " + countLabel(len(p.report.Relationships), "relationship")
	p.section("ARTIFACT GRAPH", count)
	for i, node := range p.report.ArtifactNodes {
		if i >= presentationNodeLimit {
			p.omitted(len(p.report.ArtifactNodes)-i, "artifact nodes")
			break
		}
		line := joinNonEmpty([]string{node.Kind, node.AnalyzeStatus, node.LogicalPath}, " · ")
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(line, textLineRuneLimit))
		if len(node.Architectures) > 0 {
			p.detail("    ", "architectures", strings.Join(sortedStrings(node.Architectures), ", "))
		}
		if node.PackagingTechnology != "" {
			p.detail("    ", "packaging", node.PackagingTechnology)
		}
		if node.DeclaredEntryCount != nil {
			p.detail("    ", "declared entries", strconv.Itoa(*node.DeclaredEntryCount))
		}
		if node.ModeledEntryCount != nil {
			p.detail("    ", "modeled entries", strconv.Itoa(*node.ModeledEntryCount))
		}
		if node.CoverageDetail != "" {
			p.detail("    ", "coverage", node.CoverageDetail)
		}
	}
	relationships := nonContainmentRelationships(p.report.Relationships)
	if len(relationships) == 0 {
		return
	}
	p.printf("  %s %s\n", p.style.key("Relationships"), p.style.faint("("+countLabel(len(relationships), "non-containment relationship")+")"))
	relationshipNodeLabels := make(map[string]string, len(p.report.ArtifactNodes))
	for _, node := range p.report.ArtifactNodes {
		if node.ID != "" && node.LogicalPath != "" {
			relationshipNodeLabels[node.ID] = node.LogicalPath
		}
	}
	for i, relationship := range relationships {
		if i >= presentationRelationshipLimit {
			p.printf("    %s\n", p.style.faint(fmt.Sprintf("... %d more non-containment relationships (use --json for the complete report)", len(relationships)-i)))
			break
		}
		line := relationship.Kind + " · " + presentationRelationshipEndpoints(relationship, relationshipNodeLabels)
		if relationship.Ordinal != nil {
			line += fmt.Sprintf(" · ordinal %d", *relationship.Ordinal)
		}
		p.printf("    %s %s\n", p.style.marker("◆"), boundedText(line, textLineRuneLimit))
	}
}

func nonContainmentRelationships(relationships []artifact.Edge) []artifact.Edge {
	var out []artifact.Edge
	for _, relationship := range relationships {
		if relationship.Kind != "contains" {
			out = append(out, relationship)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return presentationRelationshipSortKey(out[i]) < presentationRelationshipSortKey(out[j])
	})
	return out
}

func presentationRelationshipSortKey(relationship artifact.Edge) string {
	ordinal := "~"
	if relationship.Ordinal != nil {
		ordinal = fmt.Sprintf("%020d", *relationship.Ordinal)
	}
	return strings.Join([]string{relationship.From, relationship.Kind, ordinal, relationship.To}, "\x00")
}

func presentationRelationshipEndpoints(relationship artifact.Edge, labels map[string]string) string {
	from := firstPresentationValue(labels[relationship.From], relationship.From, "unknown source")
	to := firstPresentationValue(labels[relationship.To], relationship.To, "unknown target")
	return from + " → " + to
}

func (p *presentation) operations() {
	if len(p.report.Operations) == 0 {
		return
	}
	p.section("MODELED OPERATIONS", countLabel(len(p.report.Operations), "operation"))
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	annotateSources := len(nodeLabels) > 1
	for i, operation := range p.report.Operations {
		if i >= presentationOperationLimit {
			p.omitted(len(p.report.Operations)-i, "modeled operations")
			break
		}
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(string(operation.Kind), textLineRuneLimit))
		p.detail("    ", "support", string(operation.Support))
		p.executionContextDetails("    ", operation.Execution)
		for _, binding := range operation.ResourceBindings {
			if resource := resourceText(binding.Resource); resource != "" {
				p.detail("    ", string(binding.Role), resource)
			}
		}
		if annotateSources && nodeLabels[operation.SubjectNodeID] != "" {
			p.detail("    ", "source", nodeLabels[operation.SubjectNodeID])
		}
		if operation.SourceFunction != "" {
			p.detail("    ", "source function", displayFunctionName(operation.SourceFunction))
		}
		if operation.Architecture != "" {
			p.detail("    ", "architecture", operation.Architecture)
		}
		keys := make([]string, 0, len(operation.Qualifiers))
		for key := range operation.Qualifiers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for j, key := range keys {
			if j >= textQualifierLimit {
				p.detail("    ", "qualifier", fmt.Sprintf("... %d more", len(keys)-j))
				break
			}
			label := key
			if key == "function" && operation.SourceFunction != "" {
				label = "symbol"
			}
			p.detail("    ", label, operation.Qualifiers[key])
		}
		for j, evidenceID := range operation.EvidenceIDs {
			if j >= textEvidenceLimit {
				p.detail("    ", "evidence", fmt.Sprintf("... %d more", len(operation.EvidenceIDs)-j))
				break
			}
			if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
				p.detail("    ", "evidence", evidenceText(*evidence))
			}
		}
	}
}

func (p *presentation) features() {
	if len(p.report.Features) == 0 {
		return
	}
	retained := uniqueFeatures(p.report.Features)
	items := visibleFeaturesForText(p.report.Features)
	count := countLabel(len(items), "feature")
	if len(items) != len(retained) || len(items) > textSectionLimit {
		count = fmt.Sprintf("%d shown · %d retained", min(len(items), textSectionLimit), len(retained))
	}
	p.section("FEATURES", count)
	nodeLabels := artifactPropertiesSourceLabels(p.report)
	annotateSources := len(nodeLabels) > 1
	for i, feature := range items {
		if i >= textSectionLimit {
			p.omitted(len(items)-i, "Features")
			break
		}
		line := staticFeatureDisplayKey(feature) + " = " + feature.Value
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(line, textLineRuneLimit))
		p.detail("    ", "support", string(feature.Support))
		p.executionContextDetails("    ", feature.Execution)
		if annotateSources && nodeLabels[feature.NodeID] != "" {
			p.detail("    ", "source", nodeLabels[feature.NodeID])
		}
		if feature.SourceFunction != "" {
			p.detail("    ", "source function", displayFunctionName(feature.SourceFunction))
		}
		keys := make([]string, 0, len(feature.Qualifiers))
		for key := range feature.Qualifiers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for j, key := range keys {
			if j >= textQualifierLimit {
				p.detail("    ", "qualifier", fmt.Sprintf("... %d more", len(keys)-j))
				break
			}
			label := key
			if key == "function" && feature.SourceFunction != "" {
				label = "symbol"
			}
			p.detail("    ", label, feature.Qualifiers[key])
		}
		for j, evidenceID := range feature.EvidenceIDs {
			if j >= textEvidenceLimit {
				p.detail("    ", "evidence", fmt.Sprintf("... %d more", len(feature.EvidenceIDs)-j))
				break
			}
			if evidence := evidenceViewByID(p.evidence, evidenceID); evidence != nil {
				p.detail("    ", "evidence", evidenceText(*evidence))
			}
		}
	}
	hidden := len(retained) - len(items)
	if hidden > 0 {
		p.printf("  %s\n", p.style.faint(fmt.Sprintf("... %d lower-priority Features omitted; use --format json for every retained Feature", hidden)))
	}
}

func (p *presentation) executionContextDetails(indent string, context behavior.ExecutionContext) {
	p.detail(indent, "execution", string(executionConnectivity(context)))
	if len(context.ExecutionRootIDs) > 0 {
		p.detail(indent, "execution roots", strings.Join(context.ExecutionRootIDs, ", "))
	}
	if len(context.InvokedTargetIDs) > 0 {
		p.detail(indent, "invoked targets", strings.Join(context.InvokedTargetIDs, ", "))
	}
}

func (p *presentation) coverageAndNotes() {
	coverage := coverageForPresentation(p.report.Coverage)
	diagnostics := diagnosticsForText(p.report.Diagnostics)
	count := countLabel(len(coverage), "coverage note")
	if len(diagnostics) > 0 {
		count += " · " + countLabel(len(diagnostics), "diagnostic")
	}
	p.section("COVERAGE & NOTES", count)
	for i, item := range coverage {
		if i >= textSectionLimit {
			p.omitted(len(coverage)-i, "coverage notes")
			break
		}
		line := joinNonEmpty([]string{item.AnalysisArea, item.Status}, " · ")
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText(line, textLineRuneLimit))
		if item.Detail != "" {
			p.detail("    ", "detail", item.Detail)
		}
	}
	for i, diagnostic := range diagnostics {
		if i >= textSectionLimit {
			p.omitted(len(diagnostics)-i, "diagnostics")
			break
		}
		p.printf("  %s %s\n", p.style.marker("◆"), boundedText("diagnostic: "+diagnostic, textLineRuneLimit))
	}
	if len(coverage) == 0 && len(diagnostics) == 0 {
		p.println("  No additional extractor-specific limitation details were recorded.")
	}
	p.println("  Static analysis is bounded and does not execute the target; review unresolved and partial coverage.")
	switch p.options.Verbosity {
	case TextConcise:
		p.println(p.style.faint("  Use --detail evidence for rule mappings and evidence; --detail full for modeled operations and Features; --format json for the complete deterministic report."))
	case TextVerbose:
		p.println(p.style.faint("  Use --detail full for the artifact graph, modeled operations, and Features; --format json for every retained object."))
	default:
		p.println(p.style.faint("  Use --format json for complete, deterministic, evidence-addressable output."))
	}
}

func (p *presentation) omitted(count int, kind string) {
	if count <= 0 {
		return
	}
	p.printf("  %s\n", p.style.faint(fmt.Sprintf("... %d more %s (use --format json for the complete report)", count, kind)))
}

type rulePresentationMetadata struct {
	ID             string
	Title          string
	Namespace      string
	Description    string
	Attack         []string
	MBC            []string
	Kind           rules.RuleKind
	MinimumSupport behavior.Support
	LibraryRuleIDs []string
}

func ruleMetadata(info RuleInfo) []rulePresentationMetadata {
	out := make([]rulePresentationMetadata, 0, len(info.Rules))
	for _, item := range info.Rules {
		out = append(out, rulePresentationMetadata{
			ID: item.ID, Title: item.Title, Namespace: item.Namespace,
			Description: item.Description,
			Attack:      append([]string(nil), item.Attack...), MBC: append([]string(nil), item.MBC...),
			Kind: item.Kind, MinimumSupport: item.MinimumSupport, LibraryRuleIDs: append([]string(nil), item.LibraryRuleIDs...),
		})
	}
	return out
}

func metadataByRuleID() map[string]rulePresentationMetadata {
	out := make(map[string]rulePresentationMetadata)
	for _, item := range ruleMetadata(ListRules()) {
		out[item.ID] = item
	}
	return out
}

func writeMappings(w *trackingWriter, style presentationStyle, attack, mbc []string, indent string) {
	if values := sortedStrings(attack); len(values) > 0 {
		w.printf("%s%s  %s\n", indent, style.faint(fmt.Sprintf("%-12s", "ATT&CK")), boundedText(strings.Join(values, ", "), textLineRuneLimit))
	}
	if values := sortedStrings(mbc); len(values) > 0 {
		w.printf("%s%s  %s\n", indent, style.faint(fmt.Sprintf("%-12s", "MBC")), boundedText(strings.Join(values, ", "), textLineRuneLimit))
	}
}

func sortedCapabilityMatchGroups(capabilityMatches []behavior.CapabilityMatch) []capabilityMatchTextGroup {
	groups := groupCapabilityMatches(capabilityMatches)
	sort.SliceStable(groups, func(i, j int) bool {
		left, right := groups[i].capabilityMatch, groups[j].capabilityMatch
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.Title != right.Title {
			return left.Title < right.Title
		}
		if left.Support != right.Support {
			return left.Support < right.Support
		}
		if leftExecution, rightExecution := executionContextIdentityKey(left.Execution), executionContextIdentityKey(right.Execution); leftExecution != rightExecution {
			return leftExecution < rightExecution
		}
		return resourcesKey(left.AffectedResources) < resourcesKey(right.AffectedResources)
	})
	return groups
}

func namespaceLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "uncategorized"
	}
	return value
}

func firstPresentationValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func artifactType(report Report) string {
	for _, node := range report.ArtifactNodes {
		if node.ParentID != "" {
			continue
		}
		return joinNonEmpty([]string{node.Kind, node.MediaType}, " · ")
	}
	if len(report.ArtifactNodes) > 0 {
		return joinNonEmpty([]string{report.ArtifactNodes[0].Kind, report.ArtifactNodes[0].MediaType}, " · ")
	}
	return "not reported"
}

func analysisSummary(metadata AnalysisMetadata) string {
	if !analysisMetadataAvailable(metadata) {
		return "settings not reported"
	}
	var parts []string
	if metadata.Architecture != "" {
		parts = append(parts, "architecture "+metadata.Architecture)
	}
	if metadata.IncludeUnreferenced {
		parts = append(parts, "unreferenced content included")
	} else {
		parts = append(parts, "execution-relevant content")
	}
	if metadata.ExpandContainers {
		parts = append(parts, "container expansion enabled")
	} else {
		parts = append(parts, "container expansion disabled")
	}
	if metadata.AllowDMGMount {
		parts = append(parts, "read-only DMG mounting allowed")
	}
	if metadata.ZipPasswordSupplied {
		parts = append(parts, "ZIP password supplied")
	}
	return strings.Join(parts, " · ")
}

func artifactStatusSummary(report Report) string {
	counts := map[string]int{}
	for _, node := range report.ArtifactNodes {
		status := strings.TrimSpace(node.AnalyzeStatus)
		if status != "" {
			counts[status]++
		}
	}
	var parts []string
	for _, status := range []string{"analyzed", "partial", "skipped"} {
		if counts[status] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[status], status))
			delete(counts, status)
		}
	}
	var other []string
	for status := range counts {
		other = append(other, status)
	}
	sort.Strings(other)
	for _, status := range other {
		parts = append(parts, fmt.Sprintf("%d %s", counts[status], status))
	}
	limitations := CoverageLimitationCount(report.Coverage)
	if limitations > 0 {
		parts = append(parts, countLabel(limitations, "analysis limitation"))
	}
	return strings.Join(parts, " · ")
}

// CoverageLimitationCount returns the human-facing number of distinct coverage
// limitations after repetitive architecture-specific records are folded. It is
// shared by terminal and HTML presentation so their overview counts agree.
func CoverageLimitationCount(items []behavior.Coverage) int {
	limitations := 0
	for _, item := range coverageForPresentation(items) {
		if item.Status != "analyzed" {
			limitations++
		}
	}
	return limitations
}

// coverageForPresentation folds identical architecture-specific limitations
// into one human-facing note. The report retains every original coverage
// object; this only removes repetitive terminal output.
func coverageForPresentation(items []behavior.Coverage) []behavior.Coverage {
	type key struct {
		scope              string
		status             string
		detail             string
		architectureScoped bool
	}
	var out []behavior.Coverage
	indexes := map[key]int{}
	architectures := map[key][]string{}
	for _, item := range visibleCoverage(uniqueCoverage(items)) {
		base, arch := coverageScopeArchitecture(item.AnalysisArea)
		itemKey := key{scope: base, status: item.Status, detail: item.Detail, architectureScoped: arch != ""}
		if _, exists := indexes[itemKey]; !exists {
			indexes[itemKey] = len(out)
			out = append(out, item)
		}
		if arch != "" {
			architectures[itemKey] = append(architectures[itemKey], arch)
		}
	}
	for itemKey, values := range architectures {
		values = sortedStrings(values)
		if len(values) > 1 {
			out[indexes[itemKey]].AnalysisArea = itemKey.scope + " (" + strings.Join(values, ", ") + ")"
		}
	}
	return out
}

func coverageScopeArchitecture(scope string) (string, string) {
	index := strings.LastIndexByte(scope, '/')
	if index < 0 || index+1 >= len(scope) {
		return scope, ""
	}
	arch := scope[index+1:]
	if arch != "arm64" && arch != "x86_64" {
		return scope, ""
	}
	return scope[:index], arch
}

func sortedResources(resources []behavior.Resource) []behavior.Resource {
	out := append([]behavior.Resource(nil), resources...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return resourceClassificationText(out[i]) < resourceClassificationText(out[j])
	})
	return out
}

func resourceText(resource behavior.Resource) string {
	kind := string(resource.Kind)
	if classifications := resourceClassificationText(resource); classifications != "" {
		kind += " [" + classifications + "]"
	}
	switch {
	case kind != "" && resource.Value != "":
		return kind + ": " + resource.Value
	case resource.Value != "":
		return resource.Value
	case kind != "":
		if !resource.Unresolved() {
			return kind
		}
		return kind + ": (unresolved)"
	default:
		return ""
	}
}

func resourceClassificationText(resource behavior.Resource) string {
	values := make([]string, len(resource.Classifications))
	for index, classification := range resource.Classifications {
		values[index] = string(classification)
	}
	return strings.Join(values, ", ")
}

func countLabel(count int, singular string) string {
	label := singular
	if count != 1 {
		switch {
		case strings.HasSuffix(singular, "match"):
			label += "es"
		case strings.HasSuffix(singular, "y") && len(singular) > 1 && !strings.ContainsRune("aeiou", rune(singular[len(singular)-2])):
			label = singular[:len(singular)-1] + "ies"
		default:
			label += "s"
		}
	}
	return fmt.Sprintf("%d %s", count, label)
}

func executionInventoryCount(inventory presentationExecutionInventory) string {
	return countLabel(len(inventory.roots), "execution root") + " · " + countLabel(len(inventory.targets), "invoked target")
}

func packagingTechnologySummary(nodes []artifact.Node) string {
	seen := map[string]bool{}
	var technologies []string
	for _, node := range nodes {
		technology := strings.TrimSpace(node.PackagingTechnology)
		if technology == "" || seen[technology] {
			continue
		}
		seen[technology] = true
		technologies = append(technologies, technology)
	}
	sort.Strings(technologies)
	if len(technologies) <= presentationPackagingLimit {
		return strings.Join(technologies, ", ")
	}
	return strings.Join(technologies[:presentationPackagingLimit], ", ") + fmt.Sprintf(" · %d more", len(technologies)-presentationPackagingLimit)
}
