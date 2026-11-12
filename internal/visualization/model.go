package visualization

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/terminal"
)

const (
	visualizationSchema = "maratus.visualization.v0.15"
	maxReferenceBytes   = 512
	maxDetailRows       = 20
	maxListItems        = 12
	maxReviewItems      = 32
	maxDiagnosticItems  = 20
	maxQualifierKeys    = 128
	maxRelationshipScan = hardLinkLimit * 4
	// A loaded report cannot retain more behavior items than this across all
	// behavior collections. Keep the standalone Write API bounded too while
	// still establishing reference uniqueness for every valid loaded report.
	maxReferenceTailScan = behavior.DefaultItemLimit + 1
)

type visualDocument struct {
	SchemaVersion     string                  `json:"schema_version"`
	Title             string                  `json:"title"`
	Artifact          string                  `json:"artifact"`
	Tool              string                  `json:"tool,omitempty"`
	ToolVersion       string                  `json:"tool_version,omitempty"`
	ToolCommit        string                  `json:"tool_commit,omitempty"`
	ToolModified      bool                    `json:"tool_modified"`
	Ruleset           string                  `json:"ruleset_version,omitempty"`
	RuleCatalogDigest string                  `json:"rule_catalog_digest,omitempty"`
	Analysis          report.AnalysisMetadata `json:"analysis"`
	Source            visualCounts            `json:"source_counts"`
	Shown             visualCounts            `json:"shown_counts"`
	Summary           visualSummary           `json:"summary"`
	Projection        visualProjection        `json:"projection"`
	Nodes             []visualNode            `json:"nodes"`
	Links             []visualLink            `json:"links"`
	Diagnostics       []string                `json:"diagnostics"`
	Omissions         []string                `json:"omission_notes"`
}

type visualSummary struct {
	Capabilities        int `json:"capabilities"`
	DirectMatches       int `json:"direct_matches"`
	CorroboratedMatches int `json:"corroborated_matches"`
	HeuristicMatches    int `json:"heuristic_matches"`
	ConnectedMatches    int `json:"connected_matches"`
	UnconnectedMatches  int `json:"unconnected_matches"`
	UnknownMatches      int `json:"unknown_matches"`
	AnalyzedArtifacts   int `json:"analyzed_artifacts"`
	CoverageLimitations int `json:"coverage_limitations"`
}

type visualProjection struct {
	SelectedMembers       string                       `json:"selected_members,omitempty"`
	ArtifactType          string                       `json:"artifact_type"`
	SchemaVersion         string                       `json:"schema_version"`
	ConditionalActivation []visualProjectionActivation `json:"conditional_activation"`
	ModeledBehavior       []visualProjectionBehavior   `json:"modeled_behavior"`
	Capabilities          []visualProjectionCapability `json:"capabilities"`
	CodeContext           []visualProjectionCode       `json:"code_context"`
	CodeContextOmitted    int                          `json:"code_context_omitted,omitempty"`
	StaticObservables     []visualProjectionObservable `json:"static_observables"`
	ArtifactContext       []visualProjectionArtifact   `json:"artifact_context"`
	NetworkActivity       []visualProjectionNetwork    `json:"network_activity"`
	Coverage              []visualProjectionCoverage   `json:"coverage"`
}

type visualProjectionActivation struct {
	Context      []string `json:"context,omitempty"`
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name,omitempty"`
	Interpreter  string   `json:"interpreter,omitempty"`
	Connectivity string   `json:"connectivity,omitempty"`
}

type visualProjectionBehavior struct {
	GroupID            string   `json:"group_id"`
	Kind               string   `json:"kind"`
	Count              int      `json:"count"`
	OperationIDs       []string `json:"operation_ids"`
	Support            string   `json:"support"`
	Connectivity       string   `json:"connectivity"`
	Resources          []string `json:"resources"`
	Implementations    []string `json:"implementations"`
	RequestedArguments []string `json:"requested_arguments,omitempty"`
	Unresolved         []string `json:"unresolved"`
}

type visualProjectionCapability struct {
	GroupID               string   `json:"group_id"`
	RuleID                string   `json:"rule_id"`
	Category              string   `json:"category"`
	Title                 string   `json:"title"`
	Namespace             string   `json:"namespace,omitempty"`
	Count                 int      `json:"count"`
	MatchIDs              []string `json:"match_ids"`
	OperationIDs          []string `json:"operation_ids"`
	OperationCount        int      `json:"operation_count"`
	OperationCountLimited bool     `json:"operation_count_limited,omitempty"`
	Support               string   `json:"support"`
	Connectivity          string   `json:"connectivity"`
	Attack                []string `json:"attack"`
	Resources             []string `json:"resources"`
	Implementations       []string `json:"implementations"`
	Unresolved            []string `json:"unresolved"`
}

type visualProjectionCode struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Origin       string `json:"origin"`
	LogicalPath  string `json:"logical_path,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

type visualProjectionObservable struct {
	Category string `json:"category"`
	Value    string `json:"value"`
}

type visualProjectionArtifact struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Support string `json:"support,omitempty"`
	Count   int    `json:"count,omitempty"`
}

type visualProjectionNetwork struct {
	Direction      string   `json:"direction,omitempty"`
	Destinations   []string `json:"destinations"`
	Implementation string   `json:"implementation,omitempty"`
	Support        string   `json:"support,omitempty"`
	Unresolved     []string `json:"unresolved"`
	StaticOnly     bool     `json:"static_only"`
}

type visualProjectionCoverage struct {
	Area   string `json:"area"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func boundedVisualProjection(rep report.Report) visualProjection {
	projection, _ := buildVisualProjection(rep)
	return projection
}

// Group membership is retained separately from the bounded display strings.
// It associates rendered instances with their exact summary row without a
// textual search or an unbounded list of IDs in the HTML payload.
func buildVisualProjection(rep report.Report) (visualProjection, map[string]string) {
	summary := report.ProjectSummary(rep)
	membership := make(map[string]string)
	projection := visualProjection{
		SchemaVersion: summary.SchemaVersion, ArtifactType: terminal.EscapeTruncate(summary.Overview.ArtifactType, maxReferenceBytes), SelectedMembers: summary.Overview.SelectedMemberTypes(),
		ConditionalActivation: make([]visualProjectionActivation, 0, min(len(summary.ConditionalActivation), maxReviewItems)),
		ModeledBehavior:       make([]visualProjectionBehavior, 0, min(len(summary.ModeledBehavior), maxReviewItems)),
		Capabilities:          make([]visualProjectionCapability, 0, min(len(summary.Capabilities), maxReviewItems)),
		CodeContext:           make([]visualProjectionCode, 0, min(len(summary.CodeContext), maxReviewItems)),
		CodeContextOmitted:    summary.CodeContextOmitted,
		StaticObservables:     make([]visualProjectionObservable, 0, min(len(summary.StaticObservables), maxReviewItems)),
		ArtifactContext:       make([]visualProjectionArtifact, 0, min(len(summary.ArtifactContext), maxReviewItems)),
		NetworkActivity:       make([]visualProjectionNetwork, 0, min(len(summary.NetworkActivity), maxReviewItems)),
		Coverage:              make([]visualProjectionCoverage, 0, min(len(summary.CoverageGapsAndLimits), maxReviewItems)),
	}
	for _, item := range summary.ConditionalActivation[:min(len(summary.ConditionalActivation), maxReviewItems)] {
		var details []string
		if item.EntryPath != "" {
			details = append(details, terminal.EscapeTruncate(item.EntryPath, maxReferenceBytes))
		}
		for _, arg := range item.Arguments[:min(len(item.Arguments), 6)] {
			if arg != item.EntryPath {
				details = append(details, terminal.EscapeTruncate(arg, maxReferenceBytes))
			}
		}
		for _, fact := range item.Context[:min(len(item.Context), 8)] {
			details = append(details, fact.Label+" "+terminal.EscapeTruncate(fact.Value, maxReferenceBytes))
		}
		projection.ConditionalActivation = append(projection.ConditionalActivation, visualProjectionActivation{
			Context: details, ID: terminal.EscapeTruncate(item.ID, maxReferenceBytes),
			Kind: terminal.EscapeTruncate(item.Kind, maxReferenceBytes), Name: terminal.EscapeTruncate(item.Name, maxReferenceBytes),
			Interpreter: terminal.EscapeTruncate(item.Interpreter, maxReferenceBytes), Connectivity: terminal.EscapeTruncate(string(item.Execution.Connectivity), maxReferenceBytes),
		})
	}
	for index, item := range summary.ModeledBehavior[:min(len(summary.ModeledBehavior), maxReviewItems)] {
		group := visualID("behavior-group", index)
		addReviewMembership(membership, "operation", group, item.OperationIDs)
		projection.ModeledBehavior = append(projection.ModeledBehavior, visualProjectionBehavior{
			GroupID: group,
			Kind:    terminal.EscapeTruncate(string(item.Kind), maxReferenceBytes), Count: item.Count,
			OperationIDs: boundedProjectionStrings(item.OperationIDs),
			Support:      terminal.EscapeTruncate(string(item.Support), maxReferenceBytes), Connectivity: terminal.EscapeTruncate(string(item.Connectivity), maxReferenceBytes),
			Resources: boundedProjectionResources(item.Resources), Implementations: boundedProjectionStrings(item.Implementations), Unresolved: boundedProjectionStrings(item.Unresolved),
			RequestedArguments: boundedProjectionStrings(item.RequestedArguments),
		})
	}
	projection.Capabilities = boundedVisualCapabilities(summary.Capabilities, membership)
	for _, item := range summary.CodeContext[:min(len(summary.CodeContext), maxReviewItems)] {
		projection.CodeContext = append(projection.CodeContext, visualProjectionCode{
			Kind: terminal.EscapeTruncate(item.Kind, maxReferenceBytes), Name: terminal.EscapeTruncate(item.Name, maxReferenceBytes),
			Origin: terminal.EscapeTruncate(item.Origin, maxReferenceBytes), LogicalPath: terminal.EscapeTruncate(item.LogicalPath, maxReferenceBytes), Architecture: terminal.EscapeTruncate(item.Architecture, maxReferenceBytes),
		})
	}
	if len(summary.CodeContext) > maxReviewItems {
		projection.CodeContextOmitted += len(summary.CodeContext) - maxReviewItems
	}
	projection.ArtifactContext = boundedVisualArtifactContext(summary.ArtifactContext)
	for _, item := range summary.StaticObservables[:min(len(summary.StaticObservables), maxReviewItems)] {
		projection.StaticObservables = append(projection.StaticObservables, visualProjectionObservable{
			Category: terminal.EscapeTruncate(item.Category, maxReferenceBytes),
			Value:    terminal.EscapeTruncate(item.Value, maxReferenceBytes),
		})
	}
	for _, item := range summary.NetworkActivity[:min(len(summary.NetworkActivity), maxReviewItems)] {
		destinations := append([]string(nil), item.Destinations[:min(len(item.Destinations), maxReviewItems)]...)
		for index := range destinations {
			destinations[index] = terminal.EscapeTruncate(destinations[index], maxReferenceBytes)
		}
		projection.NetworkActivity = append(projection.NetworkActivity, visualProjectionNetwork{
			Direction: terminal.EscapeTruncate(item.Direction, maxReferenceBytes), Destinations: destinations,
			Implementation: terminal.EscapeTruncate(item.Implementation, maxReferenceBytes), Support: terminal.EscapeTruncate(string(item.Support), maxReferenceBytes),
			Unresolved: boundedProjectionStrings(item.Unresolved), StaticOnly: item.StaticOnly,
		})
	}
	for _, group := range groupCoverage(coverageLimitations(rep.Coverage)) {
		if len(projection.Coverage) == maxReviewItems {
			break
		}
		item := group.item
		projection.Coverage = append(projection.Coverage, visualProjectionCoverage{
			Area: terminal.EscapeTruncate(item.AnalysisArea, maxReferenceBytes), Status: terminal.EscapeTruncate(item.Status, maxReferenceBytes), Detail: terminal.EscapeTruncate(item.Detail, maxReferenceBytes),
		})
	}
	return projection, membership
}

func boundedVisualCapabilities(items []report.SummaryCapability, membership map[string]string) []visualProjectionCapability {
	type key struct{ category, rule, title, namespace string }
	indexes := make(map[key]int, len(items))
	rows := make([]visualProjectionCapability, 0, min(len(items), maxReviewItems))
	operationSets := make([]map[string]struct{}, 0, maxReviewItems)
	for _, item := range items {
		identity := key{string(item.Category), item.RuleID, item.Title, item.Namespace}
		index, exists := indexes[identity]
		if !exists {
			if len(rows) == maxReviewItems {
				continue
			}
			index = len(rows)
			indexes[identity] = index
			operationSets = append(operationSets, make(map[string]struct{}))
			rows = append(rows, visualProjectionCapability{
				GroupID: visualID("capability-group", index), RuleID: terminal.EscapeTruncate(item.RuleID, maxReferenceBytes),
				Category: terminal.EscapeTruncate(string(item.Category), maxReferenceBytes),
				Title:    terminal.EscapeTruncate(item.Title, maxReferenceBytes), Namespace: terminal.EscapeTruncate(item.Namespace, maxReferenceBytes),
				Support: terminal.EscapeTruncate(string(item.Support), maxReferenceBytes), Connectivity: terminal.EscapeTruncate(string(item.Connectivity), maxReferenceBytes),
			})
		}
		row := &rows[index]
		addReviewMembership(membership, "capability", row.GroupID, item.MatchIDs)
		row.Count += item.Count
		row.MatchIDs = appendUniqueProjectionStrings(row.MatchIDs, item.MatchIDs...)
		row.OperationIDs = appendUniqueProjectionStrings(row.OperationIDs, item.OperationIDs...)
		for _, id := range item.OperationIDs {
			if id == "" {
				continue
			}
			if _, exists := operationSets[index][id]; exists {
				continue
			}
			if len(operationSets[index]) == maxReferenceTailScan || len(id) > maxReferenceBytes {
				row.OperationCountLimited = true
				continue
			}
			operationSets[index][id] = struct{}{}
		}
		row.OperationCount = len(operationSets[index])
		row.Support = joinedProjectionState(row.Support, string(item.Support))
		row.Connectivity = joinedProjectionState(row.Connectivity, string(item.Connectivity))
		row.Attack = appendUniqueProjectionStrings(row.Attack, item.Attack...)
		row.Resources = appendUniqueProjectionResources(row.Resources, item.AffectedResources...)
		row.Implementations = appendUniqueProjectionStrings(row.Implementations, item.Implementations...)
		row.Unresolved = appendUniqueProjectionStrings(row.Unresolved, item.Unresolved...)
	}
	return rows
}

func addReviewMembership(membership map[string]string, kind, group string, ids []string) {
	for _, id := range ids[:min(len(ids), maxReferenceTailScan)] {
		if id != "" && len(id) <= maxReferenceBytes && len(membership) < maxReferenceTailScan {
			membership[kind+"\x00"+id] = group
		}
	}
}

func boundedVisualArtifactContext(items []report.SummaryArtifactContext) []visualProjectionArtifact {
	type key struct{ kind, value, support string }
	indexes := make(map[key]int, len(items))
	rows := make([]visualProjectionArtifact, 0, min(len(items), maxReviewItems))
	for _, item := range items {
		identity := key{item.Kind, item.Value, string(item.Support)}
		index, exists := indexes[identity]
		if !exists {
			if len(rows) == maxReviewItems {
				continue
			}
			index = len(rows)
			indexes[identity] = index
			rows = append(rows, visualProjectionArtifact{
				Kind: terminal.EscapeTruncate(item.Kind, maxReferenceBytes), Value: terminal.EscapeTruncate(item.Value, maxReferenceBytes),
				Support: terminal.EscapeTruncate(string(item.Support), maxReferenceBytes),
			})
		}
		rows[index].Count++
	}
	return rows
}

func joinedProjectionState(current, value string) string {
	value = terminal.EscapeTruncate(value, maxReferenceBytes)
	if current == "" || current == value {
		return value
	}
	parts := strings.Split(current, " + ")
	for _, part := range parts {
		if part == value {
			return current
		}
	}
	parts = append(parts, value)
	sort.Strings(parts)
	return terminal.EscapeTruncate(strings.Join(parts, " + "), maxReferenceBytes)
}

func appendUniqueProjectionStrings(target []string, values ...string) []string {
	for _, value := range values {
		value = terminal.EscapeTruncate(value, maxReferenceBytes)
		if value == "" || stringSliceContains(target, value) || len(target) == maxReviewItems {
			continue
		}
		target = append(target, value)
	}
	sort.Strings(target)
	return target
}

func appendUniqueProjectionResources(target []string, values ...behavior.Resource) []string {
	for _, resource := range values {
		if value := strings.TrimSpace(resource.Value); value != "" {
			target = appendUniqueProjectionStrings(target, value)
		}
	}
	return target
}

func boundedProjectionStrings(values []string) []string {
	values = values[:min(len(values), maxListItems)]
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, terminal.EscapeTruncate(value, maxReferenceBytes))
	}
	return out
}

func boundedProjectionResources(bindings []behavior.ResourceBinding) []string {
	values := make([]string, 0, min(len(bindings), maxListItems))
	for _, binding := range bindings[:min(len(bindings), maxListItems)] {
		value := strings.TrimSpace(binding.Resource.Value)
		if value == "" {
			continue
		}
		values = append(values, terminal.EscapeTruncate(string(binding.Role)+": "+value, maxReferenceBytes))
	}
	return values
}

type visualCounts struct {
	Artifacts          int `json:"artifacts"`
	AnalysisSelections int `json:"analysis_selections"`
	ExecutionRoots     int `json:"execution_roots"`
	InvokedTargets     int `json:"invoked_targets"`
	Operations         int `json:"modeled_operations"`
	CapabilityMatches  int `json:"capability_matches"`
	OperationRelations int `json:"operation_relations"`
	Coverage           int `json:"coverage"`
	Diagnostics        int `json:"diagnostics"`
	Links              int `json:"links,omitempty"`
}

type visualNode struct {
	ID           string         `json:"id"`
	RecordID     string         `json:"record_id,omitempty"`
	ReviewGroup  string         `json:"review_group,omitempty"`
	Type         string         `json:"type"`
	Title        string         `json:"title"`
	Subtitle     string         `json:"subtitle,omitempty"`
	Support      string         `json:"support,omitempty"`
	Connectivity string         `json:"connectivity,omitempty"`
	Status       string         `json:"status,omitempty"`
	Details      []visualDetail `json:"details,omitempty"`
}

type visualDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type visualLink struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type visualLinkIdentity struct {
	from string
	to   string
	kind string
}

type visualCoverageGroup struct {
	item        behavior.Coverage
	nodeIDs     []string
	occurrences int
}

type documentBuilder struct {
	doc                      visualDocument
	options                  normalizedOptions
	text                     textBudget
	artifactRefs             referenceIndex
	executionRootRefs        referenceIndex
	invokedTargetRefs        referenceIndex
	operationRefs            referenceIndex
	capabilityRefs           referenceIndex
	reviewGroups             map[string]string
	artifactPaths            map[string]string
	evidence                 map[string]behavior.Evidence
	ambiguousEvidence        map[string]struct{}
	artifactPropertiesByNode map[string][]behavior.ArtifactProperty
	networkByOperation       map[string][]behavior.NetworkImplementationObservation
	linkKeys                 map[visualLinkIdentity]struct{}
	linksDropped             int
	traversalDrops           int
	oversizedRefs            int
	unresolvedRefs           int
	duplicateRefs            int
	ambiguousRefs            int
	detailDrops              int
	unscannedRefs            int
	indeterminateRefs        int
	evidenceDrops            int
	evidenceUnscanned        int
	contextDrops             int
	operationRelationsShown  int
}

type textBudget struct {
	remaining int
	perString int
	truncated int
	escaped   int
	exhausted bool
}

type referenceIndex struct {
	resolved  map[string]string
	ambiguous map[string]struct{}
}

func newReferenceIndex() referenceIndex {
	return referenceIndex{resolved: make(map[string]string), ambiguous: make(map[string]struct{})}
}

func buildDocument(rep report.Report, options normalizedOptions, adjustments []string) visualDocument {
	source := visualCounts{
		Artifacts: len(rep.ArtifactNodes), AnalysisSelections: len(rep.AnalysisSelection),
		ExecutionRoots: len(rep.ExecutionRoots), InvokedTargets: len(rep.InvokedTargets), Operations: len(rep.Operations),
		CapabilityMatches: len(rep.Capabilities), OperationRelations: len(rep.OperationRelations), Coverage: len(rep.Coverage), Diagnostics: len(rep.Diagnostics),
	}
	b := documentBuilder{
		options:                  options,
		text:                     textBudget{remaining: options.textBytes, perString: options.stringBytes},
		artifactRefs:             newReferenceIndex(),
		executionRootRefs:        newReferenceIndex(),
		invokedTargetRefs:        newReferenceIndex(),
		operationRefs:            newReferenceIndex(),
		capabilityRefs:           newReferenceIndex(),
		artifactPaths:            make(map[string]string),
		evidence:                 make(map[string]behavior.Evidence),
		ambiguousEvidence:        make(map[string]struct{}),
		artifactPropertiesByNode: make(map[string][]behavior.ArtifactProperty),
		networkByOperation:       make(map[string][]behavior.NetworkImplementationObservation),
		linkKeys:                 make(map[visualLinkIdentity]struct{}),
	}
	b.doc = visualDocument{
		SchemaVersion: visualizationSchema,
		Source:        source,
		Nodes:         make([]visualNode, 0),
		Links:         make([]visualLink, 0),
		Diagnostics:   make([]string, 0),
		Omissions:     append(make([]string, 0, len(adjustments)), adjustments...),
	}
	b.doc.Projection, b.reviewGroups = buildVisualProjection(rep)
	b.doc.Summary = summarizeReport(rep)
	title := options.title
	if title == "" {
		title = "Maratus analysis map"
	}
	b.doc.Title = b.keep(title)
	b.doc.Artifact = b.keep(rep.Artifact)
	b.doc.Tool = b.keep(rep.Tool)
	b.doc.ToolVersion = b.keep(rep.ToolVersion)
	b.doc.ToolCommit = b.keep(rep.ToolCommit)
	b.doc.ToolModified = rep.ToolModified
	b.doc.Ruleset = b.keep(rep.RulesetVersion)
	b.doc.RuleCatalogDigest = b.keep(rep.RuleCatalogDigest)
	b.doc.Analysis = b.boundedAnalysisMetadata(rep.Analysis)
	b.indexReferences(b.artifactRefs, "artifact", min(len(rep.ArtifactNodes), b.options.artifactNodes), len(rep.ArtifactNodes), func(i int) string { return rep.ArtifactNodes[i].ID })
	b.indexReferences(b.executionRootRefs, "execution-root", min(len(rep.ExecutionRoots), b.options.executionRoots), len(rep.ExecutionRoots), func(i int) string { return rep.ExecutionRoots[i].ID })
	b.indexReferences(b.invokedTargetRefs, "invoked-target", min(len(rep.InvokedTargets), b.options.invokedTargets), len(rep.InvokedTargets), func(i int) string { return rep.InvokedTargets[i].ID })
	b.indexReferences(b.operationRefs, "operation", min(len(rep.Operations), b.options.modeledOperations), len(rep.Operations), func(i int) string { return rep.Operations[i].ID })
	b.indexReferences(b.capabilityRefs, "capability", min(len(rep.Capabilities), b.options.capabilityMatches), len(rep.Capabilities), func(i int) string { return rep.Capabilities[i].ID })
	b.indexEvidence(rep.Evidence)
	b.indexArtifactProperty(rep.ArtifactProperties)
	b.indexNetwork(rep.NetworkImplementations)
	b.addDiagnostics(rep.Diagnostics)
	coverageItems := coverageLimitations(rep.Coverage)
	coverage := groupCoverage(coverageItems)
	if len(coverage) < len(coverageItems) {
		b.doc.Omissions = append(b.doc.Omissions, fmt.Sprintf(
			"Coverage records: %d source records with identical scope, status, and detail were folded into %d graph nodes; affected artifact links are retained and complete records remain in JSON.",
			len(coverageItems), len(coverage),
		))
	}
	if len(rep.Features) > 0 || len(rep.Evidence) > 0 || len(rep.ArtifactProperties) > 0 || len(rep.NetworkImplementations) > 0 {
		b.doc.Omissions = append(b.doc.Omissions, fmt.Sprintf(
			"Report-only detail: %d Features, %d evidence records, %d artifact property records, and %d network/TLS observation records are not separate graph nodes; referenced details are summarized on related nodes and complete objects remain in JSON.",
			len(rep.Features), len(rep.Evidence), len(rep.ArtifactProperties), len(rep.NetworkImplementations),
		))
	}

	b.addArtifacts(rep.ArtifactNodes)
	b.addAnalysisSelections(rep.AnalysisSelection)
	b.addExecutionRoots(rep.ExecutionRoots)
	b.addInvokedTargets(rep.InvokedTargets)
	b.addOperations(rep.Operations)
	b.addCapabilityMatches(rep.Capabilities)
	b.addCoverage(coverage)
	b.addBehaviorLinks(rep.AnalysisSelection, rep.ExecutionRoots, rep.InvokedTargets, rep.Operations, rep.OperationRelations, rep.Capabilities, coverage)
	b.addArtifactLinks(rep.Relationships, rep.ArtifactNodes)
	b.finishOmissions()
	b.doc.Shown = b.countShown()
	b.doc.Shown.Links = len(b.doc.Links)
	b.doc.Shown.Diagnostics = len(b.doc.Diagnostics)
	return b.doc
}

func coverageLimitations(items []behavior.Coverage) []behavior.Coverage {
	out := make([]behavior.Coverage, 0)
	for _, item := range items {
		if item.Status != "analyzed" {
			out = append(out, item)
		}
	}
	return out
}

func groupCoverage(items []behavior.Coverage) []visualCoverageGroup {
	type key struct {
		scope, status, detail string
		architectureScoped    bool
	}
	groups := make([]visualCoverageGroup, 0, len(items))
	indexes := make(map[key]int, len(items))
	architectures := make(map[key][]string)
	nodeSeen := make(map[key]map[string]struct{})
	for _, item := range items {
		base, architecture := coverageScopeArchitecture(item.AnalysisArea)
		itemKey := key{scope: base, status: item.Status, detail: item.Detail, architectureScoped: architecture != ""}
		index, exists := indexes[itemKey]
		if !exists {
			index = len(groups)
			indexes[itemKey] = index
			groups = append(groups, visualCoverageGroup{item: item})
			nodeSeen[itemKey] = make(map[string]struct{})
		}
		groups[index].occurrences++
		if item.NodeID != "" {
			if _, exists := nodeSeen[itemKey][item.NodeID]; !exists {
				nodeSeen[itemKey][item.NodeID] = struct{}{}
				groups[index].nodeIDs = append(groups[index].nodeIDs, item.NodeID)
			}
		}
		if architecture != "" && !stringSliceContains(architectures[itemKey], architecture) {
			architectures[itemKey] = append(architectures[itemKey], architecture)
		}
	}
	for itemKey, values := range architectures {
		sort.Strings(values)
		if len(values) > 1 {
			groups[indexes[itemKey]].item.AnalysisArea = itemKey.scope + " (" + strings.Join(values, ", ") + ")"
		}
	}
	return groups
}

func coverageScopeArchitecture(scope string) (string, string) {
	index := strings.LastIndexByte(scope, '/')
	if index < 0 || index+1 >= len(scope) {
		return scope, ""
	}
	architecture := scope[index+1:]
	if architecture != "arm64" && architecture != "x86_64" {
		return scope, ""
	}
	return scope[:index], architecture
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func summarizeReport(rep report.Report) visualSummary {
	type capabilityIdentity struct{ ruleID, title, namespace string }
	capabilities := make(map[capabilityIdentity]struct{}, len(rep.Capabilities))
	var summary visualSummary
	for _, match := range rep.Capabilities {
		capabilities[capabilityIdentity{match.RuleID, match.Title, match.Namespace}] = struct{}{}
		switch match.Support {
		case behavior.SupportDirect:
			summary.DirectMatches++
		case behavior.SupportCorroborated:
			summary.CorroboratedMatches++
		case behavior.SupportHeuristic:
			summary.HeuristicMatches++
		}
		switch match.Execution.Connectivity {
		case behavior.ConnectivityConnected:
			summary.ConnectedMatches++
		case behavior.ConnectivityUnconnected:
			summary.UnconnectedMatches++
		case behavior.ConnectivityUnknown:
			summary.UnknownMatches++
		}
	}
	summary.Capabilities = len(capabilities)
	for _, node := range rep.ArtifactNodes {
		if node.AnalyzeStatus == "analyzed" {
			summary.AnalyzedArtifacts++
		}
	}
	summary.CoverageLimitations = report.CoverageLimitationCount(rep.Coverage)
	return summary
}

func (b *documentBuilder) boundedAnalysisMetadata(metadata report.AnalysisMetadata) report.AnalysisMetadata {
	metadata.Architecture = b.keep(metadata.Architecture)
	return metadata
}

func (b *documentBuilder) indexReferences(index referenceIndex, visualType string, shown, total int, sourceID func(int) string) {
	for i := 0; i < shown; i++ {
		b.addReference(index, sourceID(i), visualID(visualType, i))
	}
	b.verifyReferenceTail(index, shown, total, sourceID)
}

func (b *documentBuilder) indexEvidence(items []behavior.Evidence) {
	// Loaded reports are already bounded below this limit. A direct package
	// caller can still supply an arbitrary Report, so fail closed rather than
	// resolving a first-match ID when uniqueness cannot be established.
	if len(items) > maxReferenceTailScan {
		b.evidenceUnscanned = len(items)
		return
	}
	for _, item := range items {
		if item.ID == "" || len(item.ID) > maxReferenceBytes {
			continue
		}
		if _, ambiguous := b.ambiguousEvidence[item.ID]; ambiguous {
			b.evidenceDrops++
			continue
		}
		if _, exists := b.evidence[item.ID]; exists {
			delete(b.evidence, item.ID)
			b.ambiguousEvidence[item.ID] = struct{}{}
			b.evidenceDrops++
			continue
		}
		b.evidence[item.ID] = item
	}
}

func (b *documentBuilder) indexArtifactProperty(items []behavior.ArtifactProperty) {
	limit := min(len(items), maxReferenceTailScan)
	for i := 0; i < limit; i++ {
		key := items[i].NodeID
		if key != "" {
			if _, uniqueAndShown := b.artifactRefs.resolved[key]; !uniqueAndShown {
				b.contextDrops++
				continue
			}
		}
		if len(b.artifactPropertiesByNode[key]) >= maxListItems {
			b.contextDrops++
			continue
		}
		b.artifactPropertiesByNode[key] = append(b.artifactPropertiesByNode[key], items[i])
	}
	b.contextDrops += len(items) - limit
}

func (b *documentBuilder) indexNetwork(items []behavior.NetworkImplementationObservation) {
	limit := min(len(items), maxReferenceTailScan)
	for i := 0; i < limit; i++ {
		operationLimit := min(len(items[i].OperationIDs), maxListItems)
		seen := make(map[string]struct{}, operationLimit)
		for j := 0; j < operationLimit; j++ {
			operationID := items[i].OperationIDs[j]
			if operationID == "" || len(operationID) > maxReferenceBytes {
				b.contextDrops++
				continue
			}
			if _, duplicate := seen[operationID]; duplicate {
				b.contextDrops++
				continue
			}
			seen[operationID] = struct{}{}
			if _, uniqueAndShown := b.operationRefs.resolved[operationID]; !uniqueAndShown {
				b.contextDrops++
				continue
			}
			if len(b.networkByOperation[operationID]) >= maxListItems {
				b.contextDrops++
				continue
			}
			b.networkByOperation[operationID] = append(b.networkByOperation[operationID], items[i])
		}
		b.contextDrops += len(items[i].OperationIDs) - operationLimit
	}
	b.contextDrops += len(items) - limit
}

func (b *documentBuilder) addDiagnostics(items []string) {
	limit := min(len(items), maxDiagnosticItems)
	for i := 0; i < limit; i++ {
		if value := b.keep(items[i]); value != "" {
			b.doc.Diagnostics = append(b.doc.Diagnostics, value)
		}
	}
	if limit < len(items) {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Diagnostics: showing %d of %d in the HTML view; use JSON for the complete retained list.", limit, len(items)))
	}
}

func (b *documentBuilder) evidenceText(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	if b.evidenceUnscanned > 0 {
		b.evidenceDrops += min(len(ids), maxListItems)
		return ""
	}
	limit := min(len(ids), maxListItems)
	values := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		item, ok := b.evidence[ids[i]]
		if !ok {
			b.evidenceDrops++
			continue
		}
		if summary := b.evidenceSummary(item); summary != "" {
			values = append(values, summary)
		}
	}
	if limit < len(ids) {
		b.evidenceDrops += len(ids) - limit
	}
	return b.joinLines(values)
}

func (b *documentBuilder) evidenceSummary(item behavior.Evidence) string {
	parts := make([]string, 0, 9)
	location := firstNonEmpty(item.Logical, item.Physical, item.NodeID)
	if location != "" {
		parts = append(parts, location)
	}
	if item.Line > 0 {
		parts = append(parts, "line "+strconv.Itoa(item.Line))
	}
	if item.ByteOffsetKnown() {
		parts = append(parts, "byte "+strconv.FormatInt(item.Offset, 10))
	}
	if item.VA != 0 {
		parts = append(parts, fmt.Sprintf("VA %#x", item.VA))
	}
	if item.Function != "" {
		parts = append(parts, "function "+item.Function)
	}
	if item.Arch != "" {
		parts = append(parts, item.Arch)
	}
	if item.Method != "" || item.Kind != "" {
		parts = append(parts, b.compose(item.Method, "/", item.Kind))
	}
	if item.Value != "" {
		parts = append(parts, b.compose("match ", item.Value))
	}
	return b.joinParts(parts, " · ")
}

func (b *documentBuilder) artifactPropertiesText(nodeID string, root bool) string {
	items := append([]behavior.ArtifactProperty(nil), b.artifactPropertiesByNode[nodeID]...)
	if root && nodeID != "" {
		items = append(items, b.artifactPropertiesByNode[""]...)
	}
	values := make([]string, 0, min(len(items), maxListItems))
	for i := 0; i < len(items) && i < maxListItems; i++ {
		values = append(values, b.compose(items[i].Kind, "=", items[i].Value, " (", string(items[i].Support), ")"))
	}
	if len(items) > maxListItems {
		b.contextDrops += len(items) - maxListItems
	}
	return b.joinLines(values)
}

func (b *documentBuilder) networkText(operationID string) string {
	items := b.networkByOperation[operationID]
	values := make([]string, 0, min(len(items), maxListItems))
	for i := 0; i < len(items) && i < maxListItems; i++ {
		security := make([]string, len(items[i].SecurityProperties))
		for index := range items[i].SecurityProperties {
			security[index] = string(items[i].SecurityProperties[index])
		}
		parts := []string{
			string(items[i].Kind),
			b.joinParts([]string{items[i].APIOrTool, items[i].HTTPImplementation, items[i].TLSProvider}, " → "),
			b.joinStrings(security),
		}
		values = append(values, b.joinParts(parts, " · "))
	}
	if len(items) > maxListItems {
		b.contextDrops += len(items) - maxListItems
	}
	return b.joinLines(values)
}

func (b *documentBuilder) joinLines(values []string) string {
	return b.joinParts(values, "\n")
}

func (b *documentBuilder) joinParts(values []string, separator string) string {
	parts := make([]string, 0, len(values)*2)
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(parts) > 0 {
			parts = append(parts, separator)
		}
		parts = append(parts, value)
	}
	return b.compose(parts...)
}

func (b *documentBuilder) addArtifacts(items []artifact.Node) {
	limit := min(len(items), b.options.artifactNodes)
	for i := 0; i < limit; i++ {
		item := items[i]
		id := visualID("artifact", i)
		logical := b.keep(item.LogicalPath)
		title := path.Base(strings.TrimSuffix(logical, "/"))
		if title == "." || title == "/" || title == "" {
			title = firstNonEmpty(item.Kind, item.ID, "Artifact")
		}
		details := b.details(
			detail{"Artifact ID", item.ID}, detail{"Logical path", item.LogicalPath},
			detail{"Physical path", item.PhysicalPath}, detail{"Kind", item.Kind},
			detail{"Media type", item.MediaType}, detail{"Size", byteCount(item.Size)},
			detail{"SHA-256", item.SHA256}, detail{"Architectures", b.joinStrings(item.Architectures)},
			detail{"Provenance", item.Provenance}, detail{"Source role", item.SourceRole},
			detail{"Analysis status", item.AnalyzeStatus}, detail{"Coverage detail", item.CoverageDetail},
			detail{"Artifact properties", b.artifactPropertiesText(item.ID, item.ParentID == "")},
		)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: id, Type: "artifact", Title: b.keep(title), Subtitle: logical,
			Status: b.keep(item.AnalyzeStatus), Details: details,
		})
		if b.artifactRefs.resolved[item.ID] == id {
			b.artifactPaths[item.ID] = logical
		}
	}
	b.noteLimit("Artifact nodes", limit, len(items), b.options.artifactNodes)
}

func (b *documentBuilder) addAnalysisSelections(items []behavior.AnalysisSelection) {
	limit := min(len(items), b.options.analysisSelections)
	for i := 0; i < limit; i++ {
		item := items[i]
		reasons := make([]string, 0, len(item.Reasons))
		for _, reason := range item.Reasons {
			reasons = append(reasons, string(reason))
		}
		details := b.details(
			detail{"Artifact ID", item.NodeID}, detail{"Selection reasons", b.joinStrings(reasons)},
		)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: visualID("analysis-selection", i), Type: "analysis-selection", Title: b.keep(firstNonEmpty(item.NodeID, "Selected artifact")),
			Subtitle: b.keep(b.joinStrings(reasons)), Details: details,
		})
	}
	b.noteLimit("Analysis selections", limit, len(items), b.options.analysisSelections)
}

func (b *documentBuilder) addExecutionRoots(items []behavior.ExecutionRoot) {
	limit := min(len(items), b.options.executionRoots)
	for i := 0; i < limit; i++ {
		item := items[i]
		title := firstNonEmpty(item.Name, item.Kind, "Execution root")
		details := b.details(
			detail{"Execution root ID", item.ID}, detail{"Kind", item.Kind}, detail{"Name", item.Name},
			detail{"Declaration artifact ID", item.DeclarationNodeID}, detail{"Start artifact ID", item.StartNodeID},
			detail{"Start scope ID", item.StartScopeID}, detail{"Interpreter", item.Interpreter},
			detail{"Arguments", b.joinStrings(item.Arguments)}, detail{"Connectivity", string(behavior.ConnectivityConnected)},
			detail{"Evidence locations", b.evidenceText(item.EvidenceIDs)}, detail{"Evidence IDs", b.joinStrings(item.EvidenceIDs)},
		)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: visualID("execution-root", i), Type: "execution-root", Title: b.keep(title), Subtitle: b.keep(item.Kind),
			RecordID:     b.recordID(b.executionRootRefs, item.ID, visualID("execution-root", i)),
			Connectivity: b.keep(string(behavior.ConnectivityConnected)), Details: details,
		})
	}
	b.noteLimit("Execution roots", limit, len(items), b.options.executionRoots)
}

func (b *documentBuilder) addInvokedTargets(items []behavior.InvokedTarget) {
	limit := min(len(items), b.options.invokedTargets)
	for i := 0; i < limit; i++ {
		item := items[i]
		title := firstNonEmpty(item.Interpreter, item.Kind, "Invoked target")
		details := b.details(
			detail{"Invoked target ID", item.ID}, detail{"Kind", item.Kind}, detail{"Artifact ID", item.NodeID},
			detail{"Scope ID", item.ScopeID}, detail{"Source kind", string(item.Source.Kind)}, detail{"Source ID", item.Source.ID},
			detail{"Connectivity", string(item.Execution.Connectivity)}, detail{"Execution root IDs", b.joinStrings(item.Execution.ExecutionRootIDs)},
			detail{"Inherited target IDs", b.joinStrings(item.Execution.InvokedTargetIDs)}, detail{"Interpreter", item.Interpreter},
			detail{"Arguments", b.joinStrings(item.Arguments)}, detail{"Ordinal", optionalOrdinal(item.Ordinal)},
			detail{"Evidence locations", b.evidenceText(item.EvidenceIDs)}, detail{"Evidence IDs", b.joinStrings(item.EvidenceIDs)},
		)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: visualID("invoked-target", i), Type: "invoked-target", Title: b.keep(title), Subtitle: b.keep(item.Kind),
			RecordID:     b.recordID(b.invokedTargetRefs, item.ID, visualID("invoked-target", i)),
			Connectivity: b.keep(string(item.Execution.Connectivity)), Details: details,
		})
	}
	b.noteLimit("Invoked targets", limit, len(items), b.options.invokedTargets)
}

func (b *documentBuilder) addOperations(items []behavior.ModeledOperation) {
	limit := min(len(items), b.options.modeledOperations)
	for i := 0; i < limit; i++ {
		item := items[i]
		id := visualID("operation", i)
		resource := b.resourceBindingsText(item.ResourceBindings)
		details := []detail{
			{"Modeled operation ID", item.ID}, {"Kind", string(item.Kind)}, {"Resource bindings", resource},
			{"Artifact ID", item.SubjectNodeID}, {"Artifact path", b.artifactPaths[item.SubjectNodeID]}, {"Scope ID", item.ScopeID},
			{"Support", string(item.Support)}, {"Connectivity", string(item.Execution.Connectivity)},
			{"Execution root IDs", b.joinStrings(item.Execution.ExecutionRootIDs)}, {"Invoked target IDs", b.joinStrings(item.Execution.InvokedTargetIDs)},
			{"Source function", item.SourceFunction},
			{"Architecture", item.Architecture}, {"Line", positiveInt(item.Line)},
			{"Network context", b.networkText(item.ID)},
			{"Evidence locations", b.evidenceText(item.EvidenceIDs)}, {"Evidence IDs", b.joinStrings(item.EvidenceIDs)},
		}
		details = append(details, b.qualifierDetails(item.Qualifiers)...)
		recordID := b.recordID(b.operationRefs, item.ID, id)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: id, Type: "operation", Title: b.keep(firstNonEmpty(string(item.Kind), "Modeled operation")), Subtitle: b.keep(resource),
			RecordID: recordID, ReviewGroup: b.reviewGroup("operation", recordID),
			Support: b.keep(string(item.Support)), Connectivity: b.keep(string(item.Execution.Connectivity)),
			Details: b.details(details...),
		})
	}
	b.noteLimit("Modeled operations", limit, len(items), b.options.modeledOperations)
}

func (b *documentBuilder) addCapabilityMatches(items []behavior.CapabilityMatch) {
	limit := min(len(items), b.options.capabilityMatches)
	for i := 0; i < limit; i++ {
		item := items[i]
		id := visualID("capability", i)
		resources := make([]string, 0, min(len(item.AffectedResources), maxListItems))
		for j := 0; j < len(item.AffectedResources) && j < maxListItems; j++ {
			resources = append(resources, b.resourceText(item.AffectedResources[j]))
		}
		resourceSummary := b.joinStrings(resources)
		if len(item.AffectedResources) > maxListItems {
			resourceSummary = b.compose(resourceSummary, fmt.Sprintf(" (+%d more resources)", len(item.AffectedResources)-maxListItems))
		}
		details := b.details(
			detail{"Capability match ID", item.ID}, detail{"Rule ID", item.RuleID}, detail{"Namespace", item.Namespace},
			detail{"Subject artifact ID", item.SubjectNodeID}, detail{"Artifact path", b.artifactPaths[item.SubjectNodeID]}, detail{"Support", string(item.Support)},
			detail{"Connectivity", string(item.Execution.Connectivity)}, detail{"Execution root IDs", b.joinStrings(item.Execution.ExecutionRootIDs)},
			detail{"Invoked target IDs", b.joinStrings(item.Execution.InvokedTargetIDs)}, detail{"Resources", resourceSummary},
			detail{"Modeled operations", b.joinStrings(item.OperationIDs)},
			detail{"Evidence locations", b.evidenceText(item.EvidenceIDs)}, detail{"Evidence IDs", b.joinStrings(item.EvidenceIDs)},
			detail{"ATT&CK", b.joinStrings(item.Attack)}, detail{"MBC", b.joinStrings(item.MBC)},
			detail{"Architecture scopes", b.joinStrings(item.ArchitectureScopes)},
			detail{"Match trace", b.matchTraceText(item.MatchTrace)},
		)
		recordID := b.recordID(b.capabilityRefs, item.ID, id)
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: id, Type: "capability", Title: b.keep(firstNonEmpty(item.Title, item.RuleID, "Capability match")),
			RecordID: recordID, ReviewGroup: b.reviewGroup("capability", recordID),
			Subtitle: b.keep(item.Namespace), Support: b.keep(string(item.Support)),
			Connectivity: b.keep(string(item.Execution.Connectivity)), Details: details,
		})
	}
	b.noteLimit("Capability matches", limit, len(items), b.options.capabilityMatches)
}

func (b *documentBuilder) recordID(index referenceIndex, source, visual string) string {
	if source == "" || index.resolved[source] != visual {
		return ""
	}
	// Escaped or truncated strings remain display data, never record references.
	if kept := b.keep(source); kept == source {
		return kept
	}
	return ""
}

func (b *documentBuilder) reviewGroup(kind, recordID string) string {
	if recordID == "" {
		return ""
	}
	return b.reviewGroups[kind+"\x00"+recordID]
}

func (b *documentBuilder) matchTraceText(clauses []behavior.MatchTraceClause) string {
	values := make([]string, 0, min(len(clauses), maxListItems))
	for index := 0; index < len(clauses) && index < maxListItems; index++ {
		values = append(values, matchTraceClauseText(clauses[index]))
	}
	result := b.joinStrings(values)
	if len(clauses) > maxListItems {
		result = b.compose(result, fmt.Sprintf(" (+%d more clauses)", len(clauses)-maxListItems))
	}
	return result
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
	return clause.Path + " · " + string(clause.Kind) + " · " + strings.Join(ids, ", ")
}

func (b *documentBuilder) addCoverage(items []visualCoverageGroup) {
	limit := min(len(items), b.options.coverage)
	for i := 0; i < limit; i++ {
		group, item := items[i], items[i].item
		b.doc.Nodes = append(b.doc.Nodes, visualNode{
			ID: visualID("coverage", i), Type: "coverage", Title: b.keep(firstNonEmpty(item.AnalysisArea, "Coverage")),
			Subtitle: b.keep(item.Detail), Status: b.keep(item.Status),
			Details: b.details(detail{"Affected artifact IDs", b.joinStrings(group.nodeIDs)}, detail{"Scope", item.AnalysisArea},
				detail{"Status", item.Status}, detail{"Detail", item.Detail}, detail{"Source records", strconv.Itoa(group.occurrences)}),
		})
	}
	b.noteLimit("Coverage graph nodes", limit, len(items), b.options.coverage)
}

func (b *documentBuilder) addArtifactLinks(edges []artifact.Edge, nodes []artifact.Node) {
	scanLimit := min(len(edges), min(maxRelationshipScan, b.options.links*4))
	for i := 0; i < scanLimit; i++ {
		if len(b.doc.Links) >= b.options.links {
			b.linksDropped += scanLimit - i
			break
		}
		edge := edges[i]
		from, fromOK := b.reference(b.artifactRefs, edge.From)
		to, toOK := b.reference(b.artifactRefs, edge.To)
		if fromOK && toOK {
			b.addLink(from, to, firstNonEmpty(edge.Kind, "related"))
		}
	}
	if scanLimit < len(edges) {
		b.linksDropped += len(edges) - scanLimit
	}
	// Parent IDs are useful for reports produced before explicit relationship
	// edges were emitted. Duplicate links are removed deterministically.
	limit := min(len(nodes), b.options.artifactNodes)
	for i := 0; i < limit; i++ {
		if nodes[i].ParentID == "" {
			continue
		}
		from, fromOK := b.reference(b.artifactRefs, nodes[i].ParentID)
		to, toOK := b.reference(b.artifactRefs, nodes[i].ID)
		if fromOK && toOK {
			b.addLink(from, to, "contains")
		}
	}
}

func (b *documentBuilder) addBehaviorLinks(
	selections []behavior.AnalysisSelection,
	roots []behavior.ExecutionRoot,
	targets []behavior.InvokedTarget,
	operations []behavior.ModeledOperation,
	relations []behavior.OperationRelation,
	capabilityMatches []behavior.CapabilityMatch,
	coverage []visualCoverageGroup,
) {
	// Prioritize capability and execution-flow links. Under an unusually low
	// link limit, the analyst-facing behavior remains connected before archival
	// inventory relationships consume the remaining budget.
	for i := 0; i < len(capabilityMatches) && i < b.options.capabilityMatches; i++ {
		capabilityMatchID := visualID("capability", i)
		if artifactID, ok := b.reference(b.artifactRefs, capabilityMatches[i].SubjectNodeID); ok {
			b.addLink(artifactID, capabilityMatchID, "has capability match")
		}
		for j := 0; j < len(capabilityMatches[i].OperationIDs) && j < maxListItems; j++ {
			if operationID, ok := b.reference(b.operationRefs, capabilityMatches[i].OperationIDs[j]); ok {
				b.addLink(operationID, capabilityMatchID, "supports match")
			}
		}
		if len(capabilityMatches[i].OperationIDs) > maxListItems {
			b.traversalDrops += len(capabilityMatches[i].OperationIDs) - maxListItems
		}
	}
	for i := 0; i < len(relations) && i < b.options.operationRelations; i++ {
		from, fromOK := b.operationRelationVisualEndpoint(relations[i].From)
		to, toOK := b.operationRelationVisualEndpoint(relations[i].To)
		if fromOK && toOK {
			before := len(b.doc.Links)
			b.addLink(from, to, string(relations[i].Kind))
			if len(b.doc.Links) > before {
				b.operationRelationsShown++
			}
		}
	}
	b.noteLimit("Operation relations", min(len(relations), b.options.operationRelations), len(relations), b.options.operationRelations)
	for i := 0; i < len(operations) && i < b.options.modeledOperations; i++ {
		operationID := visualID("operation", i)
		linked := b.addExecutionContextLinks(operations[i].Execution, operationID, "owns modeled operation")
		if !linked {
			if artifactID, ok := b.reference(b.artifactRefs, operations[i].SubjectNodeID); ok {
				b.addLink(artifactID, operationID, "has modeled operation")
			}
		}
	}
	for i := 0; i < len(selections) && i < b.options.analysisSelections; i++ {
		if artifactID, ok := b.reference(b.artifactRefs, selections[i].NodeID); ok {
			b.addLink(artifactID, visualID("analysis-selection", i), "selected for analysis")
		}
	}
	for i := 0; i < len(roots) && i < b.options.executionRoots; i++ {
		rootID := visualID("execution-root", i)
		if artifactID, ok := b.reference(b.artifactRefs, roots[i].DeclarationNodeID); ok {
			b.addLink(artifactID, rootID, "declares execution root")
		}
		if roots[i].StartNodeID != "" && roots[i].StartNodeID != roots[i].DeclarationNodeID {
			if artifactID, ok := b.reference(b.artifactRefs, roots[i].StartNodeID); ok {
				b.addLink(rootID, artifactID, "starts at artifact")
			}
		}
	}
	for i := 0; i < len(targets) && i < b.options.invokedTargets; i++ {
		targetID := visualID("invoked-target", i)
		if sourceID, ok := b.entityReference(targets[i].Source); ok {
			b.addLink(sourceID, targetID, "invokes target")
		}
		if targets[i].Source.Kind != behavior.EntityKindArtifactNode || targets[i].Source.ID != targets[i].NodeID {
			if artifactID, ok := b.reference(b.artifactRefs, targets[i].NodeID); ok {
				b.addLink(targetID, artifactID, "targets artifact")
			}
		}
	}
	for i := 0; i < len(coverage) && i < b.options.coverage; i++ {
		for _, nodeID := range coverage[i].nodeIDs {
			if artifactID, ok := b.reference(b.artifactRefs, nodeID); ok {
				b.addLink(artifactID, visualID("coverage", i), "has coverage")
			}
		}
	}
}

func (b *documentBuilder) addExecutionContextLinks(context behavior.ExecutionContext, to, kind string) bool {
	linked := false
	rootLimit := min(len(context.ExecutionRootIDs), maxListItems)
	for i := 0; i < rootLimit; i++ {
		if rootID, ok := b.reference(b.executionRootRefs, context.ExecutionRootIDs[i]); ok {
			b.addLink(rootID, to, kind)
			linked = true
		}
	}
	targetLimit := min(len(context.InvokedTargetIDs), maxListItems)
	for i := 0; i < targetLimit; i++ {
		if targetID, ok := b.reference(b.invokedTargetRefs, context.InvokedTargetIDs[i]); ok {
			b.addLink(targetID, to, kind)
			linked = true
		}
	}
	b.traversalDrops += len(context.ExecutionRootIDs) - rootLimit
	b.traversalDrops += len(context.InvokedTargetIDs) - targetLimit
	return linked
}

func (b *documentBuilder) entityReference(ref behavior.EntityRef) (string, bool) {
	switch ref.Kind {
	case behavior.EntityKindArtifactNode:
		return b.reference(b.artifactRefs, ref.ID)
	case behavior.EntityKindExecutionRoot:
		return b.reference(b.executionRootRefs, ref.ID)
	case behavior.EntityKindInvokedTarget:
		return b.reference(b.invokedTargetRefs, ref.ID)
	default:
		b.unresolvedRefs++
		return "", false
	}
}

func (b *documentBuilder) addLink(from, to, kind string) {
	if from == "" || to == "" || from == to {
		return
	}
	if len(b.doc.Links) >= b.options.links {
		b.linksDropped++
		return
	}
	kind = b.keep(kind)
	if kind == "" {
		kind = "related"
	}
	key := visualLinkIdentity{from: from, to: to, kind: kind}
	if _, exists := b.linkKeys[key]; exists {
		return
	}
	b.linkKeys[key] = struct{}{}
	b.doc.Links = append(b.doc.Links, visualLink{From: from, To: to, Kind: kind})
}

func (b *documentBuilder) addReference(index referenceIndex, source, visual string) {
	if source == "" {
		return
	}
	if len(source) > maxReferenceBytes {
		b.oversizedRefs++
		return
	}
	if _, ambiguous := index.ambiguous[source]; ambiguous {
		b.duplicateRefs++
		return
	}
	if _, exists := index.resolved[source]; exists {
		delete(index.resolved, source)
		index.ambiguous[source] = struct{}{}
		b.duplicateRefs++
		return
	}
	index.resolved[source] = visual
}

func (b *documentBuilder) reference(index referenceIndex, source string) (string, bool) {
	if source == "" || len(source) > maxReferenceBytes {
		if len(source) > maxReferenceBytes {
			b.oversizedRefs++
		}
		return "", false
	}
	if _, ambiguous := index.ambiguous[source]; ambiguous {
		b.ambiguousRefs++
		return "", false
	}
	value, ok := index.resolved[source]
	if !ok {
		b.unresolvedRefs++
	}
	return value, ok
}

// verifyReferenceTail prevents a duplicate source ID outside the displayed
// category limit from turning the first displayed definition into a false
// edge target. Only IDs matching a displayed definition need to be retained,
// so the tail scan uses constant additional memory. If a direct caller supplies
// a report beyond the scan cap, uniqueness cannot be established and displayed
// references are disabled rather than guessed.
func (b *documentBuilder) verifyReferenceTail(index referenceIndex, shown, total int, sourceID func(int) string) {
	if shown >= total {
		return
	}
	scanEnd := min(total, shown+maxReferenceTailScan)
	for i := shown; i < scanEnd; i++ {
		source := sourceID(i)
		if source == "" || len(source) > maxReferenceBytes {
			continue
		}
		if _, exists := index.resolved[source]; exists {
			delete(index.resolved, source)
			index.ambiguous[source] = struct{}{}
			b.duplicateRefs++
			continue
		}
		if _, ambiguous := index.ambiguous[source]; ambiguous {
			b.duplicateRefs++
		}
	}
	if scanEnd >= total {
		return
	}
	b.unscannedRefs += total - scanEnd
	for source := range index.resolved {
		delete(index.resolved, source)
		index.ambiguous[source] = struct{}{}
		b.indeterminateRefs++
	}
}

type detail struct{ label, value string }

func (b *documentBuilder) details(items ...detail) []visualDetail {
	result := make([]visualDetail, 0, min(len(items), maxDetailRows))
	for _, item := range items {
		if item.value == "" {
			continue
		}
		if len(result) >= maxDetailRows {
			b.detailDrops++
			continue
		}
		result = append(result, visualDetail{Label: b.keep(item.label), Value: b.keep(item.value)})
	}
	return result
}

func (b *documentBuilder) keep(value string) string { return b.text.keep(value) }

func (b *documentBuilder) noteLimit(label string, shown, total, limit int) {
	if shown < total {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("%s: showing %d of %d (visualization limit %d).", label, shown, total, limit))
	}
}

func (b *documentBuilder) finishOmissions() {
	if b.operationRelationsShown < b.doc.Source.OperationRelations {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Operation relations: %d of %d source records are rendered as distinct operation-to-operation edges; resource, scope, execution-owner, bounded, duplicate, or unresolved endpoints remain available in report JSON.", b.operationRelationsShown, b.doc.Source.OperationRelations))
	}
	if b.linksDropped > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Connections: %d additional connection attempts were omitted after the %d-link limit.", b.linksDropped, b.options.links))
	}
	if b.traversalDrops > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Connections: %d additional execution-owner or modeled-operation references were not traversed after per-record limits.", b.traversalDrops))
	}
	if b.oversizedRefs > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Cross-references: %d oversized identifiers were not resolved in the graph.", b.oversizedRefs))
	}
	if b.unresolvedRefs > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Cross-references: %d ordinary reference attempts could not be resolved because their target was missing or omitted from the bounded view.", b.unresolvedRefs))
	}
	if b.duplicateRefs > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Cross-references: %d duplicate source identifier definitions were marked ambiguous and are never used to draw edges.", b.duplicateRefs))
	}
	if b.ambiguousRefs > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Cross-references: %d connection reference attempts targeted ambiguous identifiers and were omitted.", b.ambiguousRefs))
	}
	if b.unscannedRefs > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Cross-references: %d source identifiers exceeded the bounded uniqueness scan; %d displayed identifier definitions were marked ambiguous instead of drawing first-match edges.", b.unscannedRefs, b.indeterminateRefs))
	}
	if b.evidenceUnscanned > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Evidence: %d records exceeded the bounded uniqueness scan, so evidence locations were not resolved rather than guessed.", b.evidenceUnscanned))
	}
	if b.evidenceDrops > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Evidence: %d location references were omitted because they were missing, ambiguous, or beyond per-node display limits.", b.evidenceDrops))
	}
	if b.contextDrops > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Context: %d artifact property or network/TLS observation associations were omitted after bounded per-node or aggregate scans.", b.contextDrops))
	}
	if b.detailDrops > 0 {
		b.doc.Omissions = append(b.doc.Omissions, "Some detail rows were omitted to keep node panels bounded.")
	}
	if b.text.truncated > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Text: %d values were truncated by visualization string or aggregate text limits.", b.text.truncated))
	}
	if b.text.escaped > 0 {
		b.doc.Omissions = append(b.doc.Omissions,
			fmt.Sprintf("Display safety: %d values contained control, format, or invalid UTF-8 bytes and were visibly escaped.", b.text.escaped))
	}
	if b.text.exhausted {
		b.doc.Omissions = append(b.doc.Omissions, "Text: the aggregate visualization text budget was exhausted; later values may be empty.")
	}
	if b.doc.Source.CapabilityMatches == 0 {
		b.doc.Omissions = append(b.doc.Omissions, "No capability matches are recorded in this report. This is not a security verdict.")
	}
}

func (b *documentBuilder) countShown() visualCounts {
	var result visualCounts
	for _, node := range b.doc.Nodes {
		switch node.Type {
		case "artifact":
			result.Artifacts++
		case "analysis-selection":
			result.AnalysisSelections++
		case "execution-root":
			result.ExecutionRoots++
		case "invoked-target":
			result.InvokedTargets++
		case "operation":
			result.Operations++
		case "capability":
			result.CapabilityMatches++
		case "coverage":
			result.Coverage++
		}
	}
	result.OperationRelations = b.operationRelationsShown
	return result
}

func (b *documentBuilder) operationRelationVisualEndpoint(endpoint behavior.RelationEndpoint) (string, bool) {
	if endpoint.Kind != behavior.RelationEndpointOperation {
		return "", false
	}
	return b.reference(b.operationRefs, endpoint.ID)
}

func (b *textBudget) keep(value string) string {
	if value == "" {
		return ""
	}
	limit := b.perString
	if b.remaining < limit {
		limit = b.remaining
	}
	if limit <= 0 {
		b.truncated++
		b.exhausted = true
		return ""
	}
	wasTruncated := len(value) > limit
	if wasTruncated {
		value = value[:limit]
	}
	escaped := terminal.Escape(value)
	controlsEscaped := escaped != value
	if controlsEscaped {
		b.escaped++
	}
	value = escaped
	if len(value) > limit {
		value = truncateUTF8(value, limit)
		wasTruncated = true
	}
	if wasTruncated {
		b.truncated++
	}
	b.remaining -= len(value)
	if b.remaining == 0 {
		b.exhausted = true
	}
	return value
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 0 {
		return ""
	}
	suffix := "…"
	if limit < len(suffix) {
		return strings.Repeat(".", limit)
	}
	end := limit - len(suffix)
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + suffix
}

func (b *documentBuilder) qualifierDetails(values map[string]string) []detail {
	if len(values) == 0 {
		return nil
	}
	if len(values) > maxQualifierKeys {
		return []detail{{"Qualifiers", fmt.Sprintf("%d values omitted from this bounded view", len(values))}}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if len(key) > hardStringByteLimit {
			return []detail{{"Qualifiers", fmt.Sprintf("%d values omitted because at least one key exceeds the bounded view", len(values))}}
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]detail, 0, min(len(keys), maxDetailRows))
	for _, key := range keys {
		result = append(result, detail{b.compose("Qualifier · ", key), values[key]})
	}
	return result
}

func (b *documentBuilder) joinStrings(values []string) string {
	if len(values) == 0 {
		return ""
	}
	limit := min(len(values), maxListItems)
	parts := make([]string, 0, limit*2+1)
	for i := 0; i < limit; i++ {
		if i > 0 {
			parts = append(parts, ", ")
		}
		parts = append(parts, values[i])
	}
	if limit < len(values) {
		parts = append(parts, fmt.Sprintf(" (+%d more)", len(values)-limit))
	}
	return b.compose(parts...)
}

func (b *documentBuilder) resourceText(resource behavior.Resource) string {
	kind := string(resource.Kind)
	if len(resource.Classifications) > 0 {
		classes := make([]string, len(resource.Classifications))
		for index, classification := range resource.Classifications {
			classes[index] = string(classification)
		}
		kind = b.compose(kind, " [", strings.Join(classes, ", "), "]")
	}
	if resource.Value == "" {
		if kind == "" {
			return ""
		}
		if !resource.Unresolved() {
			return b.compose(kind)
		}
		return b.compose(kind, ": (unresolved)")
	}
	if kind == "" {
		return b.compose(resource.Value)
	}
	return b.compose(kind, ": ", resource.Value)
}

func (b *documentBuilder) resourceBindingsText(bindings []behavior.ResourceBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		parts = append(parts, b.compose(string(binding.Role), " = ", b.resourceText(binding.Resource)))
	}
	return b.compose(strings.Join(parts, "; "))
}

// compose bounds derived strings before concatenating untrusted parts. The
// result still passes through keep when retained, which enforces the caller's
// smaller per-string and aggregate limits.
func (b *documentBuilder) compose(parts ...string) string {
	var output strings.Builder
	capacity := 0
	for _, part := range parts {
		capacity += min(len(part), hardStringByteLimit-capacity)
		if capacity == hardStringByteLimit {
			break
		}
	}
	output.Grow(capacity)
	remaining := hardStringByteLimit
	truncated := false
	for _, part := range parts {
		if remaining == 0 {
			if part != "" {
				truncated = true
			}
			continue
		}
		if len(part) > remaining {
			output.WriteString(part[:remaining])
			remaining = 0
			truncated = true
			continue
		}
		output.WriteString(part)
		remaining -= len(part)
	}
	result := output.String()
	if truncated {
		result = result[:hardStringByteLimit-len("...")] + "..."
		b.text.truncated++
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func byteCount(value int64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatInt(value, 10) + " bytes"
}

func positiveInt(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func optionalOrdinal(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func visualID(kind string, index int) string { return fmt.Sprintf("%s-%04d", kind, index+1) }
