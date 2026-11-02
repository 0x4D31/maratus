package behavior

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// DefaultItemLimit bounds the behavior IR produced for one inspection. Evidence
// has its own, usually smaller, budget; this limit covers every other collection
// that can grow in response to adversarial input.
const (
	DefaultItemLimit = 50000
	// PostLimitCoverageAllowance reserves bounded space for the mandatory
	// behavior-IR and rule-evaluation partial markers. They are appended after
	// extraction has consumed its item budget so loss is never silent.
	PostLimitCoverageAllowance = 2
	// DefaultStringByteLimit counts logical string bytes across retained IR and
	// evidence. It leaves headroom for JSON field overhead, capability matches, and artifact
	// metadata under the report loader's independent size guard.
	DefaultStringByteLimit = 16 << 20
	maxNetworkOperationIDs = 64
)

type Graph struct {
	Scopes             []Scope
	Evidence           []Evidence
	Features           []Feature
	ExecutionRoots     []ExecutionRoot
	InvokedTargets     []InvokedTarget
	AnalysisSelections []AnalysisSelection
	Operations         []ModeledOperation
	Network            []NetworkImplementationObservation
	ArtifactProperties []ArtifactProperty
	Coverage           []Coverage
	Relations          []OperationRelation

	nextEvidence              int
	nextScope                 int
	nextFeature               int
	nextRoot                  int
	nextTarget                int
	nextOperation             int
	nextRelation              int
	nextNetworkImplementation int
	nextSourceOrderGroup      int
	nextDirectoryContext      int
	EvidenceLimit             int
	EvidenceLimitDrops        int
	EvidenceStringDrops       int
	ItemLimit                 int
	ItemsDropped              int
	InvalidItemsDropped       int
	StringByteLimit           int64
	StringBytes               int64
	StringBytesDropped        int64
	limitFinalized            bool
	scopeFunctions            map[string]string
	scopeArchitectures        map[string]string
	evidenceContexts          map[string]graphFactContext
	evidenceContextItems      int
}

type graphFactContext struct {
	scopeID      string
	function     string
	architecture string
}

func (g *Graph) AddScope(s Scope) string {
	if s.Kind == "" {
		if s.Function != "" {
			s.Kind = "function"
		} else {
			s.Kind = "artifact-node"
		}
	}
	if (s.Kind == "function") != (s.Function != "") {
		g.rejectItem()
		return ""
	}
	if !g.reserveItem(s, true) {
		return ""
	}
	g.nextScope++
	s.ID = fmt.Sprintf("scope-%04d", g.nextScope)
	g.Scopes = append(g.Scopes, s)
	if g.scopeFunctions == nil {
		g.scopeFunctions = make(map[string]string)
	}
	g.scopeFunctions[s.ID] = s.Function
	if g.scopeArchitectures == nil {
		g.scopeArchitectures = make(map[string]string)
	}
	g.scopeArchitectures[s.ID] = s.Architecture
	return s.ID
}

func (g *Graph) AddEvidence(e Evidence) string {
	if e.Function != "" && e.ScopeID == "" {
		g.rejectItem()
		return ""
	}
	if e.ScopeID != "" {
		if function := g.scopeFunction(e.ScopeID); function != "" {
			if e.Function != "" && e.Function != function {
				g.rejectItem()
				return ""
			}
			e.Function = function
		}
		if architecture := g.scopeArchitecture(e.ScopeID); architecture != "" {
			if e.Arch != "" && e.Arch != architecture {
				g.rejectItem()
				return ""
			}
			e.Arch = architecture
		}
	}
	if g.EvidenceLimit > 0 && len(g.Evidence) >= g.EvidenceLimit {
		g.EvidenceLimitDrops++
		return ""
	}
	if !g.reserveStrings(retainedStringBytes(e) + generatedIDByteReserve) {
		g.EvidenceStringDrops++
		return ""
	}
	g.nextEvidence++
	e.ID = fmt.Sprintf("ev-%04d", g.nextEvidence)
	g.Evidence = append(g.Evidence, e)
	if g.evidenceContexts != nil {
		g.evidenceContexts[e.ID] = graphFactContext{scopeID: e.ScopeID, function: e.Function, architecture: e.Arch}
		g.evidenceContextItems = len(g.Evidence)
	}
	return e.ID
}

func (g *Graph) AddFeature(feature Feature) string {
	if onlyEmptyStrings(feature.EvidenceIDs) {
		g.dropItem()
		return ""
	}
	if feature.SourceFunction != "" && feature.ScopeID == "" {
		g.rejectItem()
		return ""
	}
	if _, hiddenArchitecture := feature.Qualifiers["arch"]; hiddenArchitecture {
		g.rejectItem()
		return ""
	}
	if feature.ScopeID != "" {
		if fn := g.scopeFunction(feature.ScopeID); fn != "" {
			if feature.SourceFunction != "" && feature.SourceFunction != fn {
				g.rejectItem()
				return ""
			}
			feature.SourceFunction = fn
		}
		if architecture := g.scopeArchitecture(feature.ScopeID); architecture != "" {
			if feature.Architecture != "" && feature.Architecture != architecture {
				g.rejectItem()
				return ""
			}
			feature.Architecture = architecture
		}
	}
	if !g.evidenceContextCompatible(feature.EvidenceIDs, feature.ScopeID, feature.SourceFunction, feature.Architecture, true) {
		g.rejectItem()
		return ""
	}
	if feature.Support == "" {
		feature.Support = SupportCorroborated
	}
	if !feature.Support.Valid() {
		g.rejectItem()
		return ""
	}
	var err error
	feature.Execution, err = NormalizeExecutionContext(feature.Execution)
	if err != nil {
		g.rejectItem()
		return ""
	}
	if !g.reserveItem(feature, true) {
		return ""
	}
	g.nextFeature++
	feature.ID = fmt.Sprintf("feature-%04d", g.nextFeature)
	g.Features = append(g.Features, feature)
	return feature.ID
}

func (g *Graph) AddExecutionRoot(root ExecutionRoot) string {
	if root.Kind == "" || root.DeclarationNodeID == "" || root.StartNodeID == "" && root.StartScopeID == "" || !hasNonemptyString(root.EvidenceIDs) {
		g.rejectItem()
		return ""
	}
	root.EvidenceIDs = sortedUniqueStrings(append([]string(nil), root.EvidenceIDs...))
	root.Arguments = append([]string(nil), root.Arguments...)
	if !g.reserveItem(root, true) {
		return ""
	}
	g.nextRoot++
	root.ID = fmt.Sprintf("root-%04d", g.nextRoot)
	g.ExecutionRoots = append(g.ExecutionRoots, root)
	return root.ID
}

func (g *Graph) AddInvokedTarget(target InvokedTarget) string {
	if target.Kind == "" || target.NodeID == "" || !validEntityRef(target.Source) || target.Ordinal != nil && *target.Ordinal < 0 || !hasNonemptyString(target.EvidenceIDs) {
		g.rejectItem()
		return ""
	}
	var err error
	target.Execution, err = NormalizeExecutionContext(target.Execution)
	if err != nil {
		g.rejectItem()
		return ""
	}
	target.EvidenceIDs = sortedUniqueStrings(append([]string(nil), target.EvidenceIDs...))
	target.Arguments = append([]string(nil), target.Arguments...)
	if target.Ordinal != nil {
		ordinal := *target.Ordinal
		target.Ordinal = &ordinal
	}
	if !g.reserveItem(target, true) {
		return ""
	}
	g.nextTarget++
	target.ID = fmt.Sprintf("target-%04d", g.nextTarget)
	g.InvokedTargets = append(g.InvokedTargets, target)
	return target.ID
}

func (g *Graph) AddAnalysisSelection(selection AnalysisSelection) bool {
	selection.Reasons = normalizeSelectionReasons(selection.Reasons)
	if selection.NodeID == "" || len(selection.Reasons) == 0 {
		g.rejectItem()
		return false
	}
	for _, reason := range selection.Reasons {
		if !validSelectionReason(reason) {
			g.rejectItem()
			return false
		}
	}
	for i := range g.AnalysisSelections {
		if g.AnalysisSelections[i].NodeID != selection.NodeID {
			continue
		}
		merged := normalizeSelectionReasons(append(append([]SelectionReason(nil), g.AnalysisSelections[i].Reasons...), selection.Reasons...))
		additionalBytes := retainedStringBytes(merged) - retainedStringBytes(g.AnalysisSelections[i].Reasons)
		if additionalBytes > 0 && !g.reserveStrings(additionalBytes) {
			g.dropItem()
			return false
		}
		g.AnalysisSelections[i].Reasons = merged
		return true
	}
	if !g.reserveItem(selection, false) {
		return false
	}
	g.AnalysisSelections = append(g.AnalysisSelections, selection)
	return true
}

func (g *Graph) AddOperation(operation ModeledOperation) string {
	if !ValidOperationKind(operation.Kind) || onlyEmptyStrings(operation.EvidenceIDs) ||
		operation.SourceOrderGroup < 0 || operation.SourceOrdinal < 0 ||
		operation.WorkingDirectoryContext < 0 || operation.HomeDirectoryContext < 0 ||
		(operation.SourceOrderGroup == 0) != (operation.SourceOrdinal == 0) ||
		operation.SourceFunction != "" && operation.ScopeID == "" {
		g.rejectItem()
		return ""
	}
	bindings, err := NormalizeResourceBindings(operation.Kind, operation.ResourceBindings)
	if err != nil {
		g.rejectItem()
		return ""
	}
	operation.ResourceBindings = bindings
	if operation.ScopeID != "" {
		if fn := g.scopeFunction(operation.ScopeID); fn != "" {
			if operation.SourceFunction != "" && operation.SourceFunction != fn {
				g.rejectItem()
				return ""
			}
			operation.SourceFunction = fn
		}
		if architecture := g.scopeArchitecture(operation.ScopeID); architecture != "" {
			if operation.Architecture != "" && operation.Architecture != architecture {
				g.rejectItem()
				return ""
			}
			operation.Architecture = architecture
		}
	}
	if !g.evidenceContextCompatible(operation.EvidenceIDs, operation.ScopeID, operation.SourceFunction, operation.Architecture, true) {
		g.rejectItem()
		return ""
	}
	for _, binding := range operation.ResourceBindings {
		if !g.evidenceContextCompatible(binding.EvidenceIDs, operation.ScopeID, operation.SourceFunction, operation.Architecture, true) {
			g.rejectItem()
			return ""
		}
	}
	if operation.Support == "" {
		operation.Support = SupportCorroborated
	}
	if !operation.Support.Valid() {
		g.rejectItem()
		return ""
	}
	operation.Execution, err = NormalizeExecutionContext(operation.Execution)
	if err != nil {
		g.rejectItem()
		return ""
	}
	if !g.reserveItem(operation, true) {
		return ""
	}
	g.nextOperation++
	operation.ID = fmt.Sprintf("operation-%04d", g.nextOperation)
	g.Operations = append(g.Operations, operation)
	return operation.ID
}

// NewSourceOrderGroup allocates a transient identity for one bounded source
// parser invocation. Ordinals are comparable only inside the returned group.
func (g *Graph) NewSourceOrderGroup() int {
	g.nextSourceOrderGroup++
	return g.nextSourceOrderGroup
}

func (g *Graph) NewDirectoryContext() int {
	g.nextDirectoryContext++
	return g.nextDirectoryContext
}

func (g *Graph) AddRelation(relation OperationRelation) string {
	normalized, err := NormalizeOperationRelation(relation)
	if err != nil {
		g.rejectItem()
		return ""
	}
	operations, scopes, roots, targets := g.relationIndexes()
	if relationEndpointsResolved(normalized, operations, scopes, roots, targets) {
		callScopes := make(map[relationScopePair]struct{})
		for _, existing := range g.Relations {
			if existing.Kind == RelationCalls {
				callScopes[relationScopePair{From: existing.From.ID, To: existing.To.ID}] = struct{}{}
			}
		}
		if normalized.Kind == RelationCalls {
			callScopes[relationScopePair{From: normalized.From.ID, To: normalized.To.ID}] = struct{}{}
		}
		if err := validateRelationAgainstGraph(normalized, operations, scopes, roots, targets, callScopes); err != nil {
			g.rejectItem()
			return ""
		}
		evidence := make(map[string]Evidence, len(g.Evidence))
		for _, item := range g.Evidence {
			evidence[item.ID] = item
		}
		if err := validateRelationEvidenceLineage(normalized, evidence, g.Features, operations, scopes, roots, targets, false); err != nil {
			g.rejectItem()
			return ""
		}
		if normalized.Kind == RelationPrecedes {
			candidate := append(append([]OperationRelation(nil), g.Relations...), normalized)
			if err := validatePrecedesAcyclic(candidate); err != nil {
				g.rejectItem()
				return ""
			}
		}
	}
	if !g.reserveItem(normalized, true) {
		return ""
	}
	g.nextRelation++
	normalized.ID = fmt.Sprintf("relation-%04d", g.nextRelation)
	g.Relations = append(g.Relations, normalized)
	return normalized.ID
}

func (g *Graph) relationIndexes() (
	map[string]ModeledOperation,
	map[string]Scope,
	map[string]ExecutionRoot,
	map[string]InvokedTarget,
) {
	operations := make(map[string]ModeledOperation, len(g.Operations))
	for _, operation := range g.Operations {
		operations[operation.ID] = operation
	}
	scopes := make(map[string]Scope, len(g.Scopes))
	for _, scope := range g.Scopes {
		scopes[scope.ID] = scope
	}
	roots := make(map[string]ExecutionRoot, len(g.ExecutionRoots))
	for _, root := range g.ExecutionRoots {
		roots[root.ID] = root
	}
	targets := make(map[string]InvokedTarget, len(g.InvokedTargets))
	for _, target := range g.InvokedTargets {
		targets[target.ID] = target
	}
	return operations, scopes, roots, targets
}

func relationEndpointsResolved(
	relation OperationRelation,
	operations map[string]ModeledOperation,
	scopes map[string]Scope,
	roots map[string]ExecutionRoot,
	targets map[string]InvokedTarget,
) bool {
	for _, endpoint := range []RelationEndpoint{relation.From, relation.To} {
		switch endpoint.Kind {
		case RelationEndpointOperation:
			operation, ok := operations[endpoint.ID]
			if !ok {
				return false
			}
			if operation.ScopeID != "" {
				if _, ok := scopes[operation.ScopeID]; !ok {
					return false
				}
			}
		case RelationEndpointScope:
			if _, ok := scopes[endpoint.ID]; !ok {
				return false
			}
		case RelationEndpointExecutionRoot:
			if _, ok := roots[endpoint.ID]; !ok {
				return false
			}
		case RelationEndpointInvokedTarget:
			target, ok := targets[endpoint.ID]
			if !ok {
				return false
			}
			if target.ScopeID != "" {
				if _, ok := scopes[target.ScopeID]; !ok {
					return false
				}
			}
		}
	}
	return true
}

func (g *Graph) scopeFunction(scopeID string) string {
	if fn, ok := g.scopeFunctions[scopeID]; ok {
		return fn
	}
	for _, scope := range g.Scopes {
		if scope.ID == scopeID {
			if g.scopeFunctions == nil {
				g.scopeFunctions = make(map[string]string)
			}
			g.scopeFunctions[scopeID] = scope.Function
			return scope.Function
		}
	}
	return ""
}

func (g *Graph) scopeArchitecture(scopeID string) string {
	if architecture, ok := g.scopeArchitectures[scopeID]; ok {
		return architecture
	}
	for _, scope := range g.Scopes {
		if scope.ID == scopeID {
			if g.scopeArchitectures == nil {
				g.scopeArchitectures = make(map[string]string)
			}
			g.scopeArchitectures[scopeID] = scope.Architecture
			return scope.Architecture
		}
	}
	return ""
}

func (g *Graph) evidenceContextCompatible(evidenceIDs []string, scopeID, function, architecture string, checkFunction bool) bool {
	g.ensureEvidenceContexts()
	for _, evidenceID := range evidenceIDs {
		context, ok := g.evidenceContexts[evidenceID]
		if !ok {
			// Builders may assemble references before final validation. Unknown IDs
			// remain the report loader's responsibility.
			continue
		}
		if context.architecture != "" && architecture != context.architecture {
			return false
		}
		if checkFunction && context.function != "" && context.scopeID != scopeID {
			return false
		}
		if checkFunction && context.function != "" && function != context.function {
			return false
		}
	}
	return true
}

func (g *Graph) ensureEvidenceContexts() {
	if g.evidenceContexts != nil && g.evidenceContextItems == len(g.Evidence) {
		return
	}
	g.evidenceContexts = make(map[string]graphFactContext, len(g.Evidence))
	for _, evidence := range g.Evidence {
		g.evidenceContexts[evidence.ID] = graphFactContext{scopeID: evidence.ScopeID, function: evidence.Function, architecture: evidence.Arch}
	}
	g.evidenceContextItems = len(g.Evidence)
}

func (g *Graph) AddNetworkImplementation(observation NetworkImplementationObservation) string {
	if !ValidNetworkImplementationKind(observation.Kind) || observation.SubjectNodeID == "" || strings.TrimSpace(observation.APIOrTool) == "" || !hasNonemptyString(observation.EvidenceIDs) || !ValidNetworkImplementationTLSContext(observation.TLSProvider, observation.TLSProviderBasis) {
		g.rejectItem()
		return ""
	}
	observation.OperationIDs = sortedUniqueStrings(observation.OperationIDs)
	if len(observation.OperationIDs) > maxNetworkOperationIDs || !ValidNetworkImplementationOperationPolicy(observation.Kind, len(observation.OperationIDs) > 0) {
		g.rejectItem()
		return ""
	}
	for _, property := range observation.SecurityProperties {
		if !ValidNetworkSecurityProperty(property) {
			g.rejectItem()
			return ""
		}
	}
	observation.SecurityProperties = sortedUniqueNetworkSecurityProperties(observation.SecurityProperties)
	observation.UnresolvedProperties = sortedUniqueStrings(observation.UnresolvedProperties)
	observation.EvidenceIDs = sortedUniqueStrings(observation.EvidenceIDs)
	if observation.Support == "" {
		observation.Support = SupportCorroborated
	}
	if !observation.Support.Valid() {
		g.rejectItem()
		return ""
	}
	if observation.ScopeID != "" {
		function := g.scopeFunction(observation.ScopeID)
		if architecture := g.scopeArchitecture(observation.ScopeID); architecture != "" {
			if observation.Architecture != "" && observation.Architecture != architecture {
				g.rejectItem()
				return ""
			}
			observation.Architecture = architecture
		}
		if !g.evidenceContextCompatible(observation.EvidenceIDs, observation.ScopeID, function, observation.Architecture, true) {
			g.rejectItem()
			return ""
		}
	} else if !g.evidenceContextCompatible(observation.EvidenceIDs, "", "", observation.Architecture, true) {
		g.rejectItem()
		return ""
	}
	var err error
	observation.Execution, err = NormalizeExecutionContext(observation.Execution)
	if err != nil {
		g.rejectItem()
		return ""
	}
	if !g.reserveItem(observation, true) {
		return ""
	}
	g.nextNetworkImplementation++
	observation.ID = fmt.Sprintf("network-implementation-%04d", g.nextNetworkImplementation)
	g.Network = append(g.Network, observation)
	return observation.ID
}

func (g *Graph) AddArtifactProperty(property ArtifactProperty) bool {
	if onlyEmptyStrings(property.EvidenceIDs) {
		g.dropItem()
		return false
	}
	if property.Support == "" {
		property.Support = SupportCorroborated
	}
	if !property.Support.Valid() {
		g.rejectItem()
		return false
	}
	if !g.reserveItem(property, false) {
		return false
	}
	g.ArtifactProperties = append(g.ArtifactProperties, property)
	return true
}

func (g *Graph) AddCoverage(coverage Coverage) bool {
	if !g.reserveItem(coverage, false) {
		return false
	}
	g.Coverage = append(g.Coverage, coverage)
	return true
}

// ItemLimitReached lets analyzers stop expensive derived work once no more IR
// can be retained. A zero limit intentionally means unlimited for small unit
// graphs and callers outside the inspection pipeline.
func (g *Graph) ItemLimitReached() bool {
	return g.ItemLimit > 0 && g.itemCount() >= g.ItemLimit
}

func (g *Graph) EvidenceLimitReached() bool {
	return g.EvidenceLimit > 0 && len(g.Evidence) >= g.EvidenceLimit
}

func (g *Graph) WorkLimitReached() bool {
	return g.ItemLimitReached() || g.EvidenceLimitReached() || g.StringBytesDropped > 0 || g.StringByteLimit > 0 && g.StringBytes >= g.StringByteLimit
}

// DerivedItemLimitReached reports whether an analyzer can retain another
// non-evidence IR item. Evidence-count exhaustion does not prevent bounded
// relations from being derived over evidence and operations already retained.
func (g *Graph) DerivedItemLimitReached() bool {
	return g.ItemLimitReached() || g.StringBytesDropped > 0 || g.StringByteLimit > 0 && g.StringBytes >= g.StringByteLimit
}

// MarkWorkOmitted makes an early analyzer exit visible through FinalizeLimits.
func (g *Graph) MarkWorkOmitted() {
	if !g.WorkLimitReached() {
		return
	}
	if g.EvidenceLimitReached() && g.EvidenceLimitDrops == 0 {
		g.EvidenceLimitDrops++
	}
	g.dropItem()
}

// FinalizeLimits records an explicit partial-coverage marker if an IR budget
// discarded anything or a producer attempted to add an invalid typed record.
// This marker uses one of PostLimitCoverageAllowance's bounded slots so the
// loss is never silent and invalid input is not mislabeled as exhaustion.
func (g *Graph) FinalizeLimits() {
	if g.limitFinalized || g.ItemsDropped == 0 && g.InvalidItemsDropped == 0 && g.StringBytesDropped == 0 {
		return
	}
	g.limitFinalized = true
	var details []string
	if g.ItemsDropped > 0 {
		if g.ItemLimitReached() {
			details = append(details, fmt.Sprintf("behavior item limit %d reached; omitted %d additional items", g.ItemLimit, g.ItemsDropped))
		} else {
			details = append(details, fmt.Sprintf("omitted %d behavior items after an analysis limit was reached", g.ItemsDropped))
		}
	}
	if g.StringBytesDropped > 0 {
		details = append(details, fmt.Sprintf("retained string byte limit %d reached; omitted at least %d string bytes", g.StringByteLimit, g.StringBytesDropped))
	}
	if g.InvalidItemsDropped > 0 {
		details = append(details, fmt.Sprintf("rejected %d invalid behavior items", g.InvalidItemsDropped))
	}
	g.Coverage = append(g.Coverage, Coverage{
		AnalysisArea: "behavior-ir",
		Status:       "partial",
		Detail:       strings.Join(details, "; "),
	})
}

const generatedIDByteReserve = 16

func (g *Graph) reserveItem(item any, generatedID bool) bool {
	if g.ItemLimitReached() {
		g.dropItem()
		return false
	}
	stringBytes := retainedStringBytes(item)
	if generatedID {
		stringBytes += generatedIDByteReserve
	}
	if !g.reserveStrings(stringBytes) {
		g.dropItem()
		return false
	}
	return true
}

func (g *Graph) itemCount() int {
	return len(g.Scopes) + len(g.Features) + len(g.ExecutionRoots) + len(g.InvokedTargets) + len(g.AnalysisSelections) + len(g.Operations) + len(g.Network) + len(g.ArtifactProperties) + len(g.Coverage) + len(g.Relations)
}

func (g *Graph) reserveStrings(size int64) bool {
	if size < 0 {
		size = maxInt64
	}
	if g.StringByteLimit <= 0 {
		g.StringBytes = saturatingAddInt64(g.StringBytes, size)
		return true
	}
	if g.StringBytesDropped > 0 {
		g.StringBytesDropped = saturatingAddInt64(g.StringBytesDropped, size)
		return false
	}
	if size > g.StringByteLimit-g.StringBytes {
		g.StringBytesDropped = saturatingAddInt64(g.StringBytesDropped, size)
		return false
	}
	g.StringBytes += size
	return true
}

func hasNonemptyString(values []string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

// onlyEmptyStrings distinguishes an explicitly supplied list whose retained
// evidence IDs were all dropped from a nil list used by small isolated graph
// tests. Public reports still require concrete evidence at validation time.
func onlyEmptyStrings(values []string) bool {
	return values != nil && !hasNonemptyString(values)
}

func (g *Graph) dropItem() {
	if g.ItemsDropped < int(^uint(0)>>1) {
		g.ItemsDropped++
	}
}

func (g *Graph) rejectItem() {
	if g.InvalidItemsDropped < int(^uint(0)>>1) {
		g.InvalidItemsDropped++
	}
}

const maxInt64 = int64(^uint64(0) >> 1)

func saturatingAddInt64(left, right int64) int64 {
	if right > maxInt64-left {
		return maxInt64
	}
	return left + right
}

func retainedStringBytes(value any) int64 {
	return retainedReflectStringBytes(reflect.ValueOf(value))
}

func retainedReflectStringBytes(value reflect.Value) int64 {
	if !value.IsValid() {
		return 0
	}
	switch value.Kind() {
	case reflect.String:
		return retainedStringByteCost(value.String())
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return 0
		}
		return retainedReflectStringBytes(value.Elem())
	case reflect.Struct:
		var total int64
		for i := 0; i < value.NumField(); i++ {
			total = saturatingAddInt64(total, retainedReflectStringBytes(value.Field(i)))
		}
		return total
	case reflect.Slice, reflect.Array:
		var total int64
		for i := 0; i < value.Len(); i++ {
			total = saturatingAddInt64(total, retainedReflectStringBytes(value.Index(i)))
		}
		return total
	case reflect.Map:
		if value.IsNil() {
			return 0
		}
		var total int64
		iterator := value.MapRange()
		for iterator.Next() {
			total = saturatingAddInt64(total, retainedReflectStringBytes(iterator.Key()))
			total = saturatingAddInt64(total, retainedReflectStringBytes(iterator.Value()))
		}
		return total
	default:
		return 0
	}
}

// retainedStringByteCost bounds both in-memory string data and its JSON
// representation. This prevents control characters or invalid UTF-8 from
// expanding a budgeted graph by up to six times when a report is serialized.
func retainedStringByteCost(value string) int64 {
	rawBytes := int64(len(value))
	var jsonBytes int64
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			jsonBytes = saturatingAddInt64(jsonBytes, 6) // \ufffd
			value = value[1:]
			continue
		}
		value = value[size:]
		switch r {
		case '"', '\\':
			jsonBytes = saturatingAddInt64(jsonBytes, 2)
		case '\b', '\f', '\n', '\r', '\t':
			jsonBytes = saturatingAddInt64(jsonBytes, 2)
		case '\u2028', '\u2029':
			jsonBytes = saturatingAddInt64(jsonBytes, 6)
		default:
			if r < 0x20 {
				jsonBytes = saturatingAddInt64(jsonBytes, 6) // \u00xx
			} else {
				jsonBytes = saturatingAddInt64(jsonBytes, int64(size))
			}
		}
	}
	if jsonBytes > rawBytes {
		return jsonBytes
	}
	return rawBytes
}

// ValidateExecutionContexts checks direct graph fixtures and loaded graphs
// that did not pass through the Add methods. It does not mutate the graph;
// Sort performs normalization for valid contexts.
func (g *Graph) ValidateExecutionContexts() error {
	for i, feature := range g.Features {
		if _, err := NormalizeExecutionContext(feature.Execution); err != nil {
			return fmt.Errorf("features[%d].execution: %w", i, err)
		}
	}
	for i, target := range g.InvokedTargets {
		if _, err := NormalizeExecutionContext(target.Execution); err != nil {
			return fmt.Errorf("invoked_targets[%d].execution: %w", i, err)
		}
	}
	for i, operation := range g.Operations {
		if _, err := NormalizeExecutionContext(operation.Execution); err != nil {
			return fmt.Errorf("operations[%d].execution: %w", i, err)
		}
	}
	return nil
}

// ValidateOperations rejects direct graph fixtures that bypass AddOperation.
// Extractors and loaded reports must use the same closed operation and
// resource-binding contract.
func (g *Graph) ValidateOperations() error {
	for i, operation := range g.Operations {
		if !ValidOperationKind(operation.Kind) {
			return fmt.Errorf("operations[%d].kind has invalid value %q", i, operation.Kind)
		}
		if operation.SourceOrderGroup < 0 || operation.SourceOrdinal < 0 ||
			operation.WorkingDirectoryContext < 0 || operation.HomeDirectoryContext < 0 ||
			(operation.SourceOrderGroup == 0) != (operation.SourceOrdinal == 0) {
			return fmt.Errorf("operations[%d] has invalid transient source order %d/%d", i, operation.SourceOrderGroup, operation.SourceOrdinal)
		}
		if _, err := NormalizeResourceBindings(operation.Kind, operation.ResourceBindings); err != nil {
			return fmt.Errorf("operations[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateRelations rejects direct graph fixtures that bypass AddRelation and
// resolves every typed endpoint against the retained semantic graph.
func (g *Graph) ValidateRelations() error {
	if len(g.Relations) > MaxOperationRelations {
		return fmt.Errorf("operation_relations has %d items; limit is %d", len(g.Relations), MaxOperationRelations)
	}
	operations, scopes, roots, targets := g.relationIndexes()
	normalizedRelations := make([]OperationRelation, len(g.Relations))
	callScopes := make(map[relationScopePair]struct{})
	for index, relation := range g.Relations {
		normalized, err := NormalizeOperationRelation(relation)
		if err != nil {
			return fmt.Errorf("operation_relations[%d]: %w", index, err)
		}
		normalizedRelations[index] = normalized
		if normalized.Kind == RelationCalls {
			callScopes[relationScopePair{From: normalized.From.ID, To: normalized.To.ID}] = struct{}{}
		}
	}
	for index, relation := range normalizedRelations {
		if err := validateRelationAgainstGraph(relation, operations, scopes, roots, targets, callScopes); err != nil {
			return fmt.Errorf("operation_relations[%d]: %w", index, err)
		}
	}
	return validatePrecedesAcyclic(normalizedRelations)
}

// ValidateRelationEvidenceLineage rejects relation proofs that do not belong
// to the exact endpoint facts. Unlike AddRelation's builder-time check, this
// method is strict: every evidence ID must resolve in the retained graph.
func (g *Graph) ValidateRelationEvidenceLineage() error {
	operations, scopes, roots, targets := g.relationIndexes()
	evidence := make(map[string]Evidence, len(g.Evidence))
	for _, item := range g.Evidence {
		evidence[item.ID] = item
	}
	for index, relation := range g.Relations {
		normalized, err := NormalizeOperationRelation(relation)
		if err != nil {
			return fmt.Errorf("operation_relations[%d]: %w", index, err)
		}
		if err := validateRelationEvidenceLineage(normalized, evidence, g.Features, operations, scopes, roots, targets, true); err != nil {
			return fmt.Errorf("operation_relations[%d]: %w", index, err)
		}
	}
	return nil
}

func (g *Graph) Sort() error {
	if err := g.ValidateExecutionContexts(); err != nil {
		return err
	}
	if err := g.ValidateOperations(); err != nil {
		return err
	}
	if err := g.ValidateRelations(); err != nil {
		return err
	}
	if err := g.ValidateRelationEvidenceLineage(); err != nil {
		return err
	}
	sort.SliceStable(g.Scopes, func(i, j int) bool { return g.Scopes[i].ID < g.Scopes[j].ID })
	sort.SliceStable(g.Evidence, func(i, j int) bool { return g.Evidence[i].ID < g.Evidence[j].ID })
	for i := range g.Features {
		g.Features[i].EvidenceIDs = sortedUniqueStrings(g.Features[i].EvidenceIDs)
		if execution, err := NormalizeExecutionContext(g.Features[i].Execution); err == nil {
			g.Features[i].Execution = execution
		}
	}
	sort.SliceStable(g.Features, func(i, j int) bool { return g.Features[i].ID < g.Features[j].ID })
	for i := range g.ExecutionRoots {
		g.ExecutionRoots[i].EvidenceIDs = sortedUniqueStrings(g.ExecutionRoots[i].EvidenceIDs)
	}
	sort.SliceStable(g.ExecutionRoots, func(i, j int) bool { return g.ExecutionRoots[i].ID < g.ExecutionRoots[j].ID })
	for i := range g.InvokedTargets {
		g.InvokedTargets[i].EvidenceIDs = sortedUniqueStrings(g.InvokedTargets[i].EvidenceIDs)
		if execution, err := NormalizeExecutionContext(g.InvokedTargets[i].Execution); err == nil {
			g.InvokedTargets[i].Execution = execution
		}
	}
	sort.SliceStable(g.InvokedTargets, func(i, j int) bool { return g.InvokedTargets[i].ID < g.InvokedTargets[j].ID })
	for i := range g.AnalysisSelections {
		g.AnalysisSelections[i].Reasons = normalizeSelectionReasons(g.AnalysisSelections[i].Reasons)
	}
	sort.SliceStable(g.AnalysisSelections, func(i, j int) bool {
		if compared := strings.Compare(g.AnalysisSelections[i].NodeID, g.AnalysisSelections[j].NodeID); compared != 0 {
			return compared < 0
		}
		return compareSelectionReasons(g.AnalysisSelections[i].Reasons, g.AnalysisSelections[j].Reasons) < 0
	})
	for i := range g.Operations {
		g.Operations[i].EvidenceIDs = sortedUniqueStrings(g.Operations[i].EvidenceIDs)
		g.Operations[i].ResourceBindings, _ = NormalizeResourceBindings(g.Operations[i].Kind, g.Operations[i].ResourceBindings)
		if execution, err := NormalizeExecutionContext(g.Operations[i].Execution); err == nil {
			g.Operations[i].Execution = execution
		}
	}
	sort.SliceStable(g.Operations, func(i, j int) bool { return g.Operations[i].ID < g.Operations[j].ID })
	for i := range g.Relations {
		g.Relations[i], _ = NormalizeOperationRelation(g.Relations[i])
	}
	sort.SliceStable(g.Relations, func(i, j int) bool { return g.Relations[i].ID < g.Relations[j].ID })
	for i := range g.Network {
		g.Network[i].OperationIDs = sortedUniqueStrings(g.Network[i].OperationIDs)
		g.Network[i].SecurityProperties = sortedUniqueNetworkSecurityProperties(g.Network[i].SecurityProperties)
		g.Network[i].UnresolvedProperties = sortedUniqueStrings(g.Network[i].UnresolvedProperties)
		g.Network[i].EvidenceIDs = sortedUniqueStrings(g.Network[i].EvidenceIDs)
		if execution, err := NormalizeExecutionContext(g.Network[i].Execution); err == nil {
			g.Network[i].Execution = execution
		}
	}
	sort.SliceStable(g.Network, func(i, j int) bool {
		return compareNetworkImplementationObservations(g.Network[i], g.Network[j]) < 0
	})
	for i := range g.ArtifactProperties {
		g.ArtifactProperties[i].EvidenceIDs = sortedUniqueStrings(g.ArtifactProperties[i].EvidenceIDs)
	}
	sort.SliceStable(g.ArtifactProperties, func(i, j int) bool {
		return compareArtifactProperties(g.ArtifactProperties[i], g.ArtifactProperties[j]) < 0
	})
	sort.SliceStable(g.Coverage, func(i, j int) bool {
		return compareCoverage(g.Coverage[i], g.Coverage[j]) < 0
	})
	return nil
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
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

func sortedUniqueNetworkSecurityProperties(values []NetworkSecurityProperty) []NetworkSecurityProperty {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	out := values[:0]
	for _, value := range values {
		if value == "" || len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func compareArtifactProperties(left, right ArtifactProperty) int {
	for _, pair := range [][2]string{
		{left.NodeID, right.NodeID},
		{left.Kind, right.Kind},
		{left.Value, right.Value},
		{string(left.Support), string(right.Support)},
	} {
		if compared := strings.Compare(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	return 0
}

func compareCoverage(left, right Coverage) int {
	for _, pair := range [][2]string{
		{left.NodeID, right.NodeID},
		{left.AnalysisArea, right.AnalysisArea},
		{left.Status, right.Status},
		{left.Detail, right.Detail},
	} {
		if compared := strings.Compare(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	return 0
}

func compareStrings(left, right []string) int {
	for i := 0; i < min(len(left), len(right)); i++ {
		if compared := strings.Compare(left[i], right[i]); compared != 0 {
			return compared
		}
	}
	return len(left) - len(right)
}
