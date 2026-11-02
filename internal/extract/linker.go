package extract

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

// Operation-relation linking is derived work over attacker-controlled operations.
// The graph's item limit bounds retained relations in the normal pipeline, while
// this independent limit also bounds candidate work for callers that construct
// an otherwise-unlimited graph.
const maxOperationRelationLinkWork = 4 * behavior.DefaultItemLimit

const maxDirectCallLinkWork = 4 * behavior.DefaultItemLimit

func LinkOperationRelations(graph *behavior.Graph) {
	LinkDirectCalls(graph)
	linkOperationRelations(graph, maxOperationRelationLinkWork)
}

// LinkDirectCalls promotes directly observed function-call features into
// evidenced scope relations. The source features remain in the cheap feature
// lane; failed or budget-truncated promotion never erases the observation.
func LinkDirectCalls(graph *behavior.Graph) {
	linkDirectCalls(graph, maxDirectCallLinkWork)
}

func linkDirectCalls(graph *behavior.Graph, workLimit int) {
	type scopeLookupKey struct {
		nodeID       string
		architecture string
		function     string
	}
	scopeByID := make(map[string]behavior.Scope, len(graph.Scopes))
	functionScopes := make(map[scopeLookupKey][]string)
	for _, scope := range graph.Scopes {
		if scope.ID == "" {
			continue
		}
		scopeByID[scope.ID] = scope
		if scope.Kind == "function" && scope.NodeID != "" && scope.Function != "" {
			key := scopeLookupKey{nodeID: scope.NodeID, architecture: scope.Architecture, function: scope.Function}
			functionScopes[key] = append(functionScopes[key], scope.ID)
		}
	}
	seen := make(map[string]bool, len(graph.Relations))
	for _, relation := range graph.Relations {
		if relation.Kind == behavior.RelationCalls {
			seen[relation.From.ID+"\x00"+relation.To.ID] = true
		}
	}
	work := newDerivedWorkBudget(workLimit)
	for _, feature := range graph.Features {
		if !directCallFeatureKey(feature.Key) || feature.NodeID == "" || feature.ScopeID == "" || feature.Value == "" || len(feature.EvidenceIDs) == 0 {
			continue
		}
		caller, ok := scopeByID[feature.ScopeID]
		if !ok || caller.NodeID != feature.NodeID {
			continue
		}
		key := scopeLookupKey{nodeID: feature.NodeID, architecture: caller.Architecture, function: feature.Value}
		targetScopeIDs := functionScopes[key]
		if len(targetScopeIDs) > 1 {
			addPartialCoverageOnce(graph, feature.NodeID, "direct-call-linking", "multiple same-node function scopes share the observed call target identity; no exact calls relation was derived")
			continue
		}
		for _, targetScopeID := range targetScopeIDs {
			if graph.DerivedItemLimitReached() {
				markDerivedGraphLimit(graph, "direct-call-linking")
				return
			}
			if !work.take() {
				markDerivedWorkLimit(graph, "direct-call-linking", workLimit, "direct-call candidates")
				return
			}
			pair := feature.ScopeID + "\x00" + targetScopeID
			if seen[pair] {
				continue
			}
			if graph.AddRelation(behavior.OperationRelation{
				Kind:         behavior.RelationCalls,
				From:         behavior.IDRelationEndpoint(behavior.RelationEndpointScope, feature.ScopeID),
				To:           behavior.IDRelationEndpoint(behavior.RelationEndpointScope, targetScopeID),
				EvidenceIDs:  feature.EvidenceIDs,
				Support:      feature.Support,
				Execution:    feature.Execution,
				Architecture: caller.Architecture,
			}) == "" {
				markDerivedGraphLimit(graph, "direct-call-linking")
				return
			}
			seen[pair] = true
		}
	}
}

func directCallFeatureKey(key string) bool {
	return key == "script.function_call" || key == "macho.function_call"
}

func linkOperationRelations(graph *behavior.Graph, workLimit int) {
	type relationGroup struct {
		downloads    []behavior.ModeledOperation
		archives     []behavior.ModeledOperation
		uploads      []behavior.ModeledOperation
		invalidators []behavior.ModeledOperation
		chmods       []behavior.ModeledOperation
		execs        []behavior.ModeledOperation
	}
	type relationGroupKey struct {
		target  behavior.ResourceIdentityKey
		context behavior.ContextKey
	}
	byTarget := map[relationGroupKey]*relationGroup{}
	unknownMutations := map[behavior.ContextKey][]behavior.ModeledOperation{}
	scopeLinks := operationScopeLinks(graph)

	for _, operation := range graph.Operations {
		context, ok := relationContext(operation)
		if !ok {
			continue
		}
		target, targetOK := relationTargetKey(operation)
		if !targetOK && operationMayMutateFile(operation.Kind) {
			unknownMutations[context] = append(unknownMutations[context], operation)
		}
		if targetOK {
			key := relationGroupKey{target: target, context: context}
			if byTarget[key] == nil {
				byTarget[key] = &relationGroup{}
			}
			switch operation.Kind {
			case behavior.OperationNetworkDownload:
				byTarget[key].downloads = append(byTarget[key].downloads, operation)
				byTarget[key].invalidators = append(byTarget[key].invalidators, operation)
			case behavior.OperationArchiveCreate:
				byTarget[key].archives = append(byTarget[key].archives, operation)
				byTarget[key].invalidators = append(byTarget[key].invalidators, operation)
			case behavior.OperationDirectoryCreate,
				behavior.OperationFileCopy,
				behavior.OperationFileDelete,
				behavior.OperationFileMove,
				behavior.OperationFileWrite,
				behavior.OperationPlistModify,
				behavior.OperationScreenCapture,
				behavior.OperationShellProfileModify:
				byTarget[key].invalidators = append(byTarget[key].invalidators, operation)
			case behavior.OperationNetworkUpload:
				byTarget[key].uploads = append(byTarget[key].uploads, operation)
			case behavior.OperationFileMakeExecutable:
				byTarget[key].chmods = append(byTarget[key].chmods, operation)
			case behavior.OperationProcessExecute, behavior.OperationInterpreterInvoke:
				byTarget[key].execs = append(byTarget[key].execs, operation)
			}
		}
		if operation.Kind == behavior.OperationFileMove {
			// A move can invalidate both the destination it replaces and the
			// source identity it removes. Copy and archive sources are reads and
			// deliberately do not take this second invalidation path.
			if source, sourceOK := relationResourceKey(operation, behavior.ResourceRoleSource); sourceOK && (!targetOK || source != target) {
				sourceKey := relationGroupKey{target: source, context: context}
				if byTarget[sourceKey] == nil {
					byTarget[sourceKey] = &relationGroup{}
				}
				byTarget[sourceKey].invalidators = append(byTarget[sourceKey].invalidators, operation)
			} else if !sourceOK && targetOK {
				unknownMutations[context] = append(unknownMutations[context], operation)
			}
		}
	}
	seen := existingRelationKeys(graph.Relations)
	work := newDerivedWorkBudget(workLimit)
	keys := make([]relationGroupKey, 0, len(byTarget))
	for key := range byTarget {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].target != keys[j].target {
			return keys[i].target < keys[j].target
		}
		return behavior.CompareContextKeys(keys[i].context, keys[j].context) < 0
	})
	for _, key := range keys {
		group := byTarget[key]
		for _, archive := range group.archives {
			for _, upload := range group.uploads {
				if graph.DerivedItemLimitReached() {
					markDerivedGraphLimit(graph, "operation-relation-linking")
					return
				}
				if !work.take() {
					markDerivedWorkLimit(graph, "operation-relation-linking", workLimit, "operation-relation candidates")
					return
				}
				if !scopeLinks.compatible(archive.ScopeID, upload.ScopeID) || !operationBefore(archive, upload) {
					continue
				}
				intervening, complete := interveningFileMutation(archive, upload, group.invalidators, unknownMutations[key.context], &work)
				if !complete {
					markDerivedWorkLimit(graph, "operation-relation-linking", workLimit, "operation-relation candidates")
					return
				}
				if intervening {
					continue
				}
				if !addOperationPathRelations(graph, seen, []behavior.ModeledOperation{archive, upload}) {
					markDerivedGraphLimit(graph, "operation-relation-linking")
					return
				}
			}
		}
		for _, download := range group.downloads {
			for _, exec := range group.execs {
				if graph.DerivedItemLimitReached() {
					markDerivedGraphLimit(graph, "operation-relation-linking")
					return
				}
				if !work.take() {
					markDerivedWorkLimit(graph, "operation-relation-linking", workLimit, "operation-relation candidates")
					return
				}
				if !scopeLinks.compatible(download.ScopeID, exec.ScopeID) || !operationBefore(download, exec) {
					continue
				}
				intervening, complete := interveningFileMutation(download, exec, group.invalidators, unknownMutations[key.context], &work)
				if !complete {
					markDerivedWorkLimit(graph, "operation-relation-linking", workLimit, "operation-relation candidates")
					return
				}
				if intervening {
					continue
				}
				matchedChmod := false
				for _, chmod := range group.chmods {
					if graph.DerivedItemLimitReached() {
						markDerivedGraphLimit(graph, "operation-relation-linking")
						return
					}
					if !work.take() {
						markDerivedWorkLimit(graph, "operation-relation-linking", workLimit, "operation-relation candidates")
						return
					}
					if !scopeLinks.compatible(download.ScopeID, chmod.ScopeID) || !scopeLinks.compatible(chmod.ScopeID, exec.ScopeID) || !operationBefore(download, chmod) || !operationBefore(chmod, exec) {
						continue
					}
					matchedChmod = true
					if !addOperationPathRelations(graph, seen, []behavior.ModeledOperation{download, chmod, exec}) {
						markDerivedGraphLimit(graph, "operation-relation-linking")
						return
					}
				}
				if !matchedChmod {
					if !addOperationPathRelations(graph, seen, []behavior.ModeledOperation{download, exec}) {
						markDerivedGraphLimit(graph, "operation-relation-linking")
						return
					}
				}
			}
		}
	}
}

func operationMayMutateFile(kind behavior.OperationKind) bool {
	switch kind {
	case behavior.OperationArchiveCreate, behavior.OperationNetworkDownload,
		behavior.OperationDirectoryCreate, behavior.OperationFileCopy,
		behavior.OperationFileDelete, behavior.OperationFileMove,
		behavior.OperationFileWrite, behavior.OperationPlistModify,
		behavior.OperationScreenCapture, behavior.OperationShellProfileModify:
		return true
	}
	return false
}

func interveningFileMutation(producer, consumer behavior.ModeledOperation, invalidators, unknown []behavior.ModeledOperation, work *derivedWorkBudget) (bool, bool) {
	for _, candidates := range [2][]behavior.ModeledOperation{invalidators, unknown} {
		for _, other := range candidates {
			if other.ID == producer.ID {
				continue
			}
			if !work.take() {
				return false, false
			}
			afterProducer, afterKnown := compareOperationSource(producer, other)
			beforeConsumer, beforeKnown := compareOperationSource(other, consumer)
			if !afterKnown || !beforeKnown {
				// A same-resource or unresolved mutation cannot be placed
				// outside the interval. Do not claim which bytes are consumed.
				return true, true
			}
			if afterProducer < 0 && beforeConsumer <= 0 {
				return true, true
			}
		}
	}
	return false, true
}

func operationBefore(left, right behavior.ModeledOperation) bool {
	order, known := compareOperationSource(left, right)
	return known && order < 0
}

// compareOperationSource returns source order only where the extractor proved
// it. Different known lines in one scope are ordered directly. Different
// scopes require a shared transient parser group: lexical definition order is
// not call-site order. Equal or unknown lines likewise require a shared group
// and distinct statement ordinals. Background or alternative-branch commands
// carry explicit uncertainty and cannot supply order. Global graph append
// order is never treated as source order.
func compareOperationSource(left, right behavior.ModeledOperation) (int, bool) {
	if left.ID != "" && left.ID == right.ID {
		return 0, true
	}
	if left.SourceOrderUncertain || right.SourceOrderUncertain {
		return 0, false
	}
	sameTransientGroup := left.SourceOrderGroup != 0 &&
		left.SourceOrderGroup == right.SourceOrderGroup &&
		left.SourceOrdinal != 0 && right.SourceOrdinal != 0
	if left.ScopeID != right.ScopeID {
		if !sameTransientGroup {
			return 0, false
		}
		// Line numbers belong to their individual source scopes. In particular,
		// an inline or decoded child starts its own line coordinate system, so
		// comparing its line 1 with an outer shell line would invent order.
		// A shared parser group can cross scopes only through distinct statement
		// ordinals assigned by that parser.
		switch {
		case left.SourceOrdinal < right.SourceOrdinal:
			return -1, true
		case left.SourceOrdinal > right.SourceOrdinal:
			return 1, true
		default:
			return 0, true
		}
	}
	if left.Line > 0 && right.Line > 0 && left.Line != right.Line {
		if left.Line < right.Line {
			return -1, true
		}
		return 1, true
	}
	if !sameTransientGroup {
		return 0, false
	}
	switch {
	case left.SourceOrdinal < right.SourceOrdinal:
		return -1, true
	case left.SourceOrdinal > right.SourceOrdinal:
		return 1, true
	default:
		return 0, true
	}
}

func addOperationPathRelations(graph *behavior.Graph, seen map[string]bool, operations []behavior.ModeledOperation) bool {
	if len(operations) < 2 {
		return false
	}
	for _, operation := range operations {
		binding, kind, endpointOrder, ok := operationFlowBinding(operation)
		if !ok {
			return false
		}
		operationEndpoint := behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, operation.ID)
		resourceEndpoint := behavior.ResourceRelationEndpoint(binding.Role, binding.Resource)
		from, to := operationEndpoint, resourceEndpoint
		if endpointOrder < 0 {
			from, to = resourceEndpoint, operationEndpoint
		}
		if !addOperationRelationOnce(graph, seen, behavior.OperationRelation{
			Kind:         kind,
			From:         from,
			To:           to,
			EvidenceIDs:  operationRelationEvidence(operation, binding),
			Support:      operation.Support,
			Execution:    operation.Execution,
			Architecture: operation.Architecture,
		}) {
			return false
		}
	}
	for index := 0; index+1 < len(operations); index++ {
		left, right := operations[index], operations[index+1]
		if !addOperationRelationOnce(graph, seen, behavior.OperationRelation{
			Kind:         behavior.RelationPrecedes,
			From:         behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, left.ID),
			To:           behavior.IDRelationEndpoint(behavior.RelationEndpointOperation, right.ID),
			EvidenceIDs:  boundedEndpointRelationEvidence(operationRelationEvidence(left, behavior.ResourceBinding{}), operationRelationEvidence(right, behavior.ResourceBinding{})),
			Support:      weakerSupport(left.Support, right.Support),
			Execution:    left.Execution,
			Architecture: left.Architecture,
		}) {
			return false
		}
	}
	return true
}

func operationFlowBinding(operation behavior.ModeledOperation) (behavior.ResourceBinding, behavior.RelationKind, int, bool) {
	var role behavior.ResourceRole
	kind, order := behavior.RelationConsumes, -1
	switch operation.Kind {
	case behavior.OperationNetworkDownload:
		role, kind, order = behavior.ResourceRoleLocalOutput, behavior.RelationProduces, 1
	case behavior.OperationArchiveCreate:
		role, kind, order = behavior.ResourceRoleLocalOutput, behavior.RelationProduces, 1
	case behavior.OperationNetworkUpload:
		role = behavior.ResourceRoleLocalInput
	case behavior.OperationFileMakeExecutable:
		role = behavior.ResourceRoleTarget
	case behavior.OperationProcessExecute:
		role = behavior.ResourceRoleExecutable
	case behavior.OperationInterpreterInvoke:
		role = behavior.ResourceRoleLocalInput
	default:
		return behavior.ResourceBinding{}, "", 0, false
	}
	binding, ok := operation.FirstBinding(role)
	if !ok || binding.Resource.Kind != behavior.ResourceFile {
		return behavior.ResourceBinding{}, "", 0, false
	}
	if _, correlated := binding.Resource.CorrelationKey(); !correlated {
		return behavior.ResourceBinding{}, "", 0, false
	}
	return binding, kind, order, true
}

func operationRelationEvidence(operation behavior.ModeledOperation, binding behavior.ResourceBinding) []string {
	evidence := append([]string(nil), operation.EvidenceIDs...)
	evidence = append(evidence, binding.EvidenceIDs...)
	if len(evidence) == 0 {
		for _, candidate := range operation.ResourceBindings {
			evidence = append(evidence, candidate.EvidenceIDs...)
		}
	}
	return boundedRelationEvidence(evidence)
}

func boundedRelationEvidence(groups ...[]string) []string {
	return boundedRelationEvidenceRetaining(nil, groups...)
}

// boundedEndpointRelationEvidence reserves one canonical proof from each
// nonempty endpoint before filling the remaining relation-evidence budget. A
// shared ID can satisfy both endpoints, but a lexically early, evidence-heavy
// endpoint cannot crowd a distinct endpoint entirely out of the bounded set.
func boundedEndpointRelationEvidence(left, right []string) []string {
	required := []string{firstEvidenceID(left), firstEvidenceID(right)}
	return boundedRelationEvidenceRetaining(required, left, right)
}

func firstEvidenceID(values []string) string {
	first := ""
	for _, value := range values {
		if value != "" && (first == "" || value < first) {
			first = value
		}
	}
	return first
}

func boundedRelationEvidenceRetaining(required []string, groups ...[]string) []string {
	var evidence []string
	for _, group := range groups {
		evidence = append(evidence, group...)
	}
	sort.Strings(evidence)
	out := make([]string, 0, min(len(evidence), behavior.MaxRelationEvidenceIDs))
	selected := make(map[string]bool, len(required))
	for _, evidenceID := range required {
		if evidenceID == "" || selected[evidenceID] {
			continue
		}
		selected[evidenceID] = true
		out = append(out, evidenceID)
	}
	for _, evidenceID := range evidence {
		if evidenceID == "" || selected[evidenceID] {
			continue
		}
		selected[evidenceID] = true
		out = append(out, evidenceID)
		if len(out) == behavior.MaxRelationEvidenceIDs {
			break
		}
	}
	sort.Strings(out)
	return out
}

func weakerSupport(left, right behavior.Support) behavior.Support {
	strength := func(value behavior.Support) int {
		switch value {
		case behavior.SupportDirect:
			return 3
		case behavior.SupportCorroborated:
			return 2
		case behavior.SupportHeuristic:
			return 1
		default:
			return 0
		}
	}
	if strength(left) <= strength(right) {
		return left
	}
	return right
}

func existingRelationKeys(relations []behavior.OperationRelation) map[string]bool {
	seen := make(map[string]bool, len(relations))
	for _, relation := range relations {
		seen[operationRelationKey(relation)] = true
	}
	return seen
}

func addOperationRelationOnce(graph *behavior.Graph, seen map[string]bool, relation behavior.OperationRelation) bool {
	key := operationRelationKey(relation)
	if seen[key] {
		return true
	}
	if graph.AddRelation(relation) == "" {
		return false
	}
	seen[key] = true
	return true
}

func operationRelationKey(relation behavior.OperationRelation) string {
	endpointKey := func(endpoint behavior.RelationEndpoint) string {
		key := string(endpoint.Kind) + "\x00" + endpoint.ID + "\x00" + string(endpoint.ResourceRole)
		if endpoint.Resource != nil {
			key += "\x00" + string(endpoint.Resource.Key())
		}
		return key
	}
	return string(relation.Kind) + "\x00" + endpointKey(relation.From) + "\x00" + endpointKey(relation.To)
}

func relationTargetKey(operation behavior.ModeledOperation) (behavior.ResourceIdentityKey, bool) {
	role := behavior.ResourceRole("")
	switch operation.Kind {
	case behavior.OperationArchiveCreate,
		behavior.OperationFileCopy,
		behavior.OperationFileWrite,
		behavior.OperationNetworkDownload,
		behavior.OperationScreenCapture:
		role = behavior.ResourceRoleLocalOutput
	case behavior.OperationDirectoryCreate,
		behavior.OperationFileDelete,
		behavior.OperationFileMove,
		behavior.OperationPlistModify,
		behavior.OperationShellProfileModify:
		role = behavior.ResourceRoleTarget
	case behavior.OperationNetworkUpload:
		role = behavior.ResourceRoleLocalInput
	case behavior.OperationFileMakeExecutable:
		role = behavior.ResourceRoleTarget
	case behavior.OperationProcessExecute:
		role = behavior.ResourceRoleExecutable
	case behavior.OperationInterpreterInvoke:
		role = behavior.ResourceRoleLocalInput
	default:
		return "", false
	}
	return relationResourceKey(operation, role)
}

func relationResourceKey(operation behavior.ModeledOperation, role behavior.ResourceRole) (behavior.ResourceIdentityKey, bool) {
	binding, ok := operation.FirstBinding(role)
	if !ok || binding.Resource.Kind != behavior.ResourceFile {
		return "", false
	}
	target, ok := binding.Resource.CorrelationKey()
	if !ok {
		return "", false
	}
	if !path.IsAbs(binding.Resource.Value) {
		context := operation.WorkingDirectoryContext
		mode := behavior.FilePathLiteral
		// A leading ./ does not turn a literal tilde directory into HOME.
		value := binding.Resource.Value
		for strings.HasPrefix(value, "./") {
			value = strings.TrimPrefix(value, "./")
		}
		if strings.HasPrefix(value, "~") {
			mode = binding.FilePathInterpretation
			if mode == behavior.FilePathHomeRelative {
				context = operation.HomeDirectoryContext
			} else if mode != behavior.FilePathLiteral {
				return "", false
			}
		}
		if context == 0 {
			return "", false
		}
		// ResourceIdentityKey itself is length-prefixed. Wrap it with a
		// parser-owned context; no sample-controlled path acts as a sentinel.
		target = behavior.ResourceIdentityKey(strconv.Itoa(int(mode)) + ":" + strconv.Itoa(context) + ":" + string(target))
	}
	return target, true
}

func relationContext(operation behavior.ModeledOperation) (behavior.ContextKey, bool) {
	if operation.ScopeID == "" {
		return behavior.ContextKey{}, false
	}
	// Scope compatibility is checked explicitly after grouping, so this key is
	// intentionally node/architecture/execution scoped rather than exact-scope
	// scoped. This permits a retained direct-call relation to join two scopes.
	key, err := behavior.NewContextKey(operation.Execution, operation.SubjectNodeID, "", operation.Architecture)
	return key, err == nil
}

type operationScopeLinkIndex map[string]map[string]bool

func (links operationScopeLinkIndex) compatible(left, right string) bool {
	return left != "" && (left == right || links[left][right])
}

func operationScopeLinks(graph *behavior.Graph) operationScopeLinkIndex {
	links := operationScopeLinkIndex{}
	link := func(left, right string) {
		if left == "" || right == "" {
			return
		}
		if links[left] == nil {
			links[left] = map[string]bool{}
		}
		if links[right] == nil {
			links[right] = map[string]bool{}
		}
		links[left][right] = true
		links[right][left] = true
	}
	for _, relation := range graph.Relations {
		if relation.Kind != behavior.RelationCalls || relation.From.Kind != behavior.RelationEndpointScope || relation.To.Kind != behavior.RelationEndpointScope {
			continue
		}
		link(relation.From.ID, relation.To.ID)
	}
	return links
}
