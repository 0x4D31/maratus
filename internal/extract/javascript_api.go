package extract

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	javaScriptAPIBindingAnalysisArea = "javascript-api-binding-analysis"
	maxJavaScriptAPIBindings         = 32
	maxJavaScriptAPICalls            = 256
	maxJavaScriptAPICallBytes        = 64 << 10
)

type javaScriptAPIResourceSpec struct {
	role  behavior.ResourceRole
	kind  behavior.ResourceKind
	index int
	fixed string
}

type javaScriptAPISpec struct {
	module    string
	method    string
	kind      behavior.OperationKind
	minArgs   int
	maxArgs   int
	callback  bool
	resources []javaScriptAPIResourceSpec
}

type javaScriptAPIBinding struct {
	module string
	method string
	line   int
	text   string
	proofs []javaScriptCommandProof
}

type javaScriptAPICall struct {
	binding string
	method  string
	args    string
}

var javaScriptAPISpecs = []javaScriptAPISpec{
	jsAPINetwork("axios", "delete", 1, 2),
	jsAPINetwork("axios", "get", 1, 2),
	jsAPINetwork("axios", "head", 1, 2),
	jsAPINetwork("axios", "options", 1, 2),
	jsAPINetwork("axios", "patch", 1, 3),
	jsAPINetwork("axios", "post", 1, 3),
	jsAPINetwork("axios", "put", 1, 3),

	jsAPICallbackFile("fs", "access", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "accessSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "appendFile", behavior.OperationFileWrite, 3, 4, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs", "appendFileSync", behavior.OperationFileWrite, 2, 3, behavior.ResourceRoleLocalOutput),
	jsAPICallbackFile("fs", "chmod", behavior.OperationFilePermissionModify, 3, 3, behavior.ResourceRoleTarget),
	jsAPIFile("fs", "chmodSync", behavior.OperationFilePermissionModify, 2, 2, behavior.ResourceRoleTarget),
	jsAPICallbackCopy("fs", "copyFile", 3, 4),
	jsAPICopy("fs", "copyFileSync", 2, 3),
	jsAPICallbackCopy("fs", "cp", 3, 4),
	jsAPICopy("fs", "cpSync", 2, 3),
	jsAPIFile("fs", "createReadStream", behavior.OperationFileRead, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs", "createWriteStream", behavior.OperationFileWrite, 1, 2, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs", "existsSync", behavior.OperationFileMetadataQuery, 1, 1, behavior.ResourceRoleSource),
	jsAPIFile("fs", "globSync", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "lstat", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "lstatSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "mkdir", behavior.OperationDirectoryCreate, 2, 3, behavior.ResourceRoleTarget),
	jsAPIFile("fs", "mkdirSync", behavior.OperationDirectoryCreate, 1, 2, behavior.ResourceRoleTarget),
	jsAPICallbackFile("fs", "opendir", behavior.OperationFileEnumerate, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "opendirSync", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "open", behavior.OperationFileOpen, 3, 4, behavior.ResourceRoleSource),
	jsAPIFile("fs", "openSync", behavior.OperationFileOpen, 2, 3, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "readdir", behavior.OperationFileEnumerate, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "readdirSync", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "readFile", behavior.OperationFileRead, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "readFileSync", behavior.OperationFileRead, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "readlink", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "readlinkSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "realpath", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "realpathSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackMove("fs", "rename", 3, 3),
	jsAPIMove("fs", "renameSync", 2, 2),
	jsAPICallbackFile("fs", "rm", behavior.OperationFileDelete, 2, 3, behavior.ResourceRoleTarget),
	jsAPIFile("fs", "rmSync", behavior.OperationFileDelete, 1, 2, behavior.ResourceRoleTarget),
	jsAPICallbackFile("fs", "rmdir", behavior.OperationFileDelete, 2, 3, behavior.ResourceRoleTarget),
	jsAPIFile("fs", "rmdirSync", behavior.OperationFileDelete, 1, 2, behavior.ResourceRoleTarget),
	jsAPICallbackFile("fs", "stat", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "statSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "statfs", behavior.OperationFileMetadataQuery, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs", "statfsSync", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPICallbackFile("fs", "truncate", behavior.OperationFileWrite, 2, 3, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs", "truncateSync", behavior.OperationFileWrite, 1, 2, behavior.ResourceRoleLocalOutput),
	jsAPICallbackFile("fs", "unlink", behavior.OperationFileDelete, 2, 2, behavior.ResourceRoleTarget),
	jsAPIFile("fs", "unlinkSync", behavior.OperationFileDelete, 1, 1, behavior.ResourceRoleTarget),
	jsAPICallbackFile("fs", "writeFile", behavior.OperationFileWrite, 3, 4, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs", "writeFileSync", behavior.OperationFileWrite, 2, 3, behavior.ResourceRoleLocalOutput),

	jsAPIFile("fs/promises", "access", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "appendFile", behavior.OperationFileWrite, 2, 3, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs/promises", "chmod", behavior.OperationFilePermissionModify, 2, 2, behavior.ResourceRoleTarget),
	jsAPICopy("fs/promises", "copyFile", 2, 3),
	jsAPICopy("fs/promises", "cp", 2, 3),
	jsAPIFile("fs/promises", "glob", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "lstat", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "mkdir", behavior.OperationDirectoryCreate, 1, 2, behavior.ResourceRoleTarget),
	jsAPIFile("fs/promises", "opendir", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "open", behavior.OperationFileOpen, 2, 3, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "readdir", behavior.OperationFileEnumerate, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "readFile", behavior.OperationFileRead, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "readlink", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "realpath", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIMove("fs/promises", "rename", 2, 2),
	jsAPIFile("fs/promises", "rm", behavior.OperationFileDelete, 1, 2, behavior.ResourceRoleTarget),
	jsAPIFile("fs/promises", "rmdir", behavior.OperationFileDelete, 1, 2, behavior.ResourceRoleTarget),
	jsAPIFile("fs/promises", "stat", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "statfs", behavior.OperationFileMetadataQuery, 1, 2, behavior.ResourceRoleSource),
	jsAPIFile("fs/promises", "truncate", behavior.OperationFileWrite, 1, 2, behavior.ResourceRoleLocalOutput),
	jsAPIFile("fs/promises", "unlink", behavior.OperationFileDelete, 1, 1, behavior.ResourceRoleTarget),
	jsAPIFile("fs/promises", "writeFile", behavior.OperationFileWrite, 2, 3, behavior.ResourceRoleLocalOutput),

	jsAPIFixed("os", "arch", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "cpus", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "endianness", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "freemem", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "hostname", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "loadavg", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "machine", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "networkInterfaces", behavior.OperationNetworkConfigurationQuery, behavior.ResourceConfiguration, "local network interfaces and addresses"),
	jsAPIFixed("os", "platform", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "release", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "totalmem", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "type", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "uptime", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "version", behavior.OperationSystemInfoQuery, behavior.ResourceSystem, "macOS system and hardware"),
	jsAPIFixed("os", "homedir", behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local user"),
	jsAPIFixed("os", "userInfo", behavior.OperationUserInfoQuery, behavior.ResourceUserAccount, "local user"),

	jsAPICallbackName("dns", "lookup", 2, 3),
	jsAPICallbackName("dns", "resolve", 2, 3),
	jsAPICallbackName("dns", "resolve4", 2, 3),
	jsAPICallbackName("dns", "resolve6", 2, 3),
	jsAPIName("dns/promises", "lookup", 1, 2),
	jsAPIName("dns/promises", "resolve", 1, 2),
	jsAPIName("dns/promises", "resolve4", 1, 2),
	jsAPIName("dns/promises", "resolve6", 1, 2),
}

func init() {
	sort.Slice(javaScriptAPISpecs, func(i, j int) bool {
		if javaScriptAPISpecs[i].module != javaScriptAPISpecs[j].module {
			return javaScriptAPISpecs[i].module < javaScriptAPISpecs[j].module
		}
		return javaScriptAPISpecs[i].method < javaScriptAPISpecs[j].method
	})
}

func jsAPIFile(module, method string, kind behavior.OperationKind, minArgs, maxArgs int, role behavior.ResourceRole) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: kind, minArgs: minArgs, maxArgs: maxArgs,
		resources: []javaScriptAPIResourceSpec{{role: role, kind: behavior.ResourceFile, index: 0}}}
}

func jsAPICallbackFile(module, method string, kind behavior.OperationKind, minArgs, maxArgs int, role behavior.ResourceRole) javaScriptAPISpec {
	spec := jsAPIFile(module, method, kind, minArgs, maxArgs, role)
	spec.callback = true
	return spec
}

func jsAPICopy(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: behavior.OperationFileCopy, minArgs: minArgs, maxArgs: maxArgs,
		resources: []javaScriptAPIResourceSpec{
			{role: behavior.ResourceRoleSource, kind: behavior.ResourceFile, index: 0},
			{role: behavior.ResourceRoleLocalOutput, kind: behavior.ResourceFile, index: 1},
		}}
}

func jsAPICallbackCopy(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	spec := jsAPICopy(module, method, minArgs, maxArgs)
	spec.callback = true
	return spec
}

func jsAPIMove(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: behavior.OperationFileMove, minArgs: minArgs, maxArgs: maxArgs,
		resources: []javaScriptAPIResourceSpec{
			{role: behavior.ResourceRoleSource, kind: behavior.ResourceFile, index: 0},
			{role: behavior.ResourceRoleTarget, kind: behavior.ResourceFile, index: 1},
		}}
}

func jsAPICallbackMove(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	spec := jsAPIMove(module, method, minArgs, maxArgs)
	spec.callback = true
	return spec
}

func jsAPIFixed(module, method string, kind behavior.OperationKind, resourceKind behavior.ResourceKind, value string) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: kind, minArgs: 0, maxArgs: 0,
		resources: []javaScriptAPIResourceSpec{{role: behavior.ResourceRoleSource, kind: resourceKind, index: -1, fixed: value}}}
}

func jsAPINetwork(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: behavior.OperationNetworkConnect, minArgs: minArgs, maxArgs: maxArgs,
		resources: []javaScriptAPIResourceSpec{{role: behavior.ResourceRoleRemoteDestination, kind: behavior.ResourceURL, index: 0}}}
}

func exactJavaScriptHTTPURL(value string) bool {
	lower := strings.ToLower(value)
	return (strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) && exactJavaScriptFeatureURL(value)
}

func jsAPIName(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	return javaScriptAPISpec{module: module, method: method, kind: behavior.OperationNameResolve, minArgs: minArgs, maxArgs: maxArgs,
		resources: []javaScriptAPIResourceSpec{{role: behavior.ResourceRoleSource, kind: behavior.ResourceIdentifier, index: 0}}}
}

func jsAPICallbackName(module, method string, minArgs, maxArgs int) javaScriptAPISpec {
	spec := jsAPIName(module, method, minArgs, maxArgs)
	spec.callback = true
	return spec
}

// extractJavaScriptSourceAPIs is a closed binding-and-call recognizer, not a
// JavaScript evaluator. It admits immutable ESM/CommonJS bindings for selected
// Node builtins, exact direct or qualified calls, and documented call arities.
// Any opaque use, reassignment, duplicate binding, computed property, spread,
// or malformed call invalidates the affected identity before promotion.
func extractJavaScriptSourceAPIs(graph *behavior.Graph, content artifact.Content, prescan javaScriptCommandPrescan) {
	if prescan.index.Disposition == javaScriptStructuralLimited || prescan.index.Disposition == javaScriptStructuralMalformed {
		return
	}
	bindings := map[string]map[string]javaScriptAPIBinding{"": {}}
	invalid := map[string]map[string]bool{}
	blockedRoot := preflightJavaScriptAPIRootBindings(prescan)
	evidenceIDs := map[string][]string{}
	valueState := newJavaScriptCommandState(prescan)
	fetchSafe := javaScriptBuiltinFetchIdentitySafe(prescan)
	calls := 0
	limited := false
	unsupported := false

	for _, statement := range prescan.byLineStatements() {
		scope := statement.scopeKey
		if bindings[scope] == nil {
			bindings[scope] = map[string]javaScriptAPIBinding{}
		}
		if invalid[scope] == nil {
			invalid[scope] = map[string]bool{}
		}
		valueState.observe(statement.text, scope, statement.line)
		if fetchSafe {
			if !extractJavaScriptBuiltinFetchCalls(graph, content, statement, &valueState) {
				unsupported = true
			}
		}
		declared, recognized := javaScriptAPIDeclarations(statement.text, statement.line, statement.evidenceText, statement.bindingProofs)
		if recognized {
			if prescan.dynamicScopes[scope] || javaScriptAPIDeclarationRequiresRuntime(statement.text) && !javaScriptAPIRequireIdentitySafe(prescan, scope) {
				unsupported = true
				continue
			}
			for _, name := range sortedJavaScriptAPIBindingNames(declared) {
				binding := declared[name]
				if scope == "" && blockedRoot[name] {
					unsupported = true
					continue
				}
				if len(bindings[scope]) >= maxJavaScriptAPIBindings || totalJavaScriptAPIBindings(bindings) >= maxJavaScriptAPIBindings {
					limited = true
					continue
				}
				if _, exists := bindings[scope][name]; exists || invalid[scope][name] {
					delete(bindings[scope], name)
					invalid[scope][name] = true
					unsupported = true
					continue
				}
				bindings[scope][name] = binding
			}
			continue
		}

		visible := make(map[string]javaScriptAPIBinding, len(bindings[""])+len(bindings[scope]))
		if scope != "" {
			for name, binding := range bindings[""] {
				if !invalid[scope][name] {
					visible[name] = binding
				}
			}
		}
		for name, binding := range bindings[scope] {
			visible[name] = binding
		}

		matchedUses := map[string]int{}
		for _, name := range sortedJavaScriptAPIBindingNames(visible) {
			binding := visible[name]
			found, exact := javaScriptAPICallsFromDirectText(statement.text, statement.evidenceText, name, binding)
			if !exact {
				javaScriptAPIInvalidateBinding(bindings, invalid, scope, name)
				unsupported = true
				continue
			}
			matchedUses[name] = len(found)
			for _, call := range found {
				calls++
				if calls > maxJavaScriptAPICalls {
					limited = true
					break
				}
				spec, ok := lookupJavaScriptAPISpec(binding.module, call.method)
				if !ok {
					continue
				}
				arguments, ok := splitJavaScriptArgumentsExact(call.args, maxJavaScriptAPICallBytes, maxTextStringExpressionArguments)
				if !ok || len(arguments) < spec.minArgs || len(arguments) > spec.maxArgs || javaScriptArgumentsContainSpread(arguments) || spec.callback && !exactJavaScriptCallbackArgument(arguments[len(arguments)-1]) {
					unsupported = true
					continue
				}
				operationKind := spec.kind
				if spec.module == "axios" && (spec.method == "post" || spec.method == "put" || spec.method == "patch") && len(arguments) >= 2 {
					operationKind = behavior.OperationNetworkUpload
				}
				bindingEvidenceIDs := javaScriptAPIBindingEvidence(graph, content, binding, evidenceIDs)
				scopeID := scopeIDForJavaScriptStatement(graph, content, statement)
				callEvidenceID := addLineEvidence(graph, artifact.Content{
					NodeID: content.NodeID, LogicalPath: content.LogicalPath, PhysicalPath: content.PhysicalPath,
					Kind: content.Kind, ScopeID: scopeID, Function: statement.functionName,
				}, statement.line, "javascript-api-call", statement.evidenceText)
				if len(bindingEvidenceIDs) == 0 || callEvidenceID == "" {
					continue
				}
				resourceBindings := make([]behavior.ResourceBinding, 0, len(spec.resources))
				operationEvidenceIDs := append([]string{callEvidenceID}, bindingEvidenceIDs...)
				unresolved := false
				for _, resourceSpec := range spec.resources {
					value := resourceSpec.fixed
					if resourceSpec.index >= 0 {
						var resourceProofs []javaScriptCommandProof
						var resolved bool
						value, resourceProofs, resolved = valueState.resolveExpression(arguments[resourceSpec.index], scope, 0)
						if !resolved {
							value = ""
						}
						retained := javaScriptAPIProofEvidence(graph, content, resourceProofs)
						if len(retained) != len(resourceProofs) {
							value = ""
						}
						operationEvidenceIDs = append(operationEvidenceIDs, retained...)
						if value == "" {
							unresolved = true
						}
					}
					resource := behavior.NewResource(resourceSpec.kind, value)
					if resourceSpec.kind == behavior.ResourceFile && value != "" {
						resource = classifiedFileResource(value)
					} else if resourceSpec.kind == behavior.ResourceURL {
						if !exactJavaScriptHTTPURL(value) {
							unresolved = true
							resource = behavior.NewResource(behavior.ResourceURL, "")
						}
					}
					resourceBindings = append(resourceBindings, behavior.Bind(resourceSpec.role, resource))
				}
				resourceState := "exact-static"
				if unresolved {
					resourceState = "unresolved"
				}
				operation := behavior.ModeledOperation{
					SubjectNodeID: content.NodeID, ScopeID: scopeID, SourceFunction: statement.functionName,
					Kind: operationKind, ResourceBindings: resourceBindings,
					Qualifiers: map[string]string{
						"api": spec.module + "." + spec.method, "api_identity": javaScriptAPIIdentityQualifier(spec.module),
						"module_binding": call.binding, "resource_binding": resourceState,
					},
					EvidenceIDs: mergeEvidenceIDs(operationEvidenceIDs...), Support: behavior.SupportCorroborated,
					Execution: executionContextForContent(content), Line: statement.line,
				}
				if !enrichExistingJavaScriptAPIOperation(graph, operation) {
					operationID := graph.AddOperation(operation)
					if operationID != "" && isNetworkOperationKind(operationKind) {
						observation := networkImplementationObservation(operationID, artifact.Content{
							NodeID: content.NodeID, ScopeID: scopeID, LogicalPath: content.LogicalPath,
							PhysicalPath: content.PhysicalPath, Function: statement.functionName,
						}, "javascript", callEvidenceID)
						observation.APIOrTool = spec.module + "." + spec.method
						observation.HTTPImplementation = spec.module
						observation.EvidenceIDs = append([]string(nil), operationEvidenceIDs...)
						graph.AddNetworkImplementation(observation)
					}
				}
			}
		}
		if limited {
			break
		}
		for _, name := range sortedJavaScriptAPIBindingNames(visible) {
			occurrences := javaScriptIdentifierPositions(statement.text, name)
			if len(occurrences) != matchedUses[name] {
				javaScriptAPIInvalidateBinding(bindings, invalid, scope, name)
				unsupported = true
			}
		}
	}
	if limited {
		addPartialCoverageOnce(graph, content.NodeID, javaScriptAPIBindingAnalysisArea,
			fmt.Sprintf("Node builtin API analysis reached its limit of %d bindings or %d calls", maxJavaScriptAPIBindings, maxJavaScriptAPICalls))
	}
	if valueState.limited && calls > 0 {
		addPartialCoverageOnce(graph, content.NodeID, javaScriptAPIBindingAnalysisArea, valueState.limitDetail)
	}
	if unsupported {
		addPartialCoverageOnce(graph, content.NodeID, javaScriptAPIBindingAnalysisArea,
			"a recognized Node builtin binding or call was duplicated, reassigned, opaque, malformed, outside the exact call grammar, or used through unsupported data flow; unproved call identities remain observational and unsupported operands remain unresolved")
	}
}

func javaScriptAPIIdentityQualifier(module string) string {
	if module == "axios" {
		return "stable-javascript-module-binding-and-exact-call"
	}
	return "stable-node-builtin-binding-and-exact-call"
}

func enrichExistingJavaScriptAPIOperation(graph *behavior.Graph, candidate behavior.ModeledOperation) bool {
	for index := range graph.Operations {
		existing := &graph.Operations[index]
		if existing.SubjectNodeID != candidate.SubjectNodeID || existing.ScopeID != candidate.ScopeID ||
			existing.SourceFunction != candidate.SourceFunction || existing.Kind != candidate.Kind ||
			existing.Line != candidate.Line || !sameJavaScriptAPIResourceBindings(existing.ResourceBindings, candidate.ResourceBindings) {
			continue
		}
		if existing.Qualifiers["api_identity"] != "" {
			continue
		}
		if existing.Qualifiers == nil {
			existing.Qualifiers = map[string]string{}
		}
		for key, value := range candidate.Qualifiers {
			if retained := existing.Qualifiers[key]; retained != "" && retained != value {
				return false
			}
			existing.Qualifiers[key] = value
		}
		existing.EvidenceIDs = mergeEvidenceIDs(append(existing.EvidenceIDs, candidate.EvidenceIDs...)...)
		existing.Support = behavior.SupportCorroborated
		return true
	}
	return false
}

func javaScriptBuiltinFetchIdentitySafe(prescan javaScriptCommandPrescan) bool {
	if prescan.dynamicCode || prescan.index.Disposition == javaScriptStructuralLimited || prescan.index.Disposition == javaScriptStructuralMalformed || prescan.index.Disposition == javaScriptStructuralUnsupported {
		return false
	}
	for _, hidden := range prescan.index.HiddenUses {
		if hidden.Name == "fetch" {
			return false
		}
	}
	for _, statement := range prescan.byLineStatements() {
		occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(statement.text, maxJavaScriptAPICallBytes, maxJavaScriptCommandIdentifiersPerStatement)
		if !exact {
			return false
		}
		for _, occurrence := range occurrences {
			if occurrence.Name != "fetch" {
				continue
			}
			if occurrence.Write || occurrence.previousToken == "." || occurrence.previousToken == "function" || occurrence.previousToken == "class" {
				return false
			}
			open := skipJavaScriptSpace(statement.text, occurrence.Offset+len("fetch"))
			_, close, call := exactJavaScriptCallContent(statement.text, open, maxJavaScriptAPICallBytes)
			if !call {
				return false
			}
			after := skipJavaScriptSpace(statement.text, close+1)
			if after < len(statement.text) && statement.text[after] == '{' {
				return false
			}
		}
	}
	return true
}

// extractJavaScriptBuiltinFetchCalls models only a globally unshadowed direct
// fetch call. Unsupported destination values remain unknown; a URL substring
// does not establish the destination or successful communication.
func extractJavaScriptBuiltinFetchCalls(graph *behavior.Graph, content artifact.Content, statement javaScriptCommandStatement, state *javaScriptCommandState) bool {
	occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(statement.text, maxJavaScriptAPICallBytes, maxJavaScriptCommandIdentifiersPerStatement)
	if !exact {
		return false
	}
	complete := true
	for _, occurrence := range occurrences {
		if occurrence.Name != "fetch" {
			continue
		}
		open := skipJavaScriptSpace(statement.text, occurrence.Offset+len("fetch"))
		argumentsText, _, call := exactJavaScriptCallContent(statement.text, open, maxJavaScriptAPICallBytes)
		if !call {
			complete = false
			continue
		}
		arguments, ok := splitJavaScriptArgumentsExact(argumentsText, maxJavaScriptAPICallBytes, maxTextStringExpressionArguments)
		if !ok || len(arguments) < 1 || len(arguments) > 2 || javaScriptArgumentsContainSpread(arguments) {
			complete = false
			continue
		}
		value, proofs, resolved := state.resolveExpression(arguments[0], statement.scopeKey, 0)
		if !resolved {
			value = ""
		}
		var destination []string
		resourceBinding := "unresolved"
		if exactJavaScriptHTTPURL(value) {
			destination = []string{value}
			resourceBinding = "exact-static"
		} else {
			value = ""
			complete = false
		}
		scopeID := scopeIDForJavaScriptStatement(graph, content, statement)
		lineContent := artifact.Content{
			NodeID: content.NodeID, ScopeID: scopeID, LogicalPath: content.LogicalPath,
			PhysicalPath: content.PhysicalPath, Function: statement.functionName,
		}
		callEvidenceID := addLineEvidence(graph, lineContent, statement.line, "javascript-api-call", statement.evidenceText)
		proofEvidenceIDs := javaScriptAPIProofEvidence(graph, content, proofs)
		if len(proofEvidenceIDs) != len(proofs) {
			value, destination, resourceBinding = "", nil, "unresolved"
			complete = false
		}
		evidenceIDs := mergeEvidenceIDs(append([]string{callEvidenceID}, proofEvidenceIDs...)...)
		if callEvidenceID == "" {
			return false
		}
		kind := languageNetworkOperationKind("javascript", statement.text)
		candidate := behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: scopeID, SourceFunction: statement.functionName,
			Kind:             kind,
			ResourceBindings: networkOperationBindings(kind, destination, "", ""),
			Qualifiers: map[string]string{
				"api": "fetch", "api_identity": "unshadowed-runtime-builtin-and-exact-call", "resource_binding": resourceBinding,
			},
			EvidenceIDs: evidenceIDs, Support: behavior.SupportCorroborated,
			Execution: executionContextForContent(lineContent), Line: statement.line,
		}
		if enrichExistingJavaScriptFetchOperation(graph, candidate, value) {
			continue
		}
		operationID := graph.AddOperation(candidate)
		if operationID == "" {
			continue
		}
		observation := networkImplementationObservation(operationID, lineContent, "javascript", callEvidenceID)
		observation.APIOrTool = "fetch"
		observation.HTTPImplementation = "WHATWG fetch runtime implementation"
		observation.EvidenceIDs = append([]string(nil), evidenceIDs...)
		graph.AddNetworkImplementation(observation)
	}
	return complete
}

// The line-oriented request tracker may refine a fetch into network.download
// after proving an exact response write. Retain that stronger resource flow and
// attach builtin identity instead of reintroducing a weaker connect operation.
func enrichExistingJavaScriptFetchOperation(graph *behavior.Graph, candidate behavior.ModeledOperation, destination string) bool {
	for index := range graph.Operations {
		existing := &graph.Operations[index]
		if existing.SubjectNodeID != candidate.SubjectNodeID || existing.ScopeID != candidate.ScopeID ||
			existing.SourceFunction != candidate.SourceFunction || existing.Line != candidate.Line ||
			(existing.Kind != behavior.OperationNetworkConnect && existing.Kind != behavior.OperationNetworkDownload && existing.Kind != behavior.OperationNetworkUpload) ||
			!operationHasNetworkDestination(*existing, destination) {
			continue
		}
		if existing.Qualifiers == nil {
			existing.Qualifiers = map[string]string{}
		}
		for key, value := range candidate.Qualifiers {
			if retained := existing.Qualifiers[key]; retained != "" && retained != value {
				return false
			}
			existing.Qualifiers[key] = value
		}
		existing.EvidenceIDs = mergeEvidenceIDs(append(existing.EvidenceIDs, candidate.EvidenceIDs...)...)
		existing.Support = behavior.SupportCorroborated
		for networkIndex := range graph.Network {
			observation := &graph.Network[networkIndex]
			linked := false
			for _, operationID := range observation.OperationIDs {
				linked = linked || operationID == existing.ID
			}
			if !linked {
				continue
			}
			observation.APIOrTool = "fetch"
			observation.HTTPImplementation = "WHATWG fetch runtime implementation"
			observation.EvidenceIDs = mergeEvidenceIDs(append(observation.EvidenceIDs, candidate.EvidenceIDs...)...)
		}
		return true
	}
	return false
}

func operationHasNetworkDestination(operation behavior.ModeledOperation, destination string) bool {
	for _, binding := range operation.ResourceBindings {
		if destination == "" && (binding.Role == behavior.ResourceRoleRemoteSource || binding.Role == behavior.ResourceRoleRemoteDestination) &&
			binding.Resource.Kind == behavior.ResourceNetworkEndpoint && binding.Resource.Value == "" {
			return true
		}
		if binding.Resource.Kind == behavior.ResourceURL && binding.Resource.Value == destination {
			return true
		}
	}
	return false
}

func sameJavaScriptAPIResourceBindings(left, right []behavior.ResourceBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Role != right[index].Role || left[index].Resource.Kind != right[index].Resource.Kind ||
			left[index].Resource.Value != right[index].Resource.Value ||
			!sameJavaScriptAPIClassifications(left[index].Resource.Classifications, right[index].Resource.Classifications) {
			return false
		}
	}
	return true
}

func sameJavaScriptAPIClassifications(left, right []behavior.ResourceClassification) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedJavaScriptAPIBindingNames(bindings map[string]javaScriptAPIBinding) []string {
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func javaScriptAPIProofEvidence(graph *behavior.Graph, content artifact.Content, proofs []javaScriptCommandProof) []string {
	var evidenceIDs []string
	for _, proof := range proofs {
		evidenceID := addLineEvidence(graph, content, proof.line, proof.kind, proof.value)
		if evidenceID != "" {
			evidenceIDs = append(evidenceIDs, evidenceID)
		}
	}
	return evidenceIDs
}

// The request/write tracker uses the same closed value grammar as the API
// recognizer. Generic text assignments can retain prefixes or undecoded
// escapes, so they cannot establish a JavaScript request destination.
func javaScriptFetchLineDestinations(state *javaScriptCommandState, statements []javaScriptCommandStatement) ([]string, []javaScriptCommandProof, bool) {
	var destination []string
	var proof []javaScriptCommandProof
	calls := 0
	complete := true
	for _, statement := range statements {
		state.observe(statement.text, statement.scopeKey, statement.line)
		occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(statement.text, maxJavaScriptAPICallBytes, maxJavaScriptCommandIdentifiersPerStatement)
		if !exact {
			state.invalidateScope(statement.scopeKey)
			complete = false
			continue
		}
		for _, occurrence := range occurrences {
			if occurrence.Name != "fetch" || occurrence.Write || occurrence.previousToken == "." {
				continue
			}
			open := skipJavaScriptSpace(statement.text, occurrence.Offset+len("fetch"))
			text, _, call := exactJavaScriptCallContent(statement.text, open, maxJavaScriptAPICallBytes)
			args, known := splitJavaScriptArgumentsExact(text, maxJavaScriptAPICallBytes, maxTextStringExpressionArguments)
			if !call || !known || len(args) < 1 || len(args) > 2 || javaScriptArgumentsContainSpread(args) {
				continue
			}
			calls++
			if calls > 1 {
				// Per-line response tracking cannot distinguish these calls.
				// The structural API pass retains their individual requests.
				continue
			}
			value, causal, resolved := state.resolveExpression(args[0], statement.scopeKey, 0)
			for _, origin := range causal {
				resolved = resolved && origin.scopeKey == statement.scopeKey
			}
			if resolved && exactJavaScriptHTTPURL(value) {
				destination, proof = []string{value}, causal
			}
		}
	}
	if !complete || calls != 1 {
		return nil, nil, false
	}
	return destination, proof, true
}

func mergeEvidenceIDs(ids ...string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, id)
	}
	return result
}

// preflightJavaScriptAPIRootBindings prevents textual function order from
// masquerading as runtime order. A module binding inherited by functions is
// admitted only when every retained occurrence in the whole program is either
// its exact declaration or a supported direct call. This deliberately rejects
// member replacement, alias escape, local shadowing, and opaque data flow even
// when they appear after a function body that references the module.
func preflightJavaScriptAPIRootBindings(prescan javaScriptCommandPrescan) map[string]bool {
	blocked := map[string]bool{}
	root := map[string]javaScriptAPIBinding{}
	statements := prescan.byLineStatements()
	for _, statement := range statements {
		if statement.scopeKey != "" {
			continue
		}
		declared, recognized := javaScriptAPIDeclarations(statement.text, statement.line, statement.evidenceText, statement.bindingProofs)
		if !recognized {
			continue
		}
		for _, name := range sortedJavaScriptAPIBindingNames(declared) {
			binding := declared[name]
			if _, duplicate := root[name]; duplicate {
				blocked[name] = true
				continue
			}
			root[name] = binding
		}
	}
	for _, statement := range statements {
		declaredHere, _ := javaScriptAPIDeclarations(statement.text, statement.line, statement.evidenceText, statement.bindingProofs)
		for name, binding := range root {
			positions := javaScriptIdentifierPositions(statement.text, name)
			if len(positions) == 0 || declaredHere[name].module != "" {
				continue
			}
			calls, exact := javaScriptAPICallsFromDirectText(statement.text, statement.evidenceText, name, binding)
			if !exact || len(calls) != len(positions) {
				blocked[name] = true
			}
		}
	}
	for _, hidden := range prescan.index.HiddenUses {
		if _, inherited := root[hidden.Name]; inherited {
			blocked[hidden.Name] = true
		}
	}
	return blocked
}

func (prescan javaScriptCommandPrescan) byLineStatements() []javaScriptCommandStatement {
	var statements []javaScriptCommandStatement
	lines := make([]int, 0, len(prescan.byLine))
	for line := range prescan.byLine {
		lines = append(lines, line)
	}
	sort.Ints(lines)
	for _, line := range lines {
		statements = append(statements, prescan.byLine[line]...)
	}
	return statements
}

func scopeIDForJavaScriptStatement(graph *behavior.Graph, content artifact.Content, statement javaScriptCommandStatement) string {
	if statement.scopeKey == "" {
		return content.ScopeID
	}
	for _, scope := range graph.Scopes {
		if scope.NodeID == content.NodeID && scope.Function == statement.functionName &&
			statement.line >= scope.LineStart && statement.line <= scope.LineEnd {
			return scope.ID
		}
	}
	return ""
}

func totalJavaScriptAPIBindings(scopes map[string]map[string]javaScriptAPIBinding) int {
	total := 0
	for _, bindings := range scopes {
		total += len(bindings)
	}
	return total
}

func javaScriptAPIInvalidateBinding(scopes map[string]map[string]javaScriptAPIBinding, invalid map[string]map[string]bool, scope, name string) {
	if _, local := scopes[scope][name]; local || scope == "" {
		delete(scopes[scope], name)
		invalid[scope][name] = true
		return
	}
	// A write or opaque use in a function shadows/invalidate only that lexical
	// view; it must not erase the immutable module binding for sibling scopes.
	invalid[scope][name] = true
}

func javaScriptAPIDeclarations(line string, lineNo int, evidenceText string, proofs []javaScriptCommandProof) (map[string]javaScriptAPIBinding, bool) {
	line = strings.TrimSpace(line)
	result := map[string]javaScriptAPIBinding{}
	module, names, recognized := parseJavaScriptAPIDeclaration(line)
	if !recognized {
		return result, false
	}
	for name, method := range names {
		result[name] = javaScriptAPIBinding{module: module, method: method, line: lineNo, text: evidenceText, proofs: append([]javaScriptCommandProof(nil), proofs...)}
	}
	return result, true
}

func parseJavaScriptAPIDeclaration(line string) (string, map[string]string, bool) {
	for _, prefix := range []string{"import * as ", "import "} {
		if strings.HasPrefix(line, prefix) {
			from := strings.LastIndex(line, " from ")
			if from < len(prefix) {
				continue
			}
			module, ok := exactJavaScriptModuleLiteral(strings.TrimSpace(strings.TrimSuffix(line[from+6:], ";")))
			if !ok || !supportedJavaScriptAPIModule(module) {
				return nilStringMap()
			}
			bindingText := strings.TrimSpace(line[len(prefix):from])
			if prefix == "import " && strings.HasPrefix(bindingText, "{") {
				return module, javaScriptNamedBindings(bindingText, " as "), true
			}
			if javaScriptIdentifier(bindingText) {
				return module, map[string]string{bindingText: ""}, true
			}
			return nilStringMap()
		}
	}
	if !strings.HasPrefix(line, "const ") {
		return nilStringMap()
	}
	equal := strings.Index(line, "=")
	if equal < 7 {
		return nilStringMap()
	}
	left := strings.TrimSpace(line[len("const "):equal])
	right := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[equal+1:]), ";"))
	module, suffix, ok := exactJavaScriptRequireModule(right)
	if !ok || !supportedJavaScriptAPIModule(module) {
		return nilStringMap()
	}
	if suffix == ".promises" && module == "fs" {
		module = "fs/promises"
		suffix = ""
	}
	if suffix != "" {
		return nilStringMap()
	}
	if strings.HasPrefix(left, "{") {
		return module, javaScriptNamedBindings(left, ":"), true
	}
	if javaScriptIdentifier(left) {
		return module, map[string]string{left: ""}, true
	}
	return nilStringMap()
}

func nilStringMap() (string, map[string]string, bool) { return "", nil, false }

func exactJavaScriptRequireModule(right string) (string, string, bool) {
	if !strings.HasPrefix(right, "require") {
		return "", "", false
	}
	open := skipJavaScriptSpace(right, len("require"))
	body, close, exact := exactJavaScriptCallContent(right, open, maxJavaScriptAPICallBytes)
	if !exact {
		return "", "", false
	}
	module, ok := exactJavaScriptModuleLiteral(strings.TrimSpace(body))
	if !ok {
		return "", "", false
	}
	return module, strings.TrimSpace(right[close+1:]), true
}

func exactJavaScriptModuleLiteral(value string) (string, bool) {
	module, ok := exactJavaScriptQuotedLiteral(value)
	if !ok {
		return "", false
	}
	return strings.TrimPrefix(module, "node:"), true
}

func supportedJavaScriptAPIModule(module string) bool {
	switch module {
	case "axios", "fs", "fs/promises", "os", "dns", "dns/promises":
		return true
	default:
		return false
	}
}

func javaScriptNamedBindings(value, separator string) map[string]string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return nil
	}
	result := map[string]string{}
	for _, item := range strings.Split(value[1:len(value)-1], ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, separator)
		if len(parts) > 2 {
			return nil
		}
		method := strings.TrimSpace(parts[0])
		name := method
		if len(parts) == 2 {
			name = strings.TrimSpace(parts[1])
		}
		if !javaScriptIdentifier(method) || !javaScriptIdentifier(name) {
			return nil
		}
		if _, duplicate := result[name]; duplicate {
			return nil
		}
		result[name] = method
	}
	return result
}

func javaScriptAPIDeclarationRequiresRuntime(line string) bool {
	return strings.Contains(line, "require")
}

func javaScriptAPIRequireIdentitySafe(prescan javaScriptCommandPrescan, scope string) bool {
	if scope != "" {
		return prescan.runtimeSafe[scope]
	}
	for _, candidate := range prescan.index.Scopes {
		if candidate.Name == "require" {
			return false
		}
	}
	for _, hidden := range prescan.index.HiddenUses {
		if hidden.ScopeKey == "" && hidden.Name == "require" && hidden.Write {
			return false
		}
	}
	for _, retained := range prescan.index.Statements {
		if retained.ScopeKey != "" {
			continue
		}
		occurrences, exact := scanJavaScriptIdentifierOccurrencesExact(
			retained.DirectText,
			maxJavaScriptProcessStatementBytes,
			maxJavaScriptCommandIdentifiersPerStatement,
		)
		if !exact {
			return false
		}
		for _, occurrence := range occurrences {
			if occurrence.Name == "require" && occurrence.Write {
				return false
			}
		}
		trimmed := strings.TrimSpace(retained.DirectText)
		for _, declaration := range []string{"const require", "let require", "var require", "class require"} {
			if strings.HasPrefix(trimmed, declaration) {
				return false
			}
		}
	}
	return true
}

func javaScriptAPICallsFromDirectText(directText, source, name string, binding javaScriptAPIBinding) ([]javaScriptAPICall, bool) {
	if !javaScriptIdentifier(name) {
		return nil, false
	}
	if len(directText) != len(source) {
		return nil, false
	}
	var calls []javaScriptAPICall
	for _, start := range javaScriptIdentifierPositions(directText, name) {
		previous := previousJavaScriptSignificantByte(directText, start)
		if previous == '.' || previous == '/' {
			continue
		}
		cursor := skipJavaScriptSpace(source, start+len(name))
		method := binding.method
		if method == "" {
			if cursor >= len(source) || source[cursor] != '.' {
				continue
			}
			cursor = skipJavaScriptSpace(source, cursor+1)
			methodStart := cursor
			if cursor >= len(source) || !javaScriptIdentifierStartByte(source[cursor]) {
				continue
			}
			cursor++
			for cursor < len(source) && javaScriptIdentifierByte(source[cursor]) {
				cursor++
			}
			method = source[methodStart:cursor]
		}
		if _, ok := lookupJavaScriptAPISpec(binding.module, method); !ok {
			continue
		}
		open := skipJavaScriptSpace(source, cursor)
		body, close, exact := exactJavaScriptCallContent(source, open, maxJavaScriptAPICallBytes)
		if !exact {
			return nil, false
		}
		if next := skipJavaScriptSpace(source, close+1); next < len(source) && source[next] == '{' {
			continue
		}
		calls = append(calls, javaScriptAPICall{binding: name, method: method, args: body})
	}
	return calls, true
}

func lookupJavaScriptAPISpec(module, method string) (javaScriptAPISpec, bool) {
	index := sort.Search(len(javaScriptAPISpecs), func(index int) bool {
		if javaScriptAPISpecs[index].module != module {
			return javaScriptAPISpecs[index].module >= module
		}
		return javaScriptAPISpecs[index].method >= method
	})
	if index >= len(javaScriptAPISpecs) || javaScriptAPISpecs[index].module != module || javaScriptAPISpecs[index].method != method {
		return javaScriptAPISpec{}, false
	}
	return javaScriptAPISpecs[index], true
}

func javaScriptArgumentsContainSpread(arguments []string) bool {
	for _, argument := range arguments {
		if strings.HasPrefix(strings.TrimSpace(argument), "...") {
			return true
		}
	}
	return false
}

func exactJavaScriptCallbackArgument(argument string) bool {
	argument = strings.TrimSpace(argument)
	if javaScriptIdentifier(argument) {
		return true
	}
	if strings.HasPrefix(argument, "function") {
		open := strings.IndexByte(argument, '(')
		return open >= len("function") && strings.Contains(argument[open+1:], ")")
	}
	if strings.HasPrefix(argument, "async ") {
		argument = strings.TrimSpace(strings.TrimPrefix(argument, "async "))
	}
	arrow := strings.Index(argument, "=>")
	if arrow < 0 {
		return false
	}
	parameters := strings.TrimSpace(argument[:arrow])
	if javaScriptIdentifier(parameters) {
		return true
	}
	if len(parameters) < 2 || parameters[0] != '(' || parameters[len(parameters)-1] != ')' {
		return false
	}
	parameters = strings.TrimSpace(parameters[1 : len(parameters)-1])
	if parameters == "" {
		return true
	}
	for _, parameter := range strings.Split(parameters, ",") {
		if !javaScriptIdentifier(strings.TrimSpace(parameter)) {
			return false
		}
	}
	return true
}

func javaScriptAPIBindingEvidence(graph *behavior.Graph, content artifact.Content, binding javaScriptAPIBinding, cache map[string][]string) []string {
	key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", binding.line, binding.module, binding.method, binding.text)
	if evidenceIDs := cache[key]; len(evidenceIDs) > 0 {
		return append([]string(nil), evidenceIDs...)
	}
	evidenceID := addLineEvidence(graph, content, binding.line, "javascript-module-binding", binding.text)
	if evidenceID == "" {
		return nil
	}
	evidenceIDs := []string{evidenceID}
	for _, proof := range binding.proofs {
		proofID := addLineEvidence(graph, content, proof.line, proof.kind, proof.value)
		if proofID != "" {
			evidenceIDs = append(evidenceIDs, proofID)
		}
	}
	cache[key] = append([]string(nil), evidenceIDs...)
	return evidenceIDs
}
