package extract

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

const (
	maxPythonAPIBindings             = 32
	maxPythonAPIOrderedBindingEvents = 4096
	maxPythonAPICallsPerLine         = 64
	maxPythonAPICallBytes            = 64 << 10
)

const pythonAPIBindingAnalysisArea = "python-api-binding-analysis"

type pythonAPIBindingProof struct {
	name      string
	canonical string
	text      string
	line      int
	offset    int64
}

type pythonStableAPIBindings struct {
	bindings         map[string]pythonAPIBindingProof
	evidenceIDs      map[string]string
	builtinOpenSafe  bool
	invalidated      bool
	dynamicNamespace bool
	limited          bool
	unsupportedCalls bool
}

type pythonAPIResourceSpec struct {
	role         behavior.ResourceRole
	kind         behavior.ResourceKind
	classes      []behavior.ResourceClassification
	index        int
	parameter    string
	fixed        string
	defaultValue string
}

type pythonAPISpec struct {
	api            string
	kind           behavior.OperationKind
	minArgs        int
	maxArgs        int
	maxPositional  int
	positionalOnly int
	parameters     []string
	resources      []pythonAPIResourceSpec
}

var pythonAPISpecs = []pythonAPISpec{
	pythonUnaryFileAPI("glob.glob", behavior.OperationFileEnumerate, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("glob.iglob", behavior.OperationFileEnumerate, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.access", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.chmod", behavior.OperationFilePermissionModify, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.listdir", behavior.OperationFileEnumerate, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.lstat", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.makedirs", behavior.OperationDirectoryCreate, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.mkdir", behavior.OperationDirectoryCreate, behavior.ResourceRoleTarget),
	pythonResourceAPI("os.open", behavior.OperationFileOpen, 0, "path", behavior.ResourceFile, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.readlink", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.remove", behavior.OperationFileDelete, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.removedirs", behavior.OperationFileDelete, behavior.ResourceRoleTarget),
	pythonBinaryFileAPI("os.rename", behavior.OperationFileMove, behavior.ResourceRoleSource, behavior.ResourceRoleTarget),
	pythonBinaryFileAPI("os.renames", behavior.OperationFileMove, behavior.ResourceRoleSource, behavior.ResourceRoleTarget),
	pythonBinaryFileAPI("os.replace", behavior.OperationFileMove, behavior.ResourceRoleSource, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.rmdir", behavior.OperationFileDelete, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.scandir", behavior.OperationFileEnumerate, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.stat", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.truncate", behavior.OperationFileWrite, behavior.ResourceRoleLocalOutput),
	pythonUnaryFileAPI("os.unlink", behavior.OperationFileDelete, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("os.walk", behavior.OperationFileEnumerate, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.exists", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.getatime", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.getctime", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.getmtime", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.getsize", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.isdir", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.isfile", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.islink", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonUnaryFileAPI("os.path.realpath", behavior.OperationFileMetadataQuery, behavior.ResourceRoleSource),
	pythonBinaryFileAPI("shutil.copy", behavior.OperationFileCopy, behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput),
	pythonBinaryFileAPI("shutil.copy2", behavior.OperationFileCopy, behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput),
	pythonBinaryFileAPI("shutil.copyfile", behavior.OperationFileCopy, behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput),
	pythonBinaryFileAPI("shutil.copytree", behavior.OperationFileCopy, behavior.ResourceRoleSource, behavior.ResourceRoleLocalOutput),
	pythonBinaryFileAPI("shutil.move", behavior.OperationFileMove, behavior.ResourceRoleSource, behavior.ResourceRoleTarget),
	pythonUnaryFileAPI("shutil.rmtree", behavior.OperationFileDelete, behavior.ResourceRoleTarget),
	pythonArchiveUnpackAPI(),
	pythonResourceAPI("os.getenv", behavior.OperationEnvironmentRead, 0, "key", behavior.ResourceConfiguration, behavior.ResourceRoleSource),
	pythonResourceAPI("os.environ.get", behavior.OperationEnvironmentRead, 0, "key", behavior.ResourceConfiguration, behavior.ResourceRoleSource),
	pythonResourceAPI("socket.getaddrinfo", behavior.OperationNameResolve, 0, "host", behavior.ResourceIdentifier, behavior.ResourceRoleSource),
	pythonResourceAPI("socket.gethostbyname", behavior.OperationNameResolve, 0, "hostname", behavior.ResourceIdentifier, behavior.ResourceRoleSource),
	pythonResourceAPI("socket.gethostbyname_ex", behavior.OperationNameResolve, 0, "hostname", behavior.ResourceIdentifier, behavior.ResourceRoleSource),
	pythonFixedAPI("socket.if_nameindex", behavior.OperationNetworkConfigurationQuery, behavior.ResourceRoleSource, behavior.ResourceConfiguration, "local network interfaces"),
	pythonFixedAPI("os.getegid", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local user"),
	pythonFixedAPI("os.geteuid", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local user"),
	pythonFixedAPI("os.getgid", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local user"),
	pythonFixedAPI("os.getlogin", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local user"),
	pythonFixedAPI("os.getuid", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local user"),
	pythonFixedAPI("pwd.getpwall", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local users"),
	pythonFixedAPI("pwd.getpwnam", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local users"),
	pythonFixedAPI("pwd.getpwuid", behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.ResourceUserAccount, "local users"),
	pythonFixedAPI("os.uname", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("socket.gethostname", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.architecture", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.machine", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.mac_ver", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.node", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.platform", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.processor", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.python_build", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_branch", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_compiler", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_implementation", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_revision", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_version", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.python_version_tuple", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "Python runtime"),
	pythonFixedAPI("platform.release", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.system", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.uname", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
	pythonFixedAPI("platform.version", behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.ResourceSystem, "macOS system and hardware"),
}

func init() {
	for _, spec := range pythonAPISpecs {
		if spec.minArgs < 0 || spec.maxArgs < spec.minArgs || spec.maxPositional < 0 || spec.maxPositional > spec.maxArgs || len(spec.parameters) != spec.maxArgs {
			panic(fmt.Sprintf("invalid Python API signature table entry for %q", spec.api))
		}
	}
	sort.Slice(pythonAPISpecs, func(i, j int) bool { return pythonAPISpecs[i].api < pythonAPISpecs[j].api })
}

func pythonUnaryFileAPI(api string, kind behavior.OperationKind, role behavior.ResourceRole) pythonAPISpec {
	signature := pythonAPISignature(api)
	parameter, defaultValue := pythonUnaryFileParameter(api)
	return pythonAPISpec{api: api, kind: kind, minArgs: signature.minArgs, maxArgs: signature.maxArgs, maxPositional: signature.maxPositional, positionalOnly: signature.positionalOnly, parameters: signature.parameters, resources: []pythonAPIResourceSpec{{
		role: role, kind: behavior.ResourceFile, index: 0, parameter: parameter, defaultValue: defaultValue,
	}}}
}

func pythonBinaryFileAPI(api string, kind behavior.OperationKind, first, second behavior.ResourceRole) pythonAPISpec {
	signature := pythonAPISignature(api)
	firstParameter, secondParameter := "src", "dst"
	if api == "os.renames" {
		firstParameter, secondParameter = "old", "new"
	}
	return pythonAPISpec{api: api, kind: kind, minArgs: signature.minArgs, maxArgs: signature.maxArgs, maxPositional: signature.maxPositional, positionalOnly: signature.positionalOnly, parameters: signature.parameters, resources: []pythonAPIResourceSpec{
		{role: first, kind: behavior.ResourceFile, index: 0, parameter: firstParameter},
		{role: second, kind: behavior.ResourceFile, index: 1, parameter: secondParameter},
	}}
}

func pythonFixedAPI(api string, kind behavior.OperationKind, role behavior.ResourceRole, resourceKind behavior.ResourceKind, value string) pythonAPISpec {
	signature := pythonAPISignature(api)
	return pythonAPISpec{api: api, kind: kind, minArgs: signature.minArgs, maxArgs: signature.maxArgs, maxPositional: signature.maxPositional, positionalOnly: signature.positionalOnly, parameters: signature.parameters, resources: []pythonAPIResourceSpec{{role: role, kind: resourceKind, index: -1, fixed: value}}}
}

func pythonResourceAPI(api string, kind behavior.OperationKind, index int, parameter string, resourceKind behavior.ResourceKind, role behavior.ResourceRole) pythonAPISpec {
	signature := pythonAPISignature(api)
	return pythonAPISpec{api: api, kind: kind, minArgs: signature.minArgs, maxArgs: signature.maxArgs, maxPositional: signature.maxPositional, positionalOnly: signature.positionalOnly, parameters: signature.parameters, resources: []pythonAPIResourceSpec{{
		role: role, kind: resourceKind, index: index, parameter: parameter,
	}}}
}

func pythonArchiveUnpackAPI() pythonAPISpec {
	signature := pythonAPISignature("shutil.unpack_archive")
	return pythonAPISpec{
		api: "shutil.unpack_archive", kind: behavior.OperationArchiveExtract,
		minArgs: signature.minArgs, maxArgs: signature.maxArgs, maxPositional: signature.maxPositional,
		positionalOnly: signature.positionalOnly, parameters: signature.parameters,
		resources: []pythonAPIResourceSpec{
			{role: behavior.ResourceRoleSource, kind: behavior.ResourceFile, classes: []behavior.ResourceClassification{behavior.ResourceClassArchive}, index: 0, parameter: "filename"},
			{role: behavior.ResourceRoleLocalOutput, kind: behavior.ResourceFile, index: 1, parameter: "extract_dir", defaultValue: "."},
		},
	}
}

func pythonUnaryFileParameter(api string) (string, string) {
	switch api {
	case "glob.glob", "glob.iglob":
		return "pathname", ""
	case "os.listdir", "os.scandir":
		return "path", "."
	case "os.makedirs", "os.removedirs":
		return "name", ""
	case "os.walk":
		return "top", ""
	default:
		return "path", ""
	}
}

type pythonCallSignature struct {
	minArgs        int
	maxArgs        int
	maxPositional  int
	positionalOnly int
	parameters     []string
}

func pythonSignature(minimum, maxPositional, positionalOnly int, parameters ...string) pythonCallSignature {
	return pythonCallSignature{minArgs: minimum, maxArgs: len(parameters), maxPositional: maxPositional, positionalOnly: positionalOnly, parameters: parameters}
}

// pythonAPISignature keeps the supported grammar narrower than Python itself:
// only documented parameters and positional/keyword shapes are accepted, and
// *args/**kwargs are rejected because they make resource bindings indeterminate.
func pythonAPISignature(api string) pythonCallSignature {
	switch api {
	case "glob.glob", "glob.iglob":
		return pythonSignature(1, 1, 0, "pathname", "root_dir", "dir_fd", "recursive", "include_hidden")
	case "os.access":
		return pythonSignature(2, 2, 0, "path", "mode", "dir_fd", "effective_ids", "follow_symlinks")
	case "os.chmod":
		return pythonSignature(2, 2, 0, "path", "mode", "dir_fd", "follow_symlinks")
	case "os.listdir", "os.scandir":
		return pythonSignature(0, 1, 0, "path")
	case "os.lstat", "os.remove", "os.rmdir", "os.unlink":
		return pythonSignature(1, 1, 0, "path", "dir_fd")
	case "os.makedirs":
		return pythonSignature(1, 3, 0, "name", "mode", "exist_ok")
	case "os.mkdir":
		return pythonSignature(1, 2, 0, "path", "mode", "dir_fd")
	case "os.open":
		return pythonSignature(2, 3, 0, "path", "flags", "mode", "dir_fd")
	case "os.readlink":
		return pythonSignature(1, 1, 0, "path", "dir_fd")
	case "os.removedirs":
		return pythonSignature(1, 1, 0, "name")
	case "os.rename", "os.replace":
		return pythonSignature(2, 2, 0, "src", "dst", "src_dir_fd", "dst_dir_fd")
	case "os.renames":
		return pythonSignature(2, 2, 0, "old", "new")
	case "os.stat":
		return pythonSignature(1, 1, 0, "path", "dir_fd", "follow_symlinks")
	case "os.truncate":
		return pythonSignature(2, 2, 0, "path", "length")
	case "os.walk":
		return pythonSignature(1, 4, 0, "top", "topdown", "onerror", "followlinks")
	case "os.path.exists", "os.path.getatime", "os.path.getctime", "os.path.getmtime", "os.path.getsize", "os.path.isdir", "os.path.isfile", "os.path.islink":
		return pythonSignature(1, 1, 0, "path")
	case "os.path.realpath":
		return pythonSignature(1, 1, 0, "path", "strict")
	case "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move":
		third := "follow_symlinks"
		maxPositional := 2
		if api == "shutil.move" {
			third = "copy_function"
			maxPositional = 3
		}
		return pythonSignature(2, maxPositional, 0, "src", "dst", third)
	case "shutil.copytree":
		return pythonSignature(2, 7, 0, "src", "dst", "symlinks", "ignore", "copy_function", "ignore_dangling_symlinks", "dirs_exist_ok")
	case "shutil.rmtree":
		return pythonSignature(1, 3, 0, "path", "ignore_errors", "onerror", "onexc", "dir_fd")
	case "shutil.unpack_archive":
		return pythonSignature(1, 3, 0, "filename", "extract_dir", "format", "filter")
	case "os.getenv", "os.environ.get":
		return pythonSignature(1, 2, 0, "key", "default")
	case "socket.getaddrinfo":
		return pythonSignature(2, 6, 0, "host", "port", "family", "type", "proto", "flags")
	case "socket.gethostbyname", "socket.gethostbyname_ex":
		return pythonSignature(1, 1, 0, "hostname")
	case "pwd.getpwnam":
		return pythonSignature(1, 1, 1, "name")
	case "pwd.getpwuid":
		return pythonSignature(1, 1, 1, "uid")
	case "platform.architecture", "platform.platform":
		if api == "platform.architecture" {
			return pythonSignature(0, 2, 0, "executable", "bits")
		}
		return pythonSignature(0, 2, 0, "aliased", "terse")
	case "platform.mac_ver":
		return pythonSignature(0, 3, 0, "release", "versioninfo", "machine")
	default:
		return pythonSignature(0, 0, 0)
	}
}

func scanPythonStableAPIBindings(lines []string, offsets []int64) pythonStableAPIBindings {
	result := pythonStableAPIBindings{
		bindings: map[string]pythonAPIBindingProof{}, evidenceIDs: map[string]string{}, builtinOpenSafe: true,
	}
	for index, raw := range lines {
		if len(raw) == 0 || raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		line := stripSemanticComment("python", raw, new(bool))
		parsed := parsePythonImportLine(line)
		if parsed.disposition != pythonImportRecognized {
			continue
		}
		for _, observation := range parsed.observations {
			if observation.value == "" || strings.HasSuffix(observation.value, ".*") {
				if strings.HasSuffix(observation.value, ".*") {
					result.dynamicNamespace = true
				}
				continue
			}
			name, canonical, ok := pythonAPIModuleBinding(observation)
			if !ok {
				continue
			}
			if len(result.bindings) >= maxPythonAPIBindings {
				result.limited = true
				continue
			}
			if existing, present := result.bindings[name]; present {
				if existing.canonical != canonical {
					delete(result.bindings, name)
					result.invalidated = true
				}
				continue
			}
			offset := int64(0)
			if index < len(offsets) {
				offset = offsets[index] + int64(observation.byteOffset)
			}
			result.bindings[name] = pythonAPIBindingProof{
				name: name, canonical: canonical, text: strings.TrimSpace(raw), line: index + 1, offset: offset,
			}
		}
	}

	for _, raw := range lines {
		line := stripSemanticComment("python", raw, new(bool))
		code := pythonCodeContext(line)
		trimmed := strings.TrimSpace(code)
		parsed := parsePythonImportLine(line)
		if parsed.disposition == pythonImportRecognized {
			if pythonImportResultHasWildcard(parsed) {
				result.dynamicNamespace = true
			}
			continue
		}
		if pythonDynamicNamespaceCode(trimmed) {
			result.dynamicNamespace = true
		}
		if !pythonBuiltinNameUsedOnlyAsDirectCall(code, "open") {
			result.builtinOpenSafe = false
		}
		for name := range result.bindings {
			if !pythonStableBindingUsesOnlyQualifiedReads(code, name) {
				delete(result.bindings, name)
				result.invalidated = true
			}
		}
	}
	if result.dynamicNamespace {
		result.bindings = map[string]pythonAPIBindingProof{}
		result.builtinOpenSafe = false
	}
	return result
}

type pythonOrderedAPIBinding struct {
	proof  pythonAPIBindingProof
	indent int
}

// pythonOrderedAPIBindings is a forward-only proof lane for an import and a
// later call in the same retained lexical scope and contiguous indentation
// region. It complements, rather than replaces, the whole-file binding map:
// local imports and earlier calls may use exact source order, while global
// lookup from function bodies still requires the stricter whole-file proof.
// A dedent, ambiguous write, wildcard import, dynamic namespace access, bad
// indentation, or malformed import invalidates the affected ordered proof.
type pythonOrderedAPIBindings struct {
	byScope       map[string]map[string]pythonOrderedAPIBinding
	shadowed      map[string]map[string]bool
	blockFallback map[string]bool
	fallbackNames map[string]bool
	events        int
	limited       bool
	badIndent     bool
}

type pythonOrderedAPIBindingState struct {
	proofs        map[string]pythonAPIBindingProof
	shadowed      map[string]bool
	blockFallback bool
}

func newPythonOrderedAPIBindings(fallback map[string]pythonAPIBindingProof) pythonOrderedAPIBindings {
	fallbackNames := make(map[string]bool, len(fallback))
	for name := range fallback {
		fallbackNames[name] = true
	}
	return pythonOrderedAPIBindings{
		byScope:       map[string]map[string]pythonOrderedAPIBinding{},
		shadowed:      map[string]map[string]bool{},
		blockFallback: map[string]bool{},
		fallbackNames: fallbackNames,
	}
}

func (tracker *pythonOrderedAPIBindings) observe(scopeKey, raw, line string, lineNo int, offsetBase int64) {
	if tracker == nil || tracker.limited || strings.TrimSpace(line) == "" {
		return
	}
	indent, ok := pythonExactSourceIndent(raw)
	if !ok {
		tracker.badIndent = true
		tracker.blockScope(scopeKey)
		return
	}
	scope := tracker.byScope[scopeKey]
	if scope == nil {
		scope = map[string]pythonOrderedAPIBinding{}
		tracker.byScope[scopeKey] = scope
	}
	for name, binding := range scope {
		if binding.indent > indent {
			tracker.shadow(scopeKey, name)
		}
	}
	if pythonDynamicNamespaceCode(strings.TrimSpace(line)) {
		tracker.blockAllScopes()
		return
	}
	parsed := parsePythonImportLine(line)
	if parsed.disposition == pythonImportUnsupported || parsed.disposition == pythonImportMalformed {
		tracker.blockScope(scopeKey)
		return
	}
	if parsed.disposition == pythonImportRecognized {
		for _, observation := range parsed.observations {
			if boundName := pythonImportBoundName(observation); boundName != "" {
				tracker.shadow(scopeKey, boundName)
			}
			if strings.HasSuffix(observation.value, ".*") {
				tracker.blockScope(scopeKey)
				continue
			}
			name, canonical, supported := pythonAPIModuleBinding(observation)
			if !supported {
				continue
			}
			if len(scope) >= maxPythonAPIBindings {
				tracker.limit()
				return
			}
			proof := pythonAPIBindingProof{
				name: name, canonical: canonical, text: strings.TrimSpace(raw), line: lineNo,
				offset: offsetBase + int64(observation.byteOffset),
			}
			if !tracker.recordEvent() {
				return
			}
			tracker.ensureShadowScope(scopeKey)[name] = true
			scope[name] = pythonOrderedAPIBinding{proof: proof, indent: indent}
		}
		return
	}
	code := pythonCodeContext(line)
	candidates := make(map[string]bool, len(scope)+len(tracker.fallbackNames))
	for name := range scope {
		candidates[name] = true
	}
	for name := range tracker.fallbackNames {
		candidates[name] = true
	}
	for name := range candidates {
		if !pythonStableBindingUsesOnlyQualifiedReads(code, name) {
			tracker.shadow(scopeKey, name)
		}
	}
}

func (tracker *pythonOrderedAPIBindings) stateAt(scopeKey, raw string) pythonOrderedAPIBindingState {
	out := pythonOrderedAPIBindingState{
		proofs:   map[string]pythonAPIBindingProof{},
		shadowed: map[string]bool{},
	}
	if tracker == nil || tracker.limited {
		return out
	}
	indent, ok := pythonExactSourceIndent(raw)
	if !ok {
		return out
	}
	out.blockFallback = tracker.blockFallback[scopeKey]
	for name := range tracker.shadowed[scopeKey] {
		out.shadowed[name] = true
	}
	for name, binding := range tracker.byScope[scopeKey] {
		if binding.indent <= indent {
			out.proofs[name] = binding.proof
		}
	}
	return out
}

func (tracker *pythonOrderedAPIBindings) shadow(scopeKey, name string) {
	if name == "" || tracker == nil || tracker.limited {
		return
	}
	shadowed := tracker.ensureShadowScope(scopeKey)
	_, alreadyShadowed := shadowed[name]
	scope := tracker.byScope[scopeKey]
	_, hasProof := scope[name]
	if alreadyShadowed && !hasProof {
		return
	}
	if !tracker.recordEvent() {
		return
	}
	shadowed[name] = true
	delete(scope, name)
}

func (tracker *pythonOrderedAPIBindings) invalidateScope(scopeKey string) {
	for name := range tracker.byScope[scopeKey] {
		tracker.shadow(scopeKey, name)
	}
}

func (tracker *pythonOrderedAPIBindings) blockScope(scopeKey string) {
	if tracker == nil || tracker.limited {
		return
	}
	if !tracker.blockFallback[scopeKey] {
		if !tracker.recordEvent() {
			return
		}
		tracker.blockFallback[scopeKey] = true
	}
	tracker.invalidateScope(scopeKey)
}

func (tracker *pythonOrderedAPIBindings) blockAllScopes() {
	for scopeKey := range tracker.byScope {
		tracker.blockScope(scopeKey)
	}
	for scopeKey := range tracker.shadowed {
		tracker.blockScope(scopeKey)
	}
}

func (tracker *pythonOrderedAPIBindings) ensureShadowScope(scopeKey string) map[string]bool {
	if tracker.shadowed[scopeKey] == nil {
		tracker.shadowed[scopeKey] = map[string]bool{}
	}
	return tracker.shadowed[scopeKey]
}

func (tracker *pythonOrderedAPIBindings) recordEvent() bool {
	if tracker.events >= maxPythonAPIOrderedBindingEvents {
		tracker.limit()
		return false
	}
	tracker.events++
	return true
}

func (tracker *pythonOrderedAPIBindings) limit() {
	tracker.limited = true
	tracker.byScope = map[string]map[string]pythonOrderedAPIBinding{}
	tracker.shadowed = map[string]map[string]bool{}
	tracker.blockFallback = map[string]bool{}
}

func pythonEffectiveAPIBindings(
	bindings *pythonStableAPIBindings,
	ordered pythonOrderedAPIBindingState,
	lineNo int,
) map[string]pythonAPIBindingProof {
	proofs := map[string]pythonAPIBindingProof{}
	if bindings != nil && !ordered.blockFallback {
		for name, proof := range bindings.bindings {
			if proof.line < lineNo {
				proofs[name] = proof
			}
		}
	}
	for name := range ordered.shadowed {
		delete(proofs, name)
	}
	for name, proof := range ordered.proofs {
		if proof.line < lineNo {
			proofs[name] = proof
		}
	}
	return proofs
}

func pythonExactSourceIndent(raw string) (int, bool) {
	indent := 0
	for indent < len(raw) {
		switch raw[indent] {
		case ' ':
			indent++
		case '\t':
			return 0, false
		default:
			return indent, true
		}
	}
	return indent, true
}

func pythonImportBoundName(observation pythonSourceObservation) string {
	if observation.alias != "" {
		return observation.alias
	}
	value := strings.TrimLeft(observation.value, ".")
	components := strings.Split(value, ".")
	if len(components) == 0 {
		return ""
	}
	if observation.form == "from-import" {
		return components[len(components)-1]
	}
	return components[0]
}

// pythonBuiltinNameUsedOnlyAsDirectCall is deliberately global and
// conservative. Any retained non-call use can bind, shadow, delete, export, or
// otherwise replace the builtin in a lexical scope, so the complete file loses
// builtin identity rather than guessing which call sites remain safe.
func pythonBuiltinNameUsedOnlyAsDirectCall(code, name string) bool {
	for _, position := range pythonIdentifierPositions(code, name) {
		if pythonIdentifierHasMemberPrefix(code, position) {
			continue
		}
		prefix := strings.TrimSpace(code[:position])
		if strings.HasSuffix(prefix, "def") || strings.HasSuffix(prefix, "class") || strings.HasSuffix(prefix, "del") || strings.HasSuffix(prefix, "import") || strings.HasSuffix(prefix, "as") {
			return false
		}
		open := pythonSkipHorizontal(code, position+len(name))
		if open >= len(code) || code[open] != '(' {
			return false
		}
	}
	return true
}

func pythonIdentifierHasMemberPrefix(code string, position int) bool {
	if position <= 0 || position > len(code) {
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(code[:position]), ".")
}

func pythonAPIModuleBinding(observation pythonSourceObservation) (string, string, bool) {
	root := strings.Split(strings.TrimLeft(observation.value, "."), ".")[0]
	if !pythonSupportedAPIModule(root) {
		return "", "", false
	}
	if observation.form == "from-import" {
		// Function/class imports require a different call grammar. Keep this
		// pass limited to module bindings whose qualified identity is stable.
		return "", "", false
	}
	name := observation.alias
	canonical := observation.value
	if name == "" {
		name = root
		canonical = root
	}
	return name, canonical, javaScriptIdentifier(name)
}

func pythonSupportedAPIModule(name string) bool {
	switch name {
	case "glob", "httpx", "os", "platform", "pwd", "requests", "shutil", "socket", "subprocess", "tarfile", "urllib", "urllib2", "zipfile":
		return true
	default:
		return false
	}
}

func pythonImportResultHasWildcard(result pythonImportResult) bool {
	for _, observation := range result.observations {
		if strings.HasSuffix(observation.value, ".*") {
			return true
		}
	}
	return false
}

func pythonDynamicNamespaceCode(code string) bool {
	for _, name := range []string{"eval", "exec", "globals", "locals"} {
		for _, position := range pythonIdentifierPositions(code, name) {
			open := pythonSkipHorizontal(code, position+len(name))
			if open < len(code) && code[open] == '(' {
				return true
			}
		}
	}
	return false
}

func pythonIdentifierPositions(code, name string) []int {
	if name == "" || !javaScriptIdentifier(name) {
		return nil
	}
	var positions []int
	for cursor := 0; cursor <= len(code)-len(name); {
		relative := strings.Index(code[cursor:], name)
		if relative < 0 {
			break
		}
		position := cursor + relative
		end := position + len(name)
		if (position == 0 || !pythonIdentifierByte(code[position-1])) && (end == len(code) || !pythonIdentifierByte(code[end])) {
			positions = append(positions, position)
		}
		cursor = end
	}
	return positions
}

func pythonStableBindingUsesOnlyQualifiedReads(code, name string) bool {
	for _, position := range pythonIdentifierPositions(code, name) {
		if position > 0 && code[position-1] == '.' {
			continue
		}
		cursor := pythonSkipHorizontal(code, position+len(name))
		if cursor >= len(code) || code[cursor] != '.' || pythonRootedMemberMutation(code, position, cursor) {
			return false
		}
	}
	return true
}

func pythonRootedMemberMutation(code string, root, dot int) bool {
	prefix := strings.TrimSpace(code[:root])
	if strings.HasSuffix(prefix, "del") && (len(prefix) == 3 || !pythonIdentifierByte(prefix[len(prefix)-4])) {
		return true
	}
	cursor := dot
	for cursor < len(code) && code[cursor] == '.' {
		cursor++
		_, _, next, ok := pythonASCIIIdentifier(code, cursor)
		if !ok {
			return true
		}
		cursor = pythonSkipHorizontal(code, next)
	}
	for _, operator := range []string{"**=", "//=", "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "@=", "&=", "|=", "^=", ":="} {
		if strings.HasPrefix(code[cursor:], operator) {
			return true
		}
	}
	return strings.HasPrefix(code[cursor:], "=") && !strings.HasPrefix(code[cursor:], "==")
}

func (bindings *pythonStableAPIBindings) bindingEvidence(graph *behavior.Graph, content artifact.Content, name string) string {
	if bindings == nil {
		return ""
	}
	proof, ok := bindings.bindings[name]
	if !ok {
		return ""
	}
	return bindings.bindingProofEvidence(graph, content, proof)
}

func (bindings *pythonStableAPIBindings) bindingProofEvidence(graph *behavior.Graph, content artifact.Content, proof pythonAPIBindingProof) string {
	if bindings == nil || proof.name == "" {
		return ""
	}
	cacheKey := fmt.Sprintf("%s@%d:%d", proof.name, proof.line, proof.offset)
	if evidenceID := bindings.evidenceIDs[cacheKey]; evidenceID != "" {
		return evidenceID
	}
	evidenceID := graph.AddEvidence(behavior.Evidence{
		NodeID: content.NodeID, ScopeID: content.ScopeID, Logical: content.LogicalPath, Physical: content.PhysicalPath,
		Line: proof.line, Offset: proof.offset, OffsetKnown: true,
		Method: "python-source-binding", Kind: "python-import-binding", Value: proof.text,
	})
	if evidenceID != "" {
		bindings.evidenceIDs[cacheKey] = evidenceID
	}
	return evidenceID
}

func extractPythonSourceAPIs(
	graph *behavior.Graph,
	rootContent artifact.Content,
	lineContent artifact.Content,
	line string,
	lineNo int,
	callEvidenceID string,
	vars any,
	budget *textLineBudget,
	bindings *pythonStableAPIBindings,
	ordered pythonOrderedAPIBindingState,
) {
	code := pythonCodeContext(line)
	extractPythonBuiltinOpenRead(graph, lineContent, line, code, lineNo, callEvidenceID, budget, bindings)
	extractPythonArchiveObjectCall(graph, rootContent, lineContent, line, lineNo, callEvidenceID, vars, bindings, ordered)
	proofs := pythonEffectiveAPIBindings(bindings, ordered, lineNo)
	calls, callNamesLimited := pythonQualifiedCalls(code, maxPythonAPICallsPerLine+1)
	if callNamesLimited || len(calls) > maxPythonAPICallsPerLine {
		addPartialCoverageOnce(graph, lineContent.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("Python source API recognition reached the per-line call limit %d", maxPythonAPICallsPerLine))
		if len(calls) > maxPythonAPICallsPerLine {
			calls = calls[:maxPythonAPICallsPerLine]
		}
	}
	for _, call := range calls {
		components := strings.Split(call.value, ".")
		if len(components) < 2 {
			continue
		}
		proof, bound := proofs[components[0]]
		canonical := components[0] + "." + strings.Join(components[1:], ".")
		if bound {
			canonical = proof.canonical + "." + strings.Join(components[1:], ".")
		}
		spec, recognized := lookupPythonAPISpec(canonical)
		if !recognized {
			continue
		}
		if !bound || proof.line >= lineNo {
			bindings.unsupportedCalls = true
			continue
		}
		open := pythonSkipHorizontal(line, call.byteOffset+len(call.value))
		argumentsText, _, exact, limited := exactPythonCallContent(line, open, maxPythonAPICallBytes)
		if limited {
			addPartialCoverageOnce(graph, lineContent.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("Python source API call exceeded %d bytes", maxPythonAPICallBytes))
		}
		if !exact {
			bindings.unsupportedCalls = true
			continue
		}
		arguments, argumentLimited, malformed := exactPythonArguments(argumentsText, maxTextStringExpressionArguments)
		if argumentLimited {
			if budget != nil {
				budget.markLimited(fmt.Sprintf("Python source API argument limit %d reached", maxTextStringExpressionArguments), false)
			}
			continue
		}
		if malformed || !pythonAPISpecHasArguments(spec, arguments) {
			bindings.unsupportedCalls = true
			continue
		}
		bindingEvidenceID := bindings.bindingProofEvidence(graph, rootContent, proof)
		if bindingEvidenceID == "" {
			return
		}
		evidenceIDs := []string{callEvidenceID, bindingEvidenceID}
		resourceBindings := make([]behavior.ResourceBinding, 0, len(spec.resources))
		unresolved := false
		for _, resourceSpec := range spec.resources {
			value := resourceSpec.fixed
			if resourceSpec.index >= 0 {
				expression, present := pythonResourceArgument(arguments, resourceSpec)
				if !present {
					value = resourceSpec.defaultValue
				} else {
					value = resolveStringExpression("python", expression, vars)
				}
				if value == "" {
					unresolved = true
				}
			}
			resource := behavior.NewResource(resourceSpec.kind, value, resourceSpec.classes...)
			if resourceSpec.kind == behavior.ResourceFile && value != "" {
				classified := classifiedFileResource(value)
				classified.Classifications = append(classified.Classifications, resourceSpec.classes...)
				resource = classified
			}
			resourceBindings = append(resourceBindings, behavior.Bind(resourceSpec.role, resource))
		}
		qualifiers := map[string]string{
			"api": spec.api, "api_identity": "stable-python-import-and-exact-qualified-call", "module_binding": components[0],
		}
		if unresolved {
			qualifiers["resource_binding"] = "unresolved"
		} else {
			qualifiers["resource_binding"] = "exact-static"
		}
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: lineContent.NodeID, ScopeID: lineContent.ScopeID, SourceFunction: lineContent.Function,
			Kind: spec.kind, ResourceBindings: resourceBindings, Qualifiers: qualifiers,
			EvidenceIDs: evidenceIDs, Support: behavior.SupportCorroborated,
			Execution: executionContextForContent(lineContent), Line: lineNo,
		})
	}
}

type pythonArchiveObjectInvocation struct {
	bindingName      string
	bindingProof     pythonAPIBindingProof
	api              string
	sourceExpression string
	targetExpression string
}

func extractPythonArchiveObjectCall(
	graph *behavior.Graph,
	rootContent artifact.Content,
	lineContent artifact.Content,
	line string,
	lineNo int,
	callEvidenceID string,
	vars any,
	bindings *pythonStableAPIBindings,
	ordered pythonOrderedAPIBindingState,
) {
	invocation, ok, limited := parsePythonArchiveObjectInvocation(line, lineNo, bindings, ordered)
	if limited {
		addPartialCoverageOnce(graph, lineContent.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("Python archive extraction chain exceeded retained call or argument bounds (%d bytes, %d arguments)", maxPythonAPICallBytes, maxTextStringExpressionArguments))
	}
	if !ok {
		return
	}
	bindingEvidenceID := bindings.bindingProofEvidence(graph, rootContent, invocation.bindingProof)
	if bindingEvidenceID == "" {
		return
	}
	source := resolveStringExpression("python", invocation.sourceExpression, vars)
	target := "."
	destinationBinding := "runtime-working-directory"
	if invocation.targetExpression != "" {
		target = resolveStringExpression("python", invocation.targetExpression, vars)
		destinationBinding = "unresolved"
		if target != "" {
			destinationBinding = "exact-static"
		}
	}
	qualifiers := map[string]string{
		"api": invocation.api, "api_identity": "stable-python-import-and-exact-constructor-method-chain",
		"source_binding": "unresolved", "destination_binding": destinationBinding,
	}
	if source != "" {
		qualifiers["source_binding"] = "exact-static"
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: lineContent.NodeID, ScopeID: lineContent.ScopeID, SourceFunction: lineContent.Function,
		Kind: behavior.OperationArchiveExtract,
		ResourceBindings: behavior.Bindings(
			behavior.Bind(behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source, behavior.ResourceClassArchive)),
			behavior.Bind(behavior.ResourceRoleLocalOutput, behavior.NewResource(behavior.ResourceFile, target)),
		),
		Qualifiers: qualifiers, EvidenceIDs: []string{callEvidenceID, bindingEvidenceID},
		Support: behavior.SupportCorroborated, Execution: executionContextForContent(lineContent), Line: lineNo,
	})
}

func parsePythonArchiveObjectInvocation(line string, lineNo int, bindings *pythonStableAPIBindings, ordered pythonOrderedAPIBindingState) (pythonArchiveObjectInvocation, bool, bool) {
	if bindings == nil {
		return pythonArchiveObjectInvocation{}, false, false
	}
	inBlockComment := false
	code := strings.TrimSpace(stripSemanticComment("python", line, &inBlockComment))
	proofs := pythonEffectiveAPIBindings(bindings, ordered, lineNo)
	names := make([]string, 0, len(proofs))
	for name := range proofs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		proof := proofs[name]
		constructor := ""
		switch proof.canonical {
		case "zipfile":
			constructor = "ZipFile"
		case "tarfile":
			constructor = "open"
		default:
			continue
		}
		prefix := name + "." + constructor
		if !strings.HasPrefix(code, prefix) {
			continue
		}
		open := pythonSkipHorizontal(code, len(prefix))
		constructorText, constructorClose, exact, limited := exactPythonCallContent(code, open, maxPythonAPICallBytes)
		if limited {
			return pythonArchiveObjectInvocation{}, false, true
		}
		if !exact {
			continue
		}
		methodStart := pythonSkipHorizontal(code, constructorClose+1)
		if !strings.HasPrefix(code[methodStart:], ".extractall") {
			continue
		}
		methodOpen := pythonSkipHorizontal(code, methodStart+len(".extractall"))
		methodText, methodClose, methodExact, methodLimited := exactPythonCallContent(code, methodOpen, maxPythonAPICallBytes)
		if methodLimited {
			return pythonArchiveObjectInvocation{}, false, true
		}
		if !methodExact || strings.TrimSpace(code[methodClose+1:]) != "" {
			continue
		}
		constructorArgs, constructorLimited, constructorMalformed := exactPythonArguments(constructorText, maxTextStringExpressionArguments)
		methodArgs, methodArgsLimited, methodMalformed := exactPythonArguments(methodText, maxTextStringExpressionArguments)
		if constructorLimited || methodArgsLimited {
			return pythonArchiveObjectInvocation{}, false, true
		}
		if constructorMalformed || methodMalformed {
			continue
		}
		source, constructorOK := pythonArchiveConstructorSource(proof.canonical, constructorArgs)
		target, methodOK := pythonArchiveExtractTarget(proof.canonical, methodArgs)
		if !constructorOK || !methodOK {
			continue
		}
		return pythonArchiveObjectInvocation{
			bindingName: name, bindingProof: proof, api: proof.canonical + "." + constructor + ".extractall",
			sourceExpression: source, targetExpression: target,
		}, true, false
	}
	return pythonArchiveObjectInvocation{}, false, false
}

func pythonArchiveConstructorSource(module string, arguments []string) (string, bool) {
	positional, keywords, ok := pythonStableArgumentShape(arguments)
	if !ok {
		return "", false
	}
	parameters := []string{"file", "mode", "compression", "allowZip64", "compresslevel", "strict_timestamps", "metadata_encoding"}
	maxPositional := 5
	if module == "tarfile" {
		parameters = []string{"name", "mode", "fileobj", "bufsize"}
		maxPositional = 4
	}
	if len(positional) > maxPositional || !pythonArgumentsUseOnlyParameters(positional, keywords, parameters) {
		return "", false
	}
	for _, expression := range positional {
		if !boundedPythonExpression(expression, 0) {
			return "", false
		}
	}
	for _, expression := range keywords {
		if !boundedPythonExpression(expression, 0) {
			return "", false
		}
	}
	mode := pythonParameterExpression(positional, keywords, parameters, "mode")
	if mode != "" {
		value, exact := exactPythonStringLiteral(mode)
		if !exact || module == "zipfile" && value != "r" || module == "tarfile" && !strings.HasPrefix(value, "r") {
			return "", false
		}
	}
	source := pythonParameterExpression(positional, keywords, parameters, parameters[0])
	if source == "" || strings.TrimSpace(source) == "None" {
		return "", false
	}
	return source, true
}

func pythonArchiveExtractTarget(module string, arguments []string) (string, bool) {
	positional, keywords, ok := pythonStableArgumentShape(arguments)
	if !ok {
		return "", false
	}
	parameters := []string{"path", "members", "pwd"}
	maxPositional := 3
	if module == "tarfile" {
		parameters = []string{"path", "members", "numeric_owner", "filter"}
		maxPositional = 2
	}
	if len(positional) > maxPositional || !pythonArgumentsUseOnlyParameters(positional, keywords, parameters) {
		return "", false
	}
	for _, expression := range positional {
		if !boundedPythonExpression(expression, 0) {
			return "", false
		}
	}
	for _, expression := range keywords {
		if !boundedPythonExpression(expression, 0) {
			return "", false
		}
	}
	return pythonParameterExpression(positional, keywords, parameters, "path"), true
}

func pythonArgumentsUseOnlyParameters(positional []string, keywords map[string]string, parameters []string) bool {
	if len(positional) > len(parameters) {
		return false
	}
	indexes := make(map[string]int, len(parameters))
	for index, parameter := range parameters {
		indexes[parameter] = index
	}
	for name := range keywords {
		index, known := indexes[name]
		if !known || index < len(positional) {
			return false
		}
	}
	return true
}

func pythonParameterExpression(positional []string, keywords map[string]string, parameters []string, parameter string) string {
	for index, name := range parameters {
		if name != parameter {
			continue
		}
		if index < len(positional) {
			return positional[index]
		}
		return keywords[parameter]
	}
	return ""
}

func extractPythonBuiltinOpenRead(
	graph *behavior.Graph,
	content artifact.Content,
	line, code string,
	lineNo int,
	evidenceID string,
	budget *textLineBudget,
	bindings *pythonStableAPIBindings,
) {
	if bindings == nil || !bindings.builtinOpenSafe {
		return
	}
	for _, position := range pythonIdentifierPositions(code, "open") {
		if pythonIdentifierHasMemberPrefix(code, position) {
			continue
		}
		open := pythonSkipHorizontal(code, position+len("open"))
		argumentsText, close, exact, limited := exactPythonCallContent(line, open, maxPythonAPICallBytes)
		if limited {
			addPartialCoverageOnce(graph, content.NodeID, pythonAPIBindingAnalysisArea, fmt.Sprintf("Python builtin open call exceeded %d bytes", maxPythonAPICallBytes))
		}
		if !exact || !pythonExactReadMemberCall(line, close) {
			continue
		}
		arguments, argumentLimited, malformed := exactPythonArguments(argumentsText, maxTextStringExpressionArguments)
		if argumentLimited {
			if budget != nil {
				budget.markLimited(fmt.Sprintf("Python builtin open argument limit %d reached", maxTextStringExpressionArguments), false)
			}
			continue
		}
		positional, keywords, stable := pythonStableArgumentShape(arguments)
		if malformed || !stable || len(arguments) == 0 || len(arguments) > 8 || len(positional) > 8 {
			continue
		}
		for name := range keywords {
			switch name {
			case "file", "mode", "buffering", "encoding", "errors", "newline", "closefd", "opener":
			default:
				stable = false
			}
		}
		parameters := []string{"file", "mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"}
		for index := 0; index < len(positional) && index < len(parameters); index++ {
			if _, duplicate := keywords[parameters[index]]; duplicate {
				stable = false
			}
		}
		if !stable {
			continue
		}
		pathExpression := keywords["file"]
		if len(positional) > 0 {
			pathExpression = positional[0]
		}
		path := simpleStringLiteral(pathExpression)
		if path == "" {
			continue
		}
		resource := classifiedFileResource(path)
		graph.AddOperation(behavior.ModeledOperation{
			SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, SourceFunction: content.Function,
			Kind:             behavior.OperationFileRead,
			ResourceBindings: behavior.Bindings(behavior.Bind(behavior.ResourceRoleSource, resource)),
			Qualifiers: map[string]string{
				"api": "builtins.open.read", "api_identity": "unshadowed-builtin-and-exact-call-chain", "resource_binding": "exact-static",
			},
			EvidenceIDs: []string{evidenceID}, Support: behavior.SupportCorroborated,
			Execution: executionContextForContent(content), Line: lineNo,
		})
	}
}

func pythonExactReadMemberCall(line string, close int) bool {
	cursor := pythonSkipHorizontal(line, close+1)
	if cursor >= len(line) || line[cursor] != '.' {
		return false
	}
	cursor = pythonSkipHorizontal(line, cursor+1)
	if !strings.HasPrefix(line[cursor:], "read") {
		return false
	}
	end := cursor + len("read")
	if end < len(line) && pythonIdentifierByte(line[end]) {
		return false
	}
	open := pythonSkipHorizontal(line, end)
	_, _, exact, _ := exactPythonCallContent(line, open, maxPythonAPICallBytes)
	return exact
}

func lookupPythonAPISpec(api string) (pythonAPISpec, bool) {
	index := sort.Search(len(pythonAPISpecs), func(index int) bool { return pythonAPISpecs[index].api >= api })
	if index >= len(pythonAPISpecs) || pythonAPISpecs[index].api != api {
		return pythonAPISpec{}, false
	}
	return pythonAPISpecs[index], true
}

func pythonSourceAPICallObserved(line string, lineNo int, bindings *pythonStableAPIBindings, ordered pythonOrderedAPIBindingState) bool {
	if bindings != nil && bindings.builtinOpenSafe && pythonBuiltinOpenReadObserved(line) {
		return true
	}
	if _, ok, limited := parsePythonArchiveObjectInvocation(line, lineNo, bindings, ordered); ok || limited {
		return true
	}
	proofs := pythonEffectiveAPIBindings(bindings, ordered, lineNo)
	calls, limited := pythonQualifiedCalls(pythonCodeContext(line), maxPythonAPICallsPerLine+1)
	if limited || len(calls) > maxPythonAPICallsPerLine {
		return true
	}
	for _, call := range calls {
		components := strings.Split(call.value, ".")
		if len(components) < 2 {
			continue
		}
		canonical := call.value
		if bindings != nil {
			if proof, ok := proofs[components[0]]; ok {
				canonical = proof.canonical + "." + strings.Join(components[1:], ".")
			}
		}
		if _, ok := lookupPythonAPISpec(canonical); ok {
			return true
		}
	}
	return false
}

func pythonBuiltinOpenReadObserved(line string) bool {
	code := pythonCodeContext(line)
	for _, position := range pythonIdentifierPositions(code, "open") {
		if position > 0 && code[position-1] == '.' {
			continue
		}
		open := pythonSkipHorizontal(code, position+len("open"))
		_, close, exact, _ := exactPythonCallContent(line, open, maxPythonAPICallBytes)
		if exact && pythonExactReadMemberCall(line, close) {
			return true
		}
	}
	return false
}

func (bindings *pythonStableAPIBindings) stableSubprocessCallBinding(line string, lineNo int) (string, bool) {
	if bindings == nil {
		return "", false
	}
	calls, limited := pythonQualifiedCalls(pythonCodeContext(line), maxPythonAPICallsPerLine+1)
	if limited {
		return "", false
	}
	matched := ""
	for _, call := range calls {
		components := strings.Split(call.value, ".")
		if len(components) != 2 || !pythonSupportedSubprocessMethod(components[1]) {
			continue
		}
		proof, ok := bindings.bindings[components[0]]
		if !ok || proof.canonical != "subprocess" || proof.line >= lineNo {
			continue
		}
		if matched != "" && matched != components[0] {
			return "", false
		}
		matched = components[0]
	}
	return matched, matched != ""
}

func pythonSupportedSubprocessMethod(method string) bool {
	switch method {
	case "Popen", "call", "check_call", "check_output", "run":
		return true
	default:
		return false
	}
}

func canonicalizePythonSubprocessRoot(line, root string) string {
	if root == "" || root == "subprocess" {
		return line
	}
	calls, limited := pythonQualifiedCalls(pythonCodeContext(line), maxPythonAPICallsPerLine+1)
	if limited {
		return line
	}
	for _, call := range calls {
		components := strings.Split(call.value, ".")
		if len(components) != 2 || components[0] != root || !pythonSupportedSubprocessMethod(components[1]) {
			continue
		}
		return line[:call.byteOffset] + "subprocess" + line[call.byteOffset+len(root):]
	}
	return line
}

func pythonAPISpecHasArguments(spec pythonAPISpec, arguments []string) bool {
	positional, keywords, ok := pythonStableArgumentShape(arguments)
	if !ok || len(arguments) < spec.minArgs || len(arguments) > spec.maxArgs || len(positional) > spec.maxPositional {
		return false
	}
	parameterIndexes := make(map[string]int, len(spec.parameters))
	for index, parameter := range spec.parameters {
		parameterIndexes[parameter] = index
	}
	for name := range keywords {
		index, known := parameterIndexes[name]
		if !known || index < spec.positionalOnly || index < len(positional) {
			return false
		}
	}
	for index := 0; index < spec.minArgs; index++ {
		if index >= len(positional) && keywords[spec.parameters[index]] == "" {
			return false
		}
	}
	for _, resource := range spec.resources {
		if resource.index < 0 {
			continue
		}
		_, present := pythonResourceArgument(arguments, resource)
		if !present && resource.defaultValue == "" {
			return false
		}
	}
	return true
}

func pythonStableArgumentShape(arguments []string) ([]string, map[string]string, bool) {
	keywords := map[string]string{}
	positional := make([]string, 0, len(arguments))
	seenKeyword := false
	for _, argument := range arguments {
		trimmed := strings.TrimSpace(argument)
		if strings.HasPrefix(trimmed, "*") {
			return nil, nil, false
		}
		name, value, keyword := exactPythonKeywordArgument(trimmed)
		if keyword {
			if _, duplicate := keywords[name]; duplicate {
				return nil, nil, false
			}
			keywords[name] = value
			seenKeyword = true
			continue
		}
		if seenKeyword {
			return nil, nil, false
		}
		positional = append(positional, trimmed)
	}
	return positional, keywords, true
}

func pythonResourceArgument(arguments []string, resource pythonAPIResourceSpec) (string, bool) {
	positional, keywordValues, ok := pythonStableArgumentShape(arguments)
	if !ok {
		return "", false
	}
	if resource.index >= 0 && resource.index < len(positional) {
		if resource.parameter != "" {
			if _, duplicate := keywordValues[resource.parameter]; duplicate {
				return "", false
			}
		}
		return positional[resource.index], true
	}
	value, ok := keywordValues[resource.parameter]
	return value, ok
}

func exactPythonCallContent(line string, open, limit int) (string, int, bool, bool) {
	if open < 0 || open >= len(line) || line[open] != '(' || limit <= 0 {
		return "", 0, false, false
	}
	end := min(len(line), open+limit)
	stack := make([]byte, 0, 8)
	for index := open; index < end; {
		switch line[index] {
		case '#':
			return "", 0, false, false
		case '\'', '"':
			next, ok := skipPythonQuoted(line, index)
			if !ok || next > end {
				return "", 0, false, next > end
			}
			index = next
			continue
		case '(', '[', '{':
			if len(stack) >= maxPythonQualifiedCallComponents {
				return "", 0, false, true
			}
			stack = append(stack, line[index])
		case ')', ']', '}':
			if len(stack) == 0 || !pythonMatchingDelimiter(stack[len(stack)-1], line[index]) {
				return "", 0, false, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return line[open+1 : index], index, true, false
			}
		}
		index++
	}
	return "", 0, false, end < len(line)
}

func pythonMatchingDelimiter(open, close byte) bool {
	return open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}'
}
