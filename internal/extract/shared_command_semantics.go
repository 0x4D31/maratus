package extract

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/behavior"
)

func sharedShellCommandTool(tool string) bool {
	switch tool {
	case "system_profiler", "sw_vers", "uname", "hostinfo", "hostname", "sysctl", "ifconfig", "networksetup", "scutil", "whoami", "id", "users", "ps", "pgrep", "lsappinfo", "find", "mdfind", "rm", "unlink", "rmdir", "crontab", "defaults", "plutil", "PlistBuddy", "pbcopy", "SetFile", "chflags", "tccutil":
		return true
	default:
		return false
	}
}

var sharedMacOSCommandPaths = map[string]string{
	"/bin/ps":                   "ps",
	"/bin/rm":                   "rm",
	"/bin/rmdir":                "rmdir",
	"/bin/unlink":               "unlink",
	"/bin/chflags":              "chflags",
	"/usr/bin/crontab":          "crontab",
	"/usr/bin/defaults":         "defaults",
	"/usr/bin/find":             "find",
	"/usr/bin/hostinfo":         "hostinfo",
	"/bin/hostname":             "hostname",
	"/usr/bin/id":               "id",
	"/usr/bin/lsappinfo":        "lsappinfo",
	"/usr/bin/mdfind":           "mdfind",
	"/usr/bin/pbcopy":           "pbcopy",
	"/usr/bin/pgrep":            "pgrep",
	"/usr/bin/plutil":           "plutil",
	"/usr/bin/sw_vers":          "sw_vers",
	"/usr/bin/tccutil":          "tccutil",
	"/usr/bin/uname":            "uname",
	"/usr/bin/users":            "users",
	"/usr/bin/whoami":           "whoami",
	"/usr/libexec/PlistBuddy":   "PlistBuddy",
	"/usr/bin/SetFile":          "SetFile",
	"/usr/sbin/system_profiler": "system_profiler",
	"/usr/sbin/sysctl":          "sysctl",
	"/sbin/ifconfig":            "ifconfig",
	"/usr/sbin/networksetup":    "networksetup",
	"/usr/sbin/scutil":          "scutil",
}

func sharedMacOSCommandTool(token string) (string, bool) {
	if !strings.Contains(token, "/") {
		return token, sharedShellCommandTool(token)
	}
	tool, ok := sharedMacOSCommandPaths[token]
	return tool, ok
}

// handleSharedShellCommandSemantics is the command-adapter boundary for
// reusable macOS primitives. It models only closed argv forms; it does not
// infer that the command succeeded or that a PATH lookup selected a particular
// executable image.
func handleSharedShellCommandSemantics(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceID string) {
	handleSharedResolvedCommandSemantics(graph, content, fields, lineNo, execution, shellOperationEvidence(content, evidenceID), behavior.SupportCorroborated)
}

// handleSharedResolvedCommandSemantics is the format-neutral boundary for a
// statically resolved argv. Callers preserve their adapter-specific proof
// level: exact shell/Python/JavaScript argv may be CORROBORATED, while Rust
// remains HEURISTIC until compiler semantics are available.
func handleSharedResolvedCommandSemantics(graph *behavior.Graph, content artifact.Content, fields []string, lineNo int, execution behavior.ExecutionContext, evidenceIDs []string, support behavior.Support) {
	if len(fields) == 0 {
		return
	}
	tool, ok := sharedMacOSCommandTool(fields[0])
	if !ok {
		return
	}
	switch tool {
	case "system_profiler":
		system, software, ok := systemProfilerQueries(fields[1:])
		if !ok {
			return
		}
		if system {
			addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
		if software {
			addSharedCommandOperation(graph, content, behavior.OperationSoftwareEnumerate, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSoftware, "installed applications"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "sw_vers":
		if !validSWVersArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "uname":
		if !validUnameArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "hostinfo":
		if len(fields) != 1 {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "hostname":
		if !validHostnameArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "local host identity"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "sysctl":
		if sysctlSystemInformationQuery(fields[1:]) {
			addSharedCommandOperation(graph, content, behavior.OperationSystemInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSystem, "macOS system and hardware"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "ifconfig", "networksetup", "scutil":
		if networkConfigurationQuery(tool, fields[1:]) {
			addSharedCommandOperation(graph, content, behavior.OperationNetworkConfigurationQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceConfiguration, "local network configuration"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "whoami", "users":
		if len(fields) != 1 {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceUserAccount, "local users"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "id":
		if !validIDArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationUserInfoQuery, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceUserAccount, "local users"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "ps":
		if !validPSArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationProcessEnumerate, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceProcess, "local processes"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "pgrep":
		if !validPgrepArguments(fields[1:]) {
			return
		}
		addSharedCommandOperation(graph, content, behavior.OperationProcessEnumerate, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceProcess, "local processes"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
	case "lsappinfo":
		if len(fields) > 1 && fields[1] == "list" {
			addSharedCommandOperation(graph, content, behavior.OperationSoftwareEnumerate, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceSoftware, "running applications"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "find", "mdfind":
		if source, ok := enumerationSource(tool, fields[1:]); ok {
			addSharedCommandOperation(graph, content, behavior.OperationFileEnumerate, behavior.ResourceRoleSource, behavior.NewResource(behavior.ResourceFile, source), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "rm", "unlink", "rmdir":
		targets, capped, ok := deletionTargets(tool, fields[1:])
		if !ok {
			return
		}
		if capped {
			addPartialCoverageOnce(graph, content.NodeID, "shared-command-semantics", fmt.Sprintf("%s target recognition capped at %d exact operands", tool, behavior.MaxOperationResourceBindings))
		}
		for _, target := range targets {
			addSharedCommandOperation(graph, content, behavior.OperationFileDelete, behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, target), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "pbcopy":
		if len(fields) == 1 {
			addSharedCommandOperation(graph, content, behavior.OperationClipboardWrite, behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceClipboard, "pbcopy"), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "SetFile", "chflags":
		if target, ok := hiddenFileTarget(tool, fields[1:]); ok {
			addSharedCommandOperation(graph, content, behavior.OperationFileVisibilityModify, behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceFile, target), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool, "attribute": "hidden"})
		}
	case "crontab":
		if job, ok := cronRegistrationTarget(fields[1:]); ok {
			addSharedCommandOperation(graph, content, behavior.OperationScheduledJobRegister, behavior.ResourceRoleJob, behavior.NewResource(behavior.ResourceScheduledJob, job, behavior.ResourceClassCronJob), lineNo, execution, evidenceIDs, support, map[string]string{"tool": tool})
		}
	case "defaults", "plutil", "PlistBuddy":
		if target, key, ok := plistModificationTarget(tool, fields); ok {
			qualifiers := map[string]string{"tool": tool}
			if key != "" {
				qualifiers["key"] = key
			}
			if dyldConfigurationKey(key) {
				qualifiers["dynamic_loader_configuration"] = "true"
			}
			addSharedCommandOperation(graph, content, behavior.OperationPlistModify, behavior.ResourceRoleTarget, target, lineNo, execution, evidenceIDs, support, qualifiers)
		}
	case "tccutil":
		if service, bundleID, ok := privacyAuthorizationResetTarget(fields); ok {
			qualifiers := map[string]string{"tool": tool, "service": service}
			if bundleID != "" {
				qualifiers["bundle_identifier"] = bundleID
			}
			addSharedCommandOperation(graph, content, behavior.OperationPrivacyAuthorizationReset, behavior.ResourceRoleTarget, behavior.NewResource(behavior.ResourceConfiguration, service), lineNo, execution, evidenceIDs, support, qualifiers)
		}
	}
}

func validHostnameArguments(args []string) bool {
	if len(args) == 0 {
		return true
	}
	return len(args) == 1 && (args[0] == "-s" || args[0] == "-f")
}

func networkConfigurationQuery(tool string, args []string) bool {
	switch tool {
	case "ifconfig":
		if len(args) == 0 {
			return true
		}
		if len(args) != 1 {
			return false
		}
		argument := args[0]
		if argument == "-a" || argument == "-l" || argument == "-u" || argument == "-d" {
			return true
		}
		return networkInterfaceName(argument)
	case "scutil":
		return len(args) == 1 && (args[0] == "--dns" || args[0] == "--proxy" || args[0] == "--nwi")
	case "networksetup":
		if len(args) == 1 {
			switch args[0] {
			case "-listallhardwareports", "-listallnetworkservices", "-listnetworkserviceorder":
				return true
			}
		}
		if len(args) != 2 || args[1] == "" || strings.HasPrefix(args[1], "-") {
			return false
		}
		switch args[0] {
		case "-getinfo", "-getdnsservers", "-getsearchdomains", "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy", "-getautoproxyurl", "-getairportnetwork":
			return true
		}
	}
	return false
}

func networkInterfaceName(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func privacyAuthorizationResetTarget(fields []string) (service, bundleID string, ok bool) {
	if (len(fields) != 3 && len(fields) != 4) || fields[1] != "reset" {
		return "", "", false
	}
	service = staticShellResource(fields[2])
	if service == "" || strings.HasPrefix(service, "-") || strings.Contains(service, "/") {
		return "", "", false
	}
	if len(fields) == 4 {
		bundleID = staticShellResource(fields[3])
		if bundleID == "" || strings.HasPrefix(bundleID, "-") || strings.Contains(bundleID, "/") {
			return "", "", false
		}
	}
	return service, bundleID, true
}

func hiddenFileTarget(tool string, args []string) (string, bool) {
	var target string
	switch tool {
	case "SetFile":
		if len(args) != 3 || args[0] != "-a" || args[1] != "V" {
			return "", false
		}
		target = staticShellResource(args[2])
	case "chflags":
		if len(args) != 2 || args[0] != "hidden" {
			return "", false
		}
		target = staticShellResource(args[1])
	default:
		return "", false
	}
	return target, target != ""
}

func addSharedCommandOperation(graph *behavior.Graph, content artifact.Content, kind behavior.OperationKind, role behavior.ResourceRole, resource behavior.Resource, lineNo int, execution behavior.ExecutionContext, evidenceIDs []string, support behavior.Support, qualifiers map[string]string) {
	if resource.Kind == behavior.ResourceFile && len(resource.Classifications) == 0 && resource.Value != "" {
		resource = classifiedFileResource(resource.Value)
	}
	graph.AddOperation(behavior.ModeledOperation{
		SubjectNodeID: content.NodeID, ScopeID: content.ScopeID, SourceFunction: content.Function, Kind: kind,
		ResourceBindings: behavior.Bindings(behavior.Bind(role, resource)),
		Qualifiers:       qualifiers, EvidenceIDs: append([]string(nil), evidenceIDs...),
		Support: support, Execution: execution,
		Architecture: content.Architecture, Line: lineNo,
	})
}

func sysctlSystemInformationQuery(args []string) bool {
	if len(args) == 0 {
		return false
	}
	query := false
	for _, arg := range args {
		if arg == "-a" || arg == "-A" {
			query = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if len(arg) < 2 || strings.HasPrefix(arg, "--") {
				return false
			}
			for _, flag := range arg[1:] {
				if !strings.ContainsRune("bdehiNnoqx", flag) {
					return false
				}
			}
			continue
		}
		if strings.Contains(arg, "=") {
			return false
		}
		if strings.HasPrefix(arg, "kern.") || strings.HasPrefix(arg, "hw.") || strings.HasPrefix(arg, "machdep.cpu.") {
			query = true
			continue
		}
		return false
	}
	return query
}

func systemProfilerQueries(args []string) (system, software, ok bool) {
	if len(args) == 0 {
		return true, false, true
	}
	dataType := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch argument {
		case "-usage", "-listDataTypes":
			return false, false, false
		case "-xml", "-json":
			continue
		case "-detailLevel":
			if index+1 >= len(args) {
				return false, false, false
			}
			index++
			switch args[index] {
			case "mini", "basic", "full":
			default:
				return false, false, false
			}
		case "-timeout":
			if index+1 >= len(args) {
				return false, false, false
			}
			index++
			seconds, err := strconv.Atoi(args[index])
			if err != nil || seconds < 0 {
				return false, false, false
			}
		default:
			if !validSystemProfilerDataType(argument) {
				return false, false, false
			}
			dataType = true
			if argument == "SPApplicationsDataType" {
				software = true
			} else {
				system = true
			}
		}
	}
	if !dataType {
		system = true
	}
	return system, software, true
}

func validSWVersArguments(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "-productName", "--productName", "-productVersion", "--productVersion", "-productVersionExtra", "--productVersionExtra", "-buildVersion", "--buildVersion":
		default:
			return false
		}
	}
	return true
}

func validUnameArguments(args []string) bool {
	for _, argument := range args {
		if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
			return false
		}
		for _, flag := range argument[1:] {
			if !strings.ContainsRune("amnoprsv", flag) {
				return false
			}
		}
	}
	return true
}

func validIDArguments(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if !strings.HasPrefix(args[0], "-") {
		return len(args) == 1 && args[0] != ""
	}
	if strings.HasPrefix(args[0], "--") {
		return false
	}
	first := args[0]
	switch first {
	case "-A":
		return len(args) == 1
	case "-F", "-P", "-p":
		return optionalIDUser(args[1:])
	case "-G", "-Gn":
		rest := args[1:]
		if first == "-G" && len(rest) > 0 && rest[0] == "-n" {
			rest = rest[1:]
		}
		return optionalIDUser(rest)
	default:
		if first != "-g" && first != "-u" && !validIDPrimaryCombination(first) {
			return false
		}
		rest := args[1:]
		if (first == "-g" || first == "-u") && len(rest) > 0 && (rest[0] == "-n" || rest[0] == "-r" || rest[0] == "-nr" || rest[0] == "-rn") {
			rest = rest[1:]
		}
		return optionalIDUser(rest)
	}
}

func validSystemProfilerDataType(value string) bool {
	if !strings.HasPrefix(value, "SP") || !strings.HasSuffix(value, "DataType") || len(value) <= len("SPDataType") {
		return false
	}
	for _, character := range value[2 : len(value)-len("DataType")] {
		letter := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit {
			return false
		}
	}
	return true
}

func optionalIDUser(args []string) bool {
	return len(args) == 0 || len(args) == 1 && args[0] != "" && !strings.HasPrefix(args[0], "-")
}

func validIDPrimaryCombination(value string) bool {
	if len(value) < 2 || value[0] != '-' || value[1] != 'g' && value[1] != 'u' {
		return false
	}
	seen := map[rune]bool{}
	for _, flag := range value[2:] {
		if flag != 'n' && flag != 'r' || seen[flag] {
			return false
		}
		seen[flag] = true
	}
	return true
}

func validPgrepArguments(args []string) bool {
	if len(args) == 0 {
		return false
	}
	options := true
	patterns := 0
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if options && argument == "--" {
			return false
		}
		if options && strings.HasPrefix(argument, "-") {
			if strings.HasPrefix(argument, "--") || len(argument) < 2 {
				return false
			}
			flags := argument[1:]
			for position, flag := range flags {
				if !strings.ContainsRune("LfilnoqvxdFGPUgstu", flag) {
					return false
				}
				if strings.ContainsRune("dFGPUgstu", flag) {
					// An option that consumes a value must be the final flag in
					// its group; its value is either attached or the next argv.
					if position+1 < len(flags) {
						break
					}
					if index+1 >= len(args) {
						return false
					}
					index++
					break
				}
			}
			continue
		}
		patterns++
	}
	return patterns > 0
}

func validPSArguments(args []string) bool {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "" || strings.HasPrefix(argument, "--") {
			return false
		}
		if argument[0] != '-' {
			// Preserve the common BSD form (for example, `ps aux`) without
			// accepting an arbitrary operand as a process query.
			for _, flag := range argument {
				if !strings.ContainsRune("acEefhjlMmrSTuvwx", flag) {
					return false
				}
			}
			continue
		}
		if len(argument) == 1 {
			return false
		}
		flags := argument[1:]
		for position, flag := range flags {
			if strings.ContainsRune("OGgoptUu", flag) {
				if position+1 < len(flags) {
					if position != 0 {
						return false
					}
					// The suffix is the option's attached value.
					break
				}
				if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
					return false
				}
				index++
				break
			}
			if !strings.ContainsRune("AaCcEefhjlMmrSTuvwx", flag) {
				return false
			}
		}
	}
	return true
}

func enumerationSource(tool string, args []string) (string, bool) {
	switch tool {
	case "find":
		return findEnumerationSource(args)
	case "mdfind":
		if validMDFindArguments(args) {
			return "metadata search", true
		}
	}
	return "", false
}

func findEnumerationSource(args []string) (string, bool) {
	var explicit string
	index := 0
	for index < len(args) {
		argument := args[index]
		if argument == "-f" {
			if index+1 >= len(args) || staticShellResource(args[index+1]) == "" {
				return "", false
			}
			if explicit == "" {
				explicit = staticShellResource(args[index+1])
			}
			index += 2
			continue
		}
		if supportedFindLeadingOption(argument) {
			index++
			continue
		}
		break
	}
	if index < len(args) && !strings.HasPrefix(args[index], "-") && args[index] != "!" && args[index] != "(" && args[index] != ")" {
		if source := staticShellResource(args[index]); source != "" {
			return source, true
		}
	}
	return explicit, explicit != ""
}

func supportedFindLeadingOption(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false
	}
	if argument == "-H" || argument == "-L" || argument == "-P" {
		return true
	}
	for _, flag := range argument[1:] {
		if !strings.ContainsRune("EXdsx", flag) {
			return false
		}
	}
	return true
}

func validMDFindArguments(args []string) bool {
	if len(args) == 0 {
		return false
	}
	query := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			query = true
			continue
		}
		switch argument {
		case "-0", "-live", "-count", "-literal", "-interpret", "-reprint":
			continue
		case "-onlyin", "-attr":
			if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
				return false
			}
			index++
		case "-name", "-s":
			if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
				return false
			}
			index++
			query = true
		default:
			return false
		}
	}
	return query
}

func deletionTargets(tool string, args []string) ([]string, bool, bool) {
	out := make([]string, 0, min(len(args), behavior.MaxOperationResourceBindings))
	options := true
	capped := false
	for _, arg := range args {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if !supportedDeletionOption(tool, arg) {
				return nil, false, false
			}
			continue
		}
		if value := staticShellResource(arg); value != "" {
			out = append(out, value)
			if len(out) > behavior.MaxOperationResourceBindings {
				out = out[:behavior.MaxOperationResourceBindings]
				capped = true
				break
			}
		} else {
			return nil, false, false
		}
	}
	if tool == "unlink" && len(out) != 1 {
		return nil, false, false
	}
	return out, capped, len(out) > 0
}

func supportedDeletionOption(tool, option string) bool {
	if len(option) < 2 || option[0] != '-' || strings.HasPrefix(option, "--") {
		return false
	}
	allowed := ""
	switch tool {
	case "rm":
		allowed = "fidIPRrvWx"
	case "rmdir":
		allowed = "pv"
	case "unlink":
		return false
	default:
		return false
	}
	for _, flag := range option[1:] {
		if !strings.ContainsRune(allowed, flag) {
			return false
		}
	}
	return true
}

func cronRegistrationTarget(args []string) (string, bool) {
	index := 0
	if len(args) >= 2 && args[0] == "-u" {
		if args[1] == "" || strings.HasPrefix(args[1], "-") {
			return "", false
		}
		index = 2
	}
	if len(args)-index != 1 {
		return "", false
	}
	operand := args[index]
	if operand == "-e" || operand == "-l" || operand == "-r" || strings.HasPrefix(operand, "-") && operand != "-" {
		return "", false
	}
	if operand == "-" {
		return "standard input", true
	}
	if target := staticShellResource(operand); target != "" {
		return target, true
	}
	return "", false
}

func plistModificationTarget(tool string, fields []string) (behavior.Resource, string, bool) {
	switch tool {
	case "defaults":
		// Support only the keyed form. The four-field whole-domain form uses
		// the legacy defaults representation grammar and cannot be
		// distinguished safely from a keyed write missing its value.
		if len(fields) < 5 || fields[1] != "write" || strings.HasPrefix(fields[2], "-") || strings.HasPrefix(fields[3], "-") || !validDefaultsValue(fields[4:]) {
			return behavior.Resource{}, "", false
		}
		domain, key := fields[2], fields[3]
		if strings.Contains(domain, "/") || strings.HasSuffix(strings.ToLower(domain), ".plist") {
			target := staticShellResource(domain)
			if target != "" && !strings.HasSuffix(target, ".plist") {
				target += ".plist"
			}
			return behavior.NewResource(behavior.ResourceFile, target, behavior.ResourceClassPropertyList), key, true
		}
		return behavior.NewResource(behavior.ResourceConfiguration, domain, behavior.ResourceClassPropertyList), key, true
	case "plutil":
		arguments := append([]string(nil), fields[1:]...)
		if len(arguments) > 0 && arguments[0] == "-s" {
			arguments = arguments[1:]
		}
		if len(arguments) < 3 || arguments[0] != "-replace" && arguments[0] != "-insert" && arguments[0] != "-remove" {
			return behavior.Resource{}, "", false
		}
		verb, key := arguments[0], arguments[1]
		if key == "" || strings.HasPrefix(key, "-") {
			return behavior.Resource{}, "", false
		}
		arguments = arguments[2:]
		if len(arguments) >= 2 && arguments[len(arguments)-2] == "-s" {
			arguments = append(arguments[:len(arguments)-2], arguments[len(arguments)-1])
		}
		if verb == "-remove" {
			if len(arguments) != 1 {
				return behavior.Resource{}, "", false
			}
		} else if !validPlutilInsertion(arguments) {
			return behavior.Resource{}, "", false
		}
		target := staticShellResource(arguments[len(arguments)-1])
		if target == "" || strings.HasPrefix(target, "-") {
			return behavior.Resource{}, "", false
		}
		return behavior.NewResource(behavior.ResourceFile, target, behavior.ResourceClassPropertyList), key, true
	case "PlistBuddy":
		if len(fields) != 4 || fields[1] != "-c" || strings.ContainsAny(fields[2], ";\r\n") {
			return behavior.Resource{}, "", false
		}
		command := strings.Fields(fields[2])
		if !validPlistBuddyMutation(command) {
			return behavior.Resource{}, "", false
		}
		target := staticShellResource(fields[len(fields)-1])
		if target == "" || strings.HasPrefix(target, "-") {
			return behavior.Resource{}, "", false
		}
		return behavior.NewResource(behavior.ResourceFile, target, behavior.ResourceClassPropertyList), strings.TrimPrefix(command[1], ":"), true
	default:
		return behavior.Resource{}, "", false
	}
}

func validDefaultsValue(fields []string) bool {
	if len(fields) == 0 || fields[0] == "" {
		return false
	}
	if !strings.HasPrefix(fields[0], "-") {
		return len(fields) == 1
	}
	switch fields[0] {
	case "-string", "-data", "-int", "-integer", "-float", "-date":
		return len(fields) == 2 && fields[1] != ""
	case "-bool", "-boolean":
		if len(fields) != 2 {
			return false
		}
		switch strings.ToLower(fields[1]) {
		case "true", "false", "yes", "no":
			return true
		default:
			return false
		}
	case "-array", "-array-add":
		return len(fields) >= 2
	case "-dict", "-dict-add":
		return len(fields) >= 3 && (len(fields)-1)%2 == 0
	default:
		return false
	}
}

func validPlutilInsertion(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	typeFlag := fields[0]
	switch typeFlag {
	case "-dictionary", "-array":
		return len(fields) == 2 && fields[1] != "" && !strings.HasPrefix(fields[1], "-")
	case "-bool", "-integer", "-float", "-date", "-string", "-data", "-xml", "-json":
		return len(fields) == 3 && fields[1] != "" && fields[2] != "" && !strings.HasPrefix(fields[2], "-")
	default:
		return false
	}
}

func validPlistBuddyMutation(command []string) bool {
	if len(command) < 2 || command[1] == "" || !strings.HasPrefix(command[1], ":") {
		return false
	}
	switch command[0] {
	case "Set":
		return len(command) >= 3
	case "Add":
		if len(command) < 3 {
			return false
		}
		switch command[2] {
		case "array", "dict":
			return len(command) == 3
		case "string", "bool", "real", "integer", "date", "data":
			return len(command) >= 4
		default:
			return false
		}
	case "Delete":
		return len(command) == 2
	default:
		return false
	}
}

func dyldConfigurationKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	for _, component := range strings.FieldsFunc(upper, func(character rune) bool {
		return character == '.' || character == ':' || character == '/'
	}) {
		switch component {
		case "LSENVIRONMENT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH":
			return true
		}
	}
	return false
}
