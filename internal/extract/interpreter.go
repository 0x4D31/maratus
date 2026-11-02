package extract

import (
	"path/filepath"
	"strings"

	"github.com/0x4D31/maratus/internal/osacli"
)

// MaxInterpreterScriptTargets bounds static target enumeration for Node
// commands with an attacker-controlled number of preload/loader flags.
const MaxInterpreterScriptTargets = 256

// maxInterpreterArgumentTokens bounds option-prefix parsing. Arguments after a
// proven program operand are not parsed because they belong to that program.
const maxInterpreterArgumentTokens = 1024

type interpreterParseDisposition uint8

const (
	interpreterParseRecognized interpreterParseDisposition = iota
	interpreterParseUnsupported
	interpreterParseMalformed
	interpreterParseLimited
)

// interpreterParseResult is the single argv interpretation used by artifact
// target discovery and interpreter.invoke local_input emission. targets are
// ordered by runtime loading: Node preload/loader inputs precede its program.
type interpreterParseResult struct {
	disposition     interpreterParseDisposition
	targets         *orderedTargetSet
	suppressProgram bool
	inlineCode      string
	inlineSelected  bool
}

func newInterpreterParseResult() interpreterParseResult {
	return interpreterParseResult{
		disposition: interpreterParseRecognized,
		targets:     newOrderedTargetSet(MaxInterpreterScriptTargets),
	}
}

func (result *interpreterParseResult) addTarget(value string) bool {
	result.targets.add(value)
	if result.targets.limited {
		result.disposition = interpreterParseLimited
		return false
	}
	return true
}

func (result *interpreterParseResult) addProgramTarget(value string) bool {
	if result.suppressProgram {
		return true
	}
	return result.addTarget(value)
}

func (result interpreterParseResult) executableTargets() []string {
	return result.targets.values
}

func unsupportedInterpreterParse() interpreterParseResult {
	result := newInterpreterParseResult()
	result.disposition = interpreterParseUnsupported
	return result
}

func malformedInterpreterParse() interpreterParseResult {
	result := newInterpreterParseResult()
	result.disposition = interpreterParseMalformed
	return result
}

func limitedInterpreterParse(result interpreterParseResult) interpreterParseResult {
	result.disposition = interpreterParseLimited
	return result
}

// InterpreterScriptTargets returns statically explicit script/module-file
// targets from common interpreter argv forms. It intentionally ignores inline
// eval, stdin, validation-only, and runtime module modes. A bounded parse that
// cannot inspect the complete option prefix yields no targets.
func InterpreterScriptTargets(exe string, args []string) []string {
	targets, limited := InterpreterScriptTargetsLimited(exe, args)
	if limited {
		return nil
	}
	return targets
}

// InterpreterScriptTargetsLimited also reports whether additional explicit
// targets were omitted at the hard enumeration or argv parsing limit.
func InterpreterScriptTargetsLimited(exe string, args []string) ([]string, bool) {
	result := parseInterpreterArguments(exe, args)
	switch result.disposition {
	case interpreterParseRecognized:
		return result.executableTargets(), false
	case interpreterParseLimited:
		return result.executableTargets(), true
	default:
		return nil, false
	}
}

func parseInterpreterArguments(exe string, args []string) interpreterParseResult {
	switch exe {
	case "python", "python3":
		return parsePythonArguments(args)
	case "node":
		return parseNodeArguments(args)
	case "deno":
		return parseDenoArguments(args)
	case "bash", "sh", "zsh":
		return parseShellArguments(exe, args)
	case "osascript":
		return parseOSAScriptArguments(args)
	default:
		return newInterpreterParseResult()
	}
}

func parsePythonArguments(args []string) interpreterParseResult {
	result := newInterpreterParseResult()
	for index := 0; index < len(args); index++ {
		if index >= maxInterpreterArgumentTokens {
			return limitedInterpreterParse(result)
		}
		arg := args[index]
		switch {
		case arg == "--":
			if index+1 < len(args) && args[index+1] != "-" {
				result.addProgramTarget(args[index+1])
			}
			return result
		case arg == "-":
			return result
		case arg == "-c" || arg == "-m":
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			if arg == "-c" {
				result.inlineCode = args[index+1]
			}
			return result
		case strings.HasPrefix(arg, "-c") && len(arg) > 2,
			strings.HasPrefix(arg, "-m") && len(arg) > 2:
			if strings.HasPrefix(arg, "-c") {
				result.inlineCode = arg[2:]
			}
			return result
		case arg == "-W" || arg == "-X" || arg == "--check-hash-based-pycs":
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			index++
		case strings.HasPrefix(arg, "-W") && len(arg) > 2,
			strings.HasPrefix(arg, "-X") && len(arg) > 2,
			strings.HasPrefix(arg, "--check-hash-based-pycs="):
			continue
		case pythonStopsWithoutFile(arg):
			result.suppressProgram = true
			return result
		case knownPythonFlag(arg):
			continue
		case strings.HasPrefix(arg, "-"):
			return unsupportedInterpreterParse()
		default:
			result.addProgramTarget(arg)
			return result
		}
	}
	return result
}

func knownPythonFlag(arg string) bool {
	switch arg {
	case "-b", "-B", "-d", "-E", "-i", "-I", "-O", "-OO", "-P", "-q", "-R",
		"-s", "-S", "-u", "-v":
		return true
	default:
		return false
	}
}

func pythonStopsWithoutFile(arg string) bool {
	switch arg {
	case "-h", "-V", "--help", "--help-all", "--help-env", "--help-xoptions", "--version":
		return true
	default:
		return false
	}
}

func parseNodeArguments(args []string) interpreterParseResult {
	result := newInterpreterParseResult()
	checkSelected := false
	for index := 0; index < len(args); index++ {
		if index >= maxInterpreterArgumentTokens {
			return limitedInterpreterParse(result)
		}
		arg := args[index]
		switch {
		case arg == "--":
			if !result.inlineSelected && index+1 < len(args) && args[index+1] != "-" {
				result.addProgramTarget(args[index+1])
			}
			return result
		case arg == "-":
			return result
		case arg == "-e" || arg == "--eval" || arg == "-p" || arg == "--print":
			if checkSelected || index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			result.inlineCode = args[index+1]
			result.inlineSelected = true
			index++
			continue
		case strings.HasPrefix(arg, "-e") && len(arg) > 2,
			strings.HasPrefix(arg, "-p") && len(arg) > 2,
			strings.HasPrefix(arg, "--eval="),
			strings.HasPrefix(arg, "--print="):
			if checkSelected {
				return malformedInterpreterParse()
			}
			if strings.HasPrefix(arg, "--") {
				result.inlineCode = strings.SplitN(arg, "=", 2)[1]
			} else {
				result.inlineCode = arg[2:]
			}
			result.inlineSelected = true
			continue
		case arg == "-v" || arg == "--version":
			// Node exits before loading preloads when printing its version.
			return newInterpreterParseResult()
		case arg == "-h" || arg == "--help":
			result.suppressProgram = true
			// Help, unlike version, still loads --require modules. Continue
			// parsing because preloads may occur on either side of --help.
		case arg == "-c" || arg == "--check":
			if result.inlineSelected {
				return malformedInterpreterParse()
			}
			checkSelected = true
			result.suppressProgram = true
		case strings.HasPrefix(arg, "-r") && len(arg) > 2:
			if !addNodePreloadTarget(&result, arg[2:]) {
				return result
			}
		case nodePreloadFlagWithValue(arg):
			value := strings.SplitN(arg, "=", 2)[1]
			if value == "" {
				return malformedInterpreterParse()
			}
			if !addNodePreloadTarget(&result, value) {
				return result
			}
		case nodePreloadFlagNeedsValue(arg):
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			if !addNodePreloadTarget(&result, args[index+1]) {
				return result
			}
			index++
		case nodeFlagNeedsValue(arg):
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			index++
		case nodeFlagWithValue(arg):
			continue
		case knownNodeFlag(arg):
			continue
		case strings.HasPrefix(arg, "-"):
			return unsupportedInterpreterParse()
		default:
			if result.inlineSelected {
				return result
			}
			result.addProgramTarget(arg)
			return result
		}
	}
	return result
}

func addNodePreloadTarget(result *interpreterParseResult, value string) bool {
	if !nodePreloadTargetLooksLocal(value) {
		return true
	}
	return result.addTarget(value)
}

func nodePreloadTargetLooksLocal(value string) bool {
	if value == "" || strings.Contains(value, "://") || strings.HasPrefix(value, "@") {
		return false
	}
	for _, prefix := range []string{"node:", "npm:", "jsr:", "data:"} {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return true
	}
	// A suffix does not turn a bare module specifier into a relative path:
	// both "preload.js" and "scripts/preload.js" use package resolution.
	return false
}

func nodePreloadFlagWithValue(arg string) bool {
	for _, prefix := range []string{
		"--require=",
		"--import=",
		"--loader=",
		"--experimental-loader=",
	} {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

func nodePreloadFlagNeedsValue(arg string) bool {
	return arg == "-r" || arg == "--require" || arg == "--import" ||
		arg == "--loader" || arg == "--experimental-loader"
}

func nodeFlagNeedsValue(arg string) bool {
	switch arg {
	case "--input-type", "--conditions", "-C", "--inspect-port", "--title", "--icu-data-dir",
		"--openssl-config", "--experimental-policy":
		return true
	default:
		return false
	}
}

func nodeFlagWithValue(arg string) bool {
	if !strings.Contains(arg, "=") {
		return false
	}
	return nodeFlagNeedsValue(strings.SplitN(arg, "=", 2)[0])
}

func knownNodeFlag(arg string) bool {
	switch arg {
	case "--enable-source-maps", "--no-deprecation", "--no-warnings", "--preserve-symlinks",
		"--preserve-symlinks-main", "--trace-deprecation", "--trace-warnings",
		"--use-bundled-ca", "--use-openssl-ca":
		return true
	default:
		return false
	}
}

func parseDenoArguments(args []string) interpreterParseResult {
	result := newInterpreterParseResult()
	index := 0
	explicitRun := false
	for index < len(args) {
		if index >= maxInterpreterArgumentTokens {
			return limitedInterpreterParse(result)
		}
		arg := args[index]
		switch {
		case arg == "run":
			explicitRun = true
			index++
			goto program
		case arg == "--":
			index++
			goto directProgram
		case arg == "-h" || arg == "--help" || arg == "-V" || arg == "--version":
			result.suppressProgram = true
			return result
		case malformedDenoRunFlag(arg):
			return malformedInterpreterParse()
		case denoRunFlagNeedsValue(arg):
			if index+1 >= len(args) || !denoSeparateFlagValue(args[index+1]) {
				return malformedInterpreterParse()
			}
			index += 2
		case denoRunFlagWithValue(arg), denoRunOptionalValueFlag(arg), knownDenoRunFlag(arg):
			index++
		case strings.HasPrefix(arg, "-"):
			return unsupportedInterpreterParse()
		case denoDirectTargetLooksLocal(arg):
			result.addProgramTarget(arg)
			return result
		case knownDenoNonExecutingSubcommand(arg):
			return result
		default:
			return unsupportedInterpreterParse()
		}
	}

program:
	for ; index < len(args); index++ {
		if index >= maxInterpreterArgumentTokens {
			return limitedInterpreterParse(result)
		}
		arg := args[index]
		switch {
		case arg == "--":
			if index+1 < len(args) && args[index+1] != "-" {
				result.addProgramTarget(args[index+1])
			}
			return result
		case arg == "-":
			return result
		case malformedDenoRunFlag(arg):
			return malformedInterpreterParse()
		case denoRunFlagNeedsValue(arg):
			if index+1 >= len(args) || !denoSeparateFlagValue(args[index+1]) {
				return malformedInterpreterParse()
			}
			index++
		case denoRunFlagWithValue(arg), denoRunOptionalValueFlag(arg), knownDenoRunFlag(arg):
			continue
		case strings.HasPrefix(arg, "-"):
			return unsupportedInterpreterParse()
		default:
			result.addProgramTarget(arg)
			return result
		}
	}
	if explicitRun {
		return malformedInterpreterParse()
	}
	return result

directProgram:
	if index < len(args) && args[index] != "-" {
		if !denoDirectTargetLooksLocal(args[index]) {
			return unsupportedInterpreterParse()
		}
		result.addProgramTarget(args[index])
	}
	return result
}

func denoRunFlagNeedsValue(arg string) bool {
	switch arg {
	case "--config", "-c", "--import-map", "--cert", "--conditions", "--ext",
		"--location", "--minimum-dependency-age", "--node-modules-linker", "--seed",
		"--unsafely-ignore-certificate-errors":
		return true
	default:
		return false
	}
}

func denoRunFlagWithValue(arg string) bool {
	if !strings.Contains(arg, "=") {
		return false
	}
	parts := strings.SplitN(arg, "=", 2)
	return parts[1] != "" && denoRunFlagNeedsValue(parts[0])
}

func denoRunOptionalValueFlag(arg string) bool {
	parts := strings.SplitN(arg, "=", 2)
	name := parts[0]
	switch name {
	case "--allow-scripts", "--check", "--coverage", "--env-file", "--inspect",
		"--inspect-brk", "--inspect-wait", "--lock", "--node-modules-dir",
		"--no-check", "--reload", "-r", "--tunnel", "-t",
		"--v8-flags", "--vendor", "--watch", "--watch-exclude", "--watch-hmr":
		return len(parts) == 1 || parts[1] != ""
	default:
		return false
	}
}

func knownDenoRunFlag(arg string) bool {
	parts := strings.SplitN(arg, "=", 2)
	name := parts[0]
	switch name {
	case "--allow-all", "-A", "--allow-env", "--allow-ffi", "--allow-hrtime",
		"--allow-import", "--allow-net", "--allow-read", "--allow-run", "--allow-sys",
		"--allow-write", "--cached-only", "--frozen", "--no-code-cache", "--no-config",
		"--no-lock", "--no-npm", "--no-prompt", "--no-remote", "--quiet", "-q",
		"--unstable", "--use-env-proxy":
		if len(parts) == 1 {
			return true
		}
		return parts[1] != "" && denoPermissionListFlag(name)
	default:
		return false
	}
}

func denoPermissionListFlag(name string) bool {
	switch name {
	case "--allow-env", "--allow-ffi", "--allow-import", "--allow-net",
		"--allow-read", "--allow-run", "--allow-sys", "--allow-write":
		return true
	default:
		return false
	}
}

func malformedDenoRunFlag(arg string) bool {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return false
	}
	name := parts[0]
	if denoRunFlagNeedsValue(name) || denoRunOptionalValueFlag(name) {
		return parts[1] == ""
	}
	if knownDenoRunFlag(name) {
		return !denoPermissionListFlag(name) || parts[1] == ""
	}
	return false
}

func denoSeparateFlagValue(value string) bool {
	return value != "" && value != "--" && !strings.HasPrefix(value, "-")
}

func denoDirectTargetLooksLocal(value string) bool {
	if nodePreloadTargetLooksLocal(value) {
		return true
	}
	switch strings.ToLower(filepath.Ext(value)) {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".node", ".cts", ".mts", ".wasm":
		return true
	default:
		return false
	}
}

func knownDenoNonExecutingSubcommand(value string) bool {
	switch value {
	case "add", "check", "completions", "coverage", "doc", "fmt", "help",
		"info", "init", "lint", "outdated", "remove", "types", "uninstall",
		"upgrade", "why":
		return true
	default:
		return false
	}
}

func parseShellArguments(tool string, args []string) interpreterParseResult {
	result := newInterpreterParseResult()
	for index := 0; index < len(args); index++ {
		if index >= maxInterpreterArgumentTokens {
			return limitedInterpreterParse(result)
		}
		arg := args[index]
		switch {
		case arg == "--":
			if index+1 < len(args) && args[index+1] != "-" {
				result.addProgramTarget(args[index+1])
			}
			return result
		case arg == "-" || arg == "-s":
			return result
		case arg == "-c":
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			result.inlineCode = args[index+1]
			return result
		case shellInlineOptionCluster(arg):
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			result.inlineCode = args[index+1]
			if strings.Contains(arg, "n") {
				result.suppressProgram = true
			}
			return result
		case arg == "--help" || arg == "--version":
			result.suppressProgram = true
			return result
		case shellValidationOnlyFlag(tool, arg):
			result.suppressProgram = true
		case tool == "bash" && shellFlagNeedsValue(arg):
			if index+1 >= len(args) {
				return malformedInterpreterParse()
			}
			if arg == "-o" && args[index+1] == "noexec" {
				result.suppressProgram = true
			}
			index++
		case knownShellFlag(tool, arg):
			continue
		case strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "+"):
			return unsupportedInterpreterParse()
		default:
			result.addProgramTarget(arg)
			return result
		}
	}
	return result
}

func shellFlagNeedsValue(arg string) bool {
	switch arg {
	case "-o", "-O", "--init-file", "--rcfile":
		return true
	default:
		return false
	}
}

func shellValidationOnlyFlag(tool, arg string) bool {
	if arg == "-n" {
		return true
	}
	if tool != "bash" {
		return false
	}
	switch arg {
	case "-D", "--dump-po-strings", "--dump-strings", "--pretty-print":
		return true
	default:
		return false
	}
}

func knownShellFlag(tool, arg string) bool {
	switch arg {
	case "-e", "-f", "-u", "-v", "-x":
		return true
	}
	if tool != "bash" {
		return false
	}
	switch arg {
	case "--debugger", "--login", "--noediting", "--noprofile", "--norc", "--posix",
		"--restricted", "--verbose":
		return true
	default:
		return false
	}
}

// osascript accepts one program file followed by arguments for that program.
// An -e statement changes those trailing operands into arguments for
// inline code, so it must not be mistaken for a local file relationship.
func parseOSAScriptArguments(args []string) interpreterParseResult {
	result := newInterpreterParseResult()
	parsed := osacli.Parse(args)
	switch parsed.Disposition {
	case osacli.Unsupported:
		return unsupportedInterpreterParse()
	case osacli.Malformed:
		return malformedInterpreterParse()
	case osacli.Limited:
		return limitedInterpreterParse(result)
	}
	if parsed.Executes() && parsed.Source == osacli.File {
		result.addProgramTarget(parsed.Program)
	}
	return result
}

func interpreterLocalInput(tool string, args []string) (string, string) {
	result := parseInterpreterArguments(tool, args)
	switch result.disposition {
	case interpreterParseUnsupported:
		return "", "interpreter options were outside the bounded grammar; local input was not inferred"
	case interpreterParseMalformed:
		return "", "interpreter options were malformed; local input was not inferred"
	case interpreterParseLimited:
		return "", "interpreter option or target limit was reached; local input was not inferred"
	}

	targets := result.executableTargets()
	if len(targets) == 0 {
		return "", ""
	}
	if len(targets) != 1 {
		return "", "multiple interpreter file inputs were proven; one local input was not inferred"
	}
	localInput := staticShellResource(targets[0])
	if localInput == "" {
		return "", "interpreter input was dynamic or otherwise not a static resource; local input was not inferred"
	}
	lower := strings.ToLower(localInput)
	if strings.Contains(localInput, "://") {
		return "", "interpreter input was a non-local URL; no local input binding was inferred"
	}
	for _, prefix := range []string{"data:", "file:", "jsr:", "node:", "npm:"} {
		if strings.HasPrefix(lower, prefix) {
			return "", "interpreter input used a non-local or runtime-resolved scheme; no local input binding was inferred"
		}
	}
	return localInput, ""
}

type orderedTargetSet struct {
	values  []string
	seen    map[string]struct{}
	limit   int
	limited bool
}

func newOrderedTargetSet(limit int) *orderedTargetSet {
	return &orderedTargetSet{seen: make(map[string]struct{}), limit: limit}
}

func (set *orderedTargetSet) add(value string) {
	if value == "" || set.limited {
		return
	}
	if _, ok := set.seen[value]; ok {
		return
	}
	if len(set.values) >= set.limit {
		set.limited = true
		return
	}
	set.seen[value] = struct{}{}
	set.values = append(set.values, value)
}

// Inline code and file inputs share one option parser. In particular, flags
// after a program operand belong to that program and cannot select inline code.
func parsedInterpreterInlineCode(tool string, args []string) string {
	result := parseInterpreterArguments(tool, args)
	if result.disposition != interpreterParseRecognized || result.suppressProgram {
		return ""
	}
	return result.inlineCode
}

func shellInlineOptionCluster(arg string) bool {
	if len(arg) < 3 || arg[0] != '-' || !strings.Contains(arg, "c") {
		return false
	}
	for _, option := range arg[1:] {
		if !strings.ContainsRune("cefnuvxil", option) {
			return false
		}
	}
	return true
}
