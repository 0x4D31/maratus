package artifact

import "strings"

const (
	// XNU's interpreter activator scans exactly IMG_SHSIZE bytes and rejects a
	// declaration without a '#' or newline terminator inside that window.
	maxShebangBytes = 512
	maxShebangWords = 64
)

// ShebangLanguage returns the semantic language established by one bounded,
// exact interpreter declaration. It deliberately does not use substring
// matching: wish and bash-helper are not shells merely because their basenames
// contain "sh". The parser models common direct interpreters and a conservative
// subset of /usr/bin/env, including env -S.
func ShebangLanguage(data []byte) string {
	line, ok := boundedShebangLine(data)
	if !ok {
		return ""
	}
	words, ok := splitLiteralShebangWords(trimASCIIHorizontalSpace(line[2:]))
	if !ok || len(words) == 0 {
		return ""
	}
	if strings.HasSuffix(words[0], "/") || strings.ContainsAny(words[0], "'\"\\") {
		return ""
	}
	viaEnv := false
	if words[0] == "/usr/bin/env" {
		viaEnv = true
		words, ok = envShebangCommand(words[1:])
		if !ok || len(words) == 0 {
			return ""
		}
	}
	if strings.HasSuffix(words[0], "/") || strings.ContainsAny(words[0], "'\"\\") {
		return ""
	}
	interpreter, ok := declaredInterpreterName(words[0], viaEnv)
	if !ok {
		return ""
	}
	return targetLanguageForInterpreter(interpreter, words[1:])
}

// HasShebang reports whether data begins with a syntactically complete XNU
// interpreter declaration, independently of whether Maratus supports the named
// interpreter. This distinction keeps an unsupported Ruby/Wish script from
// being reclassified as unrelated Markdown or ordinary text while avoiding
// invented host semantics.
func HasShebang(data []byte) bool {
	line, ok := boundedShebangLine(data)
	if !ok {
		return false
	}
	declaration := trimASCIIHorizontalSpace(line[2:])
	if declaration == "" {
		return false
	}
	for index := 0; index < len(declaration); index++ {
		if asciiShebangWhitespace(declaration[index]) {
			return index > 0
		}
	}
	return true
}

// InterpreterLanguage returns the language selected by trusted structural
// invocation metadata. Complete conventional paths are required; arbitrary
// basename collisions never acquire interpreter semantics.
func InterpreterLanguage(interpreter string, arguments []string) string {
	name, arguments, ok := interpreterCommand(interpreter, arguments)
	if !ok {
		return ""
	}
	return languageForInterpreter(name, arguments)
}

// InterpreterTargetLanguage returns the semantic language only when trusted
// structural argv proves that a program-file path appended after arguments is
// consumed as the interpreter's program. Inline, module, stdin, interactive,
// and already-supplied program modes stay unresolved and must not mint an
// InvokedTarget for the appended artifact.
func InterpreterTargetLanguage(interpreter string, arguments []string) string {
	name, arguments, ok := interpreterCommand(interpreter, arguments)
	if !ok {
		return ""
	}
	return targetLanguageForInterpreter(name, arguments)
}

// targetLanguageForInterpreter recognizes only argv prefixes after which the
// next argument is still selected as the program file. This is shared by XNU
// shebangs (where the kernel appends the current path) and structural host
// adapters (where Maratus appends an invoked target). Inline code, modules,
// stdin, and an already supplied program must never confer semantics on that
// appended file.
func targetLanguageForInterpreter(name string, arguments []string) string {
	switch name {
	case "sh", "bash", "dash", "fish", "ksh", "mksh", "zsh", "bun":
		if len(arguments) == 0 || len(arguments) == 1 && arguments[0] == "--" {
			return languageForInterpreter(name, nil)
		}
		return ""
	case "node", "nodejs":
		for index, argument := range arguments {
			switch argument {
			case "--no-warnings", "--trace-warnings", "--use-strict":
				continue
			case "--":
				if index == len(arguments)-1 {
					return "javascript"
				}
				return ""
			default:
				return ""
			}
		}
		return "javascript"
	case "deno":
		if len(arguments) == 1 && arguments[0] == "run" || len(arguments) == 2 && arguments[0] == "run" && arguments[1] == "--" {
			return "javascript"
		}
		return ""
	case "osascript":
		language, consumesTarget := parseOSAScriptArguments(arguments)
		if consumesTarget {
			return language
		}
		return ""
	default:
		if !versionedPythonInterpreter(name) {
			return ""
		}
		for index, argument := range arguments {
			switch argument {
			case "-O", "-OO", "-B", "-E", "-I", "-s", "-S", "-u":
				continue
			case "--":
				if index == len(arguments)-1 {
					return "python"
				}
				return ""
			default:
				return ""
			}
		}
		return "python"
	}
}

func interpreterCommand(interpreter string, arguments []string) (string, []string, bool) {
	if interpreter == "" || strings.HasSuffix(interpreter, "/") || strings.ContainsAny(interpreter, "'\"\\") {
		return "", nil, false
	}
	viaEnv := interpreter == "/usr/bin/env"
	words := append([]string(nil), arguments...)
	if viaEnv {
		var ok bool
		words, ok = envShebangCommand(words)
		if !ok || len(words) == 0 {
			return "", nil, false
		}
		interpreter = words[0]
		words = words[1:]
	}
	name, ok := declaredInterpreterName(interpreter, viaEnv)
	if !ok {
		return "", nil, false
	}
	return name, words, true
}

func languageForInterpreter(interpreter string, arguments []string) string {
	switch interpreter {
	case "sh", "bash", "dash", "fish", "ksh", "mksh", "zsh":
		return "shell"
	case "node", "nodejs", "deno", "bun":
		return "javascript"
	case "osascript":
		return osascriptLanguage(arguments)
	default:
		if versionedPythonInterpreter(interpreter) {
			return "python"
		}
		return ""
	}
}

func osascriptLanguage(arguments []string) string {
	language, _ := parseOSAScriptArguments(arguments)
	return language
}

func parseOSAScriptArguments(arguments []string) (string, bool) {
	language := "applescript"
	consumesTarget := true
	for index := 0; index < len(arguments); {
		argument := arguments[index]
		switch {
		case argument == "--":
			// With no following positional argument, the appended artifact is
			// the program. Otherwise the first post-- value is already the
			// program and the appended artifact is only a script argument.
			return language, consumesTarget && index+1 == len(arguments)
		case argument == "-i":
			consumesTarget = false
			index++
		case argument == "-l" || argument == "-s" || argument == "-e":
			if index+1 >= len(arguments) {
				return "", false
			}
			switch argument {
			case "-l":
				language = supportedOSALanguage(arguments[index+1])
				if language == "" {
					return "", false
				}
			case "-s":
				if !validOSAScriptOutputFlags(arguments[index+1]) {
					return "", false
				}
			case "-e":
				consumesTarget = false
			}
			index += 2
		case strings.HasPrefix(argument, "-l") && len(argument) > len("-l"):
			language = supportedOSALanguage(argument[len("-l"):])
			if language == "" {
				return "", false
			}
			index++
		case strings.HasPrefix(argument, "-s") && len(argument) > len("-s"):
			if !validOSAScriptOutputFlags(argument[len("-s"):]) {
				return "", false
			}
			index++
		case strings.HasPrefix(argument, "-e") && len(argument) > len("-e"):
			consumesTarget = false
			index++
		case strings.HasPrefix(argument, "-"):
			return "", false
		default:
			// The first program file ends osascript option parsing; later values
			// are script arguments and cannot change the selected language.
			return language, false
		}
	}
	return language, consumesTarget
}

func validOSAScriptOutputFlags(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case 'e', 'h', 'o', 's':
		default:
			return false
		}
	}
	return true
}

func supportedOSALanguage(value string) string {
	switch {
	case strings.EqualFold(value, "javascript"):
		return "jxa"
	case strings.EqualFold(value, "applescript"):
		return "applescript"
	default:
		return ""
	}
}

// declaredInterpreterName accepts complete, conventional interpreter paths for
// direct kernel activation. For /usr/bin/env, a bare utility name is also
// meaningful because env performs PATH lookup. Arbitrary paths whose basename
// merely resembles an interpreter do not establish host identity.
func declaredInterpreterName(value string, viaEnv bool) (string, bool) {
	if viaEnv && !strings.Contains(value, "/") {
		return value, value != ""
	}
	for _, prefix := range []string{"/bin/", "/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", "/opt/local/bin/"} {
		if strings.HasPrefix(value, prefix) && !strings.Contains(value[len(prefix):], "/") && len(value) > len(prefix) {
			return value[len(prefix):], true
		}
	}
	return "", false
}

// splitLiteralShebangWords models the kernel-visible declaration tokens. Quote
// and backslash bytes in the interpreter token are literal path bytes; they are
// not shell syntax. Only env -S is allowed to apply its documented splitting
// grammar later.
func splitLiteralShebangWords(value string) ([]string, bool) {
	var words []string
	for index := 0; index < len(value); {
		for index < len(value) && asciiShebangWhitespace(value[index]) {
			index++
		}
		if index == len(value) {
			break
		}
		start := index
		for index < len(value) && !asciiShebangWhitespace(value[index]) {
			index++
		}
		words = append(words, value[start:index])
		if len(words) > maxShebangWords {
			return nil, false
		}
	}
	if len(words) == 0 || len(words) > maxShebangWords {
		return nil, false
	}
	return words, true
}

func boundedShebangLine(data []byte) (string, bool) {
	if len(data) < 3 || data[0] != '#' || data[1] != '!' {
		return "", false
	}
	limit := min(len(data), maxShebangBytes)
	end := -1
	for index := 2; index < limit; index++ {
		if data[index] == '#' || data[index] == '\n' {
			end = index
			break
		}
	}
	if end < 0 {
		return "", false
	}
	line := data[:end]
	if len(line) < 3 || strings.IndexByte(string(line), 0) >= 0 {
		return "", false
	}
	return string(line), true
}

func asciiShebangWhitespace(value byte) bool {
	return value == ' ' || value == '\t'
}

func trimASCIIHorizontalSpace(value string) string {
	start := 0
	for start < len(value) && asciiShebangWhitespace(value[start]) {
		start++
	}
	end := len(value)
	for end > start && asciiShebangWhitespace(value[end-1]) {
		end--
	}
	return value[start:end]
}

func splitShebangWords(value string) ([]string, bool) {
	var words []string
	var word strings.Builder
	var quote byte
	tokenStarted := false
	flush := func() bool {
		if !tokenStarted {
			return true
		}
		if len(words) >= maxShebangWords {
			return false
		}
		words = append(words, word.String())
		word.Reset()
		tokenStarted = false
		return true
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current == '\\' {
			// BSD env -S implements a closed escape grammar. Until each
			// supported escape is modeled exactly, reject backslashes instead
			// of treating them as shell-style quoting and inventing a utility.
			return nil, false
		}
		if quote != 0 {
			if current == quote {
				quote = 0
			} else {
				word.WriteByte(current)
			}
			continue
		}
		switch current {
		case '\'', '"':
			quote = current
			tokenStarted = true
		case ' ', '\t':
			if !flush() {
				return nil, false
			}
		default:
			word.WriteByte(current)
			tokenStarted = true
		}
	}
	if quote != 0 || !flush() {
		return nil, false
	}
	return words, len(words) > 0
}

func envShebangCommand(arguments []string) ([]string, bool) {
	options := true
	pathLookupOverridden := false
	for index := 0; index < len(arguments); {
		argument := arguments[index]
		if !options {
			if envAssignment(argument) {
				if strings.HasPrefix(argument, "PATH=") {
					pathLookupOverridden = true
				}
				index++
				continue
			}
			return envCommandWithLookupPolicy(arguments[index:], pathLookupOverridden)
		}
		switch {
		case argument == "--":
			options = false
			index++
		case argument == "-S":
			if index+1 >= len(arguments) {
				return nil, false
			}
			words, ok := splitShebangWords(strings.Join(arguments[index+1:], " "))
			if !ok {
				return nil, false
			}
			return envCommandWithLookupPolicy(words, pathLookupOverridden)
		case argument == "-i":
			pathLookupOverridden = true
			index++
		case argument == "-v":
			index++
		case argument == "-0":
			// macOS env reserves -0 for printing the environment and rejects it
			// when a utility is also supplied.
			return nil, false
		case argument == "-u" || argument == "-C" || argument == "-P":
			if index+1 >= len(arguments) {
				return nil, false
			}
			if argument == "-P" || argument == "-u" && arguments[index+1] == "PATH" {
				pathLookupOverridden = true
			}
			index += 2
		case strings.HasPrefix(argument, "-"):
			return nil, false
		case envAssignment(argument):
			if strings.HasPrefix(argument, "PATH=") {
				pathLookupOverridden = true
			}
			options = false
			index++
		default:
			return envCommandWithLookupPolicy(arguments[index:], pathLookupOverridden)
		}
	}
	return nil, false
}

func envCommandWithLookupPolicy(words []string, pathLookupOverridden bool) ([]string, bool) {
	if len(words) == 0 || words[0] == "" {
		return nil, false
	}
	if pathLookupOverridden && !strings.Contains(words[0], "/") {
		return nil, false
	}
	return words, true
}

func envAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	if !ok || name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		current := name[index]
		letter := current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z'
		valid := current == '_' || letter
		if index > 0 {
			valid = valid || current >= '0' && current <= '9'
		}
		if !valid {
			return false
		}
	}
	return true
}

func versionedPythonInterpreter(value string) bool {
	if value == "python" {
		return true
	}
	remainder := strings.TrimPrefix(value, "python")
	if remainder == value || remainder == "" {
		return false
	}
	digit := false
	previousDot := false
	for _, current := range remainder {
		switch {
		case current >= '0' && current <= '9':
			digit = true
			previousDot = false
		case current == '.' && digit && !previousDot:
			previousDot = true
		default:
			return false
		}
	}
	return digit && !previousDot
}
