package shellparse

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	maxFields       = 4096
	maxDecodedBytes = 1 << 20
)

var (
	// ErrFieldLimit reports that a syntactically valid command would produce
	// more argv data than static analysis is willing to materialize. Callers
	// must not interpret the returned prefix as a complete command.
	ErrFieldLimit = errors.New("shell field limit reached")
	// ErrUnsupportedSyntax reports that the lightweight argv view cannot safely
	// represent a shell command or a command-wrapper mode.
	ErrUnsupportedSyntax = errors.New("unsupported shell syntax")
)

// Fields splits a simple shell command into argv-like fields. It intentionally
// supports only quoting and escaping needed by maratus's static recognizers.
func Fields(command string) ([]string, error) {
	var fields []string
	var current strings.Builder
	var quote rune
	escaped := false
	fieldStarted := false
	decodedBytes := 0
	writeRune := func(r rune) bool {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = utf8.RuneLen(utf8.RuneError)
		}
		if size > maxDecodedBytes-decodedBytes {
			return false
		}
		current.WriteRune(r)
		decodedBytes += size
		fieldStarted = true
		return true
	}
	flush := func() error {
		if !fieldStarted {
			return nil
		}
		if len(fields) >= maxFields {
			return fmt.Errorf("%w: more than %d fields", ErrFieldLimit, maxFields)
		}
		fields = append(fields, current.String())
		current.Reset()
		fieldStarted = false
		return nil
	}
	for _, r := range command {
		if escaped {
			escaped = false
			// An unquoted or double-quoted backslash-newline is a line
			// continuation, not an argument byte or an empty argument.
			if r == '\n' {
				continue
			}
			// Inside double quotes, backslash only quotes these four
			// characters (and newline, handled above). Otherwise it is literal.
			if quote == '"' && r != '$' && r != '`' && r != '"' && r != '\\' {
				if !writeRune('\\') {
					return nil, fmt.Errorf("%w: more than %d decoded bytes", ErrFieldLimit, maxDecodedBytes)
				}
			}
			if !writeRune(r) {
				return nil, fmt.Errorf("%w: more than %d decoded bytes", ErrFieldLimit, maxDecodedBytes)
			}
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			if !writeRune(r) {
				return nil, fmt.Errorf("%w: more than %d decoded bytes", ErrFieldLimit, maxDecodedBytes)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			fieldStarted = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if !writeRune(r) {
			return nil, fmt.Errorf("%w: more than %d decoded bytes", ErrFieldLimit, maxDecodedBytes)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if quote != 0 {
		return fields, fmt.Errorf("unterminated quote")
	}
	if escaped {
		return fields, fmt.Errorf("unterminated escape")
	}
	return fields, nil
}

// NormalizeFields removes leading static assignments and unwraps inert command
// wrappers such as sudo, env, command, and nohup.
func NormalizeFields(fields []string) []string {
	fields, err := NormalizeFieldsChecked(fields)
	if err != nil {
		return nil
	}
	return fields
}

// NormalizeFieldsChecked is NormalizeFields with explicit propagation for an
// oversized command embedded in env -S/--split-string or shell syntax that
// cannot be represented safely by this package's argv approximation.
func NormalizeFieldsChecked(fields []string) ([]string, error) {
	for depth := 0; depth < 4 && len(fields) > 0; depth++ {
		before := fields
		var err error
		fields, err = stripAssignmentsChecked(fields)
		if err != nil {
			return nil, err
		}
		fields, err = unwrapCommandWrappersChecked(fields)
		if err != nil {
			return nil, err
		}
		if sameFields(before, fields) {
			return fields, nil
		}
	}
	return fields, nil
}

// UnwrapCommandWrappers returns the command payload after static wrappers such
// as sudo, env, and the shell command builtin.
func UnwrapCommandWrappers(fields []string) []string {
	fields, err := unwrapCommandWrappersChecked(fields)
	if err != nil {
		return nil
	}
	return fields
}

// Assignment returns a static shell assignment split into name and value.
func Assignment(field string) (string, string, bool) {
	if strings.HasPrefix(field, "$") {
		return "", "", false
	}
	idx := strings.IndexByte(field, '=')
	if idx <= 0 {
		return "", "", false
	}
	name := field[:idx]
	for i, r := range name {
		if i == 0 {
			if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				continue
			}
			return "", "", false
		}
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return "", "", false
	}
	return name, field[idx+1:], true
}

func stripAssignmentsChecked(fields []string) ([]string, error) {
	for len(fields) > 0 {
		_, value, ok := Assignment(fields[0])
		if !ok {
			return fields, nil
		}
		if assignmentExpansionSpansFields(value) || assignmentContainsExecutableExpansion(value) {
			return nil, fmt.Errorf("%w: leading assignment contains a multi-field expansion", ErrUnsupportedSyntax)
		}
		fields = fields[1:]
	}
	return nil, nil
}

func assignmentContainsExecutableExpansion(value string) bool {
	return strings.Contains(value, "$(") || strings.Contains(value, "<(") || strings.Contains(value, ">(") || strings.Contains(value, "`")
}

func assignmentExpansionSpansFields(value string) bool {
	commandDepth := 0
	parameterDepth := 0
	backtickOpen := false
	for index := 0; index < len(value); index++ {
		switch {
		case value[index] == '`':
			backtickOpen = !backtickOpen
		case index+1 < len(value) && (value[index] == '$' || value[index] == '<' || value[index] == '>') && value[index+1] == '(':
			commandDepth++
			index++
		case index+1 < len(value) && value[index] == '$' && value[index+1] == '{':
			parameterDepth++
			index++
		case value[index] == ')' && commandDepth > 0:
			commandDepth--
		case value[index] == '}' && parameterDepth > 0:
			parameterDepth--
		}
	}
	return commandDepth != 0 || parameterDepth != 0 || backtickOpen
}

func unwrapCommandWrappersChecked(fields []string) ([]string, error) {
	for depth := 0; depth < 4 && len(fields) > 0; depth++ {
		var next []string
		var err error
		switch filepath.Base(fields[0]) {
		case "sudo":
			next, err = unwrapSudoChecked(fields)
		case "env":
			next, err = unwrapEnvChecked(fields)
		case "command":
			next = unwrapCommandBuiltin(fields)
		case "nohup":
			next = fields[1:]
		default:
			return fields, nil
		}
		if err != nil {
			return nil, err
		}
		if len(next) == 0 || sameFields(next, fields) {
			return fields, nil
		}
		fields = next
	}
	return fields, nil
}

func unwrapSudoChecked(fields []string) ([]string, error) {
	for i := 1; i < len(fields); i++ {
		arg := fields[i]
		if arg == "--" {
			return fields[i+1:], nil
		}
		// Dropping a directory/root override would give every downstream path
		// the caller's filesystem context, potentially selecting a decoy file.
		if arg == "-D" || arg == "-R" || arg == "--chdir" || arg == "--chroot" ||
			strings.HasPrefix(arg, "-D") || strings.HasPrefix(arg, "-R") ||
			strings.HasPrefix(arg, "--chdir=") || strings.HasPrefix(arg, "--chroot=") {
			return nil, fmt.Errorf("%w: sudo changes the filesystem context", ErrUnsupportedSyntax)
		}
		if sudoOptionNeedsValue(arg) {
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("%w: sudo option requires a value", ErrUnsupportedSyntax)
			}
			if fields[i+1] == "" && (arg == "-u" || arg == "--user" || arg == "-g" || arg == "--group") {
				return nil, fmt.Errorf("%w: sudo user or group is empty", ErrUnsupportedSyntax)
			}
			if assignmentExpansionSpansFields(fields[i+1]) || assignmentContainsExecutableExpansion(fields[i+1]) {
				return nil, fmt.Errorf("%w: sudo option value contains syntax spanning argv fields", ErrUnsupportedSyntax)
			}
			i++
			continue
		}
		if sudoOptionHasInlineValue(arg) {
			if value := sudoInlineOptionValue(arg); assignmentExpansionSpansFields(value) || assignmentContainsExecutableExpansion(value) {
				return nil, fmt.Errorf("%w: sudo option value contains syntax spanning argv fields", ErrUnsupportedSyntax)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if sudoExecutionFlag(arg) {
				continue
			}
			// Query, edit, and shell modes do not directly execute the
			// remaining argv. Unknown options also cannot establish that
			// the following token is an executable.
			return nil, fmt.Errorf("%w: unsupported sudo mode or option", ErrUnsupportedSyntax)
		}
		return fields[i:], nil
	}
	return fields, nil
}

func sudoOptionNeedsValue(arg string) bool {
	switch arg {
	case "-a", "-C", "-c", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u",
		"--auth-type", "--chdir", "--close-from", "--group", "--host", "--login-class",
		"--prompt", "--role", "--type", "--user", "--command-timeout":
		return true
	default:
		return false
	}
}

func sudoExecutionFlag(arg string) bool {
	switch arg {
	case "--askpass", "--background", "--bell", "--preserve-env", "--set-home",
		"--reset-timestamp", "--non-interactive", "--preserve-groups", "--stdin":
		return true
	}
	if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
		return false
	}
	for _, option := range arg[1:] {
		if !strings.ContainsRune("AbBEHknPS", option) {
			return false
		}
	}
	return true
}

func sudoOptionHasInlineValue(arg string) bool {
	for _, prefix := range []string{
		"-a", "-C", "-c", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u",
		"--auth-type=", "--chdir=", "--close-from=", "--group=", "--host=",
		"--login-class=", "--prompt=", "--role=", "--type=", "--user=",
		"--command-timeout=", "--preserve-env=",
	} {
		if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
			return true
		}
	}
	return false
}

func sudoInlineOptionValue(arg string) string {
	for _, prefix := range []string{
		"--auth-type=", "--chdir=", "--close-from=", "--group=", "--host=",
		"--login-class=", "--prompt=", "--role=", "--type=", "--user=",
		"--command-timeout=", "--preserve-env=", "-a", "-C", "-c", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u",
	} {
		if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
			return arg[len(prefix):]
		}
	}
	return ""
}

func unwrapEnvChecked(fields []string) ([]string, error) {
	for i := 1; i < len(fields); i++ {
		arg := fields[i]
		if arg == "--" {
			return fields[i+1:], nil
		}
		if arg == "-C" || arg == "--chdir" || strings.HasPrefix(arg, "-C") || strings.HasPrefix(arg, "--chdir=") {
			return nil, fmt.Errorf("%w: env changes the working directory", ErrUnsupportedSyntax)
		}
		if arg == "-0" || arg == "--null" {
			return nil, fmt.Errorf("%w: env null-output mode does not execute a command", ErrUnsupportedSyntax)
		}
		if arg == "-S" || arg == "--split-string" {
			if i+1 >= len(fields) {
				return fields, nil
			}
			split, err := Fields(fields[i+1])
			if errors.Is(err, ErrFieldLimit) {
				return nil, err
			}
			if err != nil || len(split) == 0 {
				return fields, nil
			}
			return append(split, fields[i+2:]...), nil
		}
		if envOptionNeedsValue(arg) {
			if i+1 < len(fields) && (assignmentExpansionSpansFields(fields[i+1]) || assignmentContainsExecutableExpansion(fields[i+1])) {
				return nil, fmt.Errorf("%w: env option value contains syntax spanning argv fields", ErrUnsupportedSyntax)
			}
			i++
			continue
		}
		if envOptionHasInlineValue(arg) {
			if value := envInlineOptionValue(arg); assignmentExpansionSpansFields(value) || assignmentContainsExecutableExpansion(value) {
				return nil, fmt.Errorf("%w: env option value contains syntax spanning argv fields", ErrUnsupportedSyntax)
			}
			continue
		}
		if envFlag(arg) {
			continue
		}
		if _, value, ok := Assignment(arg); ok {
			if assignmentExpansionSpansFields(value) || assignmentContainsExecutableExpansion(value) {
				return nil, fmt.Errorf("%w: env assignment contains a multi-field expansion", ErrUnsupportedSyntax)
			}
			continue
		}
		return fields[i:], nil
	}
	return fields, nil
}

func envInlineOptionValue(arg string) string {
	for _, prefix := range []string{"--unset=", "--chdir=", "-u", "-C"} {
		if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
			return arg[len(prefix):]
		}
	}
	return ""
}

func envOptionNeedsValue(arg string) bool {
	switch arg {
	case "-u", "--unset", "-C", "--chdir":
		return true
	default:
		return false
	}
}

func envOptionHasInlineValue(arg string) bool {
	for _, prefix := range []string{"-u", "--unset=", "-C", "--chdir="} {
		if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
			return true
		}
	}
	return false
}

func envFlag(arg string) bool {
	switch arg {
	case "-0", "-i", "-", "--ignore-environment", "--null", "--debug":
		return true
	default:
		return false
	}
}

func unwrapCommandBuiltin(fields []string) []string {
	for i := 1; i < len(fields); i++ {
		if fields[i] == "--" {
			return fields[i+1:]
		}
		switch fields[i] {
		case "-p":
			continue
		case "-v", "-V":
			return fields
		}
		if strings.HasPrefix(fields[i], "-") {
			return fields
		}
		return fields[i:]
	}
	return fields
}

func sameFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
