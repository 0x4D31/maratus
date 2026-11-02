package extract

import (
	"path"
	"strings"

	"github.com/0x4D31/maratus/internal/behavior"
)

// Decoded argv has literal operands and no shell redirection. Source adapters
// supply this additional proof only after checking exact raw shell words.
type commandPathSemantics struct {
	modes        map[string]behavior.FilePathInterpretation
	output       string
	shell        bool
	argv         []string
	writes       []string
	unsupported  bool
	inputOmitted bool
}

func shellCommandPathSemantics(fields, raw []string) commandPathSemantics {
	result := commandPathSemantics{modes: shellPathInterpretations(fields, raw), shell: true}
	if len(fields) != len(raw) {
		return result
	}
	for index := 0; index < len(raw); index++ {
		start := shellRedirectionStart(raw[index])
		if start < 0 {
			result.argv = append(result.argv, fields[index])
			continue
		}
		if start > 1 || start == 1 && (raw[index][0] < '0' || raw[index][0] > '2') {
			result.unsupported = true
			return result
		}
		word := raw[index][start:]
		input, stdout := word[0] == '<', start == 0 || raw[index][0] == '1'
		heredoc := input && strings.HasPrefix(word, "<<")
		if strings.HasPrefix(word, "<<<") || strings.HasPrefix(word, ">|") {
			result.unsupported = true
			return result
		}
		word = word[1:]
		if heredoc {
			word = word[1:]
			word = strings.TrimPrefix(word, "-")
		}
		if !input && strings.HasPrefix(word, ">") {
			word = word[1:]
		}
		duplicate := strings.HasPrefix(word, "&")
		if duplicate {
			word = word[1:]
		}
		if word == "" {
			if index+1 >= len(raw) {
				result.unsupported = true
				return result
			}
			index++
			word = raw[index]
		}
		if word != "" && strings.ContainsRune("<>|", rune(word[0])) {
			result.unsupported = true
			return result
		}
		values, err := CommandFields(word)
		if err != nil || len(values) != 1 {
			result.unsupported = true
			return result
		}
		value := values[0]
		if duplicate {
			if value != "0" && value != "1" && value != "2" && value != "-" {
				result.unsupported = true
				return result
			}
			if stdout && !input && value != "1" {
				result.output = ""
			}
			continue
		}
		if input {
			result.inputOmitted = true
			continue
		}
		result.writes = append(result.writes, value)
		if stdout {
			result.output = value
		}
		mode := shellWordPathInterpretation(word)
		if existing, ok := result.modes[value]; ok && existing != mode {
			mode = behavior.FilePathUnknown
		}
		result.modes[value] = mode
	}
	return result
}

func shellRedirectionStart(raw string) int {
	quote := byte(0)
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		if char == '\\' && quote != '\'' {
			index++
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if char == '>' || char == '<' {
			return index
		}
	}
	return -1
}

func (paths commandPathSemantics) interpretation(value string) behavior.FilePathInterpretation {
	if paths.modes == nil {
		return behavior.FilePathLiteral
	}
	return paths.modes[value]
}

func (paths commandPathSemantics) writeTargets(tool string, fields []string) []string {
	switch tool {
	case "cat", "printf", "echo":
		if paths.output != "" {
			return []string{paths.output}
		}
	case "cp":
		parsed := parseFileCopyCommand(append([]string{tool}, fields[1:]...))
		if parsed.disposition == fileCopyRecognized {
			return []string{parsed.destination}
		}
	case "mv":
		if dest := parseFileMoveCommand(append([]string{tool}, fields[1:]...)).destination; dest != "" {
			return []string{dest}
		}
	case "install", "tee":
		operands := closedCommandWriteOperands(tool, fields)
		if tool == "install" && len(operands) > 0 {
			return operands[len(operands)-1:]
		}
		return operands
	}
	return nil
}

func closedCommandWriteOperands(tool string, fields []string) []string {
	index := 1
	delimited := false
	for index < len(fields) {
		word := fields[index]
		if word == "--" {
			delimited = true
			index++
			break
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			break
		}
		if tool == "tee" && len(word) > 1 && strings.Trim(word[1:], "ai") == "" {
			index++
			continue
		}
		if tool == "install" {
			switch word {
			case "-m", "-o", "-g":
				if index+1 >= len(fields) {
					return nil
				}
				index += 2
				continue
			case "-b", "-c", "-p", "-s":
				index++
				continue
			}
		}
		return nil
	}
	minimum := 1
	if tool == "install" {
		minimum = 2
	}
	if len(fields)-index < minimum {
		return nil
	}
	if !delimited {
		for _, word := range fields[index:] {
			if strings.HasPrefix(word, "-") && word != "-" {
				return nil
			}
		}
	}
	return fields[index:]
}

func (paths commandPathSemantics) supportsHostPath(value string) bool {
	if value == "" || strings.HasSuffix(value, "/") || strings.HasPrefix(value, "//") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return false
		}
	}
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(value, prefix) {
			return paths.interpretation(value) == behavior.FilePathHomeRelative && staticShellResource(strings.TrimPrefix(value, prefix)) != ""
		}
	}
	return path.IsAbs(value) && paths.fileValue(value) != ""
}

func (paths commandPathSemantics) fileValue(value string) string {
	if paths.interpretation(value) == behavior.FilePathLiteral {
		return value
	}
	return staticShellResource(value)
}
