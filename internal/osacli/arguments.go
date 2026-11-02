// Package osacli models a bounded, documented osascript argument profile.
// It parses selection only and never loads or evaluates an OSA program.
package osacli

import "strings"

const (
	MaxArguments    = 1024
	MaxProgramBytes = 32 << 20
)

type Disposition uint8

const (
	Recognized Disposition = iota
	Unsupported
	Malformed
	Limited
)

type Source uint8

const (
	Stdin Source = iota
	File
	Inline
)

type Result struct {
	Disposition Disposition
	Language    string
	Source      Source
	Program     string
	Lines       []string
	Interactive bool
	// AcceptsAppendedProgram distinguishes an option prefix from an explicit
	// stdin operand, inline program, or already selected program file.
	AcceptsAppendedProgram bool
}

func (r Result) Executes() bool {
	return r.Disposition == Recognized && !r.Interactive
}

// Parse stops at the first positional operand. Remaining values are arguments
// to the selected script and cannot change language or execution mode.
// In interactive mode supplied code is loaded, not automatically executed.
func Parse(args []string) Result {
	r := Result{Language: "applescript", AcceptsAppendedProgram: true}
	languageSet, programBytes, inspectedBytes := false, 0, 0
	failed := func(d Disposition) Result { return Result{Disposition: d} }
	inspect := func(value string) bool {
		if len(value) > MaxProgramBytes-inspectedBytes {
			return false
		}
		inspectedBytes += len(value)
		return true
	}
	selectOperand := func(value string) Result {
		r.AcceptsAppendedProgram = false
		if r.Source != Inline && value != "-" {
			if value == "" {
				return failed(Malformed)
			}
			r.Source, r.Program = File, value
		}
		return r
	}
	for i := 0; i < len(args); i++ {
		if i >= MaxArguments {
			return failed(Limited)
		}
		arg := args[i]
		if !inspect(arg) {
			return failed(Limited)
		}
		if strings.IndexByte(arg, 0) >= 0 {
			return failed(Malformed)
		}
		if arg == "--" {
			if i+1 == len(args) {
				return r
			}
			if i+1 >= MaxArguments {
				return failed(Limited)
			}
			if !inspect(args[i+1]) {
				return failed(Limited)
			}
			if strings.IndexByte(args[i+1], 0) >= 0 {
				return failed(Malformed)
			}
			return selectOperand(args[i+1])
		}
		if arg == "-i" {
			r.Interactive = true
			continue
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			return selectOperand(arg)
		}
		if len(arg) < 2 || arg[1] != 'e' && arg[1] != 'l' && arg[1] != 's' {
			return failed(Unsupported)
		}
		value := arg[2:]
		if len(arg) == 2 {
			if i+1 >= len(args) {
				return failed(Malformed)
			}
			if i+1 >= MaxArguments {
				return failed(Limited)
			}
			i++
			value = args[i]
			if !inspect(value) {
				return failed(Limited)
			}
		}
		if strings.IndexByte(value, 0) >= 0 {
			return failed(Malformed)
		}
		switch arg[1] {
		case 'e':
			if len(value) > MaxProgramBytes-programBytes {
				return failed(Limited)
			}
			programBytes += len(value)
			if len(r.Lines) > 0 {
				if programBytes == MaxProgramBytes {
					return failed(Limited)
				}
				programBytes++ // newline joining consecutive -e statements
			}
			r.Source, r.AcceptsAppendedProgram = Inline, false
			r.Lines = append(r.Lines, value)
		case 'l':
			if languageSet {
				return failed(Unsupported)
			}
			languageSet = true
			switch {
			case strings.EqualFold(value, "AppleScript"):
				r.Language = "applescript"
			case strings.EqualFold(value, "JavaScript"):
				r.Language = "jxa"
			default:
				return failed(Unsupported)
			}
		case 's':
			if value == "" {
				return failed(Malformed)
			}
			for _, flag := range value {
				if flag != 'e' && flag != 'h' && flag != 'o' && flag != 's' {
					return failed(Unsupported)
				}
			}
		}
	}
	return r
}
