package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0x4D31/maratus/internal/buildinfo"
	"github.com/0x4D31/maratus/internal/terminal"
)

type usageError struct {
	err error
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func newUsageError(err error) error {
	if err == nil {
		return nil
	}
	var existing *usageError
	if errors.As(err, &existing) {
		return err
	}
	return &usageError{err: err}
}

func usageErrorf(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

func exitCode(err error) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var usage *usageError
	if errors.As(err, &usage) {
		return 2
	}
	return 1
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		code := exitCode(err)
		if code != 0 {
			fmt.Fprintln(os.Stderr, terminalError(err))
		}
		os.Exit(code)
	}
}

func terminalError(err error) string {
	return "error: " + terminal.EscapeTruncate(err.Error(), 512)
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return usageErrorf("a command is required")
	}
	switch args[0] {
	case "help", "--help", "-h":
		return runHelp(args[1:])
	case "version":
		return runVersion(args[1:])
	case "--version":
		if len(args) != 1 {
			return usageErrorf("--version does not accept arguments")
		}
		_, err := fmt.Fprintf(os.Stdout, "maratus %s\n", buildinfo.Current().String())
		return err
	case "inspect":
		return runInspect(args[1:])
	case "__worker-inspect":
		if len(args) != 1 {
			return usageErrorf("internal inspect worker does not accept arguments")
		}
		return runInspectWorker(os.Stdin, os.Stdout)
	case "render":
		return runRender(args[1:])
	case "rules":
		return runRules(args[1:])
	default:
		return usageErrorf("unknown command %q; run \"maratus --help\" for usage", args[0])
	}
}

func runVersion(args []string) error {
	if wantsHelp(newFlagSet("version"), args) {
		versionUsage(os.Stdout)
		return nil
	}
	if len(args) != 0 {
		return usageErrorf("version does not accept arguments")
	}
	_, err := fmt.Fprintf(os.Stdout, "maratus %s\n", buildinfo.Current().String())
	return err
}

func runHelp(args []string) error {
	switch strings.Join(args, " ") {
	case "":
		usage(os.Stdout)
	case "inspect":
		inspectUsage(os.Stdout)
	case "render":
		renderUsage(os.Stdout)
	case "rules":
		rulesUsage(os.Stdout)
	case "rules list":
		rulesListUsage(os.Stdout)
	case "rules check":
		rulesCheckUsage(os.Stdout)
	case "rules vocab":
		rulesVocabUsage(os.Stdout)
	case "version":
		versionUsage(os.Stdout)
	default:
		return usageErrorf("unknown help topic %q; run \"maratus --help\" for usage", strings.Join(args, " "))
	}
	return nil
}
