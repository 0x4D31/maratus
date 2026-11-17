// Command go-macho-diff emits a small structural projection for development
// comparison. It is deliberately outside the Maratus runtime dependency graph.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	macho "github.com/blacktop/go-macho"
)

const maxInputBytes = 512 << 20

type section struct {
	Segment string `json:"segment"`
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Size    uint64 `json:"size"`
	Offset  uint32 `json:"offset"`
}

type result struct {
	Schema                string    `json:"schema"`
	InputBytes            int64     `json:"input_bytes"`
	Magic                 string    `json:"magic"`
	CPU                   string    `json:"cpu"`
	LoadCommands          uint32    `json:"load_commands"`
	Sections              []section `json:"sections"`
	Imports               []string  `json:"imports,omitempty"`
	ImportError           string    `json:"import_error,omitempty"`
	Libraries             []string  `json:"libraries,omitempty"`
	FunctionCount         int       `json:"function_count"`
	FunctionStartsPresent bool      `json:"function_starts_present"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: go-macho-diff MACHO")
	}
	out, err := inspect(args[0])
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func inspect(path string) (_ result, err error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxInputBytes {
		return result{}, fmt.Errorf("input is not a bounded regular file")
	}
	input, err := os.Open(path)
	if err != nil {
		return result{}, err
	}
	defer func() { _ = input.Close() }()
	openedInfo, err := input.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return result{}, fmt.Errorf("input changed during preflight")
	}
	var magic [4]byte
	if _, err := input.ReadAt(magic[:], 0); err != nil {
		return result{}, fmt.Errorf("read Mach-O magic: %w", err)
	}
	switch magic {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe},
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}:
	default:
		return result{}, fmt.Errorf("input is not an exact thin Mach-O")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("go-macho panic: %v", recovered)
		}
	}()
	file, err := macho.NewFile(input)
	if err != nil {
		return result{}, err
	}
	out := result{
		Schema: "maratus.development.go-macho-differential.v1", InputBytes: info.Size(),
		Magic: file.Magic.String(), CPU: file.CPU.String(), LoadCommands: file.NCommands,
		Libraries:             file.ImportedLibraries(),
		FunctionStartsPresent: file.FunctionStarts() != nil,
	}
	// GetFunctions otherwise falls back to scanning arm64e PAC prologues.
	if out.FunctionStartsPresent {
		out.FunctionCount = len(file.GetFunctions())
	}
	for _, item := range file.Sections {
		out.Sections = append(out.Sections, section{Segment: item.Seg, Name: item.Name, Address: item.Addr, Size: item.Size, Offset: item.Offset})
	}
	if imports, importErr := file.ImportedSymbolNames(); importErr != nil {
		out.ImportError = importErr.Error()
	} else {
		out.Imports = imports
	}
	sort.Strings(out.Imports)
	sort.Strings(out.Libraries)
	return out, nil
}
