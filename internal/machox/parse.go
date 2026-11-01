// Package machox contains the hostile-input boundary around Go's Mach-O
// parser. Callers must still preflight input and use process-level resource
// isolation: recovery contains panics, not hangs or excessive allocation.
package machox

import (
	"debug/macho"
	"errors"
	"io"
)

// ErrParserPanic reports that debug/macho panicked while parsing an input.
var ErrParserPanic = errors.New("debug/macho parser panic")

// NewFile delegates to debug/macho.NewFile and converts a parser panic into a
// normal parse error. The recovery scope deliberately covers only the parser
// call so bugs in Maratus's own post-parse processing are not hidden.
func NewFile(reader io.ReaderAt) (*macho.File, error) {
	return newFile(reader, macho.NewFile)
}

func newFile(reader io.ReaderAt, parse func(io.ReaderAt) (*macho.File, error)) (file *macho.File, err error) {
	defer func() {
		if recover() != nil {
			file = nil
			err = ErrParserPanic
		}
	}()
	return parse(reader)
}
