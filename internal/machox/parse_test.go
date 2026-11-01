package machox

import (
	"debug/macho"
	"errors"
	"io"
	"testing"
)

func TestNewFileContainsParserPanic(t *testing.T) {
	file, err := newFile(zeroReaderAt{}, func(io.ReaderAt) (*macho.File, error) {
		panic("malformed input")
	})
	if file != nil {
		t.Fatalf("file = %#v, want nil", file)
	}
	if !errors.Is(err, ErrParserPanic) {
		t.Fatalf("error = %v, want %v", err, ErrParserPanic)
	}
}

func TestNewFilePreservesParserError(t *testing.T) {
	want := errors.New("parse failed")
	file, err := newFile(zeroReaderAt{}, func(io.ReaderAt) (*macho.File, error) {
		return nil, want
	})
	if file != nil || !errors.Is(err, want) {
		t.Fatalf("file, error = %#v, %v, want nil, %v", file, err, want)
	}
}

type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	for index := range p {
		p[index] = 0
	}
	return len(p), nil
}
