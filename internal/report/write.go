package report

import (
	"fmt"
	"io"
)

type trackingWriter struct {
	writer io.Writer
	err    error
}

func (w *trackingWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

// printf and println intentionally discard fmt's immediate return values.
// Write records the first error, and every public renderer returns w.err after
// completing its bounded projection.
func (w *trackingWriter) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func (w *trackingWriter) println(args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}
