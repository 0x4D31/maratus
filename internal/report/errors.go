package report

import "errors"

// ErrNotReport means an input is not a Maratus report and may be inspected as
// an artifact instead. Errors from a recognized Maratus report never wrap this
// sentinel: malformed or invalid reports must fail closed.
var ErrNotReport = errors.New("not report JSON")

// ErrRecognizedReport marks a load failure that occurred after the input
// identified itself as a Maratus report. Callers must fail closed instead of
// reinterpreting the bytes as an ordinary artifact.
var ErrRecognizedReport = errors.New("recognized Maratus report")
