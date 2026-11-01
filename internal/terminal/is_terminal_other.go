//go:build !linux && !darwin

package terminal

func isTerminalFD(uintptr) bool { return false }
