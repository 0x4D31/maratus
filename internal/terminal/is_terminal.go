package terminal

import "os"

// IsTerminal reports whether file refers to a terminal device. Platform
// implementations use the terminal ioctl rather than treating every character
// device (for example /dev/null) as interactive.
func IsTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	return isTerminalFD(file.Fd())
}
