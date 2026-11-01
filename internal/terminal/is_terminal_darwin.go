//go:build darwin

package terminal

import (
	"syscall"
	"unsafe"
)

const terminalIOCTL = 0x40487413 // TIOCGETA

func isTerminalFD(fd uintptr) bool {
	var state syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, terminalIOCTL, uintptr(unsafe.Pointer(&state)))
	return errno == 0
}
