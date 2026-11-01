//go:build linux && (amd64 || arm64)

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const linuxRenameNoReplace = 1

func renameDirectoryNoReplace(oldPath, newPath string) error {
	oldPointer, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	atFDCWD := ^uintptr(99) // -100 on Linux.
	_, _, errno := syscall.Syscall6(
		linuxSysRenameat2,
		atFDCWD, uintptr(unsafe.Pointer(oldPointer)),
		atFDCWD, uintptr(unsafe.Pointer(newPointer)),
		linuxRenameNoReplace, 0,
	)
	if errno != 0 {
		return &os.LinkError{Op: "rename-noreplace", Old: oldPath, New: newPath, Err: errno}
	}
	return nil
}
