//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	darwinSysRenameatxNP = 488
	darwinRenameExcl     = 0x00000004
)

func renameDirectoryNoReplace(oldPath, newPath string) error {
	oldPointer, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	atFDCWD := ^uintptr(1) // -2 on Darwin.
	_, _, errno := syscall.Syscall6(
		darwinSysRenameatxNP,
		atFDCWD, uintptr(unsafe.Pointer(oldPointer)),
		atFDCWD, uintptr(unsafe.Pointer(newPointer)),
		darwinRenameExcl, 0,
	)
	if errno != 0 {
		return &os.LinkError{Op: "rename-excl", Old: oldPath, New: newPath, Err: errno}
	}
	return nil
}
