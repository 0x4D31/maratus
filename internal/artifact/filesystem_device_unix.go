//go:build darwin || linux

package artifact

import (
	"io/fs"
	"syscall"
)

func sameFilesystemDevice(left, right fs.FileInfo) (same, supported bool) {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK {
		return false, false
	}
	return leftStat.Dev == rightStat.Dev, true
}
