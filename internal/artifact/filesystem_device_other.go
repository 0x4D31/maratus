//go:build !darwin && !linux

package artifact

import "io/fs"

func sameFilesystemDevice(_, _ fs.FileInfo) (same, supported bool) {
	return false, false
}
