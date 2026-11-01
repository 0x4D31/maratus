//go:build darwin || linux

package artifact

import (
	"os"
	"syscall"
)

func openFileForReadNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, syscall.EBADF
	}
	return file, nil
}

func clearFileNonblocking(file *os.File) error {
	return syscall.SetNonblock(int(file.Fd()), false)
}

func nonblockingReadFlag() int {
	return syscall.O_NONBLOCK
}
