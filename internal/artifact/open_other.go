//go:build !darwin && !linux

package artifact

import "os"

func openFileForReadNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func clearFileNonblocking(_ *os.File) error {
	return nil
}

func nonblockingReadFlag() int {
	return 0
}
