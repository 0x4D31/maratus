//go:build !darwin && !linux

package report

import "os"

func openReportFileNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func clearReportFileNonblocking(_ *os.File) error {
	return nil
}
