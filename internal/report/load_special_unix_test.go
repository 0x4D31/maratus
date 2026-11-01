//go:build darwin || linux

package report

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadRejectsFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "input.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	assertLoadReturnsNotReport(t, fifo)

	alias := filepath.Join(root, "input-alias")
	if err := os.Symlink(fifo, alias); err != nil {
		t.Fatal(err)
	}
	assertLoadReturnsNotReport(t, alias)
}

func assertLoadReturnsNotReport(t *testing.T, path string) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		_, err := Load(path)
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, ErrNotReport) {
			t.Fatalf("Load(%q) error = %v, want ErrNotReport", path, err)
		}
	case <-time.After(2 * time.Second):
		// If a regression blocks in open(2), a nonblocking writer releases the
		// reader so the test process can still shut down cleanly.
		if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatalf("Load(%q) blocked on a special file", path)
	}
}
