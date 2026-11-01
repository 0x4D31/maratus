//go:build darwin || linux

package main

import (
	"fmt"
	"syscall"
)

func applyInspectWorkerResourceLimits() error {
	syscall.Umask(0o077)
	limits := []struct {
		resource int
		value    uint64
		name     string
	}{
		{syscall.RLIMIT_CPU, inspectWorkerCPUSeconds, "CPU"},
		{syscall.RLIMIT_FSIZE, inspectWorkerFileBytes, "file size"},
		{syscall.RLIMIT_NOFILE, inspectWorkerOpenFiles, "open files"},
		{syscall.RLIMIT_CORE, 0, "core size"},
	}
	for _, item := range limits {
		var current syscall.Rlimit
		if err := syscall.Getrlimit(item.resource, &current); err != nil {
			return fmt.Errorf("read %s limit: %w", item.name, err)
		}
		desired := item.value
		if desired > current.Cur {
			desired = current.Cur
		}
		if desired > current.Max {
			desired = current.Max
		}
		current.Cur = desired
		if err := syscall.Setrlimit(item.resource, &current); err != nil {
			return fmt.Errorf("set %s limit: %w", item.name, err)
		}
	}
	return nil
}
