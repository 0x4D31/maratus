//go:build !darwin && !linux

package main

import (
	"os"
	"os/exec"
)

func configureInspectWorkerProcess(command *exec.Cmd) {}

func killInspectWorkerProcess(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}
