//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func configureInspectWorkerProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killInspectWorkerProcess(process *os.Process) error {
	if process == nil {
		return nil
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err == nil || err == syscall.ESRCH {
		return nil
	}
	return process.Kill()
}
