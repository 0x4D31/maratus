//go:build !darwin && !linux

package main

func applyInspectWorkerResourceLimits() error { return nil }
