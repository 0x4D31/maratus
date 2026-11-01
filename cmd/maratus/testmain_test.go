package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == inspectWorkerHelperArgument {
		if err := runInspectWorker(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCode(err))
		}
		os.Exit(0)
	}
	if os.Getenv("MARATUS_TEST_SLEEPING_WORKER") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	executeInspection = executeDirectInspection
	os.Exit(m.Run())
}
