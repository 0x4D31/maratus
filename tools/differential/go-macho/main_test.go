package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMissingAndMalformedInputs(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("missing input error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "malformed")
	if err := os.WriteFile(path, []byte("not a Mach-O"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{path}, &bytes.Buffer{}); err == nil {
		t.Fatal("malformed input was accepted")
	}
}

func TestRunRejectsInputOverSizeBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{path}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("oversized input error = %v", err)
	}
}

func TestRunRejectsSymlinkAndFatContainer(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{link}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("symlink error = %v", err)
	}

	fat := filepath.Join(directory, "fat")
	if err := os.WriteFile(fat, []byte{0xca, 0xfe, 0xba, 0xbe}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{fat}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exact thin Mach-O") {
		t.Fatalf("fat input error = %v", err)
	}
}
