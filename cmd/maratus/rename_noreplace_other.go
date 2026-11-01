//go:build !darwin && !(linux && (amd64 || arm64))

package main

import "fmt"

func renameDirectoryNoReplace(_, _ string) error {
	return fmt.Errorf("atomic exclusive case-bundle publication is unsupported on this platform")
}
