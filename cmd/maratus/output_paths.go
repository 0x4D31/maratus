package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateInspectOutputLocations(input, output, bundle string) error {
	bundle = strings.TrimSpace(bundle)
	var destinations []string
	for index, path := range []string{output, bundle} {
		if strings.TrimSpace(path) == "" || index == 0 && path == "-" {
			continue
		}
		resolved, err := effectiveOutputPath(path)
		if err != nil {
			return fmt.Errorf("validate inspect output %q: %w", path, err)
		}
		destinations = append(destinations, resolved)
	}
	if len(destinations) == 2 && outputPathWithin(destinations[1], destinations[0]) {
		return usageErrorf("inspect output file must be outside its case bundle")
	}
	if input == "" || len(destinations) == 0 {
		return nil
	}
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("validate inspect input %q: %w", input, err)
	}
	if !info.IsDir() {
		return nil
	}
	directory, err := filepath.EvalSymlinks(input)
	if err != nil {
		return fmt.Errorf("resolve inspect input directory: %w", err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	for _, destination := range destinations {
		if outputPathWithin(directory, destination) {
			return usageErrorf("inspect outputs must be outside its input directory")
		}
	}
	return nil
}

// Atomic output replaces the final directory entry, including a symlink.
// Resolve its parent instead, retaining missing components of new bundles.
func effectiveOutputPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, suffix := filepath.Dir(absolute), filepath.Base(absolute)
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			return filepath.Join(resolved, suffix), nil
		}
		if !os.IsNotExist(err) || filepath.Dir(parent) == parent {
			return "", err
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = filepath.Dir(parent)
	}
}

func outputPathWithin(directory, path string) bool {
	if path == directory || strings.HasPrefix(path, strings.TrimSuffix(directory, string(filepath.Separator))+string(filepath.Separator)) {
		return true
	}
	// EvalSymlinks does not canonicalize case on every filesystem. Compare
	// existing parent identities too, without following the output's leaf.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if same, err := sameFilePath(directory, parent); err == nil && same {
			return true
		}
		if filepath.Dir(parent) == parent {
			return false
		}
	}
}
