package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDiscoversAndSortsSpecDeclarations(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("z.go", "package rules\nvar Zebra = Spec{Metadata: Metadata{ID: \"zebra\"}, Kind: CapabilityRule, Match: Operation(kind), MinimumSupport: support}\n")
	write("a.go", "package rules\nvar Alpha = Spec{Metadata: Metadata{ID: \"alpha\"}, Kind: CapabilityRule, Match: Operation(kind), MinimumSupport: support}\nvar ignored = Metadata{}\n")
	write("p.go", "package rules\nvar Primitive = primitiveRule(\"primitive\", \"title\", \"namespace\", kind, role, resource)\n")
	write("ignored_test.go", "package rules\nvar TestOnly = Spec{Metadata: Metadata{ID: \"test\"}, Kind: CapabilityRule, Match: Operation(kind), MinimumSupport: support}\n")
	if err := run(dir, "catalog_gen.go"); err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile(filepath.Join(dir, "catalog_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	if strings.Index(text, "Alpha") > strings.Index(text, "Primitive") || strings.Index(text, "Primitive") > strings.Index(text, "Zebra") || strings.Contains(text, "TestOnly") || strings.Contains(text, "ignored,") {
		t.Fatalf("unexpected generated catalog:\n%s", text)
	}
}

func TestRunRejectsMalformedPrimitiveRule(t *testing.T) {
	dir := t.TempDir()
	contents := "package rules\nvar One = primitiveRule(dynamicID, \"title\", \"namespace\", kind, role, resource)\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.go"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "catalog_gen.go"); err == nil || !strings.Contains(err.Error(), "literal rule ID") {
		t.Fatalf("malformed primitive rule error = %v", err)
	}
}

func TestRunRejectsDuplicateRuleID(t *testing.T) {
	dir := t.TempDir()
	contents := "package rules\nvar One = Spec{Metadata: Metadata{ID: \"same\"}, Kind: CapabilityRule, Match: Operation(kind), MinimumSupport: support}\nvar Two = Spec{Metadata: Metadata{ID: \"same\"}, Kind: CapabilityRule, Match: Operation(kind), MinimumSupport: support}\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.go"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "catalog_gen.go"); err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("duplicate rule ID error = %v", err)
	}
}

func TestRunRejectsIncompleteTypedSpec(t *testing.T) {
	dir := t.TempDir()
	contents := "package rules\nvar One = Spec{Metadata: Metadata{ID: \"one\"}, Kind: CapabilityRule, Match: Operation(kind)}\n"
	if err := os.WriteFile(filepath.Join(dir, "rules.go"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "catalog_gen.go"); err == nil || !strings.Contains(err.Error(), "Match and MinimumSupport") {
		t.Fatalf("incomplete typed Spec error = %v", err)
	}
}
