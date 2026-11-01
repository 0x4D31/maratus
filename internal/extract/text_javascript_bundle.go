package extract

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxJavaScriptBundleBytes          = 512 << 10
	maxJavaScriptBundleTables         = 8
	maxJavaScriptBundleModules        = 64
	maxJavaScriptBundleFunctions      = 64
	maxJavaScriptBundleContainerBytes = 256 << 10
	maxJavaScriptBundleFunctionBytes  = 64 << 10
)

var (
	reJavaScriptBundleTable = regexp.MustCompile(`(?m)^[\t ]*(?:const|let|var)[\t ]+([A-Za-z_$][A-Za-z0-9_$]{0,127})[\t ]*=[\t ]*\{`)
	reJavaScriptBundleEntry = regexp.MustCompile(`(?m)^[\t ]*(0[xX][0-9A-Fa-f]+|[0-9]+)[\t ]*:[\t ]*([A-Za-z_$][A-Za-z0-9_$]{0,127})[\t ]*=>[\t ]*\{`)
	reJavaScriptBundleFunc  = regexp.MustCompile(`(?m)^[\t ]*function[\t ]+([A-Za-z_$][A-Za-z0-9_$]{0,127})[\t ]*\([\t ]*([A-Za-z_$][A-Za-z0-9_$]{0,127})[\t ]*\)[\t ]*\{`)

	reJavaScriptBundleModuleAlias = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*\(\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)\s*;?\s*$`)
	reJavaScriptBundleMethodAlias = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\.([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*;?\s*$`)
)

type javaScriptBundleModule struct {
	kind          string
	specifier     string
	literalLine   int
	literalColumn int
	proof         javaScriptCommandProof
}

type javaScriptBundleLoader struct {
	name    string
	modules map[uint64]javaScriptBundleModule
	proof   javaScriptCommandProof
}

type javaScriptBundleAlias struct {
	module javaScriptBundleModule
	proofs []javaScriptCommandProof
}

type javaScriptBundleResolution struct {
	statements   []javaScriptCommandStatement
	observations []javaScriptBundleModule
	partial      bool
	detail       string
}

// resolveJavaScriptBundleBindings is a closed normalization pass for the
// canonical numeric module-table form emitted by common JavaScript bundlers.
// It neither executes the loader nor evaluates arbitrary expressions. A module
// is admitted only when its wrapper is exactly an optional use-strict directive
// followed by module.exports=require(<supported builtin>), and a loader is
// admitted only when one exact dispatch/return pair connects that table to its
// exports object. Synthetic declarations feed the ordinary typed JavaScript
// recognizers; all evidence remains on the original wrapper, loader, and alias
// source lines.
func resolveJavaScriptBundleBindings(
	lines []string,
	statements []javaScriptCommandStatement,
) javaScriptBundleResolution {
	result := javaScriptBundleResolution{statements: statements}
	normalized := make([]string, len(lines))
	for index, line := range lines {
		normalized[index] = strings.TrimSuffix(line, "\r")
	}
	source := strings.Join(normalized, "\n")
	if len(source) > maxJavaScriptBundleBytes {
		if reJavaScriptBundleTable.FindStringIndex(source[:maxJavaScriptBundleBytes]) != nil {
			result.partial = true
			result.detail = fmt.Sprintf("JavaScript bundle analysis byte limit %d reached; numeric module aliases were not normalized", maxJavaScriptBundleBytes)
		}
		return result
	}

	tables, tablePartial := javaScriptBundleTables(source, normalized)
	if tablePartial != "" {
		result.partial = true
		result.detail = tablePartial
	}
	if len(tables) == 0 {
		return result
	}
	result.observations = javaScriptBundleModuleObservations(tables)
	loaders, loaderPartial := javaScriptBundleLoaders(source, normalized, tables)
	if loaderPartial != "" && result.detail == "" {
		result.partial = true
		result.detail = loaderPartial
	}
	if len(loaders) == 0 {
		return result
	}

	moduleAliases := map[string]javaScriptBundleAlias{}
	retainedModuleAliasLines := map[int]bool{}
	for index := range result.statements {
		statement := &result.statements[index]
		if statement.scopeKey != "" {
			continue
		}
		match := reJavaScriptBundleModuleAlias.FindStringSubmatch(statement.text)
		if len(match) != 4 {
			continue
		}
		loader, ok := loaders[match[2]]
		if !ok {
			continue
		}
		moduleID, ok := parseJavaScriptBundleModuleID(match[3])
		if !ok {
			continue
		}
		module, ok := loader.modules[moduleID]
		if !ok {
			continue
		}
		aliasProof := javaScriptCommandProof{
			line:  statement.line,
			kind:  "javascript-bundle-module-binding",
			value: statement.evidenceText,
		}
		statement.bindingProofs = mergeJavaScriptCommandProofs(
			[]javaScriptCommandProof{module.proof, loader.proof, aliasProof},
			statement.bindingProofs,
		)
		switch module.kind {
		case "child_process":
			statement.text = fmt.Sprintf(`import * as %s from "child_process";`, match[1])
		case "os", "fs", "fs/promises", "dns", "dns/promises":
			statement.text = fmt.Sprintf(`import * as %s from %q;`, match[1], module.kind)
		default:
			continue
		}
		if _, duplicate := moduleAliases[match[1]]; duplicate {
			delete(moduleAliases, match[1])
			result.partial = true
			if result.detail == "" {
				result.detail = "JavaScript bundle module alias was declared more than once; the ambiguous alias was not normalized"
			}
			continue
		}
		moduleAliases[match[1]] = javaScriptBundleAlias{
			module: module,
			proofs: append([]javaScriptCommandProof(nil), statement.bindingProofs...),
		}
		retainedModuleAliasLines[statement.line] = true
	}
	if javaScriptBundleHasHiddenModuleAlias(normalized, loaders, retainedModuleAliasLines) {
		result.partial = true
		if result.detail == "" {
			result.detail = "exact numeric bundle module aliases occurred outside supported module/function statements; affected alias calls were not correlated"
		}
	}

	for index := range result.statements {
		statement := &result.statements[index]
		if statement.scopeKey != "" {
			continue
		}
		match := reJavaScriptBundleMethodAlias.FindStringSubmatch(statement.text)
		if len(match) != 4 {
			continue
		}
		alias, ok := moduleAliases[match[2]]
		if !ok || alias.module.kind != "child_process" {
			continue
		}
		method := normalizeJavaScriptProcessMethod(match[3])
		if method == "" {
			continue
		}
		aliasProof := javaScriptCommandProof{
			line:  statement.line,
			kind:  "javascript-bundle-method-binding",
			value: statement.evidenceText,
		}
		statement.bindingProofs = mergeJavaScriptCommandProofs(
			alias.proofs,
			statement.bindingProofs,
			[]javaScriptCommandProof{aliasProof},
		)
		statement.text = fmt.Sprintf(`import {%s as %s} from "child_process";`, method, match[1])
	}
	return result
}

func javaScriptBundleTables(source string, lines []string) (map[string]map[uint64]javaScriptBundleModule, string) {
	tables := map[string]map[uint64]javaScriptBundleModule{}
	for _, match := range reJavaScriptBundleTable.FindAllStringSubmatchIndex(source, maxJavaScriptBundleTables+1) {
		if len(match) != 4 {
			continue
		}
		if len(tables) >= maxJavaScriptBundleTables {
			return nil, fmt.Sprintf("JavaScript bundle table limit %d reached; numeric module aliases were not normalized", maxJavaScriptBundleTables)
		}
		name := source[match[2]:match[3]]
		open := match[1] - 1
		limit := min(len(source), open+maxJavaScriptBundleContainerBytes)
		close, ok := scanJavaScriptSyntax(source, open+1, limit, '{', nil)
		if !ok {
			continue
		}
		body := source[open+1 : close]
		modules := map[uint64]javaScriptBundleModule{}
		duplicates := map[uint64]bool{}
		for _, entry := range reJavaScriptBundleEntry.FindAllStringSubmatchIndex(body, maxJavaScriptBundleModules+1) {
			if len(entry) != 6 {
				continue
			}
			if len(modules)+len(duplicates) >= maxJavaScriptBundleModules {
				return nil, fmt.Sprintf("JavaScript bundle module limit %d reached; numeric module aliases were not normalized", maxJavaScriptBundleModules)
			}
			moduleID, parsed := parseJavaScriptBundleModuleID(body[entry[2]:entry[3]])
			if !parsed {
				continue
			}
			parameter := body[entry[4]:entry[5]]
			entryOpen := open + 1 + entry[1] - 1
			entryLimit := min(close, entryOpen+maxJavaScriptBundleFunctionBytes)
			entryClose, balanced := scanJavaScriptSyntax(source, entryOpen+1, entryLimit, '{', nil)
			if !balanced || entryClose > close {
				continue
			}
			wrapperBody := source[entryOpen+1 : entryClose]
			kind, specifier, literalOffset, exact := exactJavaScriptBundleBuiltinWrapper(wrapperBody, parameter)
			if !exact {
				continue
			}
			proofOffset := strings.Index(source[entryOpen+1:entryClose], parameter+".exports")
			if proofOffset < 0 {
				continue
			}
			proofLine := javaScriptBundleLineAt(source, entryOpen+1+proofOffset)
			literalLine, literalColumn := javaScriptBundleLineAndColumnAt(source, entryOpen+1+literalOffset)
			module := javaScriptBundleModule{
				kind: kind, specifier: specifier,
				literalLine: literalLine, literalColumn: literalColumn,
				proof: javaScriptCommandProof{
					line:  proofLine,
					kind:  "javascript-bundle-module-wrapper",
					value: javaScriptBundleEvidenceLine(lines, proofLine),
				},
			}
			if _, exists := modules[moduleID]; exists {
				delete(modules, moduleID)
				duplicates[moduleID] = true
				continue
			}
			if !duplicates[moduleID] {
				modules[moduleID] = module
			}
		}
		if len(modules) == 0 {
			continue
		}
		if _, duplicate := tables[name]; duplicate {
			delete(tables, name)
			continue
		}
		tables[name] = modules
	}
	return tables, ""
}

func javaScriptBundleLoaders(source string, lines []string, tables map[string]map[uint64]javaScriptBundleModule) (map[string]javaScriptBundleLoader, string) {
	loaders := map[string]javaScriptBundleLoader{}
	duplicates := map[string]bool{}
	functions := reJavaScriptBundleFunc.FindAllStringSubmatchIndex(source, maxJavaScriptBundleFunctions+1)
	if len(functions) > maxJavaScriptBundleFunctions {
		return nil, fmt.Sprintf("JavaScript bundle function limit %d reached; numeric module aliases were not normalized", maxJavaScriptBundleFunctions)
	}
	for _, match := range functions {
		if len(match) != 6 {
			continue
		}
		name := source[match[2]:match[3]]
		parameter := source[match[4]:match[5]]
		open := match[1] - 1
		limit := min(len(source), open+maxJavaScriptBundleFunctionBytes)
		close, ok := scanJavaScriptSyntax(source, open+1, limit, '{', nil)
		if !ok {
			continue
		}
		body := source[open+1 : close]
		var candidates []javaScriptBundleLoader
		for table, modules := range tables {
			dispatch := regexp.MustCompile(
				`(?:^|[;}])\s*` + regexp.QuoteMeta(table) + `\s*\[\s*` + regexp.QuoteMeta(parameter) + `\s*\]\s*` +
					`\(\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*,\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*\.\s*exports\s*,\s*([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*\)\s*;\s*` +
					`return\s+([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*\.\s*exports\s*;?\s*$`,
			)
			matches := dispatch.FindAllStringSubmatchIndex(body, 2)
			if len(matches) != 1 || len(matches[0]) != 10 {
				continue
			}
			found := matches[0]
			moduleOne := body[found[2]:found[3]]
			moduleTwo := body[found[4]:found[5]]
			loaderArg := body[found[6]:found[7]]
			returned := body[found[8]:found[9]]
			if moduleOne != moduleTwo || moduleOne != returned || loaderArg != name {
				continue
			}
			proofOffset := found[0]
			for proofOffset < len(body) && (body[proofOffset] == ';' || body[proofOffset] == '}') {
				proofOffset++
			}
			proofLine := javaScriptBundleLineAt(source, open+1+proofOffset)
			candidates = append(candidates, javaScriptBundleLoader{
				name:    name,
				modules: modules,
				proof: javaScriptCommandProof{
					line:  proofLine,
					kind:  "javascript-bundle-loader-dispatch",
					value: javaScriptBundleEvidenceLine(lines, proofLine),
				},
			})
		}
		if len(candidates) != 1 {
			continue
		}
		if _, exists := loaders[name]; exists {
			delete(loaders, name)
			duplicates[name] = true
			continue
		}
		if !duplicates[name] {
			loaders[name] = candidates[0]
		}
	}
	return loaders, ""
}

func exactJavaScriptBundleBuiltinWrapper(body, parameter string) (kind, specifier string, literalOffset int, exact bool) {
	for _, module := range []string{
		"child_process", "node:child_process", "os", "node:os",
		"fs", "node:fs", "fs/promises", "node:fs/promises",
		"dns", "node:dns", "dns/promises", "node:dns/promises",
	} {
		for _, quote := range []string{`"`, `'`} {
			quoted := quote + module + quote
			grammar := regexp.MustCompile(
				`^\s*(?:(?:"use strict"|'use strict')\s*;\s*)?` +
					regexp.QuoteMeta(parameter) + `\s*\.\s*exports\s*=\s*require\s*\(\s*` +
					regexp.QuoteMeta(quoted) + `\s*\)\s*;\s*$`,
			)
			if !grammar.MatchString(body) {
				continue
			}
			offset := strings.Index(body, quoted)
			if offset < 0 {
				return "", "", 0, false
			}
			return strings.TrimPrefix(module, "node:"), module, offset + len(quote), true
		}
	}
	return "", "", 0, false
}

func javaScriptBundleModuleObservations(tables map[string]map[uint64]javaScriptBundleModule) []javaScriptBundleModule {
	seen := map[string]bool{}
	var observations []javaScriptBundleModule
	for _, modules := range tables {
		for _, module := range modules {
			key := fmt.Sprintf("%s\x00%d\x00%d", module.specifier, module.literalLine, module.literalColumn)
			if module.specifier == "" || seen[key] {
				continue
			}
			seen[key] = true
			observations = append(observations, module)
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].literalLine != observations[j].literalLine {
			return observations[i].literalLine < observations[j].literalLine
		}
		if observations[i].literalColumn != observations[j].literalColumn {
			return observations[i].literalColumn < observations[j].literalColumn
		}
		return observations[i].specifier < observations[j].specifier
	})
	return observations
}

func javaScriptBundleHasHiddenModuleAlias(lines []string, loaders map[string]javaScriptBundleLoader, retained map[int]bool) bool {
	for index, line := range lines {
		match := reJavaScriptBundleModuleAlias.FindStringSubmatch(line)
		if len(match) != 4 || retained[index+1] {
			continue
		}
		loader, ok := loaders[match[2]]
		if !ok {
			continue
		}
		moduleID, parsed := parseJavaScriptBundleModuleID(match[3])
		if parsed {
			if _, exists := loader.modules[moduleID]; exists {
				return true
			}
		}
	}
	return false
}

func parseJavaScriptBundleModuleID(value string) (uint64, bool) {
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	parsed, err := strconv.ParseUint(value, base, 64)
	return parsed, err == nil
}

func javaScriptBundleLineAt(source string, offset int) int {
	if offset < 0 || offset > len(source) {
		return 0
	}
	return 1 + strings.Count(source[:offset], "\n")
}

func javaScriptBundleLineAndColumnAt(source string, offset int) (int, int) {
	if offset < 0 || offset > len(source) {
		return 0, 0
	}
	line := javaScriptBundleLineAt(source, offset)
	lineStart := strings.LastIndex(source[:offset], "\n") + 1
	return line, offset - lineStart
}

func javaScriptBundleEvidenceLine(lines []string, line int) string {
	if line <= 0 || line > len(lines) {
		return ""
	}
	return strings.TrimSuffix(lines[line-1], "\r")
}
