package extract

import "strings"

type archiveParseDisposition string

const (
	archiveParseRecognized  archiveParseDisposition = "recognized"
	archiveParseUnsupported archiveParseDisposition = "unsupported"
	archiveParseMalformed   archiveParseDisposition = "malformed"
)

// archiveCommandResult is the single semantic result of bounded archive argv
// parsing. Callers must not infer archive behavior independently from the raw
// argv: unsupported syntax fails closed and malformed invocations emit no
// modeled behavior.
type archiveCommandResult struct {
	Disposition       archiveParseDisposition
	CreatesOutput     bool
	ExtractsArchive   bool
	OutputPath        string
	InputPath         string
	ExtractionTarget  string
	TargetProvided    bool
	LocalSources      []string
	UsesSourceList    bool
	ReadsLocalSources bool
	CoverageDetail    string
}

func parseArchiveCommand(tool string, fields []string) archiveCommandResult {
	if len(fields) == 0 {
		return malformedArchiveCommand()
	}
	switch tool {
	case "tar":
		return parseTarCommand(fields[1:])
	case "zip":
		return parseZipCommand(fields[1:])
	case "unzip":
		return parseUnzipCommand(fields[1:])
	case "ditto":
		return parseDittoCommand(fields[1:])
	default:
		return unsupportedArchiveCommand(tool)
	}
}

func malformedArchiveCommand() archiveCommandResult {
	return archiveCommandResult{Disposition: archiveParseMalformed}
}

func unsupportedArchiveCommand(tool string) archiveCommandResult {
	return archiveCommandResult{
		Disposition:    archiveParseUnsupported,
		CoverageDetail: tool + " option syntax is outside the bounded archive model; archive behavior was not inferred",
	}
}

type tarModes struct {
	create      bool
	extract     bool
	toStdout    bool
	list        bool
	append      bool
	update      bool
	concatenate bool
}

func (m tarModes) count() int {
	count := 0
	for _, present := range []bool{m.create, m.extract, m.list, m.append, m.update, m.concatenate} {
		if present {
			count++
		}
	}
	return count
}

func (m *tarModes) add(option byte) {
	switch option {
	case 'c':
		m.create = true
	case 'x':
		m.extract = true
	case 'O':
		m.toStdout = true
	case 't':
		m.list = true
	case 'r':
		m.append = true
	case 'u':
		m.update = true
	case 'A':
		m.concatenate = true
	}
}

func parseTarCommand(args []string) archiveCommandResult {
	var modes tarModes
	var output string
	var sources []string
	var sourceList bool
	var extractionTarget string
	extractionTargets := 0
	nonOperational := false
	index := 0

	if len(args) > 0 {
		candidate, supported, oldModes, hasFile := parseTarOldStyle(args[0])
		if candidate {
			if !supported {
				return unsupportedArchiveCommand("tar")
			}
			modes = oldModes
			index = 1
			if hasFile {
				if index >= len(args) {
					return malformedArchiveCommand()
				}
				output = args[index]
				if output == "" {
					return malformedArchiveCommand()
				}
				index++
			}
		}
	}

	options := true
	for index < len(args) {
		field := args[index]
		if options && field == "--" {
			options = false
			index++
			continue
		}
		if !options || field == "-" || !strings.HasPrefix(field, "-") {
			sources = append(sources, field)
			index++
			continue
		}
		if strings.HasPrefix(field, "--") {
			name, value, inline := splitLongOption(field)
			switch {
			case tarLongMode(name) != 0:
				if inline {
					return unsupportedArchiveCommand("tar")
				}
				modes.add(tarLongMode(name))
				index++
			case name == "--help" || name == "--version":
				if inline {
					return unsupportedArchiveCommand("tar")
				}
				nonOperational = true
				index++
			case tarLongFlag(name):
				if inline {
					return unsupportedArchiveCommand("tar")
				}
				if name == "--to-stdout" {
					modes.toStdout = true
				}
				index++
			case tarLongValueOption(name):
				if !inline {
					if index+1 >= len(args) {
						return malformedArchiveCommand()
					}
					value = args[index+1]
					index += 2
				} else {
					index++
				}
				if tarValueMustBeNonEmpty(name) && value == "" {
					return malformedArchiveCommand()
				}
				switch name {
				case "--file":
					output = value
				case "--files-from":
					sourceList = true
				case "--directory", "--cd":
					extractionTargets++
					extractionTarget = value
				}
			default:
				return unsupportedArchiveCommand("tar")
			}
			continue
		}

		cluster := strings.TrimPrefix(field, "-")
		if cluster == "" {
			sources = append(sources, field)
			index++
			continue
		}
		consumedNext := false
		for offset := 0; offset < len(cluster); offset++ {
			option := cluster[offset]
			switch {
			case strings.ContainsRune("cxtrAu", rune(option)):
				modes.add(option)
			case strings.ContainsRune("vwjJzkmOph", rune(option)):
				// Supported value-free tar switch.
				if option == 'O' {
					modes.toStdout = true
				}
			case strings.ContainsRune("fCXTIgbs", rune(option)):
				value := cluster[offset+1:]
				if value == "" {
					if index+1 >= len(args) {
						return malformedArchiveCommand()
					}
					value = args[index+1]
					consumedNext = true
				}
				if strings.ContainsRune("fCTI", rune(option)) && value == "" {
					return malformedArchiveCommand()
				}
				switch option {
				case 'f':
					output = value
				case 'C':
					extractionTargets++
					extractionTarget = value
				case 'T', 'I':
					// bsdtar documents -I as a synonym for -T. Maratus
					// follows the macOS tool rather than GNU tar's meaning.
					sourceList = true
				}
				offset = len(cluster)
			default:
				return unsupportedArchiveCommand("tar")
			}
		}
		index++
		if consumedNext {
			index++
		}
	}

	if nonOperational {
		return archiveCommandResult{Disposition: archiveParseRecognized}
	}
	if modes.count() != 1 {
		return malformedArchiveCommand()
	}
	sources = nonEmptyStrings(sources)
	hasSources := len(sources) > 0 || sourceList
	if (modes.create || modes.append || modes.update) && !hasSources {
		return malformedArchiveCommand()
	}
	if (modes.append || modes.update) && (output == "" || output == "-") {
		return malformedArchiveCommand()
	}
	if extractionTargets != 1 {
		extractionTarget = ""
	}
	extractsArchive := modes.extract && !modes.toStdout && output != "" && output != "-"
	inputPath := ""
	if extractsArchive {
		inputPath = output
	} else {
		extractionTarget = ""
	}
	return archiveCommandResult{
		Disposition:       archiveParseRecognized,
		CreatesOutput:     modes.create && output != "" && output != "-" && hasSources,
		ExtractsArchive:   extractsArchive,
		OutputPath:        output,
		InputPath:         inputPath,
		ExtractionTarget:  extractionTarget,
		TargetProvided:    extractsArchive && extractionTargets > 0,
		LocalSources:      sources,
		UsesSourceList:    sourceList,
		ReadsLocalSources: (modes.create || modes.append || modes.update) && len(sources) > 0,
	}
}

func parseTarOldStyle(field string) (candidate, supported bool, modes tarModes, hasFile bool) {
	if field == "" || strings.HasPrefix(field, "-") || strings.ContainsAny(field, `/\.`) {
		return false, false, modes, false
	}
	for index := 0; index < len(field); index++ {
		if strings.ContainsRune("cxtrAu", rune(field[index])) {
			candidate = true
			break
		}
	}
	if !candidate {
		return false, false, modes, false
	}
	for index := 0; index < len(field); index++ {
		option := field[index]
		switch {
		case strings.ContainsRune("cxtrAu", rune(option)):
			modes.add(option)
		case strings.ContainsRune("vwjJzkmOph", rune(option)):
			if option == 'O' {
				modes.toStdout = true
			}
		case option == 'f' && !hasFile:
			hasFile = true
		default:
			return true, false, tarModes{}, false
		}
	}
	return true, true, modes, hasFile
}

func tarLongMode(name string) byte {
	switch name {
	case "--create":
		return 'c'
	case "--extract", "--get":
		return 'x'
	case "--list":
		return 't'
	case "--append":
		return 'r'
	case "--update":
		return 'u'
	case "--concatenate":
		return 'A'
	default:
		return 0
	}
}

func tarLongValueOption(name string) bool {
	switch name {
	case "--file", "--directory", "--exclude-from", "--files-from", "--use-compress-program",
		"--listed-incremental", "--block-size", "--cd", "--format", "--gid", "--gname",
		"--include", "--newer", "--newer-ctime", "--newer-mtime", "--newer-than",
		"--older", "--older-ctime", "--older-mtime", "--older-than", "--options",
		"--passphrase", "--uid", "--uname", "--exclude", "--transform", "--strip-components",
		"--owner", "--group", "--mode", "--mtime", "--after-date", "--checkpoint-action":
		return true
	default:
		return false
	}
}

func tarValueMustBeNonEmpty(name string) bool {
	switch name {
	case "--file", "--files-from", "--format", "--directory", "--cd":
		return true
	default:
		return false
	}
}

func tarLongFlag(name string) bool {
	switch name {
	case "--gzip", "--gunzip", "--ungzip", "--bzip2", "--xz", "--lzma", "--auto-compress", "--to-stdout",
		"--dereference", "--hard-dereference", "--ignore-case", "--no-recursion", "--one-file-system",
		"--preserve-permissions", "--same-permissions", "--verbose", "--interactive", "--keep-old-files",
		"--keep-newer-files", "--unlink-first", "--numeric-owner", "--acls", "--xattrs":
		return true
	default:
		return false
	}
}

func parseZipCommand(args []string) archiveCommandResult {
	var operands []string
	var explicitOutput string
	var hasExplicitOutput bool
	var sourceList bool
	nonOperational := false
	maintenance := false
	options := true

	for index := 0; index < len(args); {
		field := args[index]
		if options && field == "--" {
			options = false
			index++
			continue
		}
		if !options || field == "-" || !strings.HasPrefix(field, "-") {
			operands = append(operands, field)
			index++
			continue
		}
		if field == "-@" {
			sourceList = true
			index++
			continue
		}
		if field == "-i" || field == "-x" || field == "--include" || field == "--exclude" {
			next, ok := skipZipPatternList(args, index+1)
			if !ok {
				return malformedArchiveCommand()
			}
			index = next
			continue
		}
		if zipNonOperationalOption(field) {
			nonOperational = true
			index++
			continue
		}
		if zipMaintenanceOption(field) {
			maintenance = true
			index++
			continue
		}
		if zipExactFlag(field) {
			index++
			continue
		}
		if strings.HasPrefix(field, "--") {
			name, value, inline := splitLongOption(field)
			if name == "--include" || name == "--exclude" {
				if !inline || value == "" {
					return malformedArchiveCommand()
				}
				index++
				continue
			}
			if zipLongFlag(name) {
				if inline {
					return unsupportedArchiveCommand("zip")
				}
				index++
				continue
			}
			if !zipLongValueOption(name) {
				return unsupportedArchiveCommand("zip")
			}
			if !inline {
				if index+1 >= len(args) {
					return malformedArchiveCommand()
				}
				value = args[index+1]
				index += 2
			} else {
				index++
			}
			if zipOutputOption(name) {
				value = strings.TrimPrefix(value, "=")
				if value == "" {
					return malformedArchiveCommand()
				}
				explicitOutput = value
				hasExplicitOutput = true
			}
			continue
		}

		cluster, value, consumesNext, outputValue, disposition := parseZipShortOption(field)
		_ = cluster
		if disposition == archiveParseUnsupported {
			return unsupportedArchiveCommand("zip")
		}
		if disposition == archiveParseMalformed {
			return malformedArchiveCommand()
		}
		if consumesNext {
			if index+1 >= len(args) {
				return malformedArchiveCommand()
			}
			value = args[index+1]
			index += 2
		} else {
			index++
		}
		if outputValue {
			value = strings.TrimPrefix(value, "=")
			if value == "" {
				return malformedArchiveCommand()
			}
			explicitOutput = value
			hasExplicitOutput = true
		}
	}

	if nonOperational || maintenance {
		return archiveCommandResult{Disposition: archiveParseRecognized}
	}
	if len(operands) == 0 {
		return malformedArchiveCommand()
	}
	output := operands[0]
	if hasExplicitOutput {
		output = explicitOutput
	}
	hasPayload := len(operands) >= 2 || sourceList
	if !hasPayload {
		return malformedArchiveCommand()
	}
	sources := nonEmptyNonDashStrings(operands[1:])
	return archiveCommandResult{
		Disposition:       archiveParseRecognized,
		CreatesOutput:     output != "" && output != "-",
		OutputPath:        output,
		LocalSources:      sources,
		UsesSourceList:    sourceList,
		ReadsLocalSources: len(sources) > 0,
	}
}

func skipZipPatternList(args []string, index int) (int, bool) {
	count := 0
	for index < len(args) {
		field := args[index]
		if field == "@" {
			return index + 1, count > 0
		}
		if strings.HasPrefix(field, "-") {
			return index, count > 0
		}
		count++
		index++
	}
	return index, count > 0
}

func zipNonOperationalOption(field string) bool {
	switch field {
	case "-h", "-h2", "--help", "--more-help", "--version", "-L", "--license",
		"-so", "--show-options", "--show-command", "--show-just-unicode", "-sc", "-sU", "-sf", "-su":
		return true
	default:
		return false
	}
}

func zipMaintenanceOption(field string) bool {
	switch field {
	case "-d", "--delete", "-F", "-FF", "--fix", "-A", "--adjust-sfx", "-U", "--copy", "--copy-entries":
		return true
	default:
		return strings.HasPrefix(field, "--delete=")
	}
}

func zipExactFlag(field string) bool {
	switch field {
	case "-db", "-dc", "-dd", "-df", "-dg", "-du", "-dv", "-DF", "-FI", "-FS", "-AS", "-AC":
		return true
	default:
		return false
	}
}

func zipLongFlag(name string) bool {
	switch name {
	case "--recurse-paths", "--junk-paths", "--quiet", "--verbose", "--update", "--freshen", "--grow",
		"--move", "--symlinks", "--no-dir-entries", "--no-extra", "--junk-sfx", "--encrypt", "--test":
		return true
	default:
		return false
	}
}

func zipLongValueOption(name string) bool {
	switch name {
	case "--password", "--temp-path", "--output-file", "--out", "--from-date", "--before-date",
		"--unzip-command", "--compression-method", "--split-size", "--logfile-path", "--suffixes", "--unicode":
		return true
	default:
		return false
	}
}

func zipOutputOption(name string) bool {
	return name == "--output-file" || name == "--out"
}

func parseZipShortOption(field string) (cluster, value string, consumesNext, output bool, disposition archiveParseDisposition) {
	if !strings.HasPrefix(field, "-") || strings.HasPrefix(field, "--") || field == "-" {
		return "", "", false, false, archiveParseUnsupported
	}
	cluster = strings.TrimPrefix(field, "-")
	for index := 0; index < len(cluster); index++ {
		for _, pair := range []string{"TT", "tt", "lf", "UN", "ds"} {
			if !strings.HasPrefix(cluster[index:], pair) {
				continue
			}
			valueIndex := index + len(pair)
			if valueIndex < len(cluster) {
				return cluster, cluster[valueIndex:], false, false, archiveParseRecognized
			}
			return cluster, "", true, false, archiveParseRecognized
		}
		option := cluster[index]
		if strings.ContainsRune("PbOtZsn", rune(option)) {
			valueIndex := index + 1
			if valueIndex < len(cluster) {
				return cluster, cluster[valueIndex:], false, option == 'O', archiveParseRecognized
			}
			return cluster, "", true, option == 'O', archiveParseRecognized
		}
		if strings.ContainsRune("dFAU", rune(option)) {
			// Maintenance switches inside a cluster are accepted, but the
			// caller handles exact maintenance forms before reaching here.
			return cluster, "", false, false, archiveParseUnsupported
		}
		if !strings.ContainsRune("0123456789rjqvufgmyDXJeTkc", rune(option)) {
			return cluster, "", false, false, archiveParseUnsupported
		}
	}
	return cluster, "", false, false, archiveParseRecognized
}

func parseUnzipCommand(args []string) archiveCommandResult {
	var operands []string
	target := ""
	targets := 0
	excludes := false
	nonOperational := false
	streamOutput := false
	options := true

	for index := 0; index < len(args); {
		field := args[index]
		if options && field == "--" {
			options = false
			index++
			continue
		}
		if !options || field == "-" || !strings.HasPrefix(field, "-") {
			if !excludes {
				operands = append(operands, field)
			}
			index++
			continue
		}
		switch field {
		case "-h", "-hh", "--help", "--version":
			nonOperational = true
			index++
			continue
		case "-x":
			if len(operands) == 0 {
				return malformedArchiveCommand()
			}
			excludes = true
			index++
			continue
		case "-d":
			if index+1 >= len(args) || args[index+1] == "" {
				return malformedArchiveCommand()
			}
			target = args[index+1]
			targets++
			index += 2
			continue
		case "-P", "-O", "-I":
			if index+1 >= len(args) || args[index+1] == "" {
				return malformedArchiveCommand()
			}
			index += 2
			continue
		}
		if strings.HasPrefix(field, "-d") && len(field) > 2 {
			target = field[2:]
			targets++
			index++
			continue
		}
		clusterNonOperational, clusterStream, supported := unzipOptionCluster(strings.TrimPrefix(field, "-"))
		if !supported {
			return unsupportedArchiveCommand("unzip")
		}
		nonOperational = nonOperational || clusterNonOperational
		streamOutput = streamOutput || clusterStream
		index++
	}

	if nonOperational || streamOutput {
		return archiveCommandResult{Disposition: archiveParseRecognized}
	}
	if len(operands) == 0 || operands[0] == "" || operands[0] == "-" {
		return malformedArchiveCommand()
	}
	if targets != 1 {
		target = ""
	}
	return archiveCommandResult{
		Disposition:      archiveParseRecognized,
		ExtractsArchive:  true,
		InputPath:        operands[0],
		ExtractionTarget: target,
		TargetProvided:   targets > 0,
	}
}

func unzipOptionCluster(cluster string) (nonOperational, streamOutput, supported bool) {
	if cluster == "" {
		return false, false, false
	}
	for _, option := range cluster {
		switch {
		case strings.ContainsRune("qonjkKXDUULaCMVWBbs", option):
		case strings.ContainsRune("lvtzZ", option):
			nonOperational = true
		case strings.ContainsRune("cp", option):
			streamOutput = true
		default:
			return false, false, false
		}
	}
	return nonOperational, streamOutput, true
}

func parseDittoCommand(args []string) archiveCommandResult {
	var operands []string
	create := false
	extract := false
	nonOperational := false
	options := true

	for index := 0; index < len(args); {
		field := args[index]
		if options && field == "--" {
			options = false
			index++
			continue
		}
		if !options || field == "-" || !strings.HasPrefix(field, "-") {
			operands = append(operands, field)
			index++
			continue
		}
		if field == "-h" || field == "--help" {
			nonOperational = true
			index++
			continue
		}
		if strings.HasPrefix(field, "--") {
			name, value, inline := splitLongOption(field)
			if dittoLongValueOption(name) {
				if !inline {
					if index+1 >= len(args) {
						return malformedArchiveCommand()
					}
					value = args[index+1]
					index += 2
				} else {
					index++
				}
				if value == "" {
					return malformedArchiveCommand()
				}
				continue
			}
			if !dittoLongFlag(name) || inline {
				return unsupportedArchiveCommand("ditto")
			}
			index++
			continue
		}
		if field == "-b" || field == "-o" {
			if index+1 >= len(args) {
				return malformedArchiveCommand()
			}
			index += 2
			continue
		}
		cluster := strings.TrimPrefix(field, "-")
		if cluster == "" {
			operands = append(operands, field)
			index++
			continue
		}
		for offset := 0; offset < len(cluster); offset++ {
			switch cluster[offset] {
			case 'c':
				create = true
			case 'x':
				extract = true
			case 'v', 'V', 'X', 'z', 'j', 'k':
			default:
				return unsupportedArchiveCommand("ditto")
			}
		}
		index++
	}

	if nonOperational {
		return archiveCommandResult{Disposition: archiveParseRecognized}
	}
	if create && extract {
		return malformedArchiveCommand()
	}
	if len(operands) < 2 {
		return malformedArchiveCommand()
	}
	if extract && len(operands) != 2 {
		return unsupportedArchiveCommand("ditto")
	}
	output := operands[len(operands)-1]
	sources := nonEmptyNonDashStrings(operands[:len(operands)-1])
	input := ""
	if extract && len(sources) == 1 {
		input = sources[0]
	}
	return archiveCommandResult{
		Disposition:       archiveParseRecognized,
		CreatesOutput:     create && output != "" && output != "-",
		ExtractsArchive:   extract && input != "" && input != "-" && output != "" && output != "-",
		OutputPath:        output,
		InputPath:         input,
		ExtractionTarget:  output,
		TargetProvided:    extract,
		LocalSources:      sources,
		ReadsLocalSources: !extract && len(sources) > 0,
	}
}

func dittoLongValueOption(name string) bool {
	switch name {
	case "--arch", "--bom", "--zlibCompressionLevel", "--keepBinariesList", "--keepBinariesPattern",
		"--lang", "--outBom", "--option":
		return true
	default:
		return false
	}
}

func dittoLongFlag(name string) bool {
	switch name {
	case "--keepParent", "--rsrc", "--norsrc", "--extattr", "--noextattr", "--qtn", "--noqtn",
		"--acl", "--noacl", "--sequesterRsrc", "--password", "--hfsCompression", "--nohfsCompression",
		"--preserveHFSCompression", "--nopreserveHFSCompression", "--nocache", "--nonAtomicCopies",
		"--segmentLargeFiles", "--persistRootless", "--nopersistRootless", "--keepBinaries", "--clone", "--noclone":
		return true
	default:
		return false
	}
}

func splitLongOption(field string) (name, value string, inline bool) {
	if separator := strings.IndexByte(field, '='); separator >= 0 {
		return field[:separator], field[separator+1:], true
	}
	return field, "", false
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func nonEmptyNonDashStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && value != "-" {
			out = append(out, value)
		}
	}
	return out
}
