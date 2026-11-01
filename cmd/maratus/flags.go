package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/0x4D31/maratus/internal/artifact"
	"github.com/0x4D31/maratus/internal/report"
	"github.com/0x4D31/maratus/internal/terminal"
)

const zipPasswordEnv = "MARATUS_ZIP_PASSWORD"

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

type presentationFlags struct {
	detail *string
	color  *string
}

func addPresentationFlags(fs *flag.FlagSet) presentationFlags {
	return presentationFlags{
		detail: fs.String("detail", "summary", "text detail: summary, evidence, or full"),
		color:  fs.String("color", "auto", "text color: auto, always, or never"),
	}
}

func (flags presentationFlags) resolve(format string) (report.TextOptions, error) {
	return flags.resolveForTerminal(format, terminal.IsTerminal(os.Stdout))
}

func (flags presentationFlags) resolveForTerminal(format string, outputIsTerminal bool) (report.TextOptions, error) {
	if flags.detail == nil || flags.color == nil {
		return report.TextOptions{}, fmt.Errorf("presentation flags were not initialized")
	}
	detail := strings.ToLower(strings.TrimSpace(*flags.detail))
	mode, err := terminal.ParseColorMode(*flags.color)
	if err != nil {
		return report.TextOptions{}, err
	}
	if format != "text" {
		if detail != "summary" {
			return report.TextOptions{}, fmt.Errorf("--detail applies only to text output")
		}
		if mode == terminal.ColorAlways {
			return report.TextOptions{}, fmt.Errorf("--color=always applies only to text output")
		}
	}
	var verbosity report.TextVerbosity
	switch detail {
	case "summary":
		verbosity = report.TextConcise
	case "evidence":
		verbosity = report.TextVerbose
	case "full":
		verbosity = report.TextVeryVerbose
	default:
		return report.TextOptions{}, fmt.Errorf("invalid --detail %q (want summary, evidence, or full)", *flags.detail)
	}
	return report.TextOptions{
		Verbosity: verbosity,
		Color: terminal.ColorEnabled(
			mode,
			outputIsTerminal,
			os.Getenv("NO_COLOR"),
			os.Getenv("TERM"),
		),
	}, nil
}

type boolFlag interface {
	IsBoolFlag() bool
}

// parseInterspersed lets commands accept options before, after, or between
// positional inputs. Whether an option consumes the following argument comes
// from the value registered on fs, so adding a flag cannot require updating a
// separate flag-arity list.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagArgs = append(flagArgs, arg)
			name, hasInlineValue := flagToken(arg)
			if !hasInlineValue && flagNeedsArgument(fs, name) {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("flag needs an argument: -%s", name)
				}
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positionals, nil
}

// wantsHelp mirrors parseInterspersed's option traversal so a literal
// "--help" used as the value of any registered string option is not mistaken
// for a help request.
func wantsHelp(fs *flag.FlagSet, args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		name, hasInlineValue := flagToken(arg)
		if name == "h" || name == "help" {
			return true
		}
		if !hasInlineValue && flagNeedsArgument(fs, name) && i+1 < len(args) {
			i++
		}
	}
	return false
}

func flagToken(arg string) (name string, hasInlineValue bool) {
	name = strings.TrimLeft(arg, "-")
	if equals := strings.IndexByte(name, '='); equals >= 0 {
		return name[:equals], true
	}
	return name, false
}

func flagNeedsArgument(fs *flag.FlagSet, name string) bool {
	registered := fs.Lookup(name)
	if registered == nil {
		return false
	}
	boolean, ok := registered.Value.(boolFlag)
	return !ok || !boolean.IsBoolFlag()
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(current *flag.Flag) {
		if current.Name == name {
			set = true
		}
	})
	return set
}

func addAnalysisFlags(fs *flag.FlagSet) func() artifact.Options {
	expandContainers := fs.Bool("expand-containers", true, "expand supported archives, packages, and disk images")
	maxFileBytes := addByteSizeFlag(fs, "max-file-bytes", artifact.DefaultMaxFileBytes, "maximum bytes to read per file")
	maxArchiveBytes := addByteSizeFlag(fs, "max-archive-bytes", artifact.DefaultMaxArchiveBytes, "maximum expanded bytes and compressed decode work per archive")
	maxExpandedBytes := addByteSizeFlag(fs, "max-expanded-bytes", artifact.DefaultMaxExpandedBytes, "maximum expanded archive bytes across the inspection")
	maxTotalBytes := addByteSizeFlag(fs, "max-total-bytes", artifact.DefaultMaxTotalBytes, "maximum retained content bytes across the inspection")
	maxArchiveDepth := fs.Int("max-archive-depth", artifact.DefaultMaxArchiveDepth, "maximum nested archive depth")
	maxDirectoryDepth := fs.Int("max-directory-depth", artifact.DefaultMaxDirectoryDepth, "maximum nested filesystem directory depth")
	maxCompressionRatio := fs.Int64("max-compression-ratio", artifact.DefaultMaxCompressionRatio, "maximum uncompressed/compressed archive entry ratio")
	maxArtifactNodes := fs.Int("max-artifact-nodes", artifact.DefaultMaxArtifactNodes, "maximum artifact nodes to model")
	maxEvidence := fs.Int("max-evidence", artifact.DefaultMaxEvidence, "maximum evidence objects to retain")
	includeUnreferenced := fs.Bool("include-unreferenced", false, "also analyze unreferenced bundled binaries, scripts, support files, plug-ins, and resources")
	allowDMGMount := fs.Bool("allow-dmg-mount", false, "macOS only: mount DMGs read-only through hdiutil")
	zipPassword := fs.String("zip-password", os.Getenv(zipPasswordEnv), "password for classic encrypted ZIP entries (prefer MARATUS_ZIP_PASSWORD)")
	architecture := fs.String("architecture", "all", "architecture filter: arm64, x86_64, i386, or all")
	return func() artifact.Options {
		return artifact.Options{
			MaxFileBytes:              *maxFileBytes,
			MaxArchiveBytes:           *maxArchiveBytes,
			MaxExpandedBytes:          *maxExpandedBytes,
			MaxTotalBytes:             *maxTotalBytes,
			MaxArchiveDepth:           *maxArchiveDepth,
			MaxDirectoryDepth:         *maxDirectoryDepth,
			MaxCompressionRatio:       *maxCompressionRatio,
			MaxArtifactNodes:          *maxArtifactNodes,
			MaxArtifactPathBytes:      artifact.DefaultMaxArtifactPathBytes,
			MaxEvidence:               *maxEvidence,
			MaxDiagnostics:            artifact.DefaultMaxDiagnostics,
			MaxDiagnosticBytes:        artifact.DefaultMaxDiagnosticBytes,
			DisableContainerExpansion: !*expandContainers,
			IncludeUnreferenced:       *includeUnreferenced,
			AllowDMGMount:             *allowDMGMount,
			Architecture:              *architecture,
			ZipPassword:               *zipPassword,
		}
	}
}

type byteSizeValue struct {
	value *int64
}

func addByteSizeFlag(fs *flag.FlagSet, name string, defaultValue int64, help string) *int64 {
	value := new(int64)
	*value = defaultValue
	fs.Var(&byteSizeValue{value: value}, name, help)
	return value
}

func (v *byteSizeValue) String() string {
	if v == nil || v.value == nil {
		return "0"
	}
	return strconv.FormatInt(*v.value, 10)
}

func (v *byteSizeValue) Set(input string) error {
	value, err := parseByteSize(input)
	if err != nil {
		return err
	}
	*v.value = value
	return nil
}

func parseByteSize(input string) (int64, error) {
	multiplier := int64(1)
	number := input
	for suffix, value := range map[string]int64{
		"KiB": 1 << 10,
		"MiB": 1 << 20,
		"GiB": 1 << 30,
	} {
		if strings.HasSuffix(input, suffix) {
			multiplier = value
			number = strings.TrimSuffix(input, suffix)
			break
		}
	}
	if number == "" {
		return 0, fmt.Errorf("invalid byte size %q (use bytes or KiB, MiB, or GiB)", input)
	}
	value, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q (use bytes or KiB, MiB, or GiB): %w", input, err)
	}
	if value > 0 && value > math.MaxInt64/multiplier || value < 0 && value < math.MinInt64/multiplier {
		return 0, fmt.Errorf("byte size %q overflows int64", input)
	}
	return value * multiplier, nil
}

func validatedOptions(options func() artifact.Options) (artifact.Options, error) {
	out := options()
	if err := validatePositiveLimits(out); err != nil {
		return artifact.Options{}, err
	}
	if out.DisableContainerExpansion && out.AllowDMGMount {
		return artifact.Options{}, fmt.Errorf("--expand-containers=false and --allow-dmg-mount cannot be combined")
	}
	arch := strings.ToLower(strings.TrimSpace(out.Architecture))
	switch arch {
	case "":
		return artifact.Options{}, fmt.Errorf("--architecture must not be empty (want arm64, x86_64, i386, or all)")
	case "all":
		out.Architecture = "all"
	case "arm64", "x86_64", "i386":
		out.Architecture = arch
	default:
		return artifact.Options{}, fmt.Errorf("invalid --architecture %q (want arm64, x86_64, i386, or all)", out.Architecture)
	}
	return out, nil
}

func validatePositiveLimits(options artifact.Options) error {
	if options.MaxFileBytes <= 0 {
		return fmt.Errorf("invalid --max-file-bytes %d (must be positive)", options.MaxFileBytes)
	}
	if options.MaxArchiveBytes <= 0 {
		return fmt.Errorf("invalid --max-archive-bytes %d (must be positive)", options.MaxArchiveBytes)
	}
	if options.MaxExpandedBytes <= 0 {
		return fmt.Errorf("invalid --max-expanded-bytes %d (must be positive)", options.MaxExpandedBytes)
	}
	if options.MaxTotalBytes <= 0 {
		return fmt.Errorf("invalid --max-total-bytes %d (must be positive)", options.MaxTotalBytes)
	}
	if options.MaxArchiveDepth <= 0 {
		return fmt.Errorf("invalid --max-archive-depth %d (must be positive)", options.MaxArchiveDepth)
	}
	if options.MaxDirectoryDepth <= 0 {
		return fmt.Errorf("invalid --max-directory-depth %d (must be positive)", options.MaxDirectoryDepth)
	}
	if options.MaxCompressionRatio <= 0 {
		return fmt.Errorf("invalid --max-compression-ratio %d (must be positive)", options.MaxCompressionRatio)
	}
	if options.MaxArtifactNodes <= 0 {
		return fmt.Errorf("invalid --max-artifact-nodes %d (must be positive)", options.MaxArtifactNodes)
	}
	if options.MaxArtifactNodes > artifact.DefaultMaxArtifactNodes {
		return fmt.Errorf("invalid --max-artifact-nodes %d (maximum %d keeps emitted reports reloadable)", options.MaxArtifactNodes, artifact.DefaultMaxArtifactNodes)
	}
	if options.MaxArtifactPathBytes <= 0 {
		return fmt.Errorf("invalid --max-artifact-path-bytes %d (must be positive)", options.MaxArtifactPathBytes)
	}
	if options.MaxEvidence <= 0 {
		return fmt.Errorf("invalid --max-evidence %d (must be positive)", options.MaxEvidence)
	}
	if options.MaxEvidence > artifact.DefaultMaxEvidence {
		return fmt.Errorf("invalid --max-evidence %d (maximum %d keeps emitted reports reloadable)", options.MaxEvidence, artifact.DefaultMaxEvidence)
	}
	if options.MaxDiagnostics <= 0 {
		return fmt.Errorf("invalid --max-diagnostics %d (must be positive)", options.MaxDiagnostics)
	}
	if options.MaxDiagnosticBytes <= 0 {
		return fmt.Errorf("invalid --max-diagnostic-bytes %d (must be positive)", options.MaxDiagnosticBytes)
	}
	return nil
}
