package buildinfo

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Version and Commit are set by release builds through -ldflags. Development
// builds fall back to module and VCS metadata embedded by the Go toolchain.
var (
	Version = "dev"
	Commit  = ""
)

type Info struct {
	Version  string
	Commit   string
	Modified bool
}

func Current() Info {
	info := Info{
		Version: strings.TrimSpace(Version),
		Commit:  strings.TrimSpace(Commit),
	}
	if info.Version == "" {
		info.Version = "dev"
	}

	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if info.Version == "dev" && build.Main.Version != "" && build.Main.Version != "(devel)" {
		info.Version = build.Main.Version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = setting.Value
			}
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		}
	}
	return info
}

func (i Info) String() string {
	version := strings.TrimSpace(i.Version)
	if version == "" {
		version = "dev"
	}
	commit := strings.TrimSpace(i.Commit)
	if commit == "" {
		return version
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if i.Modified {
		commit += "-dirty"
	}
	return fmt.Sprintf("%s (%s)", version, commit)
}
