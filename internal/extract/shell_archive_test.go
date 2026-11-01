package extract

import "testing"

func TestArchiveCreatesOutputRejectsReadAndMaintenanceModes(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		fields []string
		want   bool
	}{
		{name: "tar short create", tool: "tar", fields: []string{"tar", "-czf", "/tmp/out.tgz", "src"}, want: true},
		{name: "tar old create", tool: "tar", fields: []string{"tar", "czf", "/tmp/out.tgz", "src"}, want: true},
		{name: "tar old file before create", tool: "tar", fields: []string{"tar", "fcv", "/tmp/out.tar", "src"}, want: true},
		{name: "tar long create", tool: "tar", fields: []string{"tar", "--create", "--file", "/tmp/out.tar", "src"}, want: true},
		{name: "tar inline file create", tool: "tar", fields: []string{"tar", "-czf/tmp/archive.tgz", "src"}, want: true},
		{name: "tar old attached file form unsupported", tool: "tar", fields: []string{"tar", "cfarchive", "src"}},
		{name: "tar old multiple value options unsupported", tool: "tar", fields: []string{"tar", "cbf", "20", "/tmp/out.tar", "src"}},
		{name: "tar operand resembles mode", tool: "tar", fields: []string{"tar", "--create", "--file", "/tmp/out.tar", "--", "-x"}, want: true},
		{name: "tar option value resembles mode", tool: "tar", fields: []string{"tar", "-c", "--exclude", "-x", "-f", "/tmp/out.tar", "src"}, want: true},
		{name: "tar inline bsdtar source list", tool: "tar", fields: []string{"tar", "-c", "-Ifiles.txt", "-f", "/tmp/out.tar"}, want: true},
		{name: "tar help", tool: "tar", fields: []string{"tar", "--help", "-cf", "/tmp/out.tar", "src"}},
		{name: "tar version", tool: "tar", fields: []string{"tar", "--version", "-cf", "/tmp/out.tar", "src"}},
		{name: "tar help as option value", tool: "tar", fields: []string{"tar", "-c", "--exclude", "--help", "-f", "/tmp/out.tar", "src"}, want: true},
		{name: "tar blocking factor value", tool: "tar", fields: []string{"tar", "-c", "-b", "20", "-f", "/tmp/out.tar", "src"}, want: true},
		{name: "tar blocking factor without source", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar", "-b", "20"}},
		{name: "tar format without source", tool: "tar", fields: []string{"tar", "-c", "--format", "pax", "-f", "/tmp/out.tar"}},
		{name: "tar format with source", tool: "tar", fields: []string{"tar", "-c", "--format", "pax", "-f", "/tmp/out.tar", "src"}, want: true},
		{name: "tar unknown short option", tool: "tar", fields: []string{"tar", "-compress", "/tmp/out.tar", "src"}},
		{name: "tar stdout archive unsupported", tool: "tar", fields: []string{"tar", "-cf", "-", "src"}},
		{name: "tar files from", tool: "tar", fields: []string{"tar", "--create", "--file", "/tmp/out.tar", "--files-from", "files.txt"}, want: true},
		{name: "tar inline files from", tool: "tar", fields: []string{"tar", "-c", "-Tfiles.txt", "-f", "/tmp/out.tar"}, want: true},
		{name: "tar files-from flag as option value", tool: "tar", fields: []string{"tar", "-c", "--exclude", "-T", "-f", "/tmp/out.tar"}},
		{name: "tar inline bsdtar source-list value", tool: "tar", fields: []string{"tar", "-c", "-IfilterTfiles", "-f", "/tmp/out.tar"}, want: true},
		{name: "tar missing source", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar"}},
		{name: "tar old style missing source", tool: "tar", fields: []string{"tar", "cf", "/tmp/out.tar"}},
		{name: "tar extract", tool: "tar", fields: []string{"tar", "-xzf", "/tmp/in.tgz"}},
		{name: "tar list", tool: "tar", fields: []string{"tar", "-tf", "/tmp/in.tar"}},
		{name: "tar append", tool: "tar", fields: []string{"tar", "-rf", "/tmp/in.tar", "src"}},
		{name: "tar file value is not mode", tool: "tar", fields: []string{"tar", "-fcreate", "src"}},
		{name: "zip create", tool: "zip", fields: []string{"zip", "-r", "/tmp/out.zip", "src"}, want: true},
		{name: "zip inline password create", tool: "zip", fields: []string{"zip", "-PABC", "/tmp/out.zip", "src"}, want: true},
		{name: "zip password containing output flag", tool: "zip", fields: []string{"zip", "-PFOOBAR", "/tmp/out.zip", "src"}, want: true},
		{name: "zip option value resembles maintenance", tool: "zip", fields: []string{"zip", "-P", "-d", "/tmp/out.zip", "src"}, want: true},
		{name: "zip inline compression method", tool: "zip", fields: []string{"zip", "-Zdeflate", "/tmp/out.zip", "src"}, want: true},
		{name: "zip combined compression method", tool: "zip", fields: []string{"zip", "-rZ", "deflate", "/tmp/out.zip", "src"}, want: true},
		{name: "zip combined suffixes", tool: "zip", fields: []string{"zip", "-rn", ".o:.c", "/tmp/out.zip", "src"}, want: true},
		{name: "zip combined unicode mode", tool: "zip", fields: []string{"zip", "-rUN", "Warn", "/tmp/out.zip", "src"}, want: true},
		{name: "zip dot size option", tool: "zip", fields: []string{"zip", "-ds", "10m", "/tmp/out.zip", "src"}, want: true},
		{name: "zip inline dot size option", tool: "zip", fields: []string{"zip", "-ds10m", "/tmp/out.zip", "src"}, want: true},
		{name: "zip display byte count", tool: "zip", fields: []string{"zip", "-db", "/tmp/out.zip", "src"}, want: true},
		{name: "zip df is not delete mode", tool: "zip", fields: []string{"zip", "-df", "/tmp/out.zip", "src"}, want: true},
		{name: "zip archive changed mode", tool: "zip", fields: []string{"zip", "-AC", "/tmp/out.zip", "src"}, want: true},
		{name: "zip fifo option", tool: "zip", fields: []string{"zip", "-FI", "/tmp/out.zip", "src"}, want: true},
		{name: "zip file sync option", tool: "zip", fields: []string{"zip", "-FS", "/tmp/out.zip", "src"}, want: true},
		{name: "zip stdin payload", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "-"}, want: true},
		{name: "zip stdin file list", tool: "zip", fields: []string{"zip", "-@", "/tmp/out.zip"}, want: true},
		{name: "zip stdin marker as password", tool: "zip", fields: []string{"zip", "-P", "-@", "/tmp/out.zip"}},
		{name: "zip dash as password", tool: "zip", fields: []string{"zip", "-P", "-", "/tmp/out.zip"}},
		{name: "zip stdout archive unsupported", tool: "zip", fields: []string{"zip", "-", "src"}},
		{name: "zip operand resembles mode", tool: "zip", fields: []string{"zip", "--", "/tmp/out.zip", "-d"}, want: true},
		{name: "zip missing source", tool: "zip", fields: []string{"zip", "/tmp/out.zip"}},
		{name: "zip delete", tool: "zip", fields: []string{"zip", "-d", "/tmp/out.zip", "entry"}},
		{name: "zip copy mode", tool: "zip", fields: []string{"zip", "in.zip", "--copy", "entry", "--out", "out.zip"}},
		{name: "zip create and test", tool: "zip", fields: []string{"zip", "-T", "/tmp/out.zip", "src"}, want: true},
		{name: "zip test without source", tool: "zip", fields: []string{"zip", "-T", "/tmp/out.zip"}},
		{name: "zip help", tool: "zip", fields: []string{"zip", "--help", "/tmp/out.zip", "src"}},
		{name: "zip extended help", tool: "zip", fields: []string{"zip", "-h2", "/tmp/out.zip", "src"}},
		{name: "zip license", tool: "zip", fields: []string{"zip", "-L", "/tmp/out.zip", "src"}},
		{name: "zip show options", tool: "zip", fields: []string{"zip", "-so", "/tmp/out.zip", "src"}},
		{name: "zip long show command", tool: "zip", fields: []string{"zip", "--show-command", "/tmp/out.zip", "src"}},
		{name: "zip help as option value", tool: "zip", fields: []string{"zip", "-P", "--help", "/tmp/out.zip", "src"}, want: true},
		{name: "zip show command line", tool: "zip", fields: []string{"zip", "-sc", "/tmp/out.zip", "src"}},
		{name: "zip show files unicode", tool: "zip", fields: []string{"zip", "-sU", "/tmp/out.zip", "src"}},
		{name: "ditto archive", tool: "ditto", fields: []string{"ditto", "-c", "-k", "src", "/tmp/out.zip"}, want: true},
		{name: "ditto combined archive options", tool: "ditto", fields: []string{"ditto", "-ck", "src", "/tmp/out.zip"}, want: true},
		{name: "ditto missing destination", tool: "ditto", fields: []string{"ditto", "-c", "src"}},
		{name: "ditto option value is not operand", tool: "ditto", fields: []string{"ditto", "-c", "--outBom", "/tmp/index.bom", "src"}},
		{name: "ditto option value resembles mode", tool: "ditto", fields: []string{"ditto", "-c", "--keepBinariesPattern", "-x", "src", "/tmp/out.zip"}, want: true},
		{name: "ditto help as option value", tool: "ditto", fields: []string{"ditto", "-c", "--keepBinariesPattern", "--help", "src", "/tmp/out.zip"}, want: true},
		{name: "ditto copy", tool: "ditto", fields: []string{"ditto", "src", "dst"}},
		{name: "ditto extract", tool: "ditto", fields: []string{"ditto", "-x", "-k", "/tmp/in.zip", "dst"}},
		{name: "ditto conflicting modes", tool: "ditto", fields: []string{"ditto", "-c", "-x", "/tmp/in.zip", "dst"}},
		{name: "ditto unknown short option", tool: "ditto", fields: []string{"ditto", "-compress", "src", "/tmp/out.zip"}},
		{name: "missing argv", tool: "tar", fields: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseArchiveCommand(test.tool, test.fields).CreatesOutput; got != test.want {
				t.Fatalf("parseArchiveCommand(%q, %q).CreatesOutput = %t, want %t", test.tool, test.fields, got, test.want)
			}
		})
	}
}

func TestArchiveOutputPathHonorsOptionBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		tool   string
		fields []string
		want   string
	}{
		{name: "tar compressor value", tool: "tar", fields: []string{"tar", "-c", "-Ifilter", "-f", "/tmp/out.tar", "src"}, want: "/tmp/out.tar"},
		{name: "tar blocking factor value", tool: "tar", fields: []string{"tar", "-c", "-b", "20", "-f", "/tmp/out.tar", "src"}, want: "/tmp/out.tar"},
		{name: "tar old multiple value options", tool: "tar", fields: []string{"tar", "cbf", "20", "/tmp/out.tar", "src"}, want: ""},
		{name: "tar option terminator", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar", "--", "-f"}, want: "/tmp/out.tar"},
		{name: "zip password value", tool: "zip", fields: []string{"zip", "-PFOOBAR", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip dot-size value", tool: "zip", fields: []string{"zip", "-ds", "10m", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip display byte count", tool: "zip", fields: []string{"zip", "-db", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip combined compression method", tool: "zip", fields: []string{"zip", "-rZ", "deflate", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip combined suffixes", tool: "zip", fields: []string{"zip", "-rn", ".o:.c", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip combined unicode mode", tool: "zip", fields: []string{"zip", "-rUN", "Warn", "/tmp/out.zip", "src"}, want: "/tmp/out.zip"},
		{name: "zip explicit output", tool: "zip", fields: []string{"zip", "in.zip", "src", "--out", "out.zip"}, want: "out.zip"},
		{name: "zip combined explicit output", tool: "zip", fields: []string{"zip", "-rO", "out.zip", "in.zip", "src"}, want: "out.zip"},
		{name: "zip attached explicit output", tool: "zip", fields: []string{"zip", "-O=out.zip", "in.zip", "src"}, want: "out.zip"},
		{name: "zip option terminator", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "--", "--out"}, want: "/tmp/out.zip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := parseArchiveCommand(test.tool, test.fields).OutputPath; got != test.want {
				t.Fatalf("parseArchiveCommand(%q, %q).OutputPath = %q, want %q", test.tool, test.fields, got, test.want)
			}
		})
	}
}

func TestArchiveExtractionRetainsExactInputAndDestination(t *testing.T) {
	for _, test := range []struct {
		name         string
		tool         string
		fields       []string
		wantExtract  bool
		wantInput    string
		wantTarget   string
		wantProvided bool
	}{
		{name: "tar short", tool: "tar", fields: []string{"tar", "-xzf", "/tmp/in.tgz", "-C", "/tmp/out"}, wantExtract: true, wantInput: "/tmp/in.tgz", wantTarget: "/tmp/out", wantProvided: true},
		{name: "tar long", tool: "tar", fields: []string{"tar", "--extract", "--file=/tmp/in.tar", "--directory=/tmp/out"}, wantExtract: true, wantInput: "/tmp/in.tar", wantTarget: "/tmp/out", wantProvided: true},
		{name: "tar default cwd", tool: "tar", fields: []string{"tar", "-xf", "/tmp/in.tar"}, wantExtract: true, wantInput: "/tmp/in.tar"},
		{name: "tar stdin", tool: "tar", fields: []string{"tar", "-xf", "-"}},
		{name: "tar stdout short", tool: "tar", fields: []string{"tar", "-xOf", "/tmp/in.tar", "member"}},
		{name: "tar stdout long", tool: "tar", fields: []string{"tar", "--extract", "--to-stdout", "--file", "/tmp/in.tar", "member"}},
		{name: "tar multiple directories unresolved", tool: "tar", fields: []string{"tar", "-xf", "/tmp/in.tar", "-C", "/tmp/one", "-C", "/tmp/two"}, wantExtract: true, wantInput: "/tmp/in.tar", wantProvided: true},
		{name: "ditto zip", tool: "ditto", fields: []string{"ditto", "-xk", "/tmp/in.zip", "/tmp/out"}, wantExtract: true, wantInput: "/tmp/in.zip", wantTarget: "/tmp/out", wantProvided: true},
		{name: "ditto extra operand unsupported", tool: "ditto", fields: []string{"ditto", "-xk", "/tmp/in.zip", "member", "/tmp/out"}},
		{name: "unzip common", tool: "unzip", fields: []string{"unzip", "-qo", "/tmp/in.zip", "-d", "/tmp/out"}, wantExtract: true, wantInput: "/tmp/in.zip", wantTarget: "/tmp/out", wantProvided: true},
		{name: "unzip selected member", tool: "unzip", fields: []string{"unzip", "/tmp/in.zip", "payload", "-x", "decoy", "-d/tmp/out"}, wantExtract: true, wantInput: "/tmp/in.zip", wantTarget: "/tmp/out", wantProvided: true},
		{name: "unzip default cwd", tool: "unzip", fields: []string{"unzip", "/tmp/in.zip"}, wantExtract: true, wantInput: "/tmp/in.zip"},
		{name: "unzip list", tool: "unzip", fields: []string{"unzip", "-l", "/tmp/in.zip"}},
		{name: "unzip pipe", tool: "unzip", fields: []string{"unzip", "-p", "/tmp/in.zip"}},
		{name: "unzip unknown option", tool: "unzip", fields: []string{"unzip", "--definitely-unknown", "/tmp/in.zip"}},
		{name: "unzip malformed destination", tool: "unzip", fields: []string{"unzip", "/tmp/in.zip", "-d"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseArchiveCommand(test.tool, test.fields)
			if got.ExtractsArchive != test.wantExtract || got.InputPath != test.wantInput || got.ExtractionTarget != test.wantTarget || got.TargetProvided != test.wantProvided {
				t.Fatalf("parse result = %#v, want extract %t input %q target %q provided %t", got, test.wantExtract, test.wantInput, test.wantTarget, test.wantProvided)
			}
		})
	}
}

func TestArchiveReadsLocalSourcesOnlyInSourceAddingModes(t *testing.T) {
	for _, test := range []struct {
		name   string
		tool   string
		fields []string
		want   bool
	}{
		{name: "tar create", tool: "tar", fields: []string{"tar", "-czf", "/tmp/out.tgz", "~/.ssh/id_rsa"}, want: true},
		{name: "tar stdout", tool: "tar", fields: []string{"tar", "-cf", "-", "~/.ssh/id_rsa"}, want: true},
		{name: "tar implicit stdout", tool: "tar", fields: []string{"tar", "-c", "~/.ssh/id_rsa"}, want: true},
		{name: "tar append", tool: "tar", fields: []string{"tar", "-rf", "/tmp/out.tar", "~/.ssh/id_rsa"}, want: true},
		{name: "tar update", tool: "tar", fields: []string{"tar", "-uf", "/tmp/out.tar", "~/.ssh/id_rsa"}, want: true},
		{name: "tar list", tool: "tar", fields: []string{"tar", "-tf", "/tmp/out.tar", "~/.ssh/id_rsa"}},
		{name: "tar extract", tool: "tar", fields: []string{"tar", "-xf", "/tmp/out.tar", "~/.ssh/id_rsa"}},
		{name: "tar help", tool: "tar", fields: []string{"tar", "--help", "-cf", "/tmp/out.tar", "~/.ssh/id_rsa"}},
		{name: "tar help as option value", tool: "tar", fields: []string{"tar", "-c", "--exclude", "--help", "~/.ssh/id_rsa"}, want: true},
		{name: "tar blocking factor value", tool: "tar", fields: []string{"tar", "-c", "-b", "20", "~/.ssh/id_rsa"}, want: true},
		{name: "zip add", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "~/.ssh/id_rsa"}, want: true},
		{name: "zip stdout", tool: "zip", fields: []string{"zip", "-", "~/.ssh/id_rsa"}, want: true},
		{name: "zip stdin payload", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "-"}},
		{name: "zip stdin marker as password", tool: "zip", fields: []string{"zip", "-P", "-@", "/tmp/out.zip"}},
		{name: "zip delete", tool: "zip", fields: []string{"zip", "-d", "/tmp/out.zip", "~/.ssh/id_rsa"}},
		{name: "zip help", tool: "zip", fields: []string{"zip", "--help", "/tmp/out.zip", "~/.ssh/id_rsa"}},
		{name: "zip show options", tool: "zip", fields: []string{"zip", "-so", "/tmp/out.zip", "~/.ssh/id_rsa"}},
		{name: "zip help as option value", tool: "zip", fields: []string{"zip", "-P", "--help", "/tmp/out.zip", "~/.ssh/id_rsa"}, want: true},
		{name: "ditto copy", tool: "ditto", fields: []string{"ditto", "~/.ssh/id_rsa", "/tmp/key"}, want: true},
		{name: "ditto create", tool: "ditto", fields: []string{"ditto", "-ck", "~/.ssh/id_rsa", "/tmp/out.zip"}, want: true},
		{name: "ditto extract", tool: "ditto", fields: []string{"ditto", "-xk", "~/.ssh/id_rsa", "/tmp/out"}},
		{name: "ditto help", tool: "ditto", fields: []string{"ditto", "--help", "~/.ssh/id_rsa", "/tmp/out"}},
		{name: "ditto help as option value", tool: "ditto", fields: []string{"ditto", "--keepBinariesPattern", "--help", "~/.ssh/id_rsa", "/tmp/out"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseArchiveCommand(test.tool, test.fields).ReadsLocalSources
			if got != test.want {
				t.Fatalf("source-read classification for %q = %t, want %t", test.fields, got, test.want)
			}
		})
	}
}

func TestArchiveParserDispositionAndFailClosedBoundaries(t *testing.T) {
	for _, test := range []struct {
		name        string
		tool        string
		fields      []string
		disposition archiveParseDisposition
		create      bool
		sourceList  bool
	}{
		{name: "tar missing format value", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar", "src", "--format"}, disposition: archiveParseMalformed},
		{name: "tar empty format value", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar", "src", "--format="}, disposition: archiveParseMalformed},
		{name: "tar allows empty uname", tool: "tar", fields: []string{"tar", "-cf", "/tmp/out.tar", "src", "--uname="}, disposition: archiveParseRecognized, create: true},
		{name: "tar bsdtar I source list", tool: "tar", fields: []string{"tar", "-c", "-I", "files.txt", "-f", "/tmp/out.tar"}, disposition: archiveParseRecognized, create: true, sourceList: true},
		{name: "tar unsupported mac metadata option", tool: "tar", fields: []string{"tar", "--no-mac-metadata", "-cf", "/tmp/out.tar", "src"}, disposition: archiveParseUnsupported},
		{name: "zip missing password value", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "src", "-P"}, disposition: archiveParseMalformed},
		{name: "zip empty output value", tool: "zip", fields: []string{"zip", "/tmp/out.zip", "src", "--out="}, disposition: archiveParseMalformed},
		{name: "zip list resumes at marker", tool: "zip", fields: []string{"zip", "-i", "*.c", "@", "-r", "/tmp/out.zip", "src"}, disposition: archiveParseRecognized, create: true},
		{name: "zip unknown long option", tool: "zip", fields: []string{"zip", "--definitely-unknown", "/tmp/out.zip", "src"}, disposition: archiveParseUnsupported},
		{name: "zip unknown short option", tool: "zip", fields: []string{"zip", "-Q", "/tmp/out.zip", "src"}, disposition: archiveParseUnsupported},
		{name: "ditto missing arch value", tool: "ditto", fields: []string{"ditto", "-c", "src", "/tmp/out.cpio", "--arch"}, disposition: archiveParseMalformed},
		{name: "ditto unknown long option", tool: "ditto", fields: []string{"ditto", "-c", "src", "/tmp/out.cpio", "--unknown"}, disposition: archiveParseUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseArchiveCommand(test.tool, test.fields)
			if got.Disposition != test.disposition || got.CreatesOutput != test.create || got.UsesSourceList != test.sourceList {
				t.Fatalf("parse result = %#v, want disposition %q, create %t, source list %t", got, test.disposition, test.create, test.sourceList)
			}
			if got.Disposition == archiveParseUnsupported && got.CoverageDetail == "" {
				t.Fatal("unsupported archive syntax must retain an honest coverage reason")
			}
		})
	}
}
