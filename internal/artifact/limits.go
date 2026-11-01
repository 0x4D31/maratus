package artifact

const (
	DefaultMaxFileBytes         int64 = 128 << 20
	DefaultMaxArchiveBytes      int64 = 64 << 20
	DefaultMaxExpandedBytes     int64 = 64 << 20
	DefaultMaxTotalBytes        int64 = 256 << 20
	DefaultMaxArchiveDepth            = 4
	DefaultMaxDirectoryDepth          = 32
	DefaultMaxCompressionRatio        = 100
	DefaultMaxArtifactNodes           = 20000
	DefaultMaxArtifactPathBytes int64 = 4 << 20
	DefaultMaxEvidence                = 20000
	DefaultMaxDiagnostics             = 256
	DefaultMaxDiagnosticBytes   int64 = 64 << 10
	MaxArchiveEntries                 = 4096
	MaxArchiveNameBytes               = 4096
	MaxArchiveLogicalPathBytes        = 16 << 10
)

type Options struct {
	MaxFileBytes              int64
	MaxArchiveBytes           int64
	MaxExpandedBytes          int64
	MaxTotalBytes             int64
	MaxArchiveDepth           int
	MaxDirectoryDepth         int
	MaxCompressionRatio       int64
	MaxArtifactNodes          int
	MaxArtifactPathBytes      int64
	MaxEvidence               int
	MaxDiagnostics            int
	MaxDiagnosticBytes        int64
	DisableContainerExpansion bool
	IncludeUnreferenced       bool
	AllowDMGMount             bool
	Architecture              string
	ZipPassword               string
}

func (o Options) Normalized() Options {
	return o.normalized()
}

func (o Options) normalized() Options {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	if o.MaxArchiveBytes <= 0 {
		o.MaxArchiveBytes = DefaultMaxArchiveBytes
	}
	if o.MaxExpandedBytes <= 0 {
		o.MaxExpandedBytes = DefaultMaxExpandedBytes
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if o.MaxArchiveDepth <= 0 {
		o.MaxArchiveDepth = DefaultMaxArchiveDepth
	}
	if o.MaxDirectoryDepth <= 0 {
		o.MaxDirectoryDepth = DefaultMaxDirectoryDepth
	}
	if o.MaxCompressionRatio <= 0 {
		o.MaxCompressionRatio = DefaultMaxCompressionRatio
	}
	if o.MaxArtifactNodes <= 0 {
		o.MaxArtifactNodes = DefaultMaxArtifactNodes
	}
	if o.MaxArtifactPathBytes <= 0 {
		o.MaxArtifactPathBytes = DefaultMaxArtifactPathBytes
	}
	if o.MaxEvidence <= 0 {
		o.MaxEvidence = DefaultMaxEvidence
	}
	if o.MaxDiagnostics <= 0 {
		o.MaxDiagnostics = DefaultMaxDiagnostics
	}
	if o.MaxDiagnosticBytes <= 0 {
		o.MaxDiagnosticBytes = DefaultMaxDiagnosticBytes
	}
	if o.Architecture == "" {
		o.Architecture = "all"
	}
	return o
}
