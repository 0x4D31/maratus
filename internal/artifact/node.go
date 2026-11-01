package artifact

type Node struct {
	ID            string   `json:"id"`
	ParentID      string   `json:"parent_id,omitempty"`
	LogicalPath   string   `json:"logical_path"`
	PhysicalPath  string   `json:"physical_path,omitempty"`
	Kind          string   `json:"kind"`
	MediaType     string   `json:"media_type,omitempty"`
	Size          int64    `json:"size,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Provenance    string   `json:"extraction_provenance,omitempty"`
	SourceRole    string   `json:"source_role,omitempty"`
	// PackagingTechnology is set only after a facade recognizer corroborates
	// the producer/runtime relationship. A container signature or filename hint
	// alone is not sufficient.
	PackagingTechnology string `json:"packaging_technology,omitempty"`
	// PackagingEvidence retains the bounded, located observations behind a
	// packaging-technology conclusion until the extraction layer turns them
	// into report evidence. The proof is serialized through the report evidence
	// graph rather than duplicated inside the artifact node.
	PackagingEvidence []LocatedArtifactEvidence `json:"-"`
	// DeclaredEntryCount is the number of entries established by parsed
	// container metadata. ModeledEntryCount is the bounded subset represented
	// by child artifact nodes. A difference is an explicit inventory omission,
	// not evidence that the remaining entries were absent.
	DeclaredEntryCount *int   `json:"declared_entry_count,omitempty"`
	ModeledEntryCount  *int   `json:"modeled_entry_count,omitempty"`
	AnalyzeStatus      string `json:"analysis_status"`
	CoverageDetail     string `json:"coverage_detail,omitempty"`
}

// LocatedArtifactEvidence is a direct byte observation made while parsing an
// artifact representation. Offset is always known, including when it is zero.
type LocatedArtifactEvidence struct {
	// NodeID is optional. When empty, the fact belongs to the artifact carrying
	// PackagingEvidence. Facade recognizers use it when a bundle-level
	// conclusion is supported by exact child metadata bytes.
	NodeID string
	Offset int64
	Kind   string
	Value  string
}

type Edge struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Kind        string   `json:"kind"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	// Ordinal preserves an order declared by the source format. It is nil for
	// unordered relationships; zero is a meaningful first position.
	Ordinal *int `json:"ordinal,omitempty"`
	// SupportingEvidence carries direct artifact facts until extraction assigns
	// stable report evidence IDs. It is never serialized alongside those IDs.
	SupportingEvidence []LocatedArtifactEvidence `json:"-"`
	// Invocation fields carry exact format-declared interpreter semantics into
	// the public InvokedTarget. Arguments before and after the target remain
	// separate here so extraction can insert the target's retained logical path.
	InvocationInterpreter string   `json:"-"`
	InterpreterArguments  []string `json:"-"`
	InvocationArguments   []string `json:"-"`
	// InvocationHostUnresolved retains a structural candidate while preventing
	// it from becoming host-backed execution semantics. Versioned adapters set
	// this when the target relationship is known but interpreter argv is not.
	InvocationHostUnresolved bool `json:"-"`
}

type Content struct {
	NodeID       string
	LogicalPath  string
	PhysicalPath string
	Kind         string
	MediaType    string
	// ByteOffsetBase is the node-relative origin of Data when an analyzer is
	// handed a structurally validated subimage. It is internal analysis context:
	// evidence byte offsets remain relative to the artifact node, never to an
	// implementation-specific slice buffer.
	ByteOffsetBase int64
	// SemanticLanguage is an analyzer hint established by trusted structural
	// metadata rather than the filename. For example, an Electron package may
	// declare an extensionless JavaScript program in its root package.json.
	// This is deliberately internal analysis context, not an artifact fact.
	SemanticLanguage string
	// HostSelectionUnresolved records contrary structural invocation metadata:
	// the adapter retained a candidate target but could not prove which host or
	// argv mode consumes it. Filename, shebang, mode, and body heuristics must
	// not independently turn that candidate into host-backed semantics.
	HostSelectionUnresolved bool
	// PackageInstallPath is an exact destination derived from a structurally
	// paired flat-package Payload and PackageInfo install-location. It is
	// analysis context only: archive member names must never manufacture it.
	PackageInstallPath string
	Data               []byte
	Executable         bool
	PrimaryExecutable  bool
	// BehaviorAnalysisForced records that a structural relationship (for
	// example, an app/installer entrypoint) or an include-unreferenced scan made
	// this content part of the behavior-analysis surface. SourceRole remains the
	// content's honest provenance label; extractors must not let an
	// attacker-controlled path such as vendor/ or tests/ override this flag.
	BehaviorAnalysisForced bool
	// ExecutionRootEligibilityKnown distinguishes production inspection context
	// from isolated extractor fixtures. When it is true,
	// ExecutionRootEligible says whether declarations owned by this artifact may
	// introduce an execution root. A statically invoked child remains an invoked
	// target even when it is not eligible to declare another root.
	ExecutionRootEligibilityKnown bool
	ExecutionRootEligible         bool
	// ExecutionConnectivity and the bounded ownership IDs are assigned by the
	// extraction registry after it resolves structural roots and invocation
	// relationships. They are analysis context, not artifact-format facts.
	// An empty connectivity value means the registry has not classified the
	// content yet.
	ExecutionConnectivity string
	ExecutionRootIDs      []string
	InvokedTargetIDs      []string
	// RawFeaturesOnly means the representation was structurally identified, but
	// maratus does not decode its semantics. Extractors may inspect bounded raw
	// byte strings for isolated indicators, but must not interpret the bytes as
	// executable code, text, a manifest, or another container.
	RawFeaturesOnly        bool
	SemanticCoverageArea   string
	SemanticCoverageDetail string
	Role                   string
	ScopeID                string
	Function               string
	Architecture           string
	// SupportingEvidenceIDs lets a derived analyzer retain the proof that made
	// an embedded representation reachable (for example, a native system call
	// that executes a recovered shell-command literal).
	SupportingEvidenceIDs []string
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges,omitempty"`

	nextNode int
}

func (g *Graph) AddNode(n Node) string {
	g.nextNode++
	n.ID = nodeID(g.nextNode)
	if n.AnalyzeStatus == "" {
		n.AnalyzeStatus = "analyzed"
	}
	g.Nodes = append(g.Nodes, n)
	return n.ID
}

func (g *Graph) AddEdge(from, to, kind string) {
	if from == "" || to == "" || kind == "" {
		return
	}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: kind})
}

func (g *Graph) AddOrderedEdge(from, to, kind string, ordinal int) {
	g.AddSupportedOrderedEdge(from, to, kind, ordinal, nil)
}

func (g *Graph) AddSupportedOrderedEdge(from, to, kind string, ordinal int, evidence []LocatedArtifactEvidence) {
	if from == "" || to == "" || kind == "" || ordinal < 0 {
		return
	}
	value := ordinal
	g.Edges = append(g.Edges, Edge{
		From: from, To: to, Kind: kind, Ordinal: &value,
		SupportingEvidence: append([]LocatedArtifactEvidence(nil), evidence...),
	})
}

func (g *Graph) AddSupportedInvocationEdge(from, to, kind, interpreter string, interpreterArguments, invocationArguments []string, evidence []LocatedArtifactEvidence) {
	if from == "" || to == "" || kind == "" || interpreter == "" {
		return
	}
	g.Edges = append(g.Edges, Edge{
		From:                  from,
		To:                    to,
		Kind:                  kind,
		SupportingEvidence:    append([]LocatedArtifactEvidence(nil), evidence...),
		InvocationInterpreter: interpreter,
		InterpreterArguments:  append([]string(nil), interpreterArguments...),
		InvocationArguments:   append([]string(nil), invocationArguments...),
	})
}

func (g *Graph) AddUnresolvedInvocationEdge(from, to, kind string) {
	if from == "" || to == "" || kind == "" {
		return
	}
	g.Edges = append(g.Edges, Edge{
		From: from, To: to, Kind: kind, InvocationHostUnresolved: true,
	})
}

func nodeID(n int) string {
	return "node-" + zeroPad(n, 4)
}

func zeroPad(n, width int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		s = "0"
	}
	for len(s) < width {
		s = "0" + s
	}
	return s
}
