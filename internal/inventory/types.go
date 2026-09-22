package inventory

// Confidence ranks how sure we are that a ref is a real container image.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// SourceKind describes which detector produced a finding.
type SourceKind string

const (
	SourceRendered SourceKind = "rendered-manifest"
	SourceStatic   SourceKind = "static-yaml"
	SourceRegex    SourceKind = "regex-scan"
)

// ImageFinding is one discovered container image reference.
type ImageFinding struct {
	Name       string     `json:"name" yaml:"name"`
	Confidence Confidence `json:"confidence" yaml:"confidence"`
	Source     SourceKind `json:"source" yaml:"source"`
	File       string     `json:"file,omitempty" yaml:"file,omitempty"`
	Kind       string     `json:"kind,omitempty" yaml:"kind,omitempty"`
	App        string     `json:"app,omitempty" yaml:"app,omitempty"`
	Chart      string     `json:"chart,omitempty" yaml:"chart,omitempty"`
	RepoURL    string     `json:"repoURL,omitempty" yaml:"repoURL,omitempty"`
	Revision   string     `json:"revision,omitempty" yaml:"revision,omitempty"`
}

// Result is the inventory output document.
type Result struct {
	Images []ImageFinding `json:"images" yaml:"images"`
}

// Options controls an inventory run.
// Exactly one primary input mode should be set (Chart, Manifests, ArgoApps,
// Flux, Terraform/TerraformJSON, or Gitops).
type Options struct {
	Chart         string
	Manifests     string
	ArgoApps      string // Argo CD Application YAML file or directory
	Flux          string // Flux HelmRelease / Kustomization YAML file or directory
	Gitops        string // auto-detect Argo + Flux resources under a tree
	Terraform     string // directory or file of .tf / .tf.json
	TerraformJSON string // terraform show -json / plan JSON path
	Release       string
	Values        []string
	Set           []string
	HelmBin       string
	RepoRoot      string // base for resolving local paths / valueFiles
	SkipRegex     bool
	SkipStatic    bool
}
