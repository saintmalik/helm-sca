package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Run executes inventory based on mutually exclusive input modes.
func Run(opts Options) (Result, []string, error) {
	modes := 0
	if opts.Chart != "" {
		modes++
	}
	if opts.Manifests != "" {
		modes++
	}
	if opts.ArgoApps != "" {
		modes++
	}
	if opts.Flux != "" {
		modes++
	}
	if opts.Gitops != "" {
		modes++
	}
	tf := opts.Terraform != "" || opts.TerraformJSON != ""
	if tf {
		modes++
	}
	if modes != 1 {
		return Result{}, nil, fmt.Errorf("exactly one of --chart, --manifests, --argo-apps, --flux, --gitops, or --terraform/--terraform-json is required")
	}

	var findings []ImageFinding
	var warnings []string
	var err error

	switch {
	case opts.Chart != "":
		findings, err = TemplateChart(opts)
	case opts.Manifests != "":
		findings, err = WalkManifests(opts.Manifests, !opts.SkipStatic, !opts.SkipRegex)
		findings = Dedupe(findings)
	case opts.ArgoApps != "":
		findings, warnings, err = InventoryArgoApps(opts)
	case opts.Flux != "":
		findings, warnings, err = InventoryFlux(opts)
	case opts.Gitops != "":
		findings, warnings, err = InventoryGitops(opts)
	case tf:
		findings, warnings, err = InventoryTerraform(opts)
	}
	if err != nil {
		return Result{}, warnings, err
	}
	return Result{Images: findings}, warnings, nil
}

// InventoryGitops walks a directory for Argo Applications and Flux resources.
func InventoryGitops(opts Options) ([]ImageFinding, []string, error) {
	root := opts.Gitops
	argoOpts := opts
	argoOpts.ArgoApps = root
	argoOpts.Gitops = ""
	fluxOpts := opts
	fluxOpts.Flux = root
	fluxOpts.Gitops = ""

	var findings []ImageFinding
	var warnings []string

	af, aw, err := InventoryArgoApps(argoOpts)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("argo walk: %v", err))
	} else {
		findings = append(findings, af...)
		warnings = append(warnings, aw...)
	}

	ff, fw, err := InventoryFlux(fluxOpts)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("flux walk: %v", err))
	} else {
		findings = append(findings, ff...)
		warnings = append(warnings, fw...)
	}

	if len(findings) == 0 && len(warnings) == 0 {
		warnings = append(warnings, "gitops mode: no Argo Application or Flux HelmRelease/Kustomization images found")
	}
	return Dedupe(findings), warnings, nil
}

// Write formats the result to w.
func Write(w io.Writer, result Result, format string) error {
	switch strings.ToLower(format) {
	case "list", "":
		for _, img := range result.Images {
			fmt.Fprintln(w, img.Name)
		}
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "yaml", "yml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer enc.Close()
		return enc.Encode(result)
	case "cyclonedx-json", "cdx", "cyclonedx":
		return writeCycloneDX(w, result)
	default:
		return fmt.Errorf("unknown format %q (want list|json|yaml|cyclonedx-json)", format)
	}
}

type cdxDoc struct {
	BOMFormat   string    `json:"bomFormat"`
	SpecVersion string    `json:"specVersion"`
	Version     int       `json:"version"`
	Components  []cdxComp `json:"components"`
}

type cdxComp struct {
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Version    string    `json:"version,omitempty"`
	PackageURL string    `json:"purl,omitempty"`
	Properties []cdxProp `json:"properties,omitempty"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func writeCycloneDX(w io.Writer, result Result) error {
	doc := cdxDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  make([]cdxComp, 0, len(result.Images)),
	}
	for _, img := range result.Images {
		name, version := splitNameVersion(img.Name)
		comp := cdxComp{
			Type:    "container",
			Name:    name,
			Version: version,
			Properties: []cdxProp{
				{Name: "helm-sca:confidence", Value: string(img.Confidence)},
				{Name: "helm-sca:source", Value: string(img.Source)},
			},
		}
		if img.File != "" {
			comp.Properties = append(comp.Properties, cdxProp{Name: "helm-sca:file", Value: img.File})
		}
		if img.App != "" {
			comp.Properties = append(comp.Properties, cdxProp{Name: "helm-sca:app", Value: img.App})
		}
		if img.Chart != "" {
			comp.Properties = append(comp.Properties, cdxProp{Name: "helm-sca:chart", Value: img.Chart})
		}
		if img.RepoURL != "" {
			comp.Properties = append(comp.Properties, cdxProp{Name: "helm-sca:repoURL", Value: img.RepoURL})
		}
		if img.Revision != "" {
			comp.Properties = append(comp.Properties, cdxProp{Name: "helm-sca:revision", Value: img.Revision})
		}
		comp.PackageURL = "pkg:oci/" + strings.TrimPrefix(strings.ReplaceAll(img.Name, "/", "%2F"), "")
		doc.Components = append(doc.Components, comp)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func splitNameVersion(ref string) (string, string) {
	ref = NormalizeImageRef(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	if i := strings.LastIndex(ref, ":"); i > 0 && strings.Contains(ref[:i], "/") {
		return ref[:i], ref[i+1:]
	}
	if i := strings.LastIndex(ref, ":"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}
