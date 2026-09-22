package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Flux HelmRelease (helm.toolkit.fluxcd.io) + source refs.
type fluxHelmRelease struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		ReleaseName string `yaml:"releaseName"`
		Chart       *struct {
			Spec struct {
				Chart     string `yaml:"chart"`
				Version   string `yaml:"version"`
				SourceRef struct {
					Kind      string `yaml:"kind"`
					Name      string `yaml:"name"`
					Namespace string `yaml:"namespace"`
				} `yaml:"sourceRef"`
				ValuesFiles []string `yaml:"valuesFiles"`
			} `yaml:"spec"`
		} `yaml:"chart"`
		ChartRef *struct {
			Kind      string `yaml:"kind"`
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"chartRef"`
		Values     map[string]any `yaml:"values"`
		ValuesFrom []any          `yaml:"valuesFrom"`
	} `yaml:"spec"`
}

type fluxSourceRef struct {
	Kind      string
	Name      string
	Namespace string
	URL       string // HelmRepository / OCIRepository
	Type      string // HelmRepository | OCIRepository | GitRepository | Bucket
}

type fluxKustomization struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Path string `yaml:"path"`
	} `yaml:"spec"`
}

// InventoryFlux walks Flux HelmRelease / Kustomization YAML under opts.Flux.
func InventoryFlux(opts Options) ([]ImageFinding, []string, error) {
	root := opts.Flux
	if root == "" {
		return nil, nil, fmt.Errorf("--flux path is required")
	}
	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot, _ = os.Getwd()
	}

	files, err := listYAMLFiles(root)
	if err != nil {
		return nil, nil, err
	}

	sources := indexFluxSources(files)
	var findings []ImageFinding
	var warnings []string

	for _, file := range files {
		docs, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: read failed: %v", file, err))
			continue
		}
		for _, doc := range splitYAMLDocs(string(docs)) {
			var meta struct {
				Kind string `yaml:"kind"`
			}
			if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
				continue
			}
			switch meta.Kind {
			case "HelmRelease":
				f, w := inventoryFluxHelmRelease(doc, file, opts, repoRoot, sources)
				findings = append(findings, f...)
				warnings = append(warnings, w...)
			case "Kustomization":
				// Flux kustomize.toolkit — only when apiGroup looks Flux-ish or path is set.
				var kust fluxKustomization
				if err := yaml.Unmarshal([]byte(doc), &kust); err != nil {
					continue
				}
				var full struct {
					APIVersion string `yaml:"apiVersion"`
				}
				_ = yaml.Unmarshal([]byte(doc), &full)
				if !strings.Contains(full.APIVersion, "fluxcd.io") {
					continue // native kustomization.yaml handled elsewhere
				}
				if kust.Spec.Path == "" {
					warnings = append(warnings, fmt.Sprintf("%s: Flux Kustomization %q has empty path", file, kust.Metadata.Name))
					continue
				}
				src := ArgoSource{Path: strings.TrimPrefix(kust.Spec.Path, "./")}
				f, w := inventoryPathSource(kust.Metadata.Name, file, src, opts, repoRoot, 0)
				findings = append(findings, f...)
				warnings = append(warnings, w...)
			}
		}
	}

	return Dedupe(findings), warnings, nil
}

func inventoryFluxHelmRelease(doc, file string, opts Options, repoRoot string, sources map[string]fluxSourceRef) ([]ImageFinding, []string) {
	var hr fluxHelmRelease
	if err := yaml.Unmarshal([]byte(doc), &hr); err != nil {
		return nil, []string{fmt.Sprintf("%s: HelmRelease parse failed: %v", file, err)}
	}
	name := hr.Metadata.Name
	if name == "" {
		name = "helmrelease"
	}
	release := hr.Spec.ReleaseName
	if release == "" {
		release = name
	}

	var warnings []string
	var inlineFile string
	if len(hr.Spec.Values) > 0 {
		tmp, err := os.CreateTemp("", "helm-sca-flux-values-*.yaml")
		if err == nil {
			enc := yaml.NewEncoder(tmp)
			_ = enc.Encode(hr.Spec.Values)
			_ = enc.Close()
			_ = tmp.Close()
			inlineFile = tmp.Name()
			defer os.Remove(inlineFile)
		}
	}
	if len(hr.Spec.ValuesFrom) > 0 {
		warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q valuesFrom not resolved in v1 (Secrets/ConfigMaps skipped)", file, name))
	}

	// chartRef → OCIRepository / HelmChart (best-effort URL lookup).
	if hr.Spec.ChartRef != nil {
		key := sourceKey(hr.Spec.ChartRef.Kind, hr.Spec.ChartRef.Name, hr.Spec.ChartRef.Namespace, hr.Metadata.Namespace)
		src, ok := sources[key]
		if !ok {
			// try without namespace
			src, ok = sources[sourceKey(hr.Spec.ChartRef.Kind, hr.Spec.ChartRef.Name, "", "")]
		}
		if !ok || src.URL == "" {
			warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q chartRef %s/%s not found locally", file, name, hr.Spec.ChartRef.Kind, hr.Spec.ChartRef.Name))
			return nil, warnings
		}
		if src.Type == "OCIRepository" || strings.HasPrefix(src.URL, "oci://") {
			rendered, err := TemplateRemoteChart(release, "", src.URL, "", nil, opts.Set, inlineFile, opts.HelmBin)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q OCI template failed: %v", file, name, err))
				return nil, warnings
			}
			imgs := ExtractFromYAML(rendered, file, false, false)
			for i := range imgs {
				imgs[i].App = name
				imgs[i].Chart = src.URL
				imgs[i].RepoURL = src.URL
				imgs[i].File = file
			}
			return Dedupe(imgs), warnings
		}
		warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q chartRef kind %q not templated in v1", file, name, hr.Spec.ChartRef.Kind))
		return nil, warnings
	}

	if hr.Spec.Chart == nil {
		warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q has neither chart nor chartRef", file, name))
		return nil, warnings
	}

	chart := hr.Spec.Chart.Spec.Chart
	version := hr.Spec.Chart.Spec.Version
	ref := hr.Spec.Chart.Spec.SourceRef
	key := sourceKey(ref.Kind, ref.Name, ref.Namespace, hr.Metadata.Namespace)
	src, ok := sources[key]
	if !ok {
		src, ok = sources[sourceKey(ref.Kind, ref.Name, "", "")]
	}

	// Local path chart (GitRepository / relative path under repo).
	if strings.HasPrefix(chart, "./") || strings.HasPrefix(chart, "../") || (ref.Kind == "GitRepository" && looksLikeLocalChartPath(chart, repoRoot)) {
		local := chart
		if !filepath.IsAbs(local) {
			local = filepath.Join(repoRoot, strings.TrimPrefix(chart, "./"))
		}
		if isLocalChartDir(local) {
			chartOpts := opts
			chartOpts.Chart = local
			chartOpts.Release = release
			if inlineFile != "" {
				chartOpts.Values = append(append([]string{}, opts.Values...), inlineFile)
			}
			imgs, err := TemplateChart(chartOpts)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q local chart failed: %v", file, name, err))
				return nil, warnings
			}
			for i := range imgs {
				imgs[i].App = name
				imgs[i].Chart = chart
				imgs[i].File = file
				imgs[i].Revision = version
			}
			return imgs, warnings
		}
	}

	if !ok || src.URL == "" {
		warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q sourceRef %s/%s URL not found in scanned YAML (declare HelmRepository/OCIRepository nearby)", file, name, ref.Kind, ref.Name))
		return nil, warnings
	}

	var valueFiles []string
	for _, vf := range hr.Spec.Chart.Spec.ValuesFiles {
		resolved := filepath.Join(repoRoot, vf)
		if _, err := os.Stat(resolved); err == nil {
			valueFiles = append(valueFiles, resolved)
		} else {
			warnings = append(warnings, fmt.Sprintf("%s: valuesFile %q not found locally", name, vf))
		}
	}

	rendered, err := TemplateRemoteChart(release, chart, src.URL, version, valueFiles, opts.Set, inlineFile, opts.HelmBin)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q remote helm template failed: %v", file, name, err))
		return nil, warnings
	}
	imgs := ExtractFromYAML(rendered, file, false, false)
	for i := range imgs {
		imgs[i].App = name
		imgs[i].Chart = chart
		imgs[i].RepoURL = src.URL
		imgs[i].Revision = version
		imgs[i].File = file
	}
	return Dedupe(imgs), warnings
}

func looksLikeLocalChartPath(chart, repoRoot string) bool {
	p := chart
	if !filepath.IsAbs(p) {
		p = filepath.Join(repoRoot, strings.TrimPrefix(chart, "./"))
	}
	return isLocalChartDir(p)
}

func indexFluxSources(files []string) map[string]fluxSourceRef {
	out := map[string]fluxSourceRef{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, doc := range splitYAMLDocs(string(data)) {
			var meta struct {
				APIVersion string `yaml:"apiVersion"`
				Kind       string `yaml:"kind"`
				Metadata   struct {
					Name      string `yaml:"name"`
					Namespace string `yaml:"namespace"`
				} `yaml:"metadata"`
				Spec struct {
					URL string `yaml:"url"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
				continue
			}
			switch meta.Kind {
			case "HelmRepository", "OCIRepository":
				ref := fluxSourceRef{
					Kind:      meta.Kind,
					Name:      meta.Metadata.Name,
					Namespace: meta.Metadata.Namespace,
					URL:       meta.Spec.URL,
					Type:      meta.Kind,
				}
				out[sourceKey(meta.Kind, meta.Metadata.Name, meta.Metadata.Namespace, "")] = ref
				out[sourceKey(meta.Kind, meta.Metadata.Name, "", "")] = ref
			}
		}
	}
	return out
}

func sourceKey(kind, name, ns, fallbackNS string) string {
	if ns == "" {
		ns = fallbackNS
	}
	return strings.ToLower(kind) + "/" + ns + "/" + name
}

func listYAMLFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func splitYAMLDocs(data string) []string {
	raw := strings.Split(data, "---")
	var out []string
	for _, d := range raw {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
