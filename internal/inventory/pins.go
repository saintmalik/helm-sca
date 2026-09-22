package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ChartPin is a remote Helm chart version pin discovered from GitOps / Terraform.
type ChartPin struct {
	App          string   `json:"app"`
	Chart        string   `json:"chart"`
	RepoURL      string   `json:"repoURL"`
	Version      string   `json:"version"`
	File         string   `json:"file"`
	Kind         string   `json:"kind"` // Application | HelmRelease | helm_release
	Release      string   `json:"release,omitempty"`
	ValuesFiles  []string `json:"valuesFiles,omitempty"`
	Set          []string `json:"set,omitempty"`
	InlineValues string   `json:"inlineValues,omitempty"`
}

// ListChartPins discovers remote Helm chart pins from the same input modes as inventory.
// Local charts, plain manifests, and pins without a repo URL are skipped (with warnings).
func ListChartPins(opts Options) ([]ChartPin, []string, error) {
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
		return nil, nil, fmt.Errorf("exactly one of --chart, --manifests, --argo-apps, --flux, --gitops, or --terraform/--terraform-json is required")
	}

	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot, _ = os.Getwd()
	}

	switch {
	case opts.Chart != "":
		return listPinsFromChartFlag(opts)
	case opts.Manifests != "":
		return nil, []string{"manifests mode has no chart pins to recommend"}, nil
	case opts.ArgoApps != "":
		return listArgoPins(opts, repoRoot)
	case opts.Flux != "":
		return listFluxPins(opts, repoRoot)
	case opts.Gitops != "":
		return listGitopsPins(opts, repoRoot)
	case tf:
		return listTerraformPins(opts, repoRoot)
	default:
		return nil, nil, fmt.Errorf("no input mode set")
	}
}

func listPinsFromChartFlag(opts Options) ([]ChartPin, []string, error) {
	chart := opts.Chart
	if isLocalChartDir(chart) {
		return nil, []string{"local --chart path has no remote version pin to bump"}, nil
	}
	// Reject filesystem paths that are not charts / not remote refs.
	if !strings.HasPrefix(chart, "oci://") && !strings.Contains(chart, "://") {
		if _, err := os.Stat(chart); err == nil {
			return nil, []string{fmt.Sprintf("%q is a local path without Chart.yaml — no remote pin to bump", chart)}, nil
		}
	}
	repo, name, ver := splitRemoteChartRef(chart)
	if name == "" {
		return nil, []string{fmt.Sprintf("could not parse remote chart ref %q for recommend", chart)}, nil
	}
	pin := ChartPin{
		App:     opts.Release,
		Chart:   name,
		RepoURL: repo,
		Version: ver,
		File:    "--chart",
		Kind:    "chart",
		Release: opts.Release,
		Set:     append([]string{}, opts.Set...),
	}
	if pin.Release == "" {
		pin.Release = "helm-sca"
	}
	pin.ValuesFiles = append(pin.ValuesFiles, opts.Values...)
	return []ChartPin{pin}, nil, nil
}

func splitRemoteChartRef(ref string) (repo, chart, version string) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "oci://") {
		trimmed := strings.TrimPrefix(ref, "oci://")
		// oci://host/path/chart:1.2.3 or oci://host/path/chart
		if i := strings.LastIndex(trimmed, ":"); i > 0 && !strings.Contains(trimmed[i:], "/") {
			version = trimmed[i+1:]
			trimmed = trimmed[:i]
		}
		if j := strings.LastIndex(trimmed, "/"); j >= 0 {
			return "oci://" + trimmed[:j], trimmed[j+1:], version
		}
		return "oci://" + trimmed, "", version
	}
	return "", ref, ""
}

func listGitopsPins(opts Options, repoRoot string) ([]ChartPin, []string, error) {
	argoOpts := opts
	argoOpts.ArgoApps = opts.Gitops
	argoOpts.Gitops = ""
	fluxOpts := opts
	fluxOpts.Flux = opts.Gitops
	fluxOpts.Gitops = ""

	var pins []ChartPin
	var warnings []string

	ap, aw, err := listArgoPins(argoOpts, repoRoot)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("argo pins: %v", err))
	} else {
		pins = append(pins, ap...)
		warnings = append(warnings, aw...)
	}
	fp, fw, err := listFluxPins(fluxOpts, repoRoot)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("flux pins: %v", err))
	} else {
		pins = append(pins, fp...)
		warnings = append(warnings, fw...)
	}
	return dedupePins(pins), warnings, nil
}

func listArgoPins(opts Options, repoRoot string) ([]ChartPin, []string, error) {
	root := opts.ArgoApps
	files, err := listYAMLFiles(root)
	if err != nil {
		return nil, nil, err
	}
	var pins []ChartPin
	var warnings []string
	for _, file := range files {
		apps, err := parseApplications(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: parse skipped: %v", file, err))
			continue
		}
		for _, app := range apps {
			sources := []ArgoSource{}
			if app.Spec.Source != nil {
				sources = append(sources, *app.Spec.Source)
			}
			sources = append(sources, app.Spec.Sources...)
			for _, src := range sources {
				if src.Chart == "" || src.RepoURL == "" {
					continue
				}
				pin := ChartPin{
					App:     app.Metadata.Name,
					Chart:   src.Chart,
					RepoURL: src.RepoURL,
					Version: src.TargetRevision,
					File:    file,
					Kind:    "Application",
					Release: app.Metadata.Name,
				}
				if src.Helm != nil {
					if src.Helm.ReleaseName != "" {
						pin.Release = src.Helm.ReleaseName
					}
					for _, vf := range src.Helm.ValueFiles {
						resolved := resolvePath(repoRoot, src.Path, vf)
						if _, err := os.Stat(resolved); err == nil {
							pin.ValuesFiles = append(pin.ValuesFiles, resolved)
						}
					}
					pin.InlineValues = strings.TrimSpace(src.Helm.Values)
					for _, p := range src.Helm.Parameters {
						if p.Name != "" {
							pin.Set = append(pin.Set, fmt.Sprintf("%s=%s", p.Name, p.Value))
						}
					}
				}
				pin.Set = append(pin.Set, opts.Set...)
				pins = append(pins, pin)
			}
		}
	}
	return dedupePins(pins), warnings, nil
}

func listFluxPins(opts Options, repoRoot string) ([]ChartPin, []string, error) {
	root := opts.Flux
	files, err := listYAMLFiles(root)
	if err != nil {
		return nil, nil, err
	}
	sources := indexFluxSources(files)
	var pins []ChartPin
	var warnings []string

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: read failed: %v", file, err))
			continue
		}
		for _, doc := range splitYAMLDocs(string(data)) {
			var meta struct {
				Kind string `yaml:"kind"`
			}
			if err := yaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "HelmRelease" {
				continue
			}
			var hr fluxHelmRelease
			if err := yaml.Unmarshal([]byte(doc), &hr); err != nil {
				continue
			}
			if hr.Spec.Chart == nil {
				continue
			}
			chart := hr.Spec.Chart.Spec.Chart
			version := hr.Spec.Chart.Spec.Version
			ref := hr.Spec.Chart.Spec.SourceRef
			// Skip local path charts.
			if strings.HasPrefix(chart, "./") || strings.HasPrefix(chart, "../") {
				continue
			}
			key := sourceKey(ref.Kind, ref.Name, ref.Namespace, hr.Metadata.Namespace)
			src, ok := sources[key]
			if !ok {
				src, ok = sources[sourceKey(ref.Kind, ref.Name, "", "")]
			}
			if !ok || src.URL == "" {
				warnings = append(warnings, fmt.Sprintf("%s: HelmRelease %q source URL not found — skip recommend", file, hr.Metadata.Name))
				continue
			}
			name := hr.Metadata.Name
			release := hr.Spec.ReleaseName
			if release == "" {
				release = name
			}
			pin := ChartPin{
				App:     name,
				Chart:   chart,
				RepoURL: src.URL,
				Version: version,
				File:    file,
				Kind:    "HelmRelease",
				Release: release,
				Set:     append([]string{}, opts.Set...),
			}
			for _, vf := range hr.Spec.Chart.Spec.ValuesFiles {
				resolved := filepath.Join(repoRoot, vf)
				if _, err := os.Stat(resolved); err == nil {
					pin.ValuesFiles = append(pin.ValuesFiles, resolved)
				}
			}
			if len(hr.Spec.Values) > 0 {
				b, err := yaml.Marshal(hr.Spec.Values)
				if err == nil {
					pin.InlineValues = string(b)
				}
			}
			pins = append(pins, pin)
		}
	}
	return dedupePins(pins), warnings, nil
}

func listTerraformPins(opts Options, repoRoot string) ([]ChartPin, []string, error) {
	_ = repoRoot
	var pins []ChartPin
	var warnings []string
	if opts.Terraform != "" {
		p, w, e := listTerraformHCLPins(opts)
		warnings = append(warnings, w...)
		if e != nil {
			return nil, warnings, e
		}
		pins = append(pins, p...)
	}
	if opts.TerraformJSON != "" {
		p, w, e := listTerraformJSONPins(opts.TerraformJSON)
		warnings = append(warnings, w...)
		if e != nil {
			return pins, warnings, e
		}
		pins = append(pins, p...)
	}
	return dedupePins(pins), warnings, nil
}

func listTerraformHCLPins(opts Options) ([]ChartPin, []string, error) {
	root := opts.Terraform
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				base := d.Name()
				if base == ".terraform" || base == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			name := strings.ToLower(d.Name())
			if strings.HasSuffix(name, ".tf") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else {
		files = []string{root}
	}

	var pins []ChartPin
	var warnings []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: read failed: %v", file, err))
			continue
		}
		for _, m := range helmReleaseBlockRE.FindAllStringSubmatch(string(data), -1) {
			resName := m[1]
			body := m[2]
			attrs := map[string]string{}
			for _, a := range attrStringRE.FindAllStringSubmatch(body, -1) {
				attrs[a[1]] = a[2]
			}
			chart := attrs["chart"]
			repo := attrs["repository"]
			version := attrs["version"]
			if chart == "" || repo == "" {
				continue
			}
			if strings.HasPrefix(chart, "./") || strings.HasPrefix(chart, "../") || isLocalChartDir(chart) {
				continue
			}
			release := attrs["name"]
			if release == "" {
				release = resName
			}
			pins = append(pins, ChartPin{
				App:     resName,
				Chart:   chart,
				RepoURL: repo,
				Version: version,
				File:    file,
				Kind:    "helm_release",
				Release: release,
				Set:     append([]string{}, opts.Set...),
			})
		}
	}
	return pins, warnings, nil
}

func listTerraformJSONPins(path string) ([]ChartPin, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// terraform JSON — use encoding/json via yaml which handles JSON subset poorly; use json
		return listTerraformJSONPinsJSON(path, data)
	}
	return listTerraformJSONPinsJSON(path, data)
}

func listTerraformJSONPinsJSON(path string, data []byte) ([]ChartPin, []string, error) {
	var root map[string]any
	if err := unmarshalLoose(data, &root); err != nil {
		return nil, nil, err
	}
	var pins []ChartPin
	var warnings []string
	walkTFModulePins(root, path, &pins)
	if values, ok := root["values"].(map[string]any); ok {
		if rm, ok := values["root_module"].(map[string]any); ok {
			walkTFModulePins(rm, path, &pins)
		}
	}
	if changes, ok := root["resource_changes"].([]any); ok {
		for _, c := range changes {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := cm["type"].(string)
			if typ != "helm_release" {
				continue
			}
			name, _ := cm["name"].(string)
			change, _ := cm["change"].(map[string]any)
			after, _ := change["after"].(map[string]any)
			if after == nil {
				continue
			}
			if pin := pinFromTFAttrs(name, path, after); pin != nil {
				pins = append(pins, *pin)
			}
		}
	}
	return dedupePins(pins), warnings, nil
}

func walkTFModulePins(mod map[string]any, file string, pins *[]ChartPin) {
	resources, _ := mod["resources"].([]any)
	for _, r := range resources {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := rm["type"].(string)
		if typ != "helm_release" {
			continue
		}
		name, _ := rm["name"].(string)
		values, _ := rm["values"].(map[string]any)
		if values == nil {
			continue
		}
		if pin := pinFromTFAttrs(name, file, values); pin != nil {
			*pins = append(*pins, *pin)
		}
	}
	for _, child := range []string{"child_modules", "module_calls"} {
		_ = child
	}
	children, _ := mod["child_modules"].([]any)
	for _, c := range children {
		if cm, ok := c.(map[string]any); ok {
			walkTFModulePins(cm, file, pins)
		}
	}
}

func pinFromTFAttrs(name, file string, attrs map[string]any) *ChartPin {
	chart, _ := attrs["chart"].(string)
	repo, _ := attrs["repository"].(string)
	version, _ := attrs["version"].(string)
	release, _ := attrs["name"].(string)
	if chart == "" || repo == "" {
		return nil
	}
	if strings.HasPrefix(chart, "./") || strings.HasPrefix(chart, "../") {
		return nil
	}
	if release == "" {
		release = name
	}
	return &ChartPin{
		App:     name,
		Chart:   chart,
		RepoURL: repo,
		Version: version,
		File:    file,
		Kind:    "helm_release",
		Release: release,
	}
}

func unmarshalLoose(data []byte, v any) error {
	// Prefer JSON for terraform show -json; fall back to YAML.
	if err := json.Unmarshal(data, v); err == nil {
		return nil
	}
	return yaml.Unmarshal(data, v)
}

func dedupePins(pins []ChartPin) []ChartPin {
	seen := map[string]struct{}{}
	out := make([]ChartPin, 0, len(pins))
	for _, p := range pins {
		key := strings.ToLower(p.Kind + "|" + p.App + "|" + p.Chart + "|" + p.RepoURL + "|" + p.Version + "|" + p.File)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
