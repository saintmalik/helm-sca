package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ArgoApplication is a minimal Argo CD Application subset we care about.
type ArgoApplication struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Source  *ArgoSource  `yaml:"source"`
		Sources []ArgoSource `yaml:"sources"`
	} `yaml:"spec"`
}

// ArgoSource is a Helm or path source.
type ArgoSource struct {
	RepoURL        string `yaml:"repoURL"`
	Chart          string `yaml:"chart"`
	Path           string `yaml:"path"`
	TargetRevision string `yaml:"targetRevision"`
	Helm           *struct {
		ReleaseName string   `yaml:"releaseName"`
		ValueFiles  []string `yaml:"valueFiles"`
		Values      string   `yaml:"values"`
		Parameters  []struct {
			Name  string `yaml:"name"`
			Value string `yaml:"value"`
		} `yaml:"parameters"`
	} `yaml:"helm"`
}

// InventoryArgoApps walks Application YAML and templates Helm sources best-effort.
func InventoryArgoApps(opts Options) ([]ImageFinding, []string, error) {
	root := opts.ArgoApps
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
				return nil
			}
			lower := strings.ToLower(path)
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
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

	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot, _ = os.Getwd()
	}

	var findings []ImageFinding
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
				f, w := inventorySourceAtDepth(app.Metadata.Name, file, src, opts, repoRoot, 0)
				findings = append(findings, f...)
				warnings = append(warnings, w...)
			}
		}
	}

	return Dedupe(findings), warnings, nil
}

func parseApplications(path string) ([]ArgoApplication, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var apps []ArgoApplication
	docs := strings.Split(string(data), "---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var app ArgoApplication
		if err := yaml.Unmarshal([]byte(doc), &app); err != nil {
			continue
		}
		if app.Kind != "Application" && app.Kind != "ApplicationSet" {
			continue
		}
		if app.Kind == "ApplicationSet" {
			continue // ApplicationSet expansion deferred
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func inventorySource(appName, file string, src ArgoSource, opts Options, repoRoot string) ([]ImageFinding, []string) {
	return inventorySourceAtDepth(appName, file, src, opts, repoRoot, 0)
}

func inventorySourceAtDepth(appName, file string, src ArgoSource, opts Options, repoRoot string, depth int) ([]ImageFinding, []string) {
	// Local path (Helm chart, kustomize, or raw YAML) — same git repo as Application YAML.
	if src.Chart == "" && src.Path != "" {
		return inventoryPathSource(appName, file, src, opts, repoRoot, depth)
	}

	var warnings []string

	// Remote Helm chart.
	if src.Chart != "" {
		if src.RepoURL == "" {
			warnings = append(warnings, fmt.Sprintf("%s: chart %q missing repoURL", appName, src.Chart))
			return nil, warnings
		}
		release := appName
		var valueFiles []string
		var setParams []string
		var inlineFile string
		if src.Helm != nil {
			if src.Helm.ReleaseName != "" {
				release = src.Helm.ReleaseName
			}
			for _, vf := range src.Helm.ValueFiles {
				resolved := resolvePath(repoRoot, src.Path, vf)
				if _, err := os.Stat(resolved); err == nil {
					valueFiles = append(valueFiles, resolved)
				} else {
					warnings = append(warnings, fmt.Sprintf("%s: valueFile %q not found locally (skipped)", appName, vf))
				}
			}
			if strings.TrimSpace(src.Helm.Values) != "" {
				tmp, err := os.CreateTemp("", "helm-sca-values-*.yaml")
				if err == nil {
					_, _ = tmp.WriteString(src.Helm.Values)
					_ = tmp.Close()
					inlineFile = tmp.Name()
					defer os.Remove(inlineFile)
				}
			}
			for _, p := range src.Helm.Parameters {
				if p.Name != "" {
					setParams = append(setParams, fmt.Sprintf("%s=%s", p.Name, p.Value))
				}
			}
		}
		setParams = append(setParams, opts.Set...)

		rendered, err := TemplateRemoteChart(release, src.Chart, src.RepoURL, src.TargetRevision, valueFiles, setParams, inlineFile, opts.HelmBin)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: remote helm template failed (credentials/network?): %v", appName, err))
			return nil, warnings
		}
		imgs := ExtractFromYAML(rendered, file, false, false)
		for i := range imgs {
			imgs[i].App = appName
			imgs[i].Chart = src.Chart
			imgs[i].RepoURL = src.RepoURL
			imgs[i].Revision = src.TargetRevision
			imgs[i].File = file
		}
		return Dedupe(imgs), warnings
	}

	warnings = append(warnings, fmt.Sprintf("%s: no chart or path source to inventory", appName))
	return nil, warnings
}

func resolvePath(repoRoot, sourcePath, valueFile string) string {
	if filepath.IsAbs(valueFile) {
		return valueFile
	}
	// Argo valueFiles are typically relative to the source path.
	if sourcePath != "" {
		cand := filepath.Join(repoRoot, sourcePath, valueFile)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return filepath.Join(repoRoot, valueFile)
}
