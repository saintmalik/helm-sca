package inventory

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxNestedAppDepth = 5

// hasKustomization reports whether dir contains a kustomization root.
func hasKustomization(dir string) bool {
	for _, name := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// kustomizeBuild runs kubectl kustomize (preferred) or kustomize build.
// Overridable in tests.
var kustomizeBuild = func(dir string) ([]byte, error) {
	try := func(bin string, args ...string) ([]byte, error) {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, err
		}
		cmd := exec.Command(bin, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("%s %v failed: %w: %s", bin, args, err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}

	if out, err := try("kubectl", "kustomize", dir); err == nil {
		return out, nil
	} else if !strings.Contains(err.Error(), "not found") {
		// kubectl exists but kustomize failed — try standalone before giving up.
		if out2, err2 := try("kustomize", "build", dir); err2 == nil {
			return out2, nil
		}
		return nil, err
	}
	return try("kustomize", "build", dir)
}

// inventoryPathSource expands a local Argo path: Helm chart, kustomize, or raw YAML.
func inventoryPathSource(appName, file string, src ArgoSource, opts Options, repoRoot string, depth int) ([]ImageFinding, []string) {
	var warnings []string
	local := filepath.Join(repoRoot, src.Path)

	if isLocalChartDir(local) {
		return inventoryLocalHelmPath(appName, file, src, opts, repoRoot, local)
	}

	st, err := os.Stat(local)
	if err != nil || !st.IsDir() {
		warnings = append(warnings, fmt.Sprintf("%s: local path %q not found under %s", appName, src.Path, repoRoot))
		return nil, warnings
	}

	if hasKustomization(local) {
		out, err := kustomizeBuild(local)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: kustomize failed for %q: %v", appName, src.Path, err))
			// Fall through to raw walk so we still catch embedded image refs.
		} else {
			f, w := inventoryKustomizeBundle(appName, file, src, opts, repoRoot, out, depth)
			return f, append(warnings, w...)
		}
	}

	imgs, err := WalkManifests(local, !opts.SkipStatic, !opts.SkipRegex)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: path walk failed: %v", appName, err))
		return nil, warnings
	}
	for i := range imgs {
		imgs[i].App = appName
		imgs[i].File = file
		imgs[i].RepoURL = src.RepoURL
		imgs[i].Revision = src.TargetRevision
	}
	if len(imgs) == 0 {
		warnings = append(warnings, fmt.Sprintf("%s: path %q has no extractable images", appName, src.Path))
	}
	return Dedupe(imgs), warnings
}

func inventoryLocalHelmPath(appName, file string, src ArgoSource, opts Options, repoRoot, local string) ([]ImageFinding, []string) {
	var warnings []string
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

	chartOpts := opts
	chartOpts.Chart = local
	chartOpts.Release = release
	chartOpts.Values = append(append([]string{}, valueFiles...), opts.Values...)
	if inlineFile != "" {
		chartOpts.Values = append(chartOpts.Values, inlineFile)
	}
	chartOpts.Set = setParams
	imgs, err := TemplateChart(chartOpts)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: local helm template failed: %v", appName, err))
		return nil, warnings
	}
	for i := range imgs {
		imgs[i].App = appName
		imgs[i].File = file
		imgs[i].RepoURL = src.RepoURL
		imgs[i].Revision = src.TargetRevision
		imgs[i].Chart = src.Path
	}
	return imgs, warnings
}

// inventoryKustomizeBundle extracts images from kustomize output and recursively
// inventories nested Application documents (app-of-apps), matching bash render-manifests.sh.
func inventoryKustomizeBundle(appName, file string, parent ArgoSource, opts Options, repoRoot string, data []byte, depth int) ([]ImageFinding, []string) {
	var findings []ImageFinding
	var warnings []string

	docs := bytes.Split(data, []byte("---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		var meta struct {
			Kind string `yaml:"kind"`
		}
		if err := yaml.Unmarshal(doc, &meta); err != nil {
			continue
		}
		switch meta.Kind {
		case "Application":
			if depth >= maxNestedAppDepth {
				warnings = append(warnings, fmt.Sprintf("%s: nested Application depth limit (%d) reached", appName, maxNestedAppDepth))
				continue
			}
			var app ArgoApplication
			if err := yaml.Unmarshal(doc, &app); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: nested Application parse failed: %v", appName, err))
				continue
			}
			childName := app.Metadata.Name
			if childName == "" {
				childName = appName + "/nested"
			}
			sources := []ArgoSource{}
			if app.Spec.Source != nil {
				sources = append(sources, *app.Spec.Source)
			}
			sources = append(sources, app.Spec.Sources...)
			for _, src := range sources {
				f, w := inventorySourceAtDepth(childName, file, src, opts, repoRoot, depth+1)
				findings = append(findings, f...)
				warnings = append(warnings, w...)
			}
		case "ApplicationSet":
			warnings = append(warnings, fmt.Sprintf("%s: nested ApplicationSet skipped (not expanded in v1)", appName))
		default:
			imgs := ExtractFromYAML(doc, file, !opts.SkipStatic, !opts.SkipRegex)
			for i := range imgs {
				imgs[i].App = appName
				imgs[i].RepoURL = parent.RepoURL
				imgs[i].Revision = parent.TargetRevision
			}
			findings = append(findings, imgs...)
		}
	}

	if len(findings) == 0 {
		warnings = append(warnings, fmt.Sprintf("%s: kustomize path %q produced no extractable images", appName, parent.Path))
	}
	return Dedupe(findings), warnings
}
