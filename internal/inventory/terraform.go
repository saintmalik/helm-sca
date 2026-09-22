package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// InventoryTerraform best-effort extracts images / Helm pins from Terraform or OpenTofu.
// Supports:
//   - walking .tf / .tf.json under opts.Terraform for helm_release and image-ish literals
//   - opts.TerraformJSON: terraform show -json / plan JSON (resource_changes + values.root_module)
//
// Limits (honest): no provider schema, no full graph/eval, no remote state fetch,
// interpolations (${...}) are skipped, modules are not expanded unless present in plan JSON.
func InventoryTerraform(opts Options) ([]ImageFinding, []string, error) {
	var findings []ImageFinding
	var warnings []string

	if opts.TerraformJSON != "" {
		f, w, err := inventoryTerraformJSON(opts.TerraformJSON)
		if err != nil {
			return nil, w, err
		}
		findings = append(findings, f...)
		warnings = append(warnings, w...)
	}

	if opts.Terraform != "" {
		f, w, err := inventoryTerraformHCL(opts)
		if err != nil {
			return nil, append(warnings, w...), err
		}
		findings = append(findings, f...)
		warnings = append(warnings, w...)
	}

	if opts.Terraform == "" && opts.TerraformJSON == "" {
		return nil, nil, fmt.Errorf("exactly one mode required: set --terraform and/or --terraform-json")
	}

	if len(findings) == 0 {
		warnings = append(warnings, "terraform inventory found no image refs or helm_release charts (see docs for supported shapes)")
	}
	return Dedupe(findings), warnings, nil
}

func inventoryTerraformHCL(opts Options) ([]ImageFinding, []string, error) {
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
			if strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json") {
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

	var findings []ImageFinding
	var warnings []string
	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot, _ = os.Getwd()
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: read failed: %v", file, err))
			continue
		}
		if strings.HasSuffix(strings.ToLower(file), ".tf.json") {
			f, w := parseTFJSONBytes(data, file)
			findings = append(findings, f...)
			warnings = append(warnings, w...)
			continue
		}
		f, w := parseTFHCLBestEffort(string(data), file, opts, repoRoot)
		findings = append(findings, f...)
		warnings = append(warnings, w...)
	}
	return findings, warnings, nil
}

var (
	helmReleaseBlockRE = regexp.MustCompile(`(?s)resource\s+"helm_release"\s+"([^"]+)"\s*\{(.*?)(?:\n\}\s*(?:\n|$)|$)`)
	attrStringRE       = regexp.MustCompile(`(?m)^\s*(repository|chart|version|name)\s*=\s*"([^"]+)"`)
	setBlockImageRE = regexp.MustCompile(`(?s)set\s*\{[^}]*name\s*=\s*"(?:image|[^"]*image\.repository|[^"]*\.image)"[^}]*value\s*=\s*"([^"$][^"]*)"`)
	imageLiteralRE     = regexp.MustCompile(`(?i)(?:image|container_image)\s*=\s*"([^"$][^"]+)"`)
	dockerImageRE      = regexp.MustCompile(`"(?P<ref>(?:[a-z0-9]+(?:[._-][a-z0-9]+)*\.)+[a-z]{2,}/[a-z0-9._/-]+(?::[a-z0-9._-]+)?|[a-z0-9]+/[a-z0-9._-]+:[a-z0-9._-]+)"`)
	bareVersionRE      = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([-+].*)?$`)
)

func parseTFHCLBestEffort(src, file string, opts Options, repoRoot string) ([]ImageFinding, []string) {
	var findings []ImageFinding
	var warnings []string

	for _, m := range helmReleaseBlockRE.FindAllStringSubmatch(src, -1) {
		resName := m[1]
		body := m[2]
		attrs := map[string]string{}
		for _, a := range attrStringRE.FindAllStringSubmatch(body, -1) {
			attrs[a[1]] = a[2]
		}
		chart := attrs["chart"]
		repo := attrs["repository"]
		version := attrs["version"]
		release := attrs["name"]
		if release == "" {
			release = resName
		}

		for _, imgM := range setBlockImageRE.FindAllStringSubmatch(body, -1) {
			if name := NormalizeImageRef(imgM[1]); name != "" && looksLikeContainerImage(name) {
				findings = append(findings, ImageFinding{
					Name:       name,
					Confidence: ConfidenceMedium,
					Source:     SourceStatic,
					File:       file,
					App:        resName,
					Chart:      chart,
					Kind:       "helm_release.set",
				})
			}
		}

		if chart == "" {
			warnings = append(warnings, fmt.Sprintf("%s: helm_release.%s missing chart attribute", file, resName))
			continue
		}

		// Local chart path relative to the .tf file or repo root.
		if repo == "" || !strings.HasPrefix(repo, "http") {
			local := chart
			if !filepath.IsAbs(local) {
				candidates := []string{
					filepath.Join(filepath.Dir(file), chart),
					filepath.Join(repoRoot, chart),
				}
				local = ""
				for _, c := range candidates {
					if isLocalChartDir(c) {
						local = c
						break
					}
				}
			}
			if local != "" && isLocalChartDir(local) {
				chartOpts := opts
				chartOpts.Chart = local
				chartOpts.Release = release
				imgs, err := TemplateChart(chartOpts)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: helm_release.%s template failed: %v", file, resName, err))
				} else {
					for i := range imgs {
						imgs[i].App = resName
						imgs[i].File = file
						imgs[i].Chart = chart
						imgs[i].Revision = version
					}
					findings = append(findings, imgs...)
				}
				continue
			}
		}

		if repo != "" && (strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "oci://")) {
			rendered, err := TemplateRemoteChart(release, chart, repo, version, nil, opts.Set, "", opts.HelmBin)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: helm_release.%s remote template failed: %v", file, resName, err))
				continue
			}
			imgs := ExtractFromYAML(rendered, file, false, false)
			for i := range imgs {
				imgs[i].App = resName
				imgs[i].Chart = chart
				imgs[i].RepoURL = repo
				imgs[i].Revision = version
				imgs[i].File = file
			}
			findings = append(findings, imgs...)
			continue
		}

		warnings = append(warnings, fmt.Sprintf("%s: helm_release.%s chart %q not resolved (need repository= or local chart path)", file, resName, chart))
	}

	// Generic image literals outside helm_release (kubernetes_deployment, etc.).
	for _, m := range imageLiteralRE.FindAllStringSubmatch(src, -1) {
		if name := NormalizeImageRef(m[1]); name != "" && looksLikeContainerImage(name) {
			findings = append(findings, ImageFinding{
				Name:       name,
				Confidence: ConfidenceLow,
				Source:     SourceRegex,
				File:       file,
				Kind:       "tf.image_attr",
			})
		}
	}

	return findings, warnings
}

// looksLikeContainerImage filters bare tags / versions mistaken for images.
func looksLikeContainerImage(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "${") {
		return false
	}
	// Reject pure semver / bare tags with no registry or name slash.
	if !strings.Contains(ref, "/") && !strings.Contains(ref, ":") {
		return false
	}
	if !strings.Contains(ref, "/") {
		// short name:tag like nginx:1.27 is OK; bare 1.2.3 is not.
		parts := strings.SplitN(ref, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			return false
		}
		if regexp.MustCompile(`^[0-9.]+$`).MatchString(parts[0]) {
			return false
		}
	}
	// Reject values that are only a version-like string after last colon with empty name.
	if bareVersionRE.MatchString(ref) {
		return false
	}
	return true
}

func versionOrLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func parseTFJSONBytes(data []byte, file string) ([]ImageFinding, []string) {
	// Minimal: scan string values that look like images in the JSON text.
	var findings []ImageFinding
	for _, m := range dockerImageRE.FindAllStringSubmatch(string(data), -1) {
		if name := NormalizeImageRef(m[1]); name != "" {
			findings = append(findings, ImageFinding{
				Name:       name,
				Confidence: ConfidenceLow,
				Source:     SourceRegex,
				File:       file,
				Kind:       "tf.json",
			})
		}
	}
	return findings, nil
}

func inventoryTerraformJSON(path string) ([]ImageFinding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("terraform JSON parse: %w", err)
	}

	var findings []ImageFinding
	var warnings []string

	// plan format: resource_changes[].change.after
	if rcs, ok := root["resource_changes"].([]any); ok {
		for _, rc := range rcs {
			m, ok := rc.(map[string]any)
			if !ok {
				continue
			}
			addr, _ := m["address"].(string)
			rtype, _ := m["type"].(string)
			change, _ := m["change"].(map[string]any)
			after, _ := change["after"].(map[string]any)
			if after == nil {
				continue
			}
			f, w := findingsFromTFResource(rtype, addr, after, path)
			findings = append(findings, f...)
			warnings = append(warnings, w...)
		}
	}

	// state / show format: values.root_module.resources
	if values, ok := root["values"].(map[string]any); ok {
		walkTFModule(values["root_module"], path, &findings, &warnings)
	}

	// Fallback: regex scan entire JSON for image-like strings.
	if len(findings) == 0 {
		f, _ := parseTFJSONBytes(data, path)
		findings = append(findings, f...)
		if len(f) > 0 {
			warnings = append(warnings, "terraform JSON: used literal image-string fallback (no helm_release after-values matched)")
		}
	}

	return findings, warnings, nil
}

func walkTFModule(node any, file string, findings *[]ImageFinding, warnings *[]string) {
	mod, ok := node.(map[string]any)
	if !ok {
		return
	}
	if resources, ok := mod["resources"].([]any); ok {
		for _, r := range resources {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			rtype, _ := rm["type"].(string)
			addr, _ := rm["address"].(string)
			values, _ := rm["values"].(map[string]any)
			f, w := findingsFromTFResource(rtype, addr, values, file)
			*findings = append(*findings, f...)
			*warnings = append(*warnings, w...)
		}
	}
	if children, ok := mod["child_modules"].([]any); ok {
		for _, c := range children {
			walkTFModule(c, file, findings, warnings)
		}
	}
}

func findingsFromTFResource(rtype, addr string, values map[string]any, file string) ([]ImageFinding, []string) {
	if values == nil {
		return nil, nil
	}
	var findings []ImageFinding
	var warnings []string

	switch rtype {
	case "helm_release":
		chart, _ := values["chart"].(string)
		repo, _ := values["repository"].(string)
		version, _ := values["version"].(string)
		// set blocks may appear as list of {name,value}
		if sets, ok := values["set"].([]any); ok {
			for _, s := range sets {
				sm, ok := s.(map[string]any)
				if !ok {
					continue
				}
				n, _ := sm["name"].(string)
				v, _ := sm["value"].(string)
				nl := strings.ToLower(n)
				if nl == "image" || strings.HasSuffix(nl, ".image") || strings.HasSuffix(nl, "image.repository") || nl == "image.repository" {
					if name := NormalizeImageRef(v); name != "" && looksLikeContainerImage(name) {
						findings = append(findings, ImageFinding{
							Name: name, Confidence: ConfidenceMedium, Source: SourceStatic,
							File: file, App: addr, Chart: chart, Kind: "helm_release.set",
							RepoURL: repo, Revision: version,
						})
					}
				}
			}
		}
		collectStringImages(values, file, addr, &findings)
		if chart != "" && len(findings) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s: helm_release %s chart=%s version=%s — no image attrs in plan JSON (template remotely with --flux/--chart if needed)", file, addr, chart, versionOrLatest(version)))
		}
	case "kubernetes_deployment", "kubernetes_deployment_v1",
		"kubernetes_stateful_set", "kubernetes_stateful_set_v1",
		"kubernetes_daemon_set", "kubernetes_daemon_set_v1",
		"kubernetes_cron_job", "kubernetes_cron_job_v1",
		"kubernetes_pod", "kubernetes_pod_v1",
		"kubernetes_manifest":
		collectStringImages(values, file, addr, &findings)
	default:
		// Still scan nested maps for image-like keys on unknown resources.
		collectStringImages(values, file, addr, &findings)
	}
	return findings, warnings
}

func collectStringImages(node any, file, addr string, out *[]ImageFinding) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			kl := strings.ToLower(k)
			if kl == "image" || kl == "container_image" {
				if s, ok := child.(string); ok {
					if name := NormalizeImageRef(s); name != "" && looksLikeContainerImage(name) {
						*out = append(*out, ImageFinding{
							Name: name, Confidence: ConfidenceMedium, Source: SourceStatic,
							File: file, App: addr, Kind: "tf." + k,
						})
					}
				}
			}
			collectStringImages(child, file, addr, out)
		}
	case []any:
		for _, child := range v {
			collectStringImages(child, file, addr, out)
		}
	}
}
