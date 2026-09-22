package inventory

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var imageLineRE = regexp.MustCompile(`(?i)^\s*image:\s*["']?([^"'#\s]+)["']?`)

// ExtractFromYAML parses multi-document Kubernetes YAML and returns high-confidence
// images from pod template container specs, plus optional static/regex fallbacks.
func ExtractFromYAML(data []byte, file string, includeStatic, includeRegex bool) []ImageFinding {
	var out []ImageFinding
	docs := bytes.Split(data, []byte("---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		var root map[string]any
		if err := yaml.Unmarshal(doc, &root); err != nil {
			continue
		}
		kind, _ := root["kind"].(string)
		out = append(out, extractFromResource(root, kind, file)...)
		if includeStatic {
			collectStaticImages(root, file, &out)
		}
	}
	if includeRegex {
		out = append(out, extractRegexLines(data, file)...)
	}
	return out
}

// ExtractFromFile reads a YAML file and extracts images.
func ExtractFromFile(path string, includeStatic, includeRegex bool) ([]ImageFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ExtractFromYAML(data, path, includeStatic, includeRegex), nil
}

// WalkManifests walks a directory for .yaml/.yml files and extracts images.
func WalkManifests(root string, includeStatic, includeRegex bool) ([]ImageFinding, error) {
	var out []ImageFinding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
			return nil
		}
		findings, err := ExtractFromFile(path, includeStatic, includeRegex)
		if err != nil {
			return nil // best-effort
		}
		out = append(out, findings...)
		return nil
	})
	return out, err
}

func extractFromResource(root map[string]any, kind, file string) []ImageFinding {
	spec, _ := root["spec"].(map[string]any)
	if spec == nil {
		return nil
	}

	var podSpecs []map[string]any
	switch kind {
	case "Pod":
		podSpecs = append(podSpecs, spec)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
		if tpl, ok := spec["template"].(map[string]any); ok {
			if ps, ok := tpl["spec"].(map[string]any); ok {
				podSpecs = append(podSpecs, ps)
			}
		}
	case "CronJob":
		if jt, ok := spec["jobTemplate"].(map[string]any); ok {
			if js, ok := jt["spec"].(map[string]any); ok {
				if tpl, ok := js["template"].(map[string]any); ok {
					if ps, ok := tpl["spec"].(map[string]any); ok {
						podSpecs = append(podSpecs, ps)
					}
				}
			}
		}
	case "PodTemplate":
		if tpl, ok := root["template"].(map[string]any); ok {
			if ps, ok := tpl["spec"].(map[string]any); ok {
				podSpecs = append(podSpecs, ps)
			}
		}
	default:
		// Also try generic nested template.spec for CRDs that mirror Deployments.
		if tpl, ok := spec["template"].(map[string]any); ok {
			if ps, ok := tpl["spec"].(map[string]any); ok {
				podSpecs = append(podSpecs, ps)
			}
		}
	}

	var out []ImageFinding
	for _, ps := range podSpecs {
		out = append(out, imagesFromPodSpec(ps, kind, file)...)
	}
	return out
}

func imagesFromPodSpec(podSpec map[string]any, kind, file string) []ImageFinding {
	var out []ImageFinding
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list, ok := podSpec[key].([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			img, _ := m["image"].(string)
			img = NormalizeImageRef(img)
			if img == "" {
				continue
			}
			out = append(out, ImageFinding{
				Name:       img,
				Confidence: ConfidenceHigh,
				Source:     SourceRendered,
				File:       file,
				Kind:       kind,
			})
		}
	}
	return out
}

func collectStaticImages(node any, file string, results *[]ImageFinding) {
	switch value := node.(type) {
	case map[string]any:
		if imageValue, ok := value["image"]; ok {
			switch iv := imageValue.(type) {
			case string:
				if name := NormalizeImageRef(iv); name != "" {
					*results = append(*results, ImageFinding{
						Name:       name,
						Confidence: ConfidenceMedium,
						Source:     SourceStatic,
						File:       file,
					})
				}
			case map[string]any:
				repo, _ := iv["repository"].(string)
				tag, _ := iv["tag"].(string)
				if name := JoinImage(repo, tag); name != "" {
					*results = append(*results, ImageFinding{
						Name:       name,
						Confidence: ConfidenceMedium,
						Source:     SourceStatic,
						File:       file,
					})
				}
			}
		}
		// Common Helm values shape: image.repository + image.tag at same level.
		if repo, ok := value["repository"].(string); ok {
			if tag, ok := value["tag"].(string); ok {
				if name := JoinImage(repo, tag); name != "" && looksLikeImageRepo(repo) {
					*results = append(*results, ImageFinding{
						Name:       name,
						Confidence: ConfidenceMedium,
						Source:     SourceStatic,
						File:       file,
					})
				}
			}
		}
		for _, child := range value {
			collectStaticImages(child, file, results)
		}
	case []any:
		for _, child := range value {
			collectStaticImages(child, file, results)
		}
	}
}

func looksLikeImageRepo(repo string) bool {
	repo = strings.TrimSpace(repo)
	if repo == "" || strings.Contains(repo, " ") || strings.Contains(repo, "{{") {
		return false
	}
	// Require either a slash (org/name) or a known short name used in charts.
	return strings.Contains(repo, "/") || !strings.Contains(repo, ".")
}

func extractRegexLines(data []byte, file string) []ImageFinding {
	var out []ImageFinding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		m := imageLineRE.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		name := NormalizeImageRef(m[1])
		if name == "" {
			continue
		}
		out = append(out, ImageFinding{
			Name:       name,
			Confidence: ConfidenceLow,
			Source:     SourceRegex,
			File:       file,
			Kind:       fmt.Sprintf("line:%d", i+1),
		})
	}
	return out
}
