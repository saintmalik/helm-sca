package inventory

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TemplateChart runs `helm template` and extracts images from the rendered output.
func TemplateChart(opts Options) ([]ImageFinding, error) {
	helm := opts.HelmBin
	if helm == "" {
		helm = "helm"
	}
	if _, err := exec.LookPath(helm); err != nil {
		return nil, fmt.Errorf("%s not found on PATH (required for chart mode)", helm)
	}

	release := opts.Release
	if release == "" {
		release = "helm-sca"
	}

	run := func() ([]byte, error) {
		args := []string{"template", release, opts.Chart, "--skip-tests"}
		for _, f := range opts.Values {
			args = append(args, "-f", f)
		}
		for _, s := range opts.Set {
			args = append(args, "--set", s)
		}
		cmd := exec.Command(helm, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("helm template failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}

	out, err := run()
	if err != nil {
		// Best-effort: build local chart deps once, then retry.
		if isLocalChartDir(opts.Chart) && (strings.Contains(err.Error(), "helm dependency build") ||
			strings.Contains(err.Error(), "missing in charts/ directory") ||
			strings.Contains(err.Error(), "found in Chart.yaml, but missing")) {
			dep := exec.Command(helm, "dependency", "build", opts.Chart)
			_ = dep.Run()
			out, err = run()
		}
		if err != nil {
			return nil, err
		}
	}

	includeStatic := !opts.SkipStatic
	includeRegex := !opts.SkipRegex
	findings := ExtractFromYAML(out, "helm-template:"+opts.Chart, false, false)

	// Fallbacks against the chart tree when render yields nothing (or to enrich).
	if isLocalChartDir(opts.Chart) {
		if includeStatic || len(findings) == 0 {
			staticFindings, _ := WalkManifests(opts.Chart, true, false)
			for i := range staticFindings {
				staticFindings[i].Source = SourceStatic
				staticFindings[i].Confidence = ConfidenceMedium
			}
			findings = append(findings, staticFindings...)
		}
		if includeRegex {
			regexFindings, _ := WalkManifests(opts.Chart, false, true)
			findings = append(findings, regexFindings...)
		}
	}

	for i := range findings {
		findings[i].Chart = opts.Chart
	}
	return Dedupe(findings), nil
}

// TemplateRemoteChart templates a chart from a Helm repo or OCI URL.
func TemplateRemoteChart(release, chart, repoURL, version string, valuesFiles []string, set []string, inlineValuesFile string, helmBin string) ([]byte, error) {
	helm := helmBin
	if helm == "" {
		helm = "helm"
	}
	if _, err := exec.LookPath(helm); err != nil {
		return nil, fmt.Errorf("%s not found on PATH", helm)
	}
	if release == "" {
		release = "helm-sca"
	}

	args := []string{"template", release, "--skip-tests"}
	chartRef := chart
	switch {
	case strings.HasPrefix(repoURL, "oci://") && chart == "":
		// Full OCI chart URL (Flux OCIRepository).
		chartRef = strings.TrimRight(repoURL, "/")
	case strings.HasPrefix(repoURL, "oci://"):
		chartRef = strings.TrimRight(repoURL, "/") + "/" + chart
	case strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://"):
		args = append(args, "--repo", repoURL)
	case repoURL != "" && chart != "":
		// Argo often stores OCI host without scheme.
		chartRef = "oci://" + strings.TrimRight(repoURL, "/") + "/" + chart
	case strings.HasPrefix(chart, "oci://"):
		chartRef = chart
	}
	args = append(args, chartRef)
	if version != "" && version != "HEAD" {
		args = append(args, "--version", version)
	}
	for _, f := range valuesFiles {
		args = append(args, "-f", f)
	}
	if inlineValuesFile != "" {
		args = append(args, "-f", inlineValuesFile)
	}
	for _, s := range set {
		args = append(args, "--set", s)
	}

	cmd := exec.Command(helm, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm template (remote) failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func isLocalChartDir(ref string) bool {
	if ref == "" || strings.HasPrefix(ref, "oci://") || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return false
	}
	info, err := os.Stat(ref)
	if err != nil || !info.IsDir() {
		return false
	}
	_, err = os.Stat(filepath.Join(ref, "Chart.yaml"))
	return err == nil
}
