package recommend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/saintmalik/helm-sca/internal/inventory"
	"github.com/saintmalik/helm-sca/internal/scan"
)

// Options controls recommend.
type Options struct {
	Inventory inventory.Options
	OutDir    string
	MaxApps   int
	// Candidates is how many newer versions to try (default 1 = latest only).
	Candidates int
	OnlyFixed  bool
	Format     string // markdown (default) | json | both
	// HelmBin overrides helm binary (tests).
	HelmBin string
	// DryRun skips grype scoring (resolve versions + template only). Tests use mocks via deps.
	SkipScore bool

	// Injectable deps for tests (nil = real implementations).
	ListVersions func(chart, repoURL, helmBin string) ([]string, error)
	TemplatePin  func(pin inventory.ChartPin, version, helmBin string) ([]byte, error)
	ScoreImages  func(ctx context.Context, images []string, onlyFixed bool, workDir string) (scan.Score, []string, error)
}

// Recommendation is one pin evaluation.
type Recommendation struct {
	App             string     `json:"app"`
	Chart           string     `json:"chart"`
	RepoURL         string     `json:"repoURL"`
	File            string     `json:"file"`
	Kind            string     `json:"kind"`
	Action          string     `json:"action"`
	CurrentPin      string     `json:"current_pin"`
	RecommendedPin  string     `json:"recommended_pin,omitempty"`
	Reason          string     `json:"reason"`
	CurrentCVEs     *CVECounts `json:"current_cves,omitempty"`
	RecommendedCVEs *CVECounts `json:"recommended_cves,omitempty"`
	CurrentImages   []string   `json:"current_images,omitempty"`
	CandidateImages []string   `json:"candidate_images,omitempty"`
}

// CVECounts is High/Critical fixable finding totals.
type CVECounts struct {
	High     int `json:"high"`
	Critical int `json:"critical"`
}

// Result is the recommend output document.
type Result struct {
	Recommendations []Recommendation `json:"recommendations"`
}

// Run discovers chart pins, resolves newer versions, scores current vs candidate
// image sets with Grype, and writes human-readable + JSON recommendations.
func Run(ctx context.Context, w io.Writer, opts Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.MaxApps <= 0 {
		opts.MaxApps = 12
	}
	if opts.Candidates <= 0 {
		opts.Candidates = 1
	}
	// Default OnlyFixed true unless explicitly set false by caller (zero value is false,
	// so CLI must pass true by default — see recommendCmd).
	if opts.OutDir == "" {
		opts.OutDir = "helm-sca-out"
	}
	if opts.Format == "" {
		opts.Format = "both"
	}
	if opts.HelmBin == "" {
		opts.HelmBin = "helm"
	}
	// Track whether callers injected mocks before applying defaults so unit tests
	// do not require syft/grype/helm on PATH.
	needScoreTools := opts.ScoreImages == nil
	needHelm := opts.ListVersions == nil || opts.TemplatePin == nil
	if opts.ListVersions == nil {
		opts.ListVersions = listNewerVersions
	}
	if opts.TemplatePin == nil {
		opts.TemplatePin = templatePin
	}
	if opts.ScoreImages == nil {
		opts.ScoreImages = scan.ScoreImages
	}

	pins, warnings, err := inventory.ListChartPins(opts.Inventory)
	for _, warn := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warn)
	}
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		fmt.Fprintln(w, "No remote Helm chart pins found to evaluate.")
		return writeArtifacts(opts.OutDir, Result{}, w, opts.Format, true)
	}

	if len(pins) > opts.MaxApps {
		pins = pins[:opts.MaxApps]
		fmt.Fprintf(os.Stderr, "warning: capped to --max-apps=%d pins\n", opts.MaxApps)
	}

	if !opts.SkipScore && needScoreTools {
		if err := scan.RequireTools(); err != nil {
			return err
		}
	}
	if needHelm {
		if _, err := exec.LookPath(opts.HelmBin); err != nil {
			return fmt.Errorf("%s not found on PATH (required for recommend)", opts.HelmBin)
		}
	}

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return err
	}

	var recs []Recommendation
	for _, pin := range pins {
		recs = append(recs, evaluatePin(ctx, pin, opts))
	}

	result := Result{Recommendations: recs}
	return writeArtifacts(opts.OutDir, result, w, opts.Format, false)
}

func evaluatePin(ctx context.Context, pin inventory.ChartPin, opts Options) Recommendation {
	rec := Recommendation{
		App:        pin.App,
		Chart:      pin.Chart,
		RepoURL:    pin.RepoURL,
		File:       pin.File,
		Kind:       pin.Kind,
		Action:     "none",
		CurrentPin: pin.Version,
	}
	if rec.CurrentPin == "" {
		rec.CurrentPin = "(unpinned)"
	}

	versions, err := opts.ListVersions(pin.Chart, pin.RepoURL, opts.HelmBin)
	if err != nil || len(versions) == 0 {
		rec.Reason = fmt.Sprintf("Could not resolve newer chart versions for %s from %s: %v", pin.Chart, pin.RepoURL, err)
		if err == nil {
			rec.Reason = fmt.Sprintf("No chart versions found for %s from %s (private repos need helm registry/repo auth)", pin.Chart, pin.RepoURL)
		}
		return rec
	}

	newer := filterNewer(pin.Version, versions)
	if len(newer) == 0 {
		rec.Action = "up-to-date"
		rec.RecommendedPin = versions[0]
		rec.Reason = fmt.Sprintf("Chart %s is already on latest discovered version %s. Remaining CVEs may need a newer upstream release or values overrides pinning old images.", pin.Chart, versions[0])
		return rec
	}
	if len(newer) > opts.Candidates {
		newer = newer[:opts.Candidates]
	}

	currentManifest, err := opts.TemplatePin(pin, pin.Version, opts.HelmBin)
	if err != nil {
		rec.Action = "bump-available-unverified"
		rec.RecommendedPin = newer[0]
		rec.Reason = fmt.Sprintf("Newer chart %s exists (current %s) but could not render current pin: %v — bump targetRevision and re-scan.", newer[0], pin.Version, err)
		return rec
	}
	currentImages := imageNames(inventory.ExtractFromYAML(currentManifest, pin.File, false, false))
	rec.CurrentImages = currentImages

	var currentScore scan.Score
	if !opts.SkipScore {
		work := filepath.Join(opts.OutDir, "recommend", sanitize(pin.App+"-"+pin.Version))
		var w []string
		currentScore, w, err = opts.ScoreImages(ctx, currentImages, opts.OnlyFixed, work)
		for _, msg := range w {
			fmt.Fprintln(os.Stderr, "warning:", msg)
		}
		if err != nil {
			rec.Action = "bump-available-unverified"
			rec.RecommendedPin = newer[0]
			rec.Reason = fmt.Sprintf("Newer chart %s exists but scoring current pin failed: %v", newer[0], err)
			return rec
		}
		rec.CurrentCVEs = &CVECounts{High: currentScore.High, Critical: currentScore.Critical}
	}

	best := Recommendation{}
	foundImprove := false
	for _, candVer := range newer {
		candManifest, err := opts.TemplatePin(pin, candVer, opts.HelmBin)
		if err != nil {
			continue
		}
		candImages := imageNames(inventory.ExtractFromYAML(candManifest, pin.File, false, false))
		trial := Recommendation{
			App:             pin.App,
			Chart:           pin.Chart,
			RepoURL:         pin.RepoURL,
			File:            pin.File,
			Kind:            pin.Kind,
			CurrentPin:      rec.CurrentPin,
			RecommendedPin:  candVer,
			CurrentImages:   currentImages,
			CandidateImages: candImages,
			CurrentCVEs:     rec.CurrentCVEs,
		}
		if opts.SkipScore {
			trial.Action = "bump-available-unverified"
			trial.Reason = fmt.Sprintf("Newer chart %s available (scoring skipped).", candVer)
			if !foundImprove {
				best = trial
				foundImprove = true
			}
			continue
		}
		work := filepath.Join(opts.OutDir, "recommend", sanitize(pin.App+"-"+candVer))
		candScore, w, err := opts.ScoreImages(ctx, candImages, opts.OnlyFixed, work)
		for _, msg := range w {
			fmt.Fprintln(os.Stderr, "warning:", msg)
		}
		if err != nil {
			continue
		}
		trial.RecommendedCVEs = &CVECounts{High: candScore.High, Critical: candScore.Critical}
		if scan.Improved(currentScore, candScore) {
			trial.Action = "bump-recommended"
			trial.Reason = fmt.Sprintf(
				"Bump %s %s → %s. Fixable High/Critical: %dC/%dH → %dC/%dH. Update the chart pin in %s — do not patch container image tags by hand.",
				pin.Chart, pin.Version, candVer,
				currentScore.Critical, currentScore.High, candScore.Critical, candScore.High, pin.File,
			)
			if pin.InlineValues != "" && imageOverrideRE.MatchString(pin.InlineValues) {
				trial.Reason += " Note: inline helm values override image fields — align tags when bumping the pin."
			}
			return trial
		}
		trial.Action = "bump-may-not-fix"
		trial.Reason = fmt.Sprintf(
			"Latest candidate %s exists but fixable CVE count did not improve vs %s (%dC/%dH → %dC/%dH). Wait for upstream or review values overrides.",
			candVer, pin.Version, currentScore.Critical, currentScore.High, candScore.Critical, candScore.High,
		)
		if !foundImprove || trial.Action == "bump-may-not-fix" {
			best = trial
			foundImprove = true
		}
	}

	if foundImprove {
		return best
	}
	rec.Action = "bump-available-unverified"
	rec.RecommendedPin = newer[0]
	rec.Reason = fmt.Sprintf("Newer chart %s exists (current %s) but could not compare image CVE scores (template/scan failures).", newer[0], pin.Version)
	return rec
}

var imageOverrideRE = regexp.MustCompile(`(?m)^\s*(tag|repository|registry)\s*:`)

func imageNames(findings []inventory.ImageFinding) []string {
	return uniqueImageList(findings)
}

func uniqueImageList(findings []inventory.ImageFinding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range findings {
		if f.Name == "" {
			continue
		}
		if _, ok := seen[f.Name]; ok {
			continue
		}
		seen[f.Name] = struct{}{}
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_", ".", "_")
	out := r.Replace(s)
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

func writeArtifacts(outDir string, result Result, w io.Writer, format string, alreadyWrote bool) error {
	mdPath := filepath.Join(outDir, "upgrade-recommendations.md")
	jsonPath := filepath.Join(outDir, "upgrade-recommendations.json")

	md := renderMarkdown(result)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return err
	}
	jb, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, jb, 0o644); err != nil {
		return err
	}

	switch strings.ToLower(format) {
	case "json":
		_, err = w.Write(append(jb, '\n'))
		return err
	case "markdown", "md":
		_, err = io.WriteString(w, md)
		return err
	default: // both
		if !alreadyWrote {
			_, _ = io.WriteString(w, md)
		}
		fmt.Fprintf(w, "\nWrote %s and %s\n", mdPath, jsonPath)
		return nil
	}
}

func renderMarkdown(result Result) string {
	var b strings.Builder
	b.WriteString("# Chart pin upgrade recommendations\n\n")
	b.WriteString("Bump Helm chart / `targetRevision` pins when a newer chart renders images with fewer fixable High/Critical findings (Grype `--only-fixed`). Do not hand-edit container tags in rendered YAML.\n\n")

	actionable := 0
	for _, r := range result.Recommendations {
		if r.Action == "bump-recommended" || r.Action == "bump-available-unverified" || r.Action == "bump-may-not-fix" {
			actionable++
		}
	}
	if actionable == 0 && len(result.Recommendations) == 0 {
		b.WriteString("No chart/release bumps to recommend.\n")
		return b.String()
	}
	if actionable == 0 {
		b.WriteString("No improving chart bumps found in this pass (pins may already be latest, or candidates did not reduce High/Critical).\n\n")
	}

	for _, r := range result.Recommendations {
		if r.Action == "none" && r.Reason == "" {
			continue
		}
		title := r.File
		if r.App != "" {
			title = fmt.Sprintf("%s (%s)", r.App, r.File)
		}
		b.WriteString("## `")
		b.WriteString(title)
		b.WriteString("`\n\n")
		fmt.Fprintf(&b, "**Chart:** `%s` | **Action:** `%s`\n", r.Chart, r.Action)
		if r.CurrentPin != "" {
			fmt.Fprintf(&b, "**Current pin:** `%s`\n", r.CurrentPin)
		}
		if r.RecommendedPin != "" && r.RecommendedPin != r.CurrentPin {
			fmt.Fprintf(&b, "**Recommended pin:** `%s`\n", r.RecommendedPin)
		}
		if r.CurrentCVEs != nil && r.RecommendedCVEs != nil {
			fmt.Fprintf(&b, "**Fixable CVEs (High/Critical):** %dC/%dH → %dC/%dH\n",
				r.CurrentCVEs.Critical, r.CurrentCVEs.High, r.RecommendedCVEs.Critical, r.RecommendedCVEs.High)
		}
		b.WriteString("\n")
		b.WriteString(r.Reason)
		b.WriteString("\n\n")
	}
	return b.String()
}

func templatePin(pin inventory.ChartPin, version, helmBin string) ([]byte, error) {
	var inlineFile string
	if strings.TrimSpace(pin.InlineValues) != "" {
		tmp, err := os.CreateTemp("", "helm-sca-rec-values-*.yaml")
		if err != nil {
			return nil, err
		}
		inlineFile = tmp.Name()
		_, _ = tmp.WriteString(pin.InlineValues)
		_ = tmp.Close()
		defer os.Remove(inlineFile)
	}
	return inventory.TemplateRemoteChart(pin.Release, pin.Chart, pin.RepoURL, version, pin.ValuesFiles, pin.Set, inlineFile, helmBin)
}

func listNewerVersions(chart, repoURL, helmBin string) ([]string, error) {
	versions, err := helmSearchVersions(chart, repoURL, helmBin)
	if err != nil || len(versions) == 0 {
		v, err2 := helmShowLatest(chart, repoURL, helmBin)
		if err2 != nil {
			if err != nil {
				return nil, fmt.Errorf("%v; %v", err, err2)
			}
			return nil, err2
		}
		if v != "" {
			versions = []string{v}
		}
	}
	return versions, nil
}

func helmSearchVersions(chart, repoURL, helmBin string) ([]string, error) {
	if helmBin == "" {
		helmBin = "helm"
	}
	if !(strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://")) {
		return nil, fmt.Errorf("OCI/non-HTTP repo — use helm show chart")
	}
	alias := fmt.Sprintf("helmsca-%d", hash32(repoURL))
	_ = exec.Command(helmBin, "repo", "remove", alias).Run()
	add := exec.Command(helmBin, "repo", "add", alias, repoURL)
	if out, err := add.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("helm repo add: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	defer exec.Command(helmBin, "repo", "remove", alias).Run()

	upd := exec.Command(helmBin, "repo", "update", alias)
	if out, err := upd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("helm repo update: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	cmd := exec.Command(helmBin, "search", "repo", alias+"/"+chart, "--versions", "-o", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("helm search: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	var rows []struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	var versions []string
	seen := map[string]struct{}{}
	for _, r := range rows {
		if r.Version == "" {
			continue
		}
		if _, ok := seen[r.Version]; ok {
			continue
		}
		seen[r.Version] = struct{}{}
		versions = append(versions, r.Version)
	}
	return versions, nil
}

func helmShowLatest(chart, repoURL, helmBin string) (string, error) {
	if helmBin == "" {
		helmBin = "helm"
	}
	var args []string
	switch {
	case strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://"):
		args = []string{"show", "chart", chart, "--repo", repoURL}
	case strings.HasPrefix(repoURL, "oci://"):
		ref := strings.TrimRight(repoURL, "/") + "/" + chart
		args = []string{"show", "chart", ref}
	default:
		args = []string{"show", "chart", "oci://" + strings.TrimRight(repoURL, "/") + "/" + chart}
	}
	cmd := exec.Command(helmBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm show chart: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	re := regexp.MustCompile(`(?m)^version:\s*(\S+)`)
	m := re.FindStringSubmatch(stdout.String())
	if len(m) < 2 {
		return "", fmt.Errorf("helm show chart: no version field")
	}
	return m[1], nil
}

func filterNewer(current string, versions []string) []string {
	if current == "" || current == "HEAD" || current == "(unpinned)" {
		if len(versions) == 0 {
			return nil
		}
		return versions
	}
	var out []string
	for _, v := range versions {
		if compareVersions(v, current) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// compareVersions returns 1 if a>b, -1 if a<b, 0 if equal (best-effort semver-ish).
func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	if a == b {
		return 0
	}
	ap := splitVer(a)
	bp := splitVer(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(ap) {
			ai = ap[i]
		}
		if i < len(bp) {
			bi = bp[i]
		}
		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	// Fall back to string compare for pre-release suffixes when numeric equal.
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}

func splitVer(v string) []int {
	v = strings.Split(v, "-")[0]
	v = strings.Split(v, "+")[0]
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}

func hash32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
