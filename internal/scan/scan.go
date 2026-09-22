package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/saintmalik/helm-sca/internal/inventory"
)

// DefaultWorkers caps concurrent syft/grype pairs. Image pulls dominate wall time;
// unbounded parallelism mostly thrashes registries and disks.
const DefaultWorkers = 4

// Options controls scan orchestration.
type Options struct {
	Inventory inventory.Options
	OutDir    string
	FailOn    string // none|low|medium|high|critical
	OnlyFixed bool
	Format    string
	// Workers is max concurrent syft→grype jobs. Zero means DefaultWorkers.
	Workers int
}

// Result summarizes a scan run.
type Result struct {
	Images       []string       `json:"images"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	FailedOn     string         `json:"fail_on,omitempty"`
	ReportsDir   string         `json:"reports_dir"`
}

type imageScanOutcome struct {
	warnings []string
	counts   map[string]int
}

// Run inventories images then shells out to syft and grype.
func Run(ctx context.Context, opts Options) (Result, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	inv, warnings, err := inventory.Run(opts.Inventory)
	if err != nil {
		return Result{}, warnings, err
	}

	outDir := opts.OutDir
	if outDir == "" {
		outDir = "helm-sca-out"
	}
	sbomDir := filepath.Join(outDir, "sboms")
	grypeDir := filepath.Join(outDir, "grype")
	if err := os.MkdirAll(sbomDir, 0o755); err != nil {
		return Result{}, warnings, err
	}
	if err := os.MkdirAll(grypeDir, 0o755); err != nil {
		return Result{}, warnings, err
	}

	invPath := filepath.Join(outDir, "inventory.json")
	f, err := os.Create(invPath)
	if err != nil {
		return Result{}, warnings, err
	}
	_ = inventory.Write(f, inv, "json")
	_ = f.Close()

	if _, err := exec.LookPath("syft"); err != nil {
		return Result{}, warnings, fmt.Errorf("syft not found on PATH (required for scan); install from https://github.com/anchore/syft")
	}
	if _, err := exec.LookPath("grype"); err != nil {
		return Result{}, warnings, fmt.Errorf("grype not found on PATH (required for scan); install from https://github.com/anchore/grype")
	}

	images := uniqueImageNames(inv.Images)
	result := Result{
		Images:     images,
		BySeverity: map[string]int{},
		ReportsDir: outDir,
		FailedOn:   opts.FailOn,
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	if n := len(images); n > 0 && workers > n {
		workers = n
	}

	outcomes := make([]imageScanOutcome, len(images))
	if len(images) > 0 {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i, name := range images {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					outcomes[i].warnings = []string{fmt.Sprintf("scan cancelled for %s: %v", name, ctx.Err())}
					return
				}
				outcomes[i] = scanOneImage(ctx, name, sbomDir, grypeDir, opts.OnlyFixed)
			}(i, name)
		}
		wg.Wait()
	}

	for _, o := range outcomes {
		warnings = append(warnings, o.warnings...)
		for sev, n := range o.counts {
			result.BySeverity[sev] += n
		}
	}

	threshold := strings.ToLower(strings.TrimSpace(opts.FailOn))
	if threshold == "" {
		threshold = "none"
	}
	result.FindingCount = gatedCount(result.BySeverity, threshold)

	gatePath := filepath.Join(outDir, "gate.json")
	gf, err := os.Create(gatePath)
	if err == nil {
		enc := json.NewEncoder(gf)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		_ = gf.Close()
	}

	if threshold != "none" && result.FindingCount > 0 {
		return result, warnings, fmt.Errorf("scan gate failed: %d finding(s) at or above %s", result.FindingCount, threshold)
	}
	return result, warnings, nil
}

func uniqueImageNames(findings []inventory.ImageFinding) []string {
	seen := make(map[string]struct{}, len(findings))
	out := make([]string, 0, len(findings))
	for _, img := range findings {
		if _, ok := seen[img.Name]; ok {
			continue
		}
		seen[img.Name] = struct{}{}
		out = append(out, img.Name)
	}
	return out
}

func scanOneImage(ctx context.Context, name, sbomDir, grypeDir string, onlyFixed bool) imageScanOutcome {
	var out imageScanOutcome
	safe := sanitizeFilename(name)
	sbomPath := filepath.Join(sbomDir, safe+".cdx.json")
	syftCmd := exec.CommandContext(ctx, "syft", name, "-o", "cyclonedx-json="+sbomPath, "-q")
	if combined, err := syftCmd.CombinedOutput(); err != nil {
		out.warnings = append(out.warnings, fmt.Sprintf("syft failed for %s: %v (%s)", name, err, strings.TrimSpace(string(combined))))
		return out
	}

	grypePath := filepath.Join(grypeDir, safe+".json")
	args := []string{"sbom:" + sbomPath, "-o", "json", "--file", grypePath}
	if onlyFixed {
		args = append(args, "--only-fixed")
	}
	grypeCmd := exec.CommandContext(ctx, "grype", args...)
	if combined, err := grypeCmd.CombinedOutput(); err != nil {
		// Grype exits non-zero when findings exist depending on config; still parse report if written.
		if _, statErr := os.Stat(grypePath); statErr != nil {
			out.warnings = append(out.warnings, fmt.Sprintf("grype failed for %s: %v (%s)", name, err, strings.TrimSpace(string(combined))))
			return out
		}
	}

	counts, err := countGrypeFindings(grypePath)
	if err != nil {
		out.warnings = append(out.warnings, fmt.Sprintf("parse grype report %s: %v", grypePath, err))
		return out
	}
	out.counts = counts
	return out
}

func sanitizeFilename(ref string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_")
	s := r.Replace(ref)
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

func countGrypeFindings(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report struct {
		Matches []struct {
			Vulnerability struct {
				Severity string `json:"severity"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	counts := make(map[string]int, 8)
	for _, m := range report.Matches {
		sev := strings.ToLower(m.Vulnerability.Severity)
		counts[sev]++
	}
	return counts, nil
}

func gatedCount(by map[string]int, threshold string) int {
	order := []string{"unknown", "negligible", "low", "medium", "high", "critical"}
	idx := make(map[string]int, len(order))
	for i, s := range order {
		idx[s] = i
	}
	min, ok := idx[threshold]
	if !ok {
		if threshold == "none" {
			return 0
		}
		min = idx["high"]
	}
	total := 0
	for sev, n := range by {
		if idx[sev] >= min {
			total += n
		}
	}
	return total
}
