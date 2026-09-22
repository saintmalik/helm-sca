package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Score holds fixable High/Critical counts (and full severity map) across images.
type Score struct {
	High       int            `json:"high"`
	Critical   int            `json:"critical"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	Images     []string       `json:"images,omitempty"`
}

// ScoreImages runs Syft → Grype over unique image refs and returns aggregated
// High/Critical counts. onlyFixed passes --only-fixed to Grype. workDir holds
// temporary reports; when empty a temp dir is created and removed.
func ScoreImages(ctx context.Context, images []string, onlyFixed bool, workDir string) (Score, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	score := Score{BySeverity: map[string]int{}, Images: uniqueStrings(images)}
	if len(score.Images) == 0 {
		return score, nil, nil
	}

	cleanup := false
	if workDir == "" {
		tmp, err := os.MkdirTemp("", "helm-sca-score-*")
		if err != nil {
			return score, nil, err
		}
		workDir = tmp
		cleanup = true
	}
	if cleanup {
		defer os.RemoveAll(workDir)
	}

	sbomDir := filepath.Join(workDir, "sboms")
	grypeDir := filepath.Join(workDir, "grype")
	if err := os.MkdirAll(sbomDir, 0o755); err != nil {
		return score, nil, err
	}
	if err := os.MkdirAll(grypeDir, 0o755); err != nil {
		return score, nil, err
	}

	workers := DefaultWorkers
	if n := len(score.Images); workers > n {
		workers = n
	}
	outcomes := make([]imageScanOutcome, len(score.Images))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, name := range score.Images {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				outcomes[i].warnings = []string{fmt.Sprintf("score cancelled for %s: %v", name, ctx.Err())}
				return
			}
			outcomes[i] = scanOneImage(ctx, name, sbomDir, grypeDir, onlyFixed)
		}(i, name)
	}
	wg.Wait()

	var warnings []string
	for _, o := range outcomes {
		warnings = append(warnings, o.warnings...)
		for sev, n := range o.counts {
			score.BySeverity[sev] += n
		}
	}
	score.High = score.BySeverity["high"]
	score.Critical = score.BySeverity["critical"]
	return score, warnings, nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Improved reports whether candidate has a clearer High/Critical posture than current.
func Improved(current, candidate Score) bool {
	if candidate.Critical < current.Critical {
		return true
	}
	if candidate.Critical == current.Critical && candidate.High < current.High {
		return true
	}
	return false
}

// RequireTools ensures syft and grype are on PATH.
func RequireTools() error {
	if _, err := exec.LookPath("syft"); err != nil {
		return fmt.Errorf("syft not found on PATH (required for recommend scoring); install from https://github.com/anchore/syft")
	}
	if _, err := exec.LookPath("grype"); err != nil {
		return fmt.Errorf("grype not found on PATH (required for recommend scoring); install from https://github.com/anchore/grype")
	}
	return nil
}
