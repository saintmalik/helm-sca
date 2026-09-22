package recommend

import (
	"fmt"
	"io"
)

// Options is reserved for future pin-bump recommendation logic.
type Options struct {
	ArgoApps string
	OutDir   string
	MaxApps  int
}

// Run is a v1 stub. Full chart/release pin-bump scoring remains TODO.
func Run(w io.Writer, opts Options) error {
	_, err := fmt.Fprintf(w, `# helm-sca recommend (stub)

Status: not implemented in CLI v1.

Intended behavior:
- Walk Argo Application pins (chart + targetRevision / upstream release)
- Re-render a newer candidate pin
- Compare fixable High/Critical counts (Grype) vs current pin
- Emit markdown + JSON bump recommendations when the newer pin improves the score

Inputs received:
  argo-apps: %q
  out-dir:   %q
  max-apps:  %d
`, opts.ArgoApps, opts.OutDir, opts.MaxApps)
	return err
}
