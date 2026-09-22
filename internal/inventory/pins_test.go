package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitRemoteChartRef(t *testing.T) {
	repo, chart, ver := splitRemoteChartRef("oci://ghcr.io/org/charts/app:1.2.3")
	if repo != "oci://ghcr.io/org/charts" || chart != "app" || ver != "1.2.3" {
		t.Fatalf("got repo=%q chart=%q ver=%q", repo, chart, ver)
	}
}

func TestListPinsLocalChartSkipped(t *testing.T) {
	dir := t.TempDir()
	chartDir := filepath.Join(dir, "demo")
	if err := os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("name: demo\nversion: 0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pins, warnings, err := ListChartPins(Options{Chart: chartDir, RepoRoot: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 0 {
		t.Fatalf("expected no pins for local chart, got %+v", pins)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for local chart")
	}
}
